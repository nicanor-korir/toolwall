/**
 * C-29 · the node cap used to fail OPEN, and this is the test that says it does not any more.
 *
 * `walk()` stops at 200 000 nodes so that measurement cannot itself be weaponized (T-08). That
 * bound is right; what was wrong is that it was invisible in the result:
 *
 *  - `protoKey` came back `false` — indistinguishable from "checked and clean" — for a
 *    `__proto__` sitting past the cap;
 *  - `totalBytes` stopped accumulating, so `resultBoundsFindings` could not fire `maxTotalBytes`
 *    on precisely the payloads most likely to breach it.
 *
 * Both silences point the same way: **a payload too large to inspect was trusted more than a small
 * one.** The two `fails open today` cases below are the proof, written so they would have been RED
 * before the fix.
 *
 * The last block is the other half of the bargain. A control that starts flagging things has to be
 * measured against legitimate traffic before it ships, so it walks the whole benign corpus — every
 * result, every sequence step, every tool call's arguments — and reports the real headroom between
 * the largest benign payload and the cap.
 */
import { describe, expect, it } from "vitest";

import { measure, measureAndScan } from "../../src/guards/runtime/capability-guard.js";
import { ResultGuard } from "../../src/guards/runtime/result-guard.js";
import { defaultPolicy } from "../../src/policy/parse.js";
import type { GuardContext, Verdict } from "../../src/policy/contract.js";
import { benignCorpus, createWorkspace } from "../fixtures/benign/index.js";
import { benignResultCases, benignSequenceCases } from "../fixtures/benign/results.js";

/** A cheap payload with more nodes than the cap: one flat array of `n` numbers. */
function wideArray(n: number): unknown {
  return { items: Array.from({ length: n }, (_, i) => i) };
}

const CAP = 200_000;

function ctx(): GuardContext {
  return {
    direction: "response",
    method: "tools/call",
    serverId: "srv_cap",
    era: "2025-11-25",
    correlation: { exchangeId: "x1", correlationId: "c1" },
  };
}

function guard(): ResultGuard {
  return new ResultGuard({ policy: defaultPolicy("balanced") });
}

function findings(v: Verdict): readonly { ruleId: string; message: string; remediation: string }[] {
  return "findings" in v ? v.findings : [];
}

describe("C-29 · a payload too large to inspect is not a clean bill", () => {
  it("reports truncation on the shape instead of silently returning lower bounds", () => {
    const small = measure({ a: [1, 2, 3] });
    expect(small.truncated).toBe(false);

    const big = measure(wideArray(CAP + 50));
    expect(big.truncated).toBe(true);
    // The numbers are still there and still usable — they are just declared to be lower bounds.
    expect(big.nodes).toBe(CAP);
    expect(big.totalBytes).toBeGreaterThan(0);
  });

  it("fails open today: a __proto__ past the cap reads as `protoKey: false`, so the flag is the only signal", () => {
    const payload = wideArray(CAP + 10) as { items: unknown[] };
    // `walk` is an explicit stack, so array items are visited last-pushed-first: index 0 is the
    // LAST thing it would reach, and it never does.
    payload.items.unshift(JSON.parse('{"__proto__": {"polluted": true}}'));

    const shape = measureAndScan(payload);
    // This is the fail-open, and it is inherent: the scan cannot report what it did not visit.
    expect(shape.protoKey).toBe(false);
    // What is NOT inherent is reporting that as a clean scan. `truncated` is what separates
    // "looked and found nothing" from "stopped looking".
    expect(shape.truncated).toBe(true);
  });

  it("blocks the result rather than passing it, and names the reason", () => {
    const verdict = guard().inspect({ content: [], structuredContent: wideArray(CAP + 50) }, ctx());
    expect(verdict.action).toBe("block");
    const f = findings(verdict).find((x) => x.ruleId === "toolwall/result.bounds.not-fully-inspected");
    expect(f, `expected the truncation finding, got ${findings(verdict).map((x) => x.ruleId).join(", ")}`).toBeDefined();
    // The remediation must not send an operator to a knob that cannot help: the cap is fixed.
    expect(f?.remediation).toContain("not a policy knob");
    expect(f?.message).toContain("partially checked");
  });

  it("fails open today: the same payload satisfies every size bound it defeated", () => {
    // Every `check()` in `resultBoundsFindings` compares a number that stopped accumulating at the
    // cap, so on a truncated payload they are all satisfiable by construction. Without the
    // truncation finding this verdict would be `allow` — the bigger the result, the cleaner it
    // looked.
    const shape = measureAndScan(wideArray(CAP + 50));
    const bounds = defaultPolicy("balanced").responseFor("srv_cap").bounds;
    expect(shape.totalBytes).toBeLessThanOrEqual(bounds.maxTotalBytes);
    expect(shape.maxArrayItems).toBeGreaterThan(bounds.maxArrayItems);
  });

  it("leaves a payload under the cap exactly as it was", () => {
    const verdict = guard().inspect({ content: [{ type: "text", text: "ok" }] }, ctx());
    expect(verdict.action).toBe("allow");
    expect(findings(verdict).some((f) => f.ruleId.includes("not-fully-inspected"))).toBe(false);
  });
});

describe("C-29 · the false-positive cost of a cap that now flags things", () => {
  it("no benign payload in the corpus comes close to the cap", () => {
    const ws = createWorkspace();
    try {
      const measured: { id: string; nodes: number }[] = [];

      for (const c of benignResultCases) {
        measured.push({ id: `result:${c.id}`, nodes: measureAndScan(c.result).nodes });
        if (c.call !== undefined) {
          measured.push({ id: `args:${c.id}`, nodes: measure(c.call.arguments).nodes });
        }
      }
      for (const c of benignSequenceCases) {
        for (const [i, step] of c.steps.entries()) {
          const value = step.kind === "result" ? step.result : step.arguments;
          measured.push({ id: `seq:${c.id}#${i}`, nodes: measureAndScan(value).nodes });
        }
      }
      for (const c of benignCorpus(ws)) {
        measured.push({ id: `call:${c.id}`, nodes: measure(c.args).nodes });
      }

      const truncated = measured.filter((m) => m.nodes >= CAP);
      const worst = measured.reduce((a, b) => (b.nodes > a.nodes ? b : a));

      // eslint-disable-next-line no-console
      console.log(
        `C-29 node-cap headroom: ${measured.length} benign payloads, largest is "${worst.id}" at ` +
          `${worst.nodes} nodes against a cap of ${CAP} — ${Math.round(CAP / Math.max(1, worst.nodes))}x headroom. ` +
          `Truncated: ${truncated.length}.`,
      );

      expect(truncated, "a benign payload hit the inspection cap; the new finding would be a false positive").toEqual([]);
      // Two orders of magnitude of headroom is the claim; assert it rather than eyeballing the log.
      expect(worst.nodes * 100).toBeLessThan(CAP);
    } finally {
      ws.cleanup();
    }
  });
});
