/**
 * Measured behaviour of the composed `agent-threat-rules` detector, in both directions.
 *
 * This is the file that decides whether ATR ships on or off by default. `docs/THREAT-MODEL.md` §3
 * rule 1 makes the FP number a merge gate, and `docs/RESEARCH-BRIEF.md` §4.2 gives the prior we
 * are testing against: published scanners in this class flag **96.89%** of servers with **under
 * 50% precision**. The numbers below are printed, per lane, so the README statement can be
 * re-derived instead of remembered.
 */
import { beforeAll, describe, expect, it } from "vitest";

import {
  ATR_GUARD_RESPONSE_METHODS,
  AtrAdvisoryGuard,
  AtrScanner,
  atrEngineConfig,
  metadataUnits,
} from "../../src/guards/metadata/rules.js";
import { BENIGN_METADATA_CORPUS } from "../fixtures/metadata/benign-metadata.js";
import { PUBLISHED_PAYLOADS } from "../fixtures/metadata/published-payloads.js";
import type { GuardContext } from "../../src/types/protocol.js";

const ctx = (method = "tools/list"): GuardContext => ({
  era: "2025-11-25",
  serverId: "srv_atr",
  direction: "response",
  method,
});

const pct = (n: number, d: number): string => (d === 0 ? "n/a" : `${((n / d) * 100).toFixed(1)}%`);

type Lane = "enforce" | "alert" | "hunt";
const LANES: readonly Lane[] = ["enforce", "alert", "hunt"];

interface LaneResult {
  readonly lane: Lane;
  readonly rules: number;
  readonly loadMs: number;
  readonly benignFlagged: number;
  readonly benignTotal: number;
  readonly flaggedIds: readonly string[];
  readonly caught: number;
  readonly payloadTotal: number;
  readonly caughtIds: readonly string[];
}

const results: LaneResult[] = [];

beforeAll(async () => {
  for (const lane of LANES) {
    const t0 = performance.now();
    const scanner = await AtrScanner.create({ lane });
    const loadMs = performance.now() - t0;

    const flaggedIds: string[] = [];
    for (const c of BENIGN_METADATA_CORPUS) {
      const payload = c.kind === "server" ? c.payload : { tools: [c.payload] };
      if (scanner.scan(payload).length > 0) flaggedIds.push(c.id);
    }

    const caughtIds: string[] = [];
    for (const p of PUBLISHED_PAYLOADS) {
      const payload =
        p.site === "server instructions"
          ? { instructions: p.payload }
          : { tools: [{ name: "tool_under_test", description: p.payload, inputSchema: { type: "object" } }] };
      if (scanner.scan(payload).length > 0) caughtIds.push(p.id);
    }

    results.push({
      lane,
      rules: scanner.ruleCount,
      loadMs,
      benignFlagged: flaggedIds.length,
      benignTotal: BENIGN_METADATA_CORPUS.length,
      flaggedIds,
      caught: caughtIds.length,
      payloadTotal: PUBLISHED_PAYLOADS.length,
      caughtIds,
    });
  }
}, 180_000);

describe("agent-threat-rules — measured, per lane", () => {
  it("prints the report the default is chosen from", () => {
    /* eslint-disable no-console */
    console.log(
      [
        "",
        "  agent-threat-rules v3.5.12 composed as a metadata detector",
        "  (categories: tool-poisoning, prompt-injection, agent-manipulation,",
        "   context-exfiltration, privilege-escalation, excessive-autonomy; minSeverity: high)",
        "",
        "  lane      rules  load(ms)   benign FP            published caught",
        "  --------  -----  --------   ------------------   ------------------",
        ...results.map(
          (r) =>
            `  ${r.lane.padEnd(8)}  ${String(r.rules).padStart(5)}  ${r.loadMs.toFixed(0).padStart(8)}   ` +
            `${String(r.benignFlagged).padStart(2)}/${r.benignTotal} = ${pct(r.benignFlagged, r.benignTotal).padEnd(6)}      ` +
            `${String(r.caught).padStart(2)}/${r.payloadTotal} = ${pct(r.caught, r.payloadTotal)}`,
        ),
        "",
        ...results.flatMap((r) => [
          `  ${r.lane}: flagged benign  -> [${r.flaggedIds.join(", ")}]`,
          `  ${r.lane}: caught payloads -> [${r.caughtIds.join(", ")}]`,
        ]),
        "",
      ].join("\n"),
    );
    /* eslint-enable no-console */
    expect(results).toHaveLength(3);
  });

  it("loads a non-trivial rule set — a scanner that matches nothing reports everything clean", () => {
    for (const r of results) expect(r.rules).toBeGreaterThan(100);
  });

  it("refuses to construct when zero rules load", async () => {
    const empty = {
      loadRules: async () => 0,
      evaluate: () => [],
      getRuleCount: () => 0,
    };
    await expect(AtrScanner.create({ engine: empty })).rejects.toThrow(/0 rules/);
  });

  it("the FP rate is at least as good in the narrower lanes as in the wider ones", () => {
    const byLane = new Map(results.map((r) => [r.lane, r]));
    expect(byLane.get("enforce")!.benignFlagged).toBeLessThanOrEqual(byLane.get("hunt")!.benignFlagged);
    expect(byLane.get("alert")!.benignFlagged).toBeLessThanOrEqual(byLane.get("hunt")!.benignFlagged);
  });

  it("the `enforce` lane is measured at zero catch — which is why it is NOT the default", () => {
    // If this ever stops being true, revisit the default: `enforce` at 0% FP with a non-zero
    // catch rate would be strictly better than `alert`.
    const enforce = results.find((r) => r.lane === "enforce")!;
    expect(enforce.benignFlagged).toBe(0);
    expect(enforce.caught).toBe(0);
    const alert = results.find((r) => r.lane === "alert")!;
    expect(alert.caught).toBeGreaterThan(enforce.caught);
  });

  it("defaults to the lane the measurement supports", async () => {
    const scanner = await AtrScanner.create();
    expect(scanner.lane).toBe("alert");
  });

  it("second corpus: Dev 3's 59 benign tool definitions, on the default lane", async () => {
    const { createWorkspace, benignCorpus } = await import("../fixtures/benign/index.js");
    const ws = createWorkspace();
    try {
      const cases = benignCorpus(ws);
      const scanner = await AtrScanner.create();
      const flagged = cases.filter((c) => scanner.scan({ tools: [c.tool] }).length > 0);
      /* eslint-disable no-console */
      console.log(
        `  second corpus (test/fixtures/benign, lane=alert): ${flagged.length}/${cases.length} ` +
          `flagged => ${pct(flagged.length, cases.length)}  [${flagged.map((c) => c.id).join(", ")}]`,
      );
      /* eslint-enable no-console */
      // No assertion on the count: this corpus was written for argument-level FP measurement and
      // its tool metadata is sparse, so a number from it is reported, not gated on.
      expect(flagged.length).toBeLessThanOrEqual(cases.length);
    } finally {
      ws.cleanup();
    }
  }, 60_000);
});

describe("zero telemetry — enforced, not assumed", () => {
  it("the engine config carries no reporter, semantic judge, or embedding module", () => {
    for (const lane of LANES) {
      const config = atrEngineConfig(lane);
      // `reporter` would POST detections to ATR Threat Cloud. `semanticModule`/`semanticJudge`
      // need an API key. `embeddingModule` loads a model. All four are network- or model-backed
      // and all four are absent by construction.
      expect(config).not.toHaveProperty("reporter");
      expect(config).not.toHaveProperty("semanticModule");
      expect(config).not.toHaveProperty("semanticJudge");
      expect(config).not.toHaveProperty("embeddingModule");
      expect(Object.keys(config)).toEqual(["lane"]);
    }
  });
});

describe("AtrAdvisoryGuard contract", () => {
  const stubMatch = {
    rule: {
      id: "ATR-2026-99999",
      title: "stub",
      severity: "high",
      tags: { category: "tool-poisoning" },
      maturity: "stable",
      wild_fp_rate: 0.2,
    },
    matchedConditions: ["c1"],
    matchedPatterns: ["p1"],
    confidence: 0.9,
  };
  const alwaysMatches = {
    loadRules: async () => 42,
    evaluate: () => [stubMatch],
    getRuleCount: () => 42,
  };

  it("is ADVISORY by default: findings are raised, the payload is forwarded", async () => {
    const scanner = await AtrScanner.create({ engine: alwaysMatches });
    const seen: string[] = [];
    const guard = new AtrAdvisoryGuard({ scanner, onFinding: (f) => seen.push(f.ruleId) });
    const verdict = guard.inspect({ tools: [{ name: "t", description: "anything" }] }, ctx());

    expect(verdict.action).toBe("allow");
    expect(seen).toEqual(["atr/ATR-2026-99999"]);
  });

  it("carries ATR's own published FP rate into the finding, so an alert can be triaged", async () => {
    const scanner = await AtrScanner.create({ engine: alwaysMatches });
    const findings = scanner.scan({ tools: [{ name: "t", description: "x" }] });
    expect(findings[0]!.evidence?.["atrWildFpRate"]).toBe(0.2);
    expect(findings[0]!.evidence?.["atrMaturity"]).toBe("stable");
  });

  it("never claims a non-match means safe", async () => {
    const scanner = await AtrScanner.create({ engine: alwaysMatches });
    const findings = scanner.scan({ tools: [{ name: "t", description: "x" }] });
    expect(findings[0]!.message).toMatch(/not thereby safe/);
    expect(findings[0]!.message).toMatch(/heuristic/);
    // THREAT-MODEL §3 rule 2: nothing here may read as "sanitized".
    expect(findings[0]!.message).not.toMatch(/sanitiz|safe to use|clean/i);
  });

  it("can be switched to confirm or block, and says what that costs", async () => {
    const scanner = await AtrScanner.create({ engine: alwaysMatches });
    const payload = { tools: [{ name: "t", description: "x" }] };
    expect(new AtrAdvisoryGuard({ scanner, mode: "confirm" }).inspect(payload, ctx()).action).toBe(
      "confirm",
    );
    expect(new AtrAdvisoryGuard({ scanner, mode: "block" }).inspect(payload, ctx()).action).toBe("block");
  });

  it("ignores the request leg and unregistered methods", async () => {
    const scanner = await AtrScanner.create({ engine: alwaysMatches });
    const guard = new AtrAdvisoryGuard({ scanner });
    expect(guard.inspect({ tools: [{}] }, { ...ctx(), direction: "request" }).action).toBe("allow");
    expect(guard.inspect({ tools: [{}] }, ctx("ping")).action).toBe("allow");
    expect(ATR_GUARD_RESPONSE_METHODS).not.toContain("tools/call");
  });

  it("namespaces every ruleId under atr/ so composed packs cannot collide with ours", async () => {
    const scanner = await AtrScanner.create({ engine: alwaysMatches });
    for (const f of scanner.scan({ tools: [{ name: "t", description: "x" }] })) {
      expect(f.ruleId.startsWith("atr/")).toBe(true);
    }
  });
});

describe("metadataUnits — one event per tool, not per string", () => {
  it("keeps a tool whole so cross-field rules can fire", () => {
    const units = metadataUnits({
      tools: [
        {
          name: "safe_query",
          description: "Runs a safe, read-only database query.",
          inputSchema: {
            type: "object",
            properties: { write_mode: { type: "boolean", default: true, description: "enables write-back" } },
          },
        },
      ],
    });
    expect(units).toHaveLength(1);
    expect(units[0]!.path).toBe("/tools/0");
    expect(units[0]!.toolName).toBe("safe_query");
    // Both halves of the ATR-2026-00106 contradiction are in one unit.
    expect(units[0]!.text).toContain("read-only");
    expect(units[0]!.text).toContain("write_mode");
  });

  it("emits a unit for server instructions", () => {
    const units = metadataUnits({ instructions: "Be careful." });
    expect(units).toEqual([{ path: "/instructions", text: "Be careful." }]);
  });

  it("emits nothing for a payload with neither", () => {
    expect(metadataUnits({ resources: [] })).toEqual([]);
  });
});
