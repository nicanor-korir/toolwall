import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { benignCorpus, corpusSummary, corpusToolSource, createWorkspace, egressPolicyDocument, starterPolicyDocument, type BenignCase, type Workspace } from "../fixtures/benign/index.js";
import { CapabilityGuard } from "../../src/guards/runtime/capability-guard.js";
import { SchemaGuard } from "../../src/guards/runtime/schema-guard.js";
import { defaultPolicy, parsePolicy, type ResolvedPolicy } from "../../src/policy/parse.js";
import { inferredPolicy } from "../../src/policy/infer.js";
import { TIERS, type StrictnessTier } from "../../src/policy/schema.js";
import type { AuditSink, Finding, GuardContext, Verdict } from "../../src/policy/contract.js";
import { isBlocking } from "../../src/policy/contract.js";

/**
 * FALSE-POSITIVE HARNESS.
 *
 * Hard project rule (docs/THREAT-MODEL.md §3, docs/ARCHITECTURE.md "Non-negotiables"): every rule
 * ships with a measured false-positive rate on a benign corpus. No FP number, no merge.
 *
 * Two definitions are reported separately because they cost the user different things:
 *   - BLOCK RATE     — benign calls the guard refuses outright. This is the number that gets a
 *                      security tool uninstalled.
 *   - FRICTION RATE  — benign calls that are blocked OR pushed to human confirmation. Confirmation
 *                      is cheaper than a block but it is not free, and a tier that confirms
 *                      everything is a tier nobody leaves on.
 *
 * Two configuration scenarios, because the honest answer differs:
 *   - DAY ZERO       — the user installed toolwall and wrote no `toolwall-policy.json`.
 *   - CONFIGURED     — the operator wrote the starter policy in `test/fixtures/benign/index.ts`.
 *
 * ## Measured result, 2026-08-19, 63-case corpus (run this file to regenerate)
 *
 * | scenario            | tier       | blocked | confirm | BLOCK RATE | FRICTION RATE |
 * |---------------------|------------|---------|---------|------------|---------------|
 * | day-zero            | permissive | 0       | 0       | 0.0%       | 0.0%          |
 * | day-zero            | balanced   | 0       | 0       | 0.0%       | 0.0%          |
 * | day-zero            | strict     | 63      | 0       | 100.0%     | 100.0%        |
 * | configured          | permissive | 0       | 0       | 0.0%       | 0.0%          |
 * | configured          | balanced   | 0       | 0       | 0.0%       | 0.0%          |
 * | configured          | strict     | 1       | 28      | 1.6%       | 46.0%         |
 * | **inferred**        | permissive | **0**   | **0**   | **0.0%**   | **0.0%**      |
 * | **inferred**        | balanced   | **0**   | **0**   | **0.0%**   | **0.0%**      |
 * | inferred            | strict     | 63      | 0       | 100.0%     | 100.0%        |
 * | inferred-notmp      | permissive | 1       | 0       | 1.6%       | 1.6%          |
 * | inferred-notmp      | balanced   | 1       | 0       | 1.6%       | 1.6%          |
 * | inferred+configured | balanced   | 0       | 0       | 0.0%       | 0.0%          |
 * | inferred+configured | strict     | 1       | 28      | 1.6%       | 46.0%         |
 *
 * ## The four cases added for the single-label metadata deny (round 3)
 *
 * The corpus grew 59 -> 63 when `deniedDestination` gained the single-label short forms `metadata`
 * and `instance-data`. A bare label is a different shape from an FQDN and could plausibly collide
 * with an internal service name, and the corpus as it stood **contained no single-label hostname
 * and no `host`-role argument at all** — so a 0.0% reading from it would have measured nothing.
 * The added cases are the collision, not a demonstration: `http://api:8080/health` (compose/k8s
 * service naming), `http://metadata-service:8080` (a name CONTAINING the denied label),
 * `https://metadata.internal.acme.example.com` (a company's own metadata service, whose leftmost
 * label is the denied one), and a bare `host: "db"` argument on a tool declaring
 * `format: "hostname"`.
 *
 * **`toolwall/egress.denied-destination` fires on 0 of the 63 in every scenario and at every
 * tier.** The starter policy's host list gained `api`, `metadata-service` and `db` alongside it,
 * because that policy is modelled as what an operator writes after looking at their own traffic
 * and those three ARE their traffic — leaving them out would have measured a mis-specified
 * fixture rather than a rule. `memory`'s citation host is still deliberately absent, so
 * `enforce: "scan"` still costs exactly the one case it always cost.
 *
 * **The inference gate (Week 3).** `inferred` at `balanced` is the row that decides whether
 * inferred capability policy may default ON, and it measures **0.0% blocked / 0.0% friction** —
 * identical to the day-zero baseline it has to beat. Inference therefore costs nothing on this
 * corpus while raising the zero-config catch rate from 0.0% to 88.2% (see `infer.test.ts`).
 *
 * Two rows are there to price the choices honestly rather than to flatter the number:
 *
 *  - **`inferred-notmp` = 1.7% blocked** is the same configuration with `includeTempDir: false`.
 *    The single block is `fs.sibling-directory-with-shared-prefix`, a legitimate access to a
 *    directory outside the workspace. So the 0.0% above depends on `os.tmpdir()` being one of the
 *    inferred roots, and that is a real widening of the grant — stated in `InferenceOptions`, and
 *    measured here rather than left implicit. Anything outside the workspace and outside the temp
 *    directory IS blocked at zero configuration, which is the point, and it is also the shape of
 *    the false positive a user would eventually hit (a second checkout elsewhere on disk).
 *  - **`inferred` at `strict` is still 100%**, unchanged. Inference infers what a tool may *touch*;
 *    it does not register the tool, so `strict`'s `unknownTool: "block"` still fires on all 59.
 *    Inference does not make `strict` usable without a policy file and must not be claimed to.
 *
 * Read those three non-zero numbers honestly:
 *
 *  - **strict + no policy = 100% blocked.** `strict` sets `unknownTool: "block"`, so with no
 *    servers declared every call is an unknown tool. This is the tier behaving exactly as
 *    specified, and `parsePolicy` emits a warning for precisely this configuration — but it means
 *    `strict` is unusable until a policy exists. It is not a default and must never become one.
 *  - **strict + policy = 47.5% friction** comes almost entirely from `capability.mutation`:
 *    strict sets `mutation: "confirm"`, so all 27 genuinely state-changing calls in the corpus ask
 *    a human. That is what the tier is for, but roughly one call in two prompting is the real cost
 *    and it should be quoted whenever `strict` is recommended.
 *  - **strict + policy = 1.7% blocked** is one case, `misc.slack-blocks-undeclared`:
 *    `schema.undeclared-property` firing on a tool whose published schema omits a parameter the
 *    API behind it genuinely accepts. Under-specified schemas are common, so this rule's cost
 *    scales with how sloppy your servers' schemas are, not with how hostile your traffic is.
 */

interface Outcome {
  readonly caseId: string;
  readonly action: Verdict["action"];
  readonly findings: readonly Finding[];
}

type Scenario =
  | "day-zero"
  | "configured"
  | "egress-roles"
  | "egress-scan"
  /** Day zero PLUS inferred capability policy — no policy file, profiles derived from pinned schemas. */
  | "inferred"
  /** Inferred policy with `includeTempDir: false`, to price that option honestly. */
  | "inferred-notmp"
  /** The starter policy with inference underneath it — inference as a floor, not a replacement. */
  | "inferred+configured";

interface Report {
  readonly tier: StrictnessTier;
  readonly scenario: Scenario;
  readonly total: number;
  readonly blocked: number;
  readonly confirmed: number;
  readonly blockRate: number;
  readonly frictionRate: number;
  readonly ruleCounts: ReadonlyMap<string, number>;
  readonly outcomes: readonly Outcome[];
}

let ws: Workspace;
let corpus: readonly BenignCase[];

beforeAll(() => {
  ws = createWorkspace();
  corpus = benignCorpus(ws);
});
afterAll(() => ws.cleanup());

function findingsOf(v: Verdict): readonly Finding[] {
  return "findings" in v ? v.findings : [];
}

function run(policy: ResolvedPolicy, tier: StrictnessTier, scenario: Scenario): Report {
  const tools = corpusToolSource(corpus);
  // `allow` verdicts carry no findings under Dev 1's contract, so informational records arrive
  // through the audit sink. They are collected here so the report can show what the guards noticed
  // on calls they permitted — but they are never counted as false positives.
  let audited: Finding[] = [];
  const audit: AuditSink = (f) => {
    audited.push(...f);
  };
  const schemaGuard = new SchemaGuard({ policy, tools, audit });
  const capabilityGuard = new CapabilityGuard({ policy, tools, baseDir: ws.root, audit });

  const outcomes: Outcome[] = [];
  const ruleCounts = new Map<string, number>();
  let blocked = 0;
  let confirmed = 0;

  for (const c of corpus) {
    const ctx: GuardContext = { era: "2025-11-25", serverId: c.serverId, direction: "request", method: "tools/call" };
    const payload = { method: "tools/call", params: { name: c.tool.name, arguments: c.args } };

    audited = [];
    const verdicts = [schemaGuard.inspect(payload.params, ctx), capabilityGuard.inspect(payload.params, ctx)];
    const findings = [...verdicts.flatMap(findingsOf), ...audited];
    // Fail-closed aggregation: the strictest verdict wins.
    const action: Verdict["action"] = verdicts.some((v) => v.action === "block")
      ? "block"
      : verdicts.some((v) => v.action === "confirm")
        ? "confirm"
        : "allow";

    if (action === "block") blocked++;
    if (action === "confirm") confirmed++;

    // Only count rules that actually contributed to friction; `info`/`low` notes are audit records,
    // not false positives, and counting them would flatter the numbers in the wrong direction.
    if (action !== "allow") {
      for (const f of findings) {
        if (!isBlocking(f.severity)) continue;
        ruleCounts.set(f.ruleId, (ruleCounts.get(f.ruleId) ?? 0) + 1);
      }
    }

    outcomes.push({ caseId: c.id, action, findings });
  }

  const total = corpus.length;
  return {
    tier,
    scenario,
    total,
    blocked,
    confirmed,
    blockRate: blocked / total,
    frictionRate: (blocked + confirmed) / total,
    ruleCounts,
    outcomes,
  };
}

function documentFor(scenario: Scenario, tier: StrictnessTier): Record<string, unknown> {
  switch (scenario) {
    case "configured":
      return { ...starterPolicyDocument(ws), tier };
    case "egress-roles":
      return { ...egressPolicyDocument(ws, "roles"), tier };
    case "egress-scan":
      return { ...egressPolicyDocument(ws, "scan"), tier };
    case "day-zero":
    case "inferred":
    case "inferred-notmp":
    case "inferred+configured":
      throw new Error(`${scenario} has no document`);
  }
}

function reportFor(tier: StrictnessTier, scenario: Scenario): Report {
  if (scenario === "day-zero") return run(defaultPolicy(tier), tier, scenario);
  if (scenario === "inferred" || scenario === "inferred-notmp") {
    // The workspace root stands in for the operator's project directory (`process.cwd()` in
    // production). Nothing else is configured: no policy file, no declared roots, no host list.
    const policy = inferredPolicy(defaultPolicy(tier), corpusToolSource(corpus), {
      roots: [ws.root],
      includeTempDir: scenario === "inferred",
    });
    return run(policy, tier, scenario);
  }
  if (scenario === "inferred+configured") {
    const parsed = parsePolicy({ ...starterPolicyDocument(ws), tier });
    if (!parsed.ok) throw new Error(`policy failed to parse: ${JSON.stringify(parsed.errors, null, 2)}`);
    return run(inferredPolicy(parsed.policy, corpusToolSource(corpus), { roots: [ws.root] }), tier, scenario);
  }
  const parsed = parsePolicy(documentFor(scenario, tier));
  if (!parsed.ok) throw new Error(`policy failed to parse: ${JSON.stringify(parsed.errors, null, 2)}`);
  return run(parsed.policy, tier, scenario);
}

const SCENARIOS: readonly Scenario[] = [
  "day-zero",
  "configured",
  "egress-roles",
  "egress-scan",
  "inferred",
  "inferred-notmp",
  "inferred+configured",
];

function pct(n: number): string {
  return `${(n * 100).toFixed(1)}%`;
}

describe("false-positive harness (benign corpus)", () => {
  it("reports measured false-positive rates for every tier and scenario", () => {
    const summary = corpusSummary();
    const reports: Report[] = [];
    for (const scenario of SCENARIOS) {
      for (const tier of TIERS) reports.push(reportFor(tier, scenario));
    }

    const lines: string[] = [];
    lines.push("");
    lines.push("=".repeat(78));
    lines.push(`FALSE-POSITIVE REPORT — benign corpus of ${summary.total} realistic tool calls`);
    lines.push(`servers: ${Object.entries(summary.byServer).map(([k, v]) => `${k}=${v}`).join("  ")}`);
    lines.push("=".repeat(78));
    lines.push("");
    lines.push("scenario     tier         blocked   confirm   BLOCK RATE   FRICTION RATE");
    lines.push("-".repeat(78));
    for (const r of reports) {
      lines.push(
        `${r.scenario.padEnd(12)} ${r.tier.padEnd(12)} ${String(r.blocked).padStart(7)} ${String(r.confirmed).padStart(9)} ${pct(r.blockRate).padStart(12)} ${pct(r.frictionRate).padStart(15)}`,
      );
    }
    lines.push("-".repeat(78));
    lines.push("");
    lines.push("Rules that fired on BENIGN traffic (per tier/scenario), with the cases they hit:");
    for (const r of reports) {
      if (r.ruleCounts.size === 0) continue;
      lines.push(`  [${r.scenario} / ${r.tier}]`);
      for (const [rule, count] of [...r.ruleCounts].sort((a, b) => b[1] - a[1])) {
        const hits = r.outcomes
          .filter((o) => o.action !== "allow" && o.findings.some((f) => f.ruleId === rule && isBlocking(f.severity)))
          .map((o) => o.caseId);
        lines.push(`    ${rule.padEnd(38)} ${String(count).padStart(3)}  e.g. ${hits.slice(0, 3).join(", ")}`);
      }
    }
    lines.push("");
    lines.push("Cases BLOCKED (true false positives — each one is a broken user workflow):");
    for (const r of reports) {
      const b = r.outcomes.filter((o) => o.action === "block").map((o) => o.caseId);
      if (b.length > 0) lines.push(`  [${r.scenario} / ${r.tier}] ${b.join(", ")}`);
    }
    lines.push("=".repeat(78));
    // eslint-disable-next-line no-console
    console.log(lines.join("\n"));

    // Every report must be present; the assertions live in the dedicated cases below.
    expect(reports).toHaveLength(SCENARIOS.length * TIERS.length);
  });

  /* ---------------- the hard gates ---------------- */

  it("BLOCK RATE is 0% at the default tier (balanced), day zero", () => {
    const r = reportFor("balanced", "day-zero");
    expect(r.outcomes.filter((o) => o.action === "block").map((o) => o.caseId)).toEqual([]);
    expect(r.blockRate).toBe(0);
  });

  it("FRICTION RATE is 0% at the default tier (balanced), day zero", () => {
    // The default posture must not merely avoid blocking — it must not nag either. A tier that
    // asks for confirmation on every benign call is a tier the user turns off within a day.
    const r = reportFor("balanced", "day-zero");
    expect(r.frictionRate).toBe(0);
  });

  it("THE INFERENCE GATE: block and friction are both 0% with inference ON at the default tier, day zero", () => {
    // The condition on shipping inferred capability policy default-ON. Inference is allowed to
    // raise the catch rate for free; it is not allowed to cost a single benign call, because the
    // 0.0% day-zero baseline is the thing that makes the default posture survivable.
    const r = reportFor("balanced", "inferred");
    expect(r.outcomes.filter((o) => o.action === "block").map((o) => o.caseId)).toEqual([]);
    expect(r.outcomes.filter((o) => o.action === "confirm").map((o) => o.caseId)).toEqual([]);
    expect(r.blockRate).toBe(0);
    expect(r.frictionRate).toBe(0);
  });

  it("inference as a floor does not disturb an operator's own policy", () => {
    const r = reportFor("balanced", "inferred+configured");
    expect(r.blockRate).toBe(0);
    expect(r.frictionRate).toBe(0);
  });

  it("prices includeTempDir honestly: dropping it costs exactly one named benign case", () => {
    // Recorded as a test so the trade cannot quietly change. If someone tightens the roots, this
    // is the number they are choosing to pay.
    const r = reportFor("balanced", "inferred-notmp");
    expect(r.outcomes.filter((o) => o.action === "block").map((o) => o.caseId)).toEqual(["fs.sibling-directory-with-shared-prefix"]);
  });

  it("BLOCK RATE is 0% at the default tier (balanced) once configured", () => {
    const r = reportFor("balanced", "configured");
    expect(r.outcomes.filter((o) => o.action === "block").map((o) => o.caseId)).toEqual([]);
  });

  it("BLOCK RATE is 0% at permissive in the day-zero and configured scenarios", () => {
    for (const scenario of ["day-zero", "configured"] as const) {
      const r = reportFor("permissive", scenario);
      expect({ scenario, blocked: r.outcomes.filter((o) => o.action === "block").map((o) => o.caseId) }).toEqual({ scenario, blocked: [] });
    }
  });

  it("declaring a server egress allowlist does not break role-bound URL traffic", () => {
    // The whole point of gating deny-by-default on `declared`: an operator who writes a sane
    // allowlist for their own hosts must not have their ordinary HTTP calls blocked.
    const r = reportFor("balanced", "egress-roles");
    expect(r.outcomes.filter((o) => o.action === "block").map((o) => o.caseId)).toEqual([]);
  });

  it("strict tier, properly configured, blocks at most one benign case and names it", () => {
    // Strict is allowed to cost something — that is what it is for — but the cost must be counted,
    // attributable to a named rule, and small. The single expected block is
    // `misc.slack-blocks-undeclared`-style under-specification via schema.undeclared-property.
    const r = reportFor("strict", "configured");
    const blocked = r.outcomes.filter((o) => o.action === "block");
    expect(blocked.length).toBeLessThanOrEqual(1);
    for (const o of blocked) {
      expect(o.findings.some((f) => isBlocking(f.severity))).toBe(true);
      for (const f of o.findings) {
        if (!isBlocking(f.severity)) continue;
        expect(f.remediation, `rule ${f.ruleId} must tell the operator what to do`).toBeTruthy();
      }
    }
  });

  it("every blocking finding anywhere in the corpus carries rule, tool and remediation", () => {
    for (const scenario of SCENARIOS) {
      for (const tier of TIERS) {
        for (const o of reportFor(tier, scenario).outcomes) {
          for (const f of o.findings) {
            if (!isBlocking(f.severity)) continue;
            const where = `${tier}/${scenario}/${o.caseId} rule=${f.ruleId}`;
            expect(f.ruleId, where).toMatch(/^toolwall\//);
            expect(f.evidence?.["tool"], where).toBeTruthy();
            expect(f.remediation, where).toBeTruthy();
            expect(f.message.length, where).toBeGreaterThan(10);
            expect(typeof f.locus, where).toBe("string");
          }
        }
      }
    }
  });

  it("no rule inspects argument content: renaming every non-role argument changes nothing", () => {
    // The structural claim behind the FP number. If a guard were secretly scanning strings for
    // `../`, `;` or backticks, replacing that content with inert text would change the verdict.
    const policy = (() => {
      const parsed = parsePolicy({ ...starterPolicyDocument(ws), tier: "balanced" });
      if (!parsed.ok) throw new Error("policy parse failed");
      return parsed.policy;
    })();
    const tools = corpusToolSource(corpus);
    const cap = new CapabilityGuard({ policy, tools, baseDir: ws.root });

    for (const c of corpus) {
      const ctx: GuardContext = { era: "2025-11-25", serverId: c.serverId, direction: "request", method: "tools/call" };
      const original = cap.inspect({ name: c.tool.name, arguments: c.args }, ctx);

      // Replace every string that is NOT bound to a capability role with dangerous-looking text.
      // Every argument name the starter policy or a `format` declaration binds to a capability
      // role. `host` is here because a `format: "hostname"` property IS role-bound — replacing its
      // value changes what the call reaches, which is the guard working, not content inspection.
      const roleBound = new Set(["path", "paths", "repo_path", "source", "destination", "url", "host"]);
      const mutated: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(c.args)) {
        mutated[k] = roleBound.has(k) ? v : typeof v === "string" ? "`; rm -rf /` ../../../etc/passwd $(whoami)" : v;
      }
      const after = cap.inspect({ name: c.tool.name, arguments: mutated }, ctx);
      expect(after.action, `case ${c.id}`).toBe(original.action);
    }
  });
});
