/**
 * Composition of `agent-threat-rules` (ATR) as a **signal**, not as a gate.
 *
 * ## Why compose rather than write our own
 *
 * `docs/ARCHITECTURE.md` decides it: *"Detection rules — Compose `agent-threat-rules` (MIT, 85
 * tool-poisoning rules, TS engine). Do not write our own regex list."* `docs/RESEARCH-BRIEF.md`
 * §4.1 says why in the other direction: `docs/IDEA.md`'s hand-written blocklist scores **0/5**
 * against the published payloads. A hand-rolled phrase list is the one thing this project has
 * measured itself out of shipping. ATR is MIT, ships a TypeScript engine, is maintained, is used
 * by Cisco AI Defense, and — the part that matters most — carries per-rule `wild_fp_rate` and
 * maturity metadata, so its own authors have already done the calibration work we would otherwise
 * be guessing at.
 *
 * ## Why the output is advisory by default
 *
 * `docs/RESEARCH-BRIEF.md` §4.2: on 64,611 servers, existing scanners flag **96.89% as risky**
 * while **fewer than 50% of sampled alerts are true positives** (arXiv:2607.11086). An AppSec
 * Santa audit found 6 of 27 Cisco mcp-scanner detections genuine (~78% FP). A detector with that
 * profile wired to `block` is a detector that gets turned off, taking the pinning engine — which
 * *is* deterministic — off with it. `docs/RESEARCH-BRIEF.md` §4.3's framing applies directly:
 * *"alert fatigue will take its toll, and users may miss signs of malicious behavior (or, worse,
 * stop using MCP security controls altogether)."*
 *
 * So the default is `"advisory"`: findings go to the side channel (contract C-2) and the verdict
 * is `allow`. `"confirm"` and `"block"` exist and are one option away, and the doc comment on each
 * says what the operator is signing up for. **Nothing in this file may say or imply that a payload
 * ATR did not flag is safe** (`docs/THREAT-MODEL.md` §3 rule 2).
 *
 * ## Zero telemetry, enforced here
 *
 * `ATREngineConfig` accepts a `reporter` that POSTs detections to "ATR Threat Cloud". toolwall's
 * non-negotiable #3 is zero telemetry and no network calls in the default path. This module never
 * constructs a reporter, never accepts one from its own options, and `rules.test.ts` asserts the
 * config object we hand to the engine has no `reporter` key. Likewise `semanticModule`,
 * `semanticJudge` and `embeddingModule` are never wired: all three are network- or model-backed
 * and `docs/THREAT-MODEL.md` §3 rule 4 keeps LLM classification out of the deterministic core.
 *
 * ## The measured numbers, and what they made us choose
 *
 * ATR grades its own rules by maturity and exposes three lanes: `enforce` (stable only), `alert`
 * (stable + test), `hunt` (everything). Measured by `test/unit/atr-fp.test.ts` on 2026-08-19,
 * `agent-threat-rules@3.5.12`, 783 rules loaded, categories restricted to the metadata-relevant
 * set, `minSeverity: "high"`:
 *
 * ```
 * lane      benign FP (31-case metadata corpus)   published payloads caught (8)
 * enforce   0/31 = 0.0%                           0/8  = 0.0%
 * alert     2/31 = 6.5%                           5/8  = 62.5%
 * hunt      2/31 = 6.5%                           5/8  = 62.5%
 * ```
 *
 * Read that honestly. **The `enforce` lane detects none of the published payloads.** Shipping it
 * would be a control that costs nothing and does nothing — a different flavour of the theater
 * §4.1 already caught us in. `alert` catches 5 of 8, including all three Invariant payloads and
 * the Trail of Bits line-jumping one, at a cost of 2 false positives, **both of them the same
 * secrets-scanner server** whose descriptions contain "private key", "~/.ssh/id_rsa" and
 * "exfiltration" because finding those is what the tool does. That is a legible, characteristic
 * failure mode rather than random noise.
 *
 * So: default lane `"alert"`, default mode `"advisory"`. A 6.5% false-positive rate is
 * unacceptable for a control that breaks tooling and entirely acceptable for one that writes a
 * line to an audit log, which is the whole argument for the advisory tier. **The guard is not
 * constructed unless an operator opts in** — nothing in `src/index.ts` builds one by default —
 * because 62.5% catch on a corpus of 8 reconstructions is not a number to auto-enable on.
 *
 * Both figures are on small corpora and must not be quoted as ecosystem rates.
 *
 * ## Cost
 *
 * `load()` parses ~780 YAML rule files. It is a startup cost, paid once, off the hot path.
 * Evaluation itself is synchronous regex matching and runs on the `tools/list` cold path only —
 * never on `tools/call`, which is where the 5ms budget lives.
 */
import type { Finding, Guard, GuardContext, Verdict } from "../../types/protocol.js";
import { ALLOW, TOOLWALL_BLOCKED } from "../../types/protocol.js";
import { readToolList } from "./surface.js";

/**
 * The slice of ATR's surface this module uses. Declared structurally rather than imported as types
 * so that a breaking change in ATR's type exports shows up here as one compile error in one file
 * instead of scattered through the guard.
 */
interface AtrRule {
  readonly id: string;
  readonly title: string;
  readonly severity: string;
  readonly tags?: { readonly category?: string; readonly [k: string]: unknown };
  readonly maturity?: string;
  readonly status?: string;
  readonly wild_fp_rate?: number;
  readonly confidence?: number;
  readonly references?: Record<string, unknown>;
}

interface AtrMatch {
  readonly rule: AtrRule;
  readonly matchedConditions: readonly string[];
  readonly matchedPatterns: readonly string[];
  readonly confidence: number;
}

interface AtrEngineLike {
  loadRules(): Promise<number>;
  evaluate(event: {
    type: string;
    timestamp: string;
    content: string;
    fields?: Record<string, string>;
    scanContext?: "mcp" | "skill";
  }): AtrMatch[];
  getRuleCount(): number;
}

/** ATR's detection lanes, least to most inclusive. See the file header. */
export type AtrLane = "enforce" | "alert" | "hunt";

/**
 * What a match does to the verdict.
 *
 * - `"advisory"` (default) — findings reach `onFinding` and the audit log; the verdict is `allow`.
 * - `"confirm"` — a human decides. Budget this: `docs/RESEARCH-BRIEF.md` §4.3 measures human
 *   confirmation at **13.6% effectiveness** (n=1,053), so a prompt on every listing is a rubber
 *   stamp, not a control.
 * - `"block"` — refuse the listing. Only defensible with a measured FP rate on *your* servers;
 *   the published ecosystem-wide numbers do not support it as a default.
 */
export type AtrMode = "advisory" | "confirm" | "block";

export interface AtrScannerOptions {
  /**
   * Detection lane. Default `"alert"`. `"enforce"` sounds safer and is measured at 0/8 catch —
   * see the table in the file header before changing this.
   */
  readonly lane?: AtrLane;
  /**
   * Only surface matches at or above this ATR severity. Default `"high"`, because the lower bands
   * are where the published false-positive numbers come from.
   */
  readonly minSeverity?: "info" | "low" | "medium" | "high" | "critical";
  /**
   * Restrict to these ATR rule categories. Default is the metadata-relevant set; ATR also ships
   * rules for runtime behaviour, model abuse and skill compromise that have no metadata artefact
   * to match against and would only add noise here.
   */
  readonly categories?: readonly string[];
  /** Pre-built engine, for tests. When absent one is constructed from the bundled rule set. */
  readonly engine?: AtrEngineLike;
  /** Cap on findings emitted per payload. Default 20. */
  readonly maxFindings?: number;
}

/** ATR categories that describe something visible in tool *metadata*. */
export const METADATA_RULE_CATEGORIES: readonly string[] = [
  "tool-poisoning",
  "prompt-injection",
  "agent-manipulation",
  "context-exfiltration",
  "privilege-escalation",
  "excessive-autonomy",
];

const SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"] as const;

function severityAtLeast(actual: string, floor: string): boolean {
  const a = SEVERITY_ORDER.indexOf(actual.toLowerCase() as (typeof SEVERITY_ORDER)[number]);
  const f = SEVERITY_ORDER.indexOf(floor as (typeof SEVERITY_ORDER)[number]);
  return a >= 0 && f >= 0 && a >= f;
}

/** Map ATR's severity vocabulary onto toolwall's. */
function toFindingSeverity(atr: string): Finding["severity"] {
  switch (atr.toLowerCase()) {
    case "critical":
      return "critical";
    case "high":
      return "high";
    case "medium":
      return "medium";
    case "low":
      return "low";
    default:
      return "info";
  }
}

/** One inspectable piece of metadata: a string plus where it came from. */
export interface MetadataUnit {
  /** RFC 6901 JSON Pointer into the payload. */
  readonly path: string;
  /** Tool name, when this unit belongs to a tool. */
  readonly toolName?: string;
  /** The text ATR evaluates. */
  readonly text: string;
}

/**
 * Flatten a `tools/list` result (or a server descriptor) into the units ATR should see.
 *
 * One event per tool rather than one per string: several tool-poisoning rules are cross-field by
 * construction — ATR-2026-00106 keys on a read-only *claim* in the description contradicted by a
 * write-capable *parameter* in the schema — and splitting the tool into per-string events would
 * make those rules structurally unable to fire. The per-tool text therefore concatenates the whole
 * pinned surface, and the JSON Pointer in the finding points at the tool, not at a guessed field.
 */
export function metadataUnits(payload: unknown, basePath = ""): MetadataUnit[] {
  const units: MetadataUnit[] = [];
  const tools = readToolList(payload);

  if (tools !== null) {
    for (let i = 0; i < tools.length; i++) {
      const tool = tools[i];
      if (tool === null || typeof tool !== "object" || Array.isArray(tool)) continue;
      const record = tool as Record<string, unknown>;
      const name = typeof record["name"] === "string" ? record["name"] : undefined;
      units.push({
        path: `${basePath}/tools/${i}`,
        ...(name === undefined ? {} : { toolName: name }),
        text: flattenStrings(record).join("\n"),
      });
    }
    return units;
  }

  if (payload !== null && typeof payload === "object" && !Array.isArray(payload)) {
    const instructions = (payload as Record<string, unknown>)["instructions"];
    if (typeof instructions === "string" && instructions.length > 0) {
      units.push({ path: `${basePath}/instructions`, text: instructions });
    }
  }
  return units;
}

/**
 * Every string in a value, in document order, **including object keys.**
 *
 * Keys are not decoration here. A JSON Schema's property *names* are metadata the model reads —
 * `write_mode`, `sidenote`, `debug_context` — and several ATR rules key on exactly that: rule
 * ATR-2026-00106 fires on a read-only claim in the description contradicted by a `write_mode`
 * parameter, and the parameter is a key, not a value. Flattening values only made that rule
 * structurally unable to fire, which a test caught.
 */
function flattenStrings(value: unknown, depth = 0): string[] {
  if (depth > 32) return [];
  if (typeof value === "string") return [value];
  if (Array.isArray(value)) return value.flatMap((v) => flattenStrings(v, depth + 1));
  if (value !== null && typeof value === "object") {
    return Object.entries(value as Record<string, unknown>).flatMap(([key, v]) => [
      key,
      ...flattenStrings(v, depth + 1),
    ]);
  }
  return [];
}

/**
 * A loaded ATR rule set, wrapped so the rest of toolwall sees `Finding[]` and never ATR's types.
 * Build with {@link createAtrScanner}; the constructor is private because an engine with no rules
 * loaded silently detects nothing, which is the worst possible failure mode for a detector.
 */
export class AtrScanner {
  readonly #engine: AtrEngineLike;
  readonly #minSeverity: string;
  readonly #categories: ReadonlySet<string>;
  readonly #maxFindings: number;
  readonly ruleCount: number;
  readonly lane: AtrLane;

  private constructor(
    engine: AtrEngineLike,
    lane: AtrLane,
    minSeverity: string,
    categories: ReadonlySet<string>,
    maxFindings: number,
    ruleCount: number,
  ) {
    this.#engine = engine;
    this.lane = lane;
    this.#minSeverity = minSeverity;
    this.#categories = categories;
    this.#maxFindings = maxFindings;
    this.ruleCount = ruleCount;
  }

  /**
   * Load the bundled rule set. Async and slow (~780 YAML files); call it once at startup.
   *
   * @throws if the rule set loads zero rules — a scanner that silently matches nothing is worse
   *   than no scanner, because it reports "clean" on everything.
   */
  static async create(options: AtrScannerOptions = {}): Promise<AtrScanner> {
    const lane = options.lane ?? "alert";
    let engine = options.engine;
    if (engine === undefined) {
      // `agent-threat-rules` is an OPTIONAL dependency: 9.3 MB unpacked for a guard that is off
      // by default. The import is dynamic and the failure is explained rather than thrown as a
      // module-resolution stack trace, because "advisory detector unavailable" must never look
      // like "toolwall is broken".
      let mod: { ATREngine: new (config: Record<string, unknown>) => AtrEngineLike };
      try {
        mod = (await import("agent-threat-rules")) as unknown as typeof mod;
      } catch (error) {
        throw new Error(
          "the optional `agent-threat-rules` package is not installed, so the advisory rule " +
            "detector cannot start. Install it (`npm i agent-threat-rules`) or leave this guard " +
            `unregistered — the pinning engine does not depend on it. Cause: ${(error as Error).message}`,
        );
      }
      // The config is written out in full, deliberately: `reporter`, `semanticModule`,
      // `semanticJudge` and `embeddingModule` are the four keys that would make this module talk
      // to the network or to a model, and their absence here is the enforcement of
      // `docs/ARCHITECTURE.md` non-negotiable #3. See `atrEngineConfig()`.
      engine = new mod.ATREngine(atrEngineConfig(lane));
    }
    const ruleCount = await engine.loadRules();
    if (ruleCount === 0) {
      throw new Error(
        "agent-threat-rules loaded 0 rules; refusing to run a detector that cannot detect " +
          "anything, because it would report every server as clean",
      );
    }
    return new AtrScanner(
      engine,
      lane,
      options.minSeverity ?? "high",
      new Set(options.categories ?? METADATA_RULE_CATEGORIES),
      options.maxFindings ?? 20,
      ruleCount,
    );
  }

  /** Evaluate one payload and return toolwall findings. Synchronous; cold path only. */
  scan(payload: unknown, basePath = ""): Finding[] {
    const findings: Finding[] = [];
    const now = new Date().toISOString();

    for (const unit of metadataUnits(payload, basePath)) {
      if (findings.length >= this.#maxFindings) break;
      // `type: "mcp_exchange"` with only `content`/`tool_name`/`tool_description` populated.
      // `tool_response`, `user_input` and `agent_output` are deliberately left unset: feeding tool
      // METADATA into a rule written for a tool RESULT is a category error that manufactures
      // false positives, and ATR's field resolver simply does not match when the field is absent.
      const matches = this.#engine.evaluate({
        type: "mcp_exchange",
        timestamp: now,
        content: unit.text,
        fields: {
          ...(unit.toolName === undefined ? {} : { tool_name: unit.toolName }),
          tool_description: unit.text,
        },
        scanContext: "mcp",
      });

      for (const match of matches) {
        if (findings.length >= this.#maxFindings) break;
        const category = typeof match.rule.tags?.category === "string" ? match.rule.tags.category : "";
        if (this.#categories.size > 0 && !this.#categories.has(category)) continue;
        if (!severityAtLeast(match.rule.severity, this.#minSeverity)) continue;
        findings.push(this.#toFinding(match, unit, category));
      }
    }
    return findings;
  }

  #toFinding(match: AtrMatch, unit: MetadataUnit, category: string): Finding {
    return {
      // Namespaced under `atr/` so a composed rule pack can never collide with a toolwall ruleId.
      ruleId: `atr/${match.rule.id}`,
      severity: toFindingSeverity(match.rule.severity),
      message:
        `agent-threat-rules ${match.rule.id} matched: ${match.rule.title}. ` +
        `This is a heuristic pattern match on server-supplied text, not a determination that the ` +
        `tool is malicious — and a tool it does NOT match is not thereby safe.`,
      locus: unit.path,
      remediation:
        "Read the flagged text yourself and decide. Published scanners in this class flag ~97% of " +
        "servers with under 50% precision, so treat this as a prompt to look, not as a finding.",
      evidence: {
        atrRuleId: match.rule.id,
        atrSeverity: match.rule.severity,
        atrCategory: category,
        atrMaturity: match.rule.maturity ?? "unknown",
        // ATR's own measured false-positive rate for this rule, where it publishes one. Carrying
        // it into the finding is the difference between an alert and an alert you can triage.
        ...(match.rule.wild_fp_rate === undefined ? {} : { atrWildFpRate: match.rule.wild_fp_rate }),
        ...(match.rule.confidence === undefined ? {} : { atrConfidence: match.rule.confidence }),
        matchConfidence: match.confidence,
        matchedConditions: match.matchedConditions,
        ...(unit.toolName === undefined ? {} : { toolName: unit.toolName }),
      },
    };
  }
}

/**
 * The exact config handed to `ATREngine`. Exported so a test can assert what is *not* in it —
 * `reporter` (Threat Cloud telemetry), `semanticModule`, `semanticJudge`, `embeddingModule`.
 */
export function atrEngineConfig(lane: AtrLane): Record<string, unknown> {
  return { lane };
}

export interface AtrAdvisoryGuardOptions {
  readonly scanner: AtrScanner;
  /** Default `"advisory"`. See {@link AtrMode}. */
  readonly mode?: AtrMode;
  readonly blockCode?: number;
  /**
   * Side channel for advisory findings (contract C-2: `{ action: "allow" }` carries no findings).
   * Wire this to the audit log or the findings are dropped on the floor.
   */
  readonly onFinding?: (finding: Finding, ctx: GuardContext) => void;
  /** Methods whose response this guard evaluates. Default {@link ATR_GUARD_RESPONSE_METHODS}. */
  readonly methods?: readonly string[];
}

/** Response-leg methods carrying metadata worth evaluating. Registered by the integrator. */
export const ATR_GUARD_RESPONSE_METHODS: readonly string[] = [
  "initialize",
  "server/discover",
  "tools/list",
];

/**
 * Raises ATR matches as findings. **Advisory by default: the verdict is `allow`.**
 *
 * Ordering note for whoever registers this: it belongs *after* `MetadataPinGuard`, for the same
 * reason contract C-10 puts identity first. If the definition drifted, the text this guard is
 * reading is attacker-controlled as of that moment and the pin finding is the one the operator
 * needs to see.
 */
export class AtrAdvisoryGuard implements Guard {
  readonly name = "metadata.atr";

  readonly #scanner: AtrScanner;
  readonly #mode: AtrMode;
  readonly #blockCode: number;
  readonly #onFinding: (finding: Finding, ctx: GuardContext) => void;
  readonly #methods: ReadonlySet<string>;

  constructor(options: AtrAdvisoryGuardOptions) {
    this.#scanner = options.scanner;
    this.#mode = options.mode ?? "advisory";
    this.#blockCode = options.blockCode ?? TOOLWALL_BLOCKED;
    this.#onFinding = options.onFinding ?? (() => undefined);
    this.#methods = new Set(options.methods ?? ATR_GUARD_RESPONSE_METHODS);
  }

  inspect(payload: unknown, ctx: GuardContext): Verdict {
    if (ctx.direction !== "response") return ALLOW;
    if (!this.#methods.has(ctx.method)) return ALLOW;

    const findings = this.#scanner.scan(payload);
    if (findings.length === 0) return ALLOW;
    for (const f of findings) this.#onFinding(f, ctx);

    switch (this.#mode) {
      case "block":
        return { action: "block", findings, code: this.#blockCode };
      case "confirm":
        return { action: "confirm", findings };
      case "advisory":
      default:
        // Findings already went to the side channel. The listing is forwarded untouched: a
        // heuristic with a published sub-50% precision does not get to break a user's tooling.
        return ALLOW;
    }
  }
}
