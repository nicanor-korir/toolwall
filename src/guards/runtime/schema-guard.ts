import {
  ERROR_INVALID_PARAMS,
  blockingFindings,
  type AuditSink,
  type Finding,
  type Guard,
  type GuardContext,
  type ToolCallParams,
  type ToolDefinition,
  type ToolDefinitionSource,
  type Verdict,
} from "../../policy/contract.js";
import type { ResolvedPolicy } from "../../policy/parse.js";
import type { SchemaEnforcement } from "../../policy/schema.js";
import { SchemaValidator } from "./json-schema.js";

/**
 * Strict enforcement of the tool's own declared `inputSchema`, before the call leaves the proxy.
 *
 * ## Why this is the highest-value low-FP control in the runtime area
 *
 * The `inputSchema` is a **contract the server published about itself**. Enforcing it is
 * deterministic: either `op` is one of the five enum values or it is not. There is no judgement
 * call, no heuristic, and therefore no false-positive surface beyond genuine schema/behaviour
 * mismatches on the server's side. Contrast argument string scanning, which asks an unanswerable
 * question ("is this semicolon hostile?") and gets it wrong ~78% of the time in the field.
 *
 * It is also the control that makes the capability model complete: a calculator whose schema says
 * `{ a: number, b: number, op: enum }` cannot be handed a filesystem path, not because we
 * recognised the string as a path, but because a string is not a number. That is the mechanism the
 * brief describes as "enforced by policy, not by guessing at the string".
 *
 * ## Two deliberate limits
 *
 * 1. **We enforce the PINNED definition, not the live one.** `ToolDefinitionSource` is expected to
 *    be backed by Dev 2's pin store. Enforcing a schema the server just mutated would let an
 *    attacker legalise their own arguments by widening the schema first (T-02).
 * 2. **Server-supplied `pattern` regexes are ours to compile, so they are ours to be DoS'd by.**
 *    CVE-2026-0621 is a ReDoS in the SDK's own UriTemplate handling — same class, same input
 *    source. Patterns over `maxPatternLength`, or containing a nested-quantifier construct, are not
 *    evaluated at all; a finding records the skip. We never turn the server's regex into our outage.
 */

export interface SchemaGuardOptions {
  readonly policy: ResolvedPolicy;
  readonly tools: ToolDefinitionSource;
  /**
   * Where non-blocking findings go. Dev 1's `{ action: "allow" }` carries no findings, so records
   * of what the guard could NOT check (an unresolvable $ref, a regex we refused to compile) would
   * otherwise be lost — and a silent gap is worse than a noisy one.
   */
  readonly audit?: AuditSink;
}

export class SchemaGuard implements Guard {
  readonly name = "schema-guard";
  readonly #policy: ResolvedPolicy;
  readonly #tools: ToolDefinitionSource;
  readonly #audit: AuditSink | undefined;
  /** Shared with nothing: the regex cache inside is per-guard, so one server's patterns stay there. */
  readonly #validator = new SchemaValidator();

  constructor(opts: SchemaGuardOptions) {
    this.#policy = opts.policy;
    this.#tools = opts.tools;
    this.#audit = opts.audit;
  }

  /** Emit non-blocking findings to the audit sink and return a bare `allow`. */
  #allow(findings: readonly Finding[], ctx: GuardContext): Verdict {
    if (findings.length > 0) this.#audit?.(findings, ctx);
    return { action: "allow" };
  }

  inspect(payload: unknown, ctx: GuardContext): Verdict {
    if (ctx.direction !== "request" || ctx.method !== "tools/call") return { action: "allow" };

    const params = extractToolCall(payload);
    if (params === undefined) return { action: "allow" };

    const { grant } = this.#policy.grantFor(ctx.serverId, params.name);
    const cfg = grant.schema;
    if (!cfg.enabled) return { action: "allow" };

    const tool = this.#tools.get(ctx.serverId, params.name);
    if (tool === undefined) {
      if (!cfg.requireKnownSchema) {
        return this.#allow(
          [
            {
              ruleId: "toolwall/schema.definition-unavailable",
              severity: "low",
              locus: "",
              message: "No pinned tool definition available; schema enforcement was skipped for this call.",
              remediation:
                'Ensure tools/list has been observed for this server, or set schema.requireKnownSchema = true (default at tier "strict") to fail closed instead.',
              evidence: { tool: params.name, serverId: ctx.serverId },
            },
          ],
          ctx,
        );
      }
      return {
        action: "block",
        code: ERROR_INVALID_PARAMS,
        findings: [
          {
            ruleId: "toolwall/schema.definition-unavailable",
            severity: "high",
            locus: "",
            message: "No pinned tool definition is available, and schema.requireKnownSchema is set. Failing closed.",
            remediation: "Connect and list tools before calling, or lower schema.requireKnownSchema for this server.",
            evidence: { tool: params.name, serverId: ctx.serverId },
          },
        ],
      };
    }

    const root = tool.inputSchema;
    if (root === null || typeof root !== "object" || Array.isArray(root)) {
      return this.#malformedSchema(tool, cfg, "inputSchema is not an object", ctx);
    }
    if (root["type"] !== undefined && root["type"] !== "object") {
      return this.#malformedSchema(tool, cfg, `inputSchema.type is ${JSON.stringify(root["type"])}, expected "object"`, ctx);
    }

    const args = params.arguments ?? {};
    const findings = this.#validator.validate(args, root, {
      toolName: tool.name,
      locusPrefix: "/arguments",
      ruleGroup: "schema",
      cfg,
    });

    // A finding blocks only at `medium` and above. `info`/`low` findings record things the guard
    // could NOT check (an unresolvable $ref, a regex we refused to compile) — those are our
    // limitations, and blocking a user's call because of our own limitation is not security, it is
    // just an outage. They still reach the audit log, so the gap is visible rather than silent.
    if (blockingFindings(findings).length === 0) return this.#allow(findings, ctx);
    return { action: "block", code: ERROR_INVALID_PARAMS, findings };
  }

  #malformedSchema(tool: ToolDefinition, cfg: SchemaEnforcement, detail: string, ctx: GuardContext): Verdict {
    const finding: Finding = {
      ruleId: "toolwall/schema.malformed",
      severity: cfg.requireKnownSchema ? "high" : "low",
      locus: "",
      message: `The server's published inputSchema could not be enforced: ${detail}.`,
      remediation:
        "A schema that cannot be parsed cannot constrain anything. Treat this server as unverified; report the malformed schema upstream.",
      evidence: { tool: tool.name, detail },
    };
    // Fail-open on OUR inability to parse is a bypass a poisoned server can trigger deliberately,
    // so at tiers that require a known schema we fail closed instead.
    return cfg.requireKnownSchema
      ? { action: "block", code: ERROR_INVALID_PARAMS, findings: [finding] }
      : this.#allow([finding], ctx);
  }

}

/* ---------------------------------------------------------------- */
/* Helpers                                                            */
/* ---------------------------------------------------------------- */

export function extractToolCall(payload: unknown): ToolCallParams | undefined {
  if (payload === null || typeof payload !== "object") return undefined;
  const p = payload as Record<string, unknown>;
  const candidate = (p["params"] !== null && typeof p["params"] === "object" ? p["params"] : p) as Record<string, unknown>;
  const name = candidate["name"];
  if (typeof name !== "string") return undefined;
  const argsRaw = candidate["arguments"];
  const args = argsRaw !== null && typeof argsRaw === "object" && !Array.isArray(argsRaw) ? (argsRaw as Record<string, unknown>) : undefined;
  return args === undefined ? { name } : { name, arguments: args };
}

/**
 * Re-exported from `./json-schema.js`, where the validator now lives. Kept here because tests and
 * the red-team corpus import them from this module.
 */
export { checkFormat, looksCatastrophic } from "./json-schema.js";
