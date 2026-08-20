/**
 * The guard contract, as owned by Dev 1, plus the MCP payload shapes the runtime guards need.
 *
 * `src/types/protocol.ts` is Dev 1's file and is NOT edited here. Everything below either
 * re-exports from it or adds a shape it does not define.
 *
 * Two consequences of Dev 1's contract that shaped this module:
 *
 *  1. **`{ action: "allow" }` carries no findings.** Informational audit records (a symlink was
 *     traversed but stayed in-root; a server `readOnlyHint` was honoured) therefore cannot ride
 *     back on the verdict. They are emitted to an injected `AuditSink` instead, so the audit trail
 *     survives without widening Dev 1's type. If `allow` ever grows a `findings?` field, the sink
 *     becomes redundant and these guards can drop it.
 *  2. **`Finding.locus` must resolve against the payload the guard was given**, and Dev 1 defines
 *     that payload as the raw JSON-RPC `params`. So an argument at `path` has locus
 *     `/arguments/path`, not `/path`.
 */

export type {
  ProtocolEra,
  GuardDirection,
  GuardContext,
  CorrelatedGuardContext,
  MessageCorrelation,
  FindingSeverity,
  FindingLocus,
  Finding,
  Verdict,
  Guard,
  ConfirmationProvider,
} from "../types/protocol.js";

export {
  DEFAULT_PROTOCOL_ERA,
  KNOWN_PROTOCOL_ERAS,
  isProtocolEra,
  severityRank,
  FINDING_SEVERITY_ORDER,
  ALLOW,
  isReservedMcpErrorCode,
  TOOLWALL_INTERNAL_ERROR,
  TOOLWALL_BLOCKED,
  // C-13. `correlationId` pairs a RESULT with the REQUEST it answers; `exchangeId` does not and
  // must never be used for that — an MRTR retry deliberately reuses it, so two live messages can
  // share one. See the note above `MessageCorrelation` in src/types/protocol.ts.
  correlationIdOf,
  isCorrelated,
} from "../types/protocol.js";

import type { Finding, FindingSeverity, GuardContext } from "../types/protocol.js";

/**
 * JSON-RPC "Invalid params". Used for a *schema* rejection, where the statement "these params are
 * invalid" is literally true and the client can act on it. Capability-policy blocks use Dev 1's
 * `TOOLWALL_BLOCKED` instead, because the params are well-formed — they are simply not permitted.
 * Neither code falls in the spec-reserved `-32099..-32020` range (RESEARCH-BRIEF §1.9).
 */
export const ERROR_INVALID_PARAMS = -32602;

/** `info`/`low` findings record what a guard could NOT check. They never justify a block. */
export function isBlocking(severity: FindingSeverity): boolean {
  return severity !== "info" && severity !== "low";
}

export function blockingFindings(findings: readonly Finding[]): Finding[] {
  return findings.filter((f) => isBlocking(f.severity));
}

/**
 * Where non-blocking findings go, since an `allow` verdict cannot carry them. Wired to
 * `src/audit/` by the integrator; a no-op by default.
 */
export type AuditSink = (findings: readonly Finding[], ctx: GuardContext) => void;

/* ------------------------------------------------------------------ */
/* MCP shapes (RESEARCH-BRIEF §1.4, verbatim) — not defined by Dev 1    */
/* ------------------------------------------------------------------ */

/**
 * ALL HINTS, NOT GUARANTEES. Server-supplied and therefore attacker-controlled.
 * Spec: "Clients should never make tool use decisions based on ToolAnnotations received from
 * untrusted servers."
 */
export interface ToolAnnotations {
  title?: string;
  /** default false */
  readOnlyHint?: boolean;
  /** default TRUE */
  destructiveHint?: boolean;
  /** default false */
  idempotentHint?: boolean;
  /** default TRUE */
  openWorldHint?: boolean;
}

export interface JsonSchemaNode {
  [key: string]: unknown;
}

export interface ToolDefinition {
  name: string;
  title?: string;
  description?: string;
  /** REQUIRED by the spec; `type` is always "object". */
  inputSchema: JsonSchemaNode & { type?: unknown };
  outputSchema?: JsonSchemaNode;
  annotations?: ToolAnnotations;
  _meta?: Record<string, unknown>;
}

/**
 * Read-only lookup of the tool definition currently in force for a connection.
 *
 * In production this is backed by Dev 2's pin store, so the schema being enforced is the *pinned*
 * one rather than whatever the server most recently claimed — enforcing an attacker-mutated schema
 * would let an attacker legalise their own arguments by widening the schema first (T-02).
 */
export interface ToolDefinitionSource {
  /**
   * @param scope The authorization context the definition was pinned under (`PinScope` in
   *   `src/audit/manifest.ts`). Omit it for the default scope.
   *
   *   **Why this parameter exists even though no guard passes it yet.** Pins are keyed on
   *   `(serverId, scope, kind, subject)`: `2026-07-28` says `tools/list` MAY vary by the
   *   authorization presented, so a token narrowed from `repo:write` to `repo:read` legitimately
   *   sees a different tool surface. Without the parameter a pin-backed source can only ever read
   *   the default scope, so the moment scope keying is enabled the lookup returns `undefined` for
   *   every tool and every call routes into `requireKnownSchema` — fail-safe, not fail-open, but a
   *   silently unenforceable schema layer either way.
   *
   *   `GuardContext` carries no authorization field today (the additive `authorizationScope?`
   *   requested of Dev 1 in `MetadataPinGuardOptions.resolveScope`), so the guards call this with
   *   two arguments and the session-wide scope is supplied at construction instead — see
   *   `PinnedToolDefinitionSource` in `src/index.ts`. When `GuardContext` gains the field, the
   *   guards pass `ctx.authorizationScope` here and the per-call case closes too.
   */
  get(serverId: string, toolName: string, scope?: string): ToolDefinition | undefined;
}

/** The `params` of a `tools/call` request — the payload a request-leg guard receives. */
export interface ToolCallParams {
  name: string;
  arguments?: Record<string, unknown>;
  _meta?: Record<string, unknown>;
}
