/**
 * toolwall — the one interface everything hangs off.
 *
 * Owner: Dev 1 (stream-engine). This module is the stable contract that
 * `src/guards/**` (Dev 2, Dev 3) and `src/policy/**` (Dev 3) build against.
 * Treat every exported shape here as public API: additive changes only.
 *
 * See `docs/ARCHITECTURE.md` § "The one interface everything hangs off".
 */

// ---------------------------------------------------------------------------
// Protocol era
// ---------------------------------------------------------------------------

/**
 * Protocol era. Isolates 2025-11-25 vs 2026-07-28 so the latter is a module,
 * not a rewrite.
 *
 * Verified 2026-08-19 (`docs/RESEARCH-BRIEF.md` §3):
 * - The current published MCP revision is `2026-07-28`.
 * - `@modelcontextprotocol/sdk@1.30.0` implements `2025-11-25` and has no
 *   knowledge of `2026-07-28` (`dist/esm/types.js:2`).
 *
 * We therefore speak `2025-11-25` on the wire and keep the era as a runtime
 * value so the 2026 shape (MRTR, `server/discover`, no handshake) can be added
 * behind an adapter rather than a rewrite.
 */
export type ProtocolEra = '2025-11-25' | '2026-07-28';

/** The era toolwall actually negotiates today. See `ProtocolEra`. */
export const DEFAULT_PROTOCOL_ERA: ProtocolEra = '2025-11-25';

/** Every era toolwall knows how to reason about. */
export const KNOWN_PROTOCOL_ERAS: readonly ProtocolEra[] = ['2025-11-25', '2026-07-28'];

export function isProtocolEra(value: unknown): value is ProtocolEra {
    return typeof value === 'string' && (KNOWN_PROTOCOL_ERAS as readonly string[]).includes(value);
}

// ---------------------------------------------------------------------------
// Guard context
// ---------------------------------------------------------------------------

/**
 * Which leg of a message exchange a guard is inspecting.
 *
 * - `"request"`  — the payload is travelling *towards the untrusted server*.
 *   This covers client->server request params AND client->server notification
 *   params.
 * - `"response"` — the payload is travelling *towards the trusted client*.
 *   This covers server->client results, server->client request params
 *   (sampling/elicitation/roots, which are live requests under 2025-11-25),
 *   and server->client notification params.
 *
 * Note this names the *direction of travel*, not the JSON-RPC message kind:
 * everything arriving from the server is attacker-controlled data and is
 * inspected on the `"response"` leg regardless of whether it is a result, a
 * request, or a notification. See `docs/THREAT-MODEL.md` §0.
 */
export type GuardDirection = 'request' | 'response';

export interface GuardContext {
    readonly era: ProtocolEra;
    /**
     * Stable per-connection identity of the upstream server.
     *
     * MUST NOT be derived from `serverInfo.name`, which is self-reported and
     * which the spec explicitly says SHOULD NOT be relied upon for
     * disambiguation (T-04, `docs/RESEARCH-BRIEF.md` §1.8). toolwall derives it
     * from the spawn spec via the single implementation in
     * `src/audit/identity.ts`; `deriveServerId()` in `src/transport/spawn.ts` is
     * the adapter that turns a `SpawnSpec` into that identity. The pin store
     * keys on the same function, and must — see that file's header.
     */
    readonly serverId: string;
    readonly direction: GuardDirection;
    /** JSON-RPC method the payload belongs to, e.g. `"tools/call"`. */
    readonly method: string;
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

/**
 * Severity of a finding. Ordered least to most severe.
 *
 * `"info"` and `"low"` MUST NOT be used to justify a `block`; they exist so
 * detectors can record a weak signal without asserting a control
 * (`docs/THREAT-MODEL.md` §3).
 */
export type FindingSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export const FINDING_SEVERITY_ORDER: readonly FindingSeverity[] = ['info', 'low', 'medium', 'high', 'critical'];

/** Total order over `FindingSeverity`. Higher number = more severe. */
export function severityRank(severity: FindingSeverity): number {
    return FINDING_SEVERITY_ORDER.indexOf(severity);
}

/**
 * A JSON Pointer (RFC 6901) into the inspected payload, e.g.
 * `"/tools/3/description"` or `"/arguments/path"`. `""` means "the payload
 * itself". Guards MUST emit a pointer that actually resolves against the
 * payload they were given, so the CLI can render a diff a human can read.
 */
export type FindingLocus = string;

/**
 * One thing a guard noticed. A `Finding` is evidence, not a decision — the
 * decision is the `Verdict`.
 */
export interface Finding {
    /**
     * Stable identifier for the rule that fired, e.g. `"toolwall/pin-drift"` or
     * `"atr/tool-poisoning-0042"`. Namespaced by owner so composed rule packs
     * (`agent-threat-rules`) never collide with ours.
     */
    readonly ruleId: string;
    readonly severity: FindingSeverity;
    /**
     * Human-readable description of what was observed. State the observation,
     * never a safety claim: "description changed since pinning", not
     * "description sanitized" (`docs/THREAT-MODEL.md` §3 rule 2).
     */
    readonly message: string;
    /** Where in the payload the finding sits. See `FindingLocus`. */
    readonly locus: FindingLocus;
    /** What a human should actually do about it. One sentence, actionable. */
    readonly remediation: string;
    /**
     * Optional structured evidence (the pinned hash vs the observed hash, the
     * matched substring, ...). Must be JSON-serializable and MUST NOT contain
     * secrets — it can end up in the audit log and in a JSON-RPC error `data`.
     */
    readonly evidence?: Readonly<Record<string, unknown>>;
}

// ---------------------------------------------------------------------------
// Verdicts
// ---------------------------------------------------------------------------

export type Verdict =
    /** Forward untouched. The transport MUST NOT re-serialize or clone. */
    | { readonly action: 'allow' }
    /** Modified payload, forwarded. `payload` replaces the inspected payload. */
    | { readonly action: 'annotate'; readonly payload: unknown; readonly findings: readonly Finding[] }
    /** Needs a human (T-06). Fails closed when no `ConfirmationProvider` is wired. */
    | { readonly action: 'confirm'; readonly findings: readonly Finding[] }
    /** JSON-RPC error to the client. Can never be overridden by a transport error path. */
    | { readonly action: 'block'; readonly findings: readonly Finding[]; readonly code: number };

/** Convenience singleton; `allow` carries no data so it never needs allocating. */
export const ALLOW: Verdict = Object.freeze({ action: 'allow' });

// ---------------------------------------------------------------------------
// Guards
// ---------------------------------------------------------------------------

export interface Guard {
    readonly name: string;
    /**
     * MUST be pure and synchronous where possible — this is the sub-5ms hot path.
     *
     * `payload` is the raw JSON-RPC `params` (request leg) or `result`
     * (response leg). It is the live object the transport will forward: a guard
     * MUST NOT mutate it. To change it, return `{ action: "annotate", payload }`
     * with a new value.
     *
     * A guard that throws is treated as a `block` (fail closed on security).
     */
    inspect(payload: unknown, ctx: GuardContext): Verdict;
}

// ---------------------------------------------------------------------------
// Transport-layer extensions (Dev 1 owned, consumed by Dev 3 in week 2)
// ---------------------------------------------------------------------------

/**
 * Resolves a `confirm` verdict against a human (T-06).
 *
 * Implemented by Dev 3 (`src/guards/runtime/`) in week 2. Until one is wired
 * into the proxy, a `confirm` verdict fails closed — see
 * `GuardPipelineOptions.confirmationProvider` in `src/transport/pipeline.ts`.
 *
 * The implementation MUST NOT write to stdout: under stdio transport stdout is
 * the protocol channel. Prompt on stderr or out of band.
 */
export interface ConfirmationProvider {
    confirm(findings: readonly Finding[], ctx: GuardContext): Promise<boolean>;
}

/**
 * JSON-RPC error codes toolwall itself emits.
 *
 * `-32020`..`-32099` are reserved for the MCP spec and implementations MUST NOT
 * invent codes in that range (`docs/RESEARCH-BRIEF.md` §1.9). `GuardPipeline`
 * rewrites any guard-supplied code that lands in the reserved range.
 */
export const RESERVED_MCP_ERROR_CODE_MIN = -32099;
export const RESERVED_MCP_ERROR_CODE_MAX = -32020;

export function isReservedMcpErrorCode(code: number): boolean {
    return code >= RESERVED_MCP_ERROR_CODE_MIN && code <= RESERVED_MCP_ERROR_CODE_MAX;
}

/** JSON-RPC "Internal error". toolwall's fail-closed default. */
export const TOOLWALL_INTERNAL_ERROR = -32603;
/** JSON-RPC "Invalid request". Default code for a policy block. */
export const TOOLWALL_BLOCKED = -32600;
