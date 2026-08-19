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

/**
 * Where a payload sits in a multi-message exchange.
 *
 * Added in week 2 for MRTR (`docs/RESEARCH-BRIEF.md` §1.3). Every field is
 * optional and every field is written by **toolwall**, never copied from the
 * server: a guard may read this without treating it as attacker-controlled.
 *
 * Under `2026-07-28` a server answers a `tools/call` with
 * `resultType: "input_required"` plus `inputRequests` — sampling, elicitation
 * and roots requests embedded *inside a result*. The retry that follows carries
 * a **different JSON-RPC id**, so id alone cannot tie the two halves of the
 * exchange together. `exchangeId` does: it is stable across the whole round
 * trip, including the retry.
 */
export interface MessageCorrelation {
    /**
     * Stable per-proxy identifier for one logical exchange, preserved across an
     * `input_required` round trip even though the JSON-RPC id changes. Opaque;
     * meaningful only within a single toolwall process.
     */
    readonly exchangeId: string;
    /**
     * JSON-RPC id of the message on the leg it arrived on, when there is one.
     * Absent for notifications and for payloads toolwall originated itself
     * (the re-verification listing after a reconnect).
     */
    readonly requestId?: string | number;
    /**
     * For a payload lifted out of an enclosing message, the method of that
     * enclosing message — e.g. `"tools/call"` for a `sampling/createMessage`
     * found in its `inputRequests`. Absent for a payload inspected in its own
     * right.
     */
    readonly outerMethod?: string;
    /**
     * The server-assigned key this payload sat under in
     * `InputRequiredResult.inputRequests`. Server-controlled *data*: it is
     * carried so a guard can point at the right entry, and MUST NOT be treated
     * as trusted.
     */
    readonly inputRequestKey?: string;
    /**
     * SHA-256 of the `requestState` that accompanied this exchange, hex, or
     * `undefined` when there was none.
     *
     * The spec is explicit that `requestState` is opaque and that a client
     * **MUST NOT parse it**; toolwall hashes it for correlation and never
     * inspects, decodes, stores or rewrites the value itself. The hash is what
     * links a retry back to the exchange that asked for input.
     */
    readonly requestStateHash?: string;
    /**
     * True when this payload is the client's retry of an earlier
     * `input_required` exchange — i.e. it echoed a `requestState` toolwall has
     * seen before.
     */
    readonly isRetry?: boolean;
    /** True when toolwall originated this message rather than relaying a peer's. */
    readonly synthetic?: boolean;
}

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
    /**
     * JSON-RPC method the payload belongs to, e.g. `"tools/call"`.
     *
     * For an MRTR payload lifted out of `inputRequests` this is the **embedded**
     * method (`sampling/createMessage`, `elicitation/create`, `roots/list`), not
     * the enclosing `tools/call`. That is deliberate: a guard registered for
     * `("response", "sampling/createMessage")` then fires under **both** eras —
     * on the live server->client request under `2025-11-25`, and on the embedded
     * copy under `2026-07-28` — without knowing which era it is running in. The
     * enclosing method is available as `correlation.outerMethod`.
     */
    readonly method: string;
    /**
     * Where this payload sits in a multi-message exchange. Optional and purely
     * additive: guards written before week 2 ignore it and stay correct.
     */
    readonly correlation?: MessageCorrelation;
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

/**
 * `-32020 HeaderMismatch`, defined by the MCP spec (`docs/RESEARCH-BRIEF.md` §1.9).
 *
 * This sits **inside** the reserved `-32020..-32099` range that `GuardPipeline`
 * rewrites, and that is correct: the rule is that implementations MUST NOT
 * *invent* codes in that range. `-32020` is not invented — it is the code the
 * spec assigns to exactly this condition, "the mirrored headers disagree with
 * the JSON-RPC body". So it is emitted **by the transport**, from
 * `src/transport/headers.ts`, and never by a guard. A guard returning `-32020`
 * would still be rewritten to `-32600`, because a guard cannot know it is
 * speaking about the spec's condition rather than its own.
 */
export const MCP_HEADER_MISMATCH = -32020;

/**
 * `-32022 UnsupportedProtocolVersion`, defined by the MCP spec (§1.9).
 *
 * Emitted by `src/transport/headers.ts` when a request declares a revision that
 * does **not** mandate header/body mirroring. The spec tells intermediaries
 * enforcing policy on mirrored headers to verify the revision requires
 * header-body validation and to *reject* otherwise rather than trusting
 * unvalidated headers — so this is a refusal to police, not a claim the version
 * is unknown. Same reserved-range reasoning as `MCP_HEADER_MISMATCH`.
 */
export const MCP_UNSUPPORTED_PROTOCOL_VERSION = -32022;
