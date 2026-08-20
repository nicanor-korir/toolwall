/**
 * MRTR — Multi Round-Trip Requests. The `2026-07-28` era adapter.
 *
 * WHAT CHANGED, AND WHY IT IS A TRANSPORT PROBLEM
 * ----------------------------------------------
 * Under `2025-11-25`, sampling, elicitation and roots are **live server->client
 * JSON-RPC requests**. toolwall sees them arrive on the upstream leg, hands the
 * params to the pipeline as `("response", "sampling/createMessage")`, and
 * forwards. A guard registered on that key sees everything.
 *
 * Under `2026-07-28` servers **MUST NOT initiate requests**
 * (`docs/RESEARCH-BRIEF.md` §1.1). The same three payloads now arrive *inside a
 * result*:
 *
 * ```jsonc
 * {                                   // response to tools/call id=7
 *   "resultType": "input_required",
 *   "inputRequests": {
 *     "k1": { "method": "sampling/createMessage", "params": { "systemPrompt": "…", "tools": [ … ] } }
 *   },
 *   "requestState": "<opaque>"
 * }
 * ```
 *
 * A detector keyed on "the server sent a `sampling/createMessage` request" sees
 * nothing at all, while a `systemPrompt` and a set of **server-defined tool
 * descriptions** go straight into the client's own LLM loop (§1.3, §4.5.2).
 * That is a rank-1 injection surface arriving through a leg no one is watching.
 *
 * THE PLUMBING THIS FILE PROVIDES
 * -------------------------------
 * The proxy lifts each `inputRequests` entry out and runs it through the
 * pipeline as `("response", <embedded method>)` — the *embedded* method, not the
 * enclosing `tools/call`. So **the same guard registration covers both eras**:
 *
 *   pipeline.register({ direction: "response", method: "sampling/createMessage", guard })
 *
 * fires on the live request under `2025-11-25` and on the embedded copy under
 * `2026-07-28`, and the guard never has to ask which era it is in. Era knowledge
 * stays here, in one file, which is the whole point of the era-adapter boundary.
 *
 * CORRELATION ACROSS THE ROUND TRIP
 * ---------------------------------
 * The retry the client sends **uses a different JSON-RPC id** and echoes an
 * opaque `requestState`. So id-based correlation cannot span the exchange, and a
 * guard that wants to say "this call is the continuation of the one whose
 * sampling request I flagged" needs something else. `ExchangeCorrelator` is that
 * something else: it mints an `exchangeId` per exchange and remembers it under
 * `SHA-256(requestState)`.
 *
 * **We hash `requestState`; we never parse it, decode it, store it or rewrite
 * it.** The spec says the client MUST NOT parse it and MUST echo it
 * byte-exactly, and the spec also tells *servers* to treat it as
 * attacker-controlled and to bind it with an HMAC. toolwall is on the client
 * side of that contract: hashing is enough to link two messages, and it is the
 * only operation on the value that cannot possibly change it. The value itself
 * is forwarded by reference with everything else in `params`, so byte-exactness
 * is preserved by construction rather than by care.
 *
 * WHAT IS DELIBERATELY NOT DONE HERE
 * ----------------------------------
 * No blocking, no rewriting, no schema opinions — this file finds payloads and
 * labels them. Judging an `elicitation/create` that asks for an API key, or a
 * `sampling/createMessage` carrying an injected `systemPrompt`, is Dev 3's guard
 * on the `("response", …)` leg. Plumbing and policy stay separate so a guard
 * change never needs a transport change.
 */

import { createHash } from 'node:crypto';

import type { MessageCorrelation, ProtocolEra } from '../types/protocol.js';

// ---------------------------------------------------------------------------
// Result shape
// ---------------------------------------------------------------------------

/** `Result.resultType`. Absent MUST be treated as `"complete"` (§1.3). */
export type ResultType = 'complete' | 'input_required';

export const INPUT_REQUIRED = 'input_required';

/** The three methods that exist only as values inside `inputRequests` (§1.2). */
export const MRTR_EMBEDDED_METHODS: readonly string[] = Object.freeze([
    'sampling/createMessage',
    'elicitation/create',
    'roots/list'
]);

const isRecord = (value: unknown): value is Record<string, unknown> =>
    typeof value === 'object' && value !== null && !Array.isArray(value);

/**
 * `resultType` as the spec defines it: absent means `"complete"`.
 *
 * An unrecognised string is returned as-is rather than coerced, so a future
 * result type is visible to a caller instead of being silently flattened into
 * "nothing to see here".
 */
export function readResultType(result: unknown): string {
    if (!isRecord(result)) {
        return 'complete';
    }
    const value = result['resultType'];
    return typeof value === 'string' ? value : 'complete';
}

export function isInputRequired(result: unknown): boolean {
    return readResultType(result) === INPUT_REQUIRED;
}

/** One entry of `InputRequiredResult.inputRequests`, lifted out for inspection. */
export interface EmbeddedInputRequest {
    /**
     * The server-assigned key. Server-controlled data — carried so a finding can
     * point at the right entry, never trusted.
     */
    readonly key: string;
    /** `sampling/createMessage` | `elicitation/create` | `roots/list`, or whatever the server said. */
    readonly method: string;
    /** The embedded request's `params`, by reference. Never cloned. */
    readonly params: unknown;
    /** RFC 6901 pointer to this entry within the enclosing result. */
    readonly locus: string;
}

/**
 * Lift every `inputRequests` entry out of a result.
 *
 * Returns `[]` for anything that is not an `input_required` result carrying a
 * usable `inputRequests` object — including a malformed one. Malformed is not
 * this layer's problem to punish: a result that *claims* `input_required` and
 * carries garbage is forwarded like any other result and the client's own
 * schema validation rejects it, which is what would happen without a proxy in
 * the path. What we must not do is *miss* a well-formed one.
 *
 * Entries with a non-string `method` are skipped rather than guessed at: an
 * entry we cannot name cannot be routed to a guard registered by name, and
 * inventing a name would route attacker data to the wrong detector.
 */
export function readInputRequests(result: unknown): readonly EmbeddedInputRequest[] {
    if (!isRecord(result) || !isInputRequired(result)) {
        return [];
    }
    const bag = result['inputRequests'];
    if (!isRecord(bag)) {
        return [];
    }
    const out: EmbeddedInputRequest[] = [];
    for (const [key, value] of Object.entries(bag)) {
        if (!isRecord(value)) {
            continue;
        }
        const method = value['method'];
        if (typeof method !== 'string' || method.length === 0) {
            continue;
        }
        out.push({
            key,
            method,
            params: value['params'],
            locus: `/inputRequests/${escapePointerToken(key)}/params`
        });
    }
    return out;
}

/** RFC 6901: `~` -> `~0`, `/` -> `~1`. A server-assigned key may contain both. */
function escapePointerToken(token: string): string {
    return token.replace(/~/gu, '~0').replace(/\//gu, '~1');
}

// ---------------------------------------------------------------------------
// requestState
// ---------------------------------------------------------------------------

/**
 * Where the client echoes `requestState` back on the retry.
 *
 * `params.requestState` is the primary location — it mirrors where the server
 * put it in the result. The `_meta` form is accepted as a fallback because the
 * reserved `io.modelcontextprotocol/` prefix is where per-request protocol
 * plumbing lives generally (§1.10), and reading one extra key costs nothing
 * while missing the echo would silently break correlation.
 *
 * **This is the one place in toolwall inferred from the brief's prose rather
 * than from a byte-exact schema read**, because §1.3 states the echo
 * requirement without naming the field's position on the retry. Both locations
 * are checked, neither is written, and correlation degrades to "no link" rather
 * than to a wrong link if the real location turns out to be a third one — see
 * `correlateRetry`, which returns `undefined` rather than guessing.
 */
const REQUEST_STATE_META_KEY = 'io.modelcontextprotocol/requestState';

export function readRequestState(container: unknown): string | undefined {
    if (!isRecord(container)) {
        return undefined;
    }
    const direct = container['requestState'];
    if (typeof direct === 'string' && direct.length > 0) {
        return direct;
    }
    const meta = container['_meta'];
    if (isRecord(meta)) {
        const fromMeta = meta[REQUEST_STATE_META_KEY];
        if (typeof fromMeta === 'string' && fromMeta.length > 0) {
            return fromMeta;
        }
    }
    return undefined;
}

/**
 * SHA-256 of an opaque `requestState`, hex.
 *
 * The only operation toolwall performs on this value. Not parsed, not decoded,
 * not persisted, not logged in the clear — the spec's own guidance is that it
 * is an attacker-controlled bearer token, and a hash is a link that cannot leak
 * one.
 */
export function hashRequestState(state: string): string {
    return createHash('sha256').update(state, 'utf8').digest('hex');
}

// ---------------------------------------------------------------------------
// Correlation
// ---------------------------------------------------------------------------

/**
 * Ties the two halves of an MRTR round trip together.
 *
 * Bounded on purpose. An `input_required` result costs the proxy one map entry;
 * a server that emits thousands of them and never sees a retry would otherwise
 * be handed a memory leak with an attacker's name on it (T-08). `Map` iterates
 * in insertion order, so evicting the oldest is one `next()`.
 */
export class ExchangeCorrelator {
    readonly #byStateHash = new Map<string, string>();
    readonly #limit: number;
    #counter = 0;
    #correlationCounter = 0;

    constructor(limit = 512) {
        this.#limit = Math.max(1, limit);
    }

    /** A fresh exchange id. Opaque, process-local, monotonic. */
    mint(): string {
        this.#counter += 1;
        return `x${this.#counter.toString(36)}`;
    }

    /**
     * A fresh **correlation id** — the C-13 pairing key for one request/response
     * round trip.
     *
     * A separate counter from `mint()` on purpose, and the prefix differs, so
     * the two id spaces can never be confused for one another in a log, an audit
     * record or a debugger. An exchange id may be reused by an MRTR retry; a
     * correlation id never is, which is exactly why a result can be matched to
     * its own request with it and cannot with the other.
     */
    mintCorrelationId(): string {
        this.#correlationCounter += 1;
        return `c${this.#correlationCounter.toString(36)}`;
    }

    get size(): number {
        return this.#byStateHash.size;
    }

    /**
     * Record that `exchangeId` issued this `requestState`, so the retry that
     * echoes it can be recognised. Returns the hash that was keyed on.
     */
    remember(requestState: string, exchangeId: string): string {
        const hash = hashRequestState(requestState);
        // Re-inserting moves the key to the end, which is what keeps a live
        // exchange from being evicted by traffic that arrived after it.
        this.#byStateHash.delete(hash);
        this.#byStateHash.set(hash, exchangeId);
        while (this.#byStateHash.size > this.#limit) {
            const oldest = this.#byStateHash.keys().next();
            if (oldest.done === true) break;
            this.#byStateHash.delete(oldest.value);
        }
        return hash;
    }

    /**
     * Recognise a retry. Returns the original exchange id and the state hash,
     * or `undefined` when this is not a continuation of anything we saw.
     *
     * `undefined` is a real answer, not a failure: an unrecognised
     * `requestState` may be a first-party retry after a proxy restart, or a
     * client echoing something we never issued. Either way, saying "no link"
     * is correct and saying "linked to the most recent exchange" would be a
     * fabrication a guard might act on.
     */
    correlateRetry(params: unknown): { exchangeId: string; requestStateHash: string } | undefined {
        const state = readRequestState(params);
        if (state === undefined) {
            return undefined;
        }
        const requestStateHash = hashRequestState(state);
        const exchangeId = this.#byStateHash.get(requestStateHash);
        if (exchangeId === undefined) {
            return undefined;
        }
        return { exchangeId, requestStateHash };
    }
}

// ---------------------------------------------------------------------------
// Era gate
// ---------------------------------------------------------------------------

/**
 * Whether MRTR lifting applies.
 *
 * Under `2025-11-25` there is nothing to lift — the same payloads arrive as
 * live requests and are already inspected on the `("response", …)` leg — and
 * scanning every result for `resultType` would be work done on the hot path for
 * a shape that cannot occur. The check is one string comparison per result, and
 * it short-circuits before touching the payload at all.
 */
export function eraUsesMrtr(era: ProtocolEra): boolean {
    return era === '2026-07-28';
}

/**
 * Build the correlation record for an embedded input request.
 *
 * `correlationId` is the **enclosing** round trip's, not a new one: the embedded
 * request is a payload inside a result, it has no request leg and no response
 * leg of its own, so minting an id for it would create a key nothing can ever
 * pair with. Siblings are distinguished by `inputRequestKey`.
 */
export function correlationForEmbedded(options: {
    readonly correlationId: string;
    readonly exchangeId: string;
    readonly outerMethod: string;
    readonly requestId?: string | number;
    readonly inputRequestKey: string;
    readonly requestStateHash?: string;
}): MessageCorrelation & { readonly correlationId: string } {
    return {
        correlationId: options.correlationId,
        exchangeId: options.exchangeId,
        ...(options.requestId !== undefined ? { requestId: options.requestId } : {}),
        outerMethod: options.outerMethod,
        inputRequestKey: options.inputRequestKey,
        ...(options.requestStateHash !== undefined ? { requestStateHash: options.requestStateHash } : {})
    };
}
