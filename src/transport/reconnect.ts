/**
 * Zero-downtime reconnection with request buffering.
 *
 * WHAT THIS IS FOR
 * ----------------
 * toolwall sits in the middle of somebody's editor session. When the upstream
 * MCP server blips — a crash-loop, a `npm install` that restarts a dev server, a
 * watcher-triggered reload — the failure a user actually experiences today is
 * that their whole client session dies, because the proxy tears down its
 * client-facing leg the moment the upstream leg closes. A security tool that
 * takes the session down with the thing it was watching is a security tool that
 * gets uninstalled.
 *
 * So: buffer, retry, and only then fail loudly.
 *
 *   attempt 1 after 150ms · attempt 2 after 600ms · attempt 3 after 1200ms
 *   -> at most 3 attempts spread over ~1.95s, then an explicit JSON-RPC
 *      `-32603` to every buffered caller.
 *
 * `-32603` (Internal error) is deliberate and still valid: the reserved MCP
 * range is `-32020..-32099` and `-32603` is plain JSON-RPC
 * (`docs/RESEARCH-BRIEF.md` §1.9).
 *
 * THE SECURITY CONSTRAINT — READ BEFORE CHANGING ANYTHING HERE
 * ------------------------------------------------------------
 * **A reconnect is a new server process, and a reconnect must never be a path
 * around a guard.** The pin store is keyed on `serverId`, which is derived from
 * the *launch spec* and is therefore identical across a restart — by design, so
 * a routine restart does not orphan every pin. The consequence is that
 * `MetadataPinGuard`'s in-memory "what this connection is currently
 * advertising" cache would survive the restart too, and a `tools/call` released
 * after the reconnect would be checked against a catalogue the **previous**
 * process advertised. An attacker who can make the server exit — and a
 * crash-looping server is something an attacker can often arrange — would get a
 * definition swap for free.
 *
 * `ToolwallProxy.#reverifyAfterReconnect()` closes that: before a single
 * buffered request is released it (1) drives a synthetic
 * `notifications/tools/list_changed` through the pipeline so the cached
 * catalogue is marked stale, (2) replays the captured handshake so the new
 * process's `instructions` are re-checked, and (3) issues its own `tools/list`
 * and runs the result through the same `("response", "tools/list")` guards a
 * client-originated listing would hit. A block there fails the buffer closed;
 * it is not retried and it is not downgraded.
 *
 * REPLAY SEMANTICS — a deliberate, stated deviation
 * -------------------------------------------------
 * `docs/PROMPT.md` says "buffer the JSON-RPC queries". There are two populations
 * hiding inside that phrase and they do not have the same safety properties:
 *
 *   - **Never-sent requests** that arrive while the link is down. Replaying
 *     these is exactly-once. Always buffered, all methods.
 *   - **In-flight requests** already written to a server that then died. Their
 *     execution status is *unknown*: the server may have completed the side
 *     effect and lost only the response. Replaying `tools/call
 *     {name:"send_invoice"}` is at-least-once delivery of somebody's money.
 *
 * We will not silently double-execute a side-effecting tool to make a graph look
 * better. Default `replayInFlight: "read-only-methods"` replays only the
 * listing/read methods and returns `-32603` for the rest with a message that
 * says the execution status is unknown. `"all"` and `"none"` are available for
 * operators who know their server. Note the safe set is keyed on the
 * **method**, never on `annotations.readOnlyHint`, which is attacker-controlled
 * (§1.4).
 *
 * The residual risk in that default, stated rather than glossed
 * ------------------------------------------------------------
 * This file used to describe the replayed methods as "observationally free".
 * **That is false against an untrusted peer**, and red team round 2 was right
 * to call it out. `prompts/get`, `resources/read` and `completion/complete` are
 * read-only *by contract*, and the contract is the untrusted party's. Nothing
 * stops a hostile server from incrementing a counter, charging a request, or
 * advancing an attack state machine inside `resources/read` — the method name
 * is a promise the server made, not a property toolwall can verify.
 *
 * The default nevertheless stands, and the reason is a comparison rather than a
 * claim of safety:
 *
 *   - The blast radius is bounded to what a server does to ITSELF. Re-executing
 *     `resources/read` cannot spend the user's money or write the user's disk;
 *     the tool that could is `tools/call`, and `tools/call` is excluded.
 *   - A server that wants to be re-executed does not need this path. It can
 *     simply return two results, or crash-loop and be re-read by the client.
 *     Denying the replay would remove a convenience, not a capability.
 *   - The alternative default (`"none"`) makes every upstream blip visible to
 *     the user as a failed listing, which is the behaviour that gets a security
 *     proxy uninstalled — and an uninstalled proxy enforces nothing.
 *
 * So: at-most-twice execution of server-side-only effects is accepted, in
 * exchange for session continuity, and `--replay-in-flight none` is documented
 * for operators who do not accept it. What is NOT accepted, at any setting, is
 * silently repeating a `tools/call`.
 */

import { McpError, ErrorCode } from '@modelcontextprotocol/sdk/types.js';

import { TOOLWALL_INTERNAL_ERROR } from '../types/protocol.js';

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

/** How an in-flight request is treated when the connection it was riding on died. */
export type ReplayPolicy = 'none' | 'read-only-methods' | 'all';

export interface ReconnectPolicy {
    /**
     * Off unless a `createUpstreamTransport` factory is supplied — without one
     * there is nothing to reconnect *to*, and pretending otherwise would just
     * add latency to a failure.
     */
    readonly enabled: boolean;
    /** Reconnection attempts before giving up. `docs/PROMPT.md`: 3. */
    readonly maxAttempts: number;
    /**
     * Delay before each attempt, in order. Length need not match
     * `maxAttempts`; the last entry repeats. Defaults sum to ~1.95s over three
     * attempts, which is the "~2 seconds" the brief asks for.
     */
    readonly backoffMs: readonly number[];
    /**
     * Hard bound on buffered callers. A dead upstream plus an enthusiastic
     * client is an unbounded memory sink otherwise (T-08 — the proxy is itself
     * a target). Over the bound, the newest caller gets `-32603` immediately
     * rather than the process getting an OOM.
     */
    readonly maxBufferedRequests: number;
    readonly replayInFlight: ReplayPolicy;
    /**
     * Re-verify the new process against the pin store before releasing the
     * buffer. **Leave this on.** See this file's header.
     */
    readonly reverifyOnReconnect: boolean;
    /** Budget for the whole re-verification exchange (handshake + listing). */
    readonly reverifyTimeoutMs: number;
}

export const DEFAULT_RECONNECT_POLICY: ReconnectPolicy = Object.freeze({
    enabled: false,
    maxAttempts: 3,
    backoffMs: Object.freeze([150, 600, 1200]) as readonly number[],
    maxBufferedRequests: 256,
    replayInFlight: 'read-only-methods',
    reverifyOnReconnect: true,
    reverifyTimeoutMs: 10_000
});

export function resolveReconnectPolicy(partial: Partial<ReconnectPolicy> | undefined, hasFactory: boolean): ReconnectPolicy {
    const merged: ReconnectPolicy = { ...DEFAULT_RECONNECT_POLICY, ...(partial ?? {}) };
    return {
        ...merged,
        // Cannot reconnect without something to reconnect to.
        enabled: merged.enabled && hasFactory,
        maxAttempts: Math.max(0, Math.trunc(merged.maxAttempts)),
        maxBufferedRequests: Math.max(0, Math.trunc(merged.maxBufferedRequests))
    };
}

/** Total wall-clock the backoff schedule will spend across `maxAttempts`. */
export function totalBackoffMs(policy: ReconnectPolicy): number {
    let total = 0;
    for (let i = 0; i < policy.maxAttempts; i++) {
        total += backoffForAttempt(policy, i);
    }
    return total;
}

export function backoffForAttempt(policy: ReconnectPolicy, index: number): number {
    if (policy.backoffMs.length === 0) {
        return 0;
    }
    return policy.backoffMs[Math.min(index, policy.backoffMs.length - 1)] ?? 0;
}

// ---------------------------------------------------------------------------
// Method classification
// ---------------------------------------------------------------------------

/**
 * Methods the SPEC defines as read-only, across both eras — which is not the
 * same thing as methods whose re-execution is free.
 *
 * Read the file header before changing this set. A hostile server can make
 * `prompts/get` or `resources/read` side-effecting; the method name is its
 * promise, not our guarantee. The set is drawn this way because the effects it
 * exposes to double-execution are confined to the server's own state, while
 * `tools/call` — the method that reaches the user's money, disk and accounts —
 * is excluded no matter what.
 *
 * This is a *method* allowlist, not an annotation check. `annotations
 * .readOnlyHint` comes from the server and the schema's own doc comment says
 * clients should never make tool-use decisions on it (§1.4) — a server that
 * wanted its side-effecting tool replayed would simply claim `readOnlyHint`.
 */
const READ_ONLY_METHODS: ReadonlySet<string> = new Set([
    'initialize',
    'server/discover',
    'ping',
    'tools/list',
    'prompts/list',
    'prompts/get',
    'resources/list',
    'resources/read',
    'resources/templates/list',
    'completion/complete'
]);

export function isReplayableMethod(method: string, policy: ReplayPolicy): boolean {
    switch (policy) {
        case 'all':
            return true;
        case 'none':
            return false;
        case 'read-only-methods':
        default:
            return READ_ONLY_METHODS.has(method);
    }
}

/** Exposed so a test can assert the set rather than trust the comment above it. */
export const REPLAYABLE_READ_ONLY_METHODS: readonly string[] = Object.freeze([...READ_ONLY_METHODS].sort());

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/**
 * What a caller gets when the retry budget is spent, the buffer is full, or the
 * new process failed re-verification.
 *
 * Always `-32603`. The message names which of those happened, because "the
 * upstream is gone" and "the upstream came back as something you did not
 * approve" are different problems for the human reading the error.
 */
export class UpstreamUnavailableError extends Error {
    readonly code = TOOLWALL_INTERNAL_ERROR;
    readonly reason: 'retries-exhausted' | 'buffer-full' | 'reverification-failed' | 'shutting-down' | 'not-replayable';
    readonly attempts: number;

    constructor(reason: UpstreamUnavailableError['reason'], message: string, attempts = 0) {
        super(message);
        this.name = 'UpstreamUnavailableError';
        this.reason = reason;
        this.attempts = attempts;
    }
}

/**
 * True when this rejection means "the connection went away", as opposed to the
 * server answering with an error of its own.
 *
 * `Protocol._onclose` rejects every outstanding response handler with
 * `McpError(ErrorCode.ConnectionClosed)`, which is `-32000`
 * (`shared/protocol.js:263`), and `Protocol.request` rejects with a plain
 * `Error("Not connected")` when there is no transport at all. Those two are the
 * whole population; anything else came from the peer and must be relayed
 * verbatim, never retried.
 */
export function isConnectionLoss(error: unknown): boolean {
    if (error instanceof McpError) {
        return error.code === ErrorCode.ConnectionClosed;
    }
    if (error instanceof Error) {
        return error.message === 'Not connected';
    }
    return false;
}

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

export type LinkState = 'connected' | 'reconnecting' | 'dead';

interface Waiter {
    readonly method: string;
    readonly resolve: () => void;
    readonly reject: (error: Error) => void;
    readonly dispose: () => void;
}

/**
 * The buffer, expressed as a gate rather than as a queue of payloads.
 *
 * A relay awaits `acquire(method, signal)`. While the link is healthy that
 * returns an already-resolved promise and costs one `if` — the hot path is
 * untouched, which matters because this sits in front of every single request.
 * While the link is down the promise parks, which parks the *whole relay
 * closure*: its `params`, its abort signal and its response continuation stay
 * exactly where they were, so releasing the buffer is just resolving promises.
 * Nothing is re-serialized, nothing is copied, and request/response correlation
 * cannot drift because it was never taken apart.
 *
 * Ordering: waiters are released in the order they parked, so a client that
 * issued A then B still gets A dispatched before B.
 */
export class ReconnectGate {
    #state: LinkState = 'connected';
    #waiters: Waiter[] = [];
    readonly #policy: ReconnectPolicy;
    #downSince = 0;

    constructor(policy: ReconnectPolicy) {
        this.#policy = policy;
    }

    get state(): LinkState {
        return this.#state;
    }

    get buffered(): number {
        return this.#waiters.length;
    }

    get downtimeMs(): number {
        return this.#downSince === 0 ? 0 : Date.now() - this.#downSince;
    }

    /** Called when the upstream leg closes and a reconnect is about to start. */
    beginOutage(): void {
        if (this.#state === 'reconnecting') {
            return;
        }
        this.#state = 'reconnecting';
        this.#downSince = Date.now();
    }

    /** Release every parked caller, in arrival order. */
    resume(): void {
        this.#state = 'connected';
        this.#downSince = 0;
        const waiters = this.#waiters;
        this.#waiters = [];
        for (const waiter of waiters) {
            waiter.dispose();
            waiter.resolve();
        }
    }

    /** Fail every parked caller and refuse new ones. Terminal. */
    fail(error: Error): void {
        this.#state = 'dead';
        const waiters = this.#waiters;
        this.#waiters = [];
        for (const waiter of waiters) {
            waiter.dispose();
            waiter.reject(error);
        }
    }

    /**
     * Wait until the link can carry `method`.
     *
     * Resolves immediately when connected. Parks while reconnecting. Rejects
     * with `UpstreamUnavailableError` when the link is dead, when the buffer is
     * full, or when the caller's own abort signal fires — a client that gave up
     * on a request must not have it dispatched to a server that just came back.
     */
    acquire(method: string, signal?: AbortSignal): Promise<void> {
        if (this.#state === 'connected') {
            return Promise.resolve();
        }
        if (this.#state === 'dead') {
            return Promise.reject(
                new UpstreamUnavailableError(
                    'retries-exhausted',
                    `toolwall could not reach the upstream MCP server, so ${method} was not delivered.`
                )
            );
        }
        if (this.#waiters.length >= this.#policy.maxBufferedRequests) {
            return Promise.reject(
                new UpstreamUnavailableError(
                    'buffer-full',
                    `toolwall is holding ${this.#waiters.length} requests while the upstream MCP server is unreachable, ` +
                        `which is its configured limit, so ${method} was refused rather than queued.`
                )
            );
        }
        if (signal?.aborted === true) {
            return Promise.reject(
                new UpstreamUnavailableError('shutting-down', `${method} was cancelled while the upstream was unreachable.`)
            );
        }

        return new Promise<void>((resolve, reject) => {
            const onAbort = (): void => {
                this.#remove(waiter);
                reject(new UpstreamUnavailableError('shutting-down', `${method} was cancelled while the upstream was unreachable.`));
            };
            const waiter: Waiter = {
                method,
                resolve,
                reject,
                dispose: () => signal?.removeEventListener('abort', onAbort)
            };
            signal?.addEventListener('abort', onAbort, { once: true });
            this.#waiters.push(waiter);
        });
    }

    #remove(waiter: Waiter): void {
        const idx = this.#waiters.indexOf(waiter);
        if (idx !== -1) {
            this.#waiters.splice(idx, 1);
        }
        waiter.dispose();
    }
}

/** `setTimeout` as a promise, with an unref'd timer so it never holds the process open. */
export function delay(ms: number): Promise<void> {
    if (ms <= 0) {
        return Promise.resolve();
    }
    return new Promise<void>(resolve => {
        const timer = setTimeout(resolve, ms);
        if (typeof timer.unref === 'function') {
            timer.unref();
        }
    });
}
