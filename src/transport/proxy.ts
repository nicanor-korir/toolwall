/**
 * ToolwallProxy — a bidirectional MCP passthrough built on the SDK's fallback
 * hooks.
 *
 * SHAPE
 * -----
 *   [ trusted client ] <--stdio--> Server | Client <--stdio--> [ untrusted server ]
 *                                  \_____ ToolwallProxy _____/
 *
 * A client-facing `Server` and an upstream-facing `Client` wired together. Every
 * message that is not a toolwall concern is relayed through
 * `fallbackRequestHandler` / `fallbackNotificationHandler`, so unknown and
 * future methods forward without us enumerating anything.
 *
 * VERIFIED AGAINST @modelcontextprotocol/sdk@1.30.0 (read, not assumed)
 * --------------------------------------------------------------------
 * `dist/esm/shared/protocol.js`
 *   :274  `this._notificationHandlers.get(m) ?? this.fallbackNotificationHandler`
 *   :285  `this._requestHandlers.get(m)      ?? this.fallbackRequestHandler`
 * `dist/esm/shared/protocol.d.ts`
 *   :261  fallbackRequestHandler?: (request: JSONRPCRequest, extra) => Promise<SendResultT>
 *   :265  fallbackNotificationHandler?: (notification: Notification) => Promise<void>
 *
 * The dispatch is `get(method) ?? fallback`, so the fallback only fires for
 * methods that have NO registered handler. `Protocol`'s constructor registers
 * three by default (`notifications/cancelled`, `notifications/progress`, and a
 * `ping` auto-pong), and `Server`'s constructor registers two more
 * (`initialize`, `notifications/initialized`). Left in place, those five would
 * be silently swallowed by the proxy instead of reaching the peer. We remove
 * the ones that must relay — see `#detachDefaultHandlers`.
 *
 * WHAT "BYTE-IDENTICAL" HONESTLY MEANS HERE
 * -----------------------------------------
 * Measured, not assumed: the SDK's own stdio codec is not byte-preserving. It
 * parses each line with `JSONRPCMessageSchema` (`shared/stdio.js:34`), and zod
 * rebuilds objects with declared keys first, so
 *   {"method":"m","id":7,"jsonrpc":"2.0"}
 * comes back out as
 *   {"jsonrpc":"2.0","id":7,"method":"m"}
 * That normalization happens on *every* MCP peer's read path, direct connection
 * or not. So the property toolwall actually guarantees, and tests, is:
 *
 *   the bytes a client's transport delivers are identical whether it talks to
 *   the server directly or through toolwall,
 *
 * and no field is added, dropped or altered anywhere in `params` / `result`
 * (both are parsed with loose schemas, so their contents survive verbatim).
 *
 * When no guard is registered for a (direction, method) pair, toolwall performs
 * zero work on the payload: no inspection, no clone, no canonicalization. The
 * same object reference goes out.
 */

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { Protocol } from '@modelcontextprotocol/sdk/shared/protocol.js';
import { McpError } from '@modelcontextprotocol/sdk/types.js';
import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';
import type { JSONRPCRequest, Notification, Result } from '@modelcontextprotocol/sdk/types.js';
import type { RequestHandlerExtra } from '@modelcontextprotocol/sdk/shared/protocol.js';
import { z } from 'zod';

import type { Finding, GuardContext, GuardDirection, ProtocolEra } from '../types/protocol.js';
import { DEFAULT_PROTOCOL_ERA, TOOLWALL_INTERNAL_ERROR } from '../types/protocol.js';
import type { GuardPipeline } from './pipeline.js';
import { DefaultGuardPipeline } from './pipeline.js';

// ---------------------------------------------------------------------------
// Passthrough schema
// ---------------------------------------------------------------------------

/**
 * `Protocol.request()` runs the response through `safeParse(resultSchema, ...)`
 * (`shared/protocol.js:696`). Every named result schema in the SDK would reshape
 * or reject a payload we are only relaying, so we use `z.unknown()`: it accepts
 * anything and returns the value untouched. This is the whole reason the proxy
 * can forward results from future protocol revisions it has never heard of.
 */
const PassthroughResultSchema = z.unknown();

/**
 * Effectively "no proxy-side timeout". The SDK defaults to 60s
 * (`DEFAULT_REQUEST_TIMEOUT_MSEC`) and turns expiry into a `-32001` the real
 * client never asked for. Timeouts belong to the client, which owns the user's
 * patience and will send `notifications/cancelled` when it gives up; we relay
 * that. 2147483647ms is the largest value `setTimeout` handles without
 * overflowing to 1ms (~24.8 days).
 */
export const NO_PROXY_TIMEOUT_MS = 2_147_483_647;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/**
 * An error whose `code` / `message` / `data` are relayed onto the wire exactly
 * as given.
 *
 * `Protocol._onrequest` builds the JSON-RPC error response from
 * `error['code']`, `error.message` and `error['data']`
 * (`shared/protocol.js`, the rejection arm of `_onrequest`). `McpError`
 * rewrites its own message to `MCP error ${code}: ${message}`
 * (`types.js:2031`), so rethrowing an upstream `McpError` would corrupt the
 * message the client sees. We unwrap it instead.
 */
export class RelayedRpcError extends Error {
    readonly code: number;
    readonly data: unknown;

    constructor(code: number, message: string, data?: unknown) {
        super(message);
        this.name = 'RelayedRpcError';
        this.code = code;
        this.data = data;
    }

    /** Undo `McpError`'s message rewriting so the peer's text survives the hop. */
    static fromUpstream(error: unknown): RelayedRpcError {
        if (error instanceof McpError) {
            const prefix = `MCP error ${error.code}: `;
            const message = error.message.startsWith(prefix) ? error.message.slice(prefix.length) : error.message;
            return new RelayedRpcError(error.code, message, error.data);
        }
        if (error instanceof Error) {
            return new RelayedRpcError(TOOLWALL_INTERNAL_ERROR, error.message);
        }
        return new RelayedRpcError(TOOLWALL_INTERNAL_ERROR, String(error));
    }
}

/**
 * What a blocked finding looks like on the wire to the client.
 *
 * `ruleId`, `severity`, `locus` and `remediation` are written by toolwall and are safe to
 * forward. `message` and `evidence` are NOT: they quote the payload that triggered the block, so
 * on a `tools/list` drift they carry the attacker's injected text verbatim — the very string the
 * block exists to keep away from the model. A JSON-RPC error goes to the LLM client, which
 * routinely surfaces error text to the model, so relaying them would hand the payload to its
 * intended reader through the alarm about it.
 *
 * The full finding, including the field-level diff a human needs, still goes to `onEvent`
 * (toolwall's stderr under the CLI) and to the audit log. Those are operator channels; this one
 * is not.
 */
export interface RedactedFinding {
    readonly ruleId: string;
    readonly severity: Finding['severity'];
    readonly locus: string;
    readonly remediation: string;
    readonly detail: string;
}

const DETAIL_WITHHELD =
    "withheld from the client: it quotes the untrusted server's own text. The full finding, " +
    "including the field-level diff, is on toolwall's stderr and in the audit log.";

export function redactFindingForClient(finding: Finding): RedactedFinding {
    return {
        ruleId: finding.ruleId,
        severity: finding.severity,
        locus: finding.locus,
        remediation: finding.remediation,
        detail: DETAIL_WITHHELD
    };
}

/** Thrown when a guard blocks. Fails closed: no request reaches the far side. */
export class GuardBlockedError extends RelayedRpcError {
    readonly findings: readonly Finding[];

    constructor(code: number, findings: readonly Finding[], ctx: GuardContext) {
        // Rule ids only. The old form inlined `findings[0].message`, which put the blocked
        // server's text into the error string itself.
        const rules = findings.map(f => f.ruleId).join(', ');
        const summary =
            findings.length === 0
                ? 'blocked by policy'
                : `${findings.length} finding${findings.length === 1 ? '' : 's'} [${rules}]`;
        super(code, `toolwall blocked ${ctx.direction} ${ctx.method}: ${summary}`, {
            toolwall: {
                blocked: true,
                serverId: ctx.serverId,
                era: ctx.era,
                direction: ctx.direction,
                method: ctx.method,
                findings: findings.map(redactFindingForClient)
            }
        });
        this.name = 'GuardBlockedError';
        // Unredacted, for the operator-facing paths that consume the thrown error directly.
        this.findings = findings;
    }
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

export type ProxyEvent =
    | { readonly kind: 'blocked'; readonly ctx: GuardContext; readonly code: number; readonly findings: readonly Finding[] }
    | { readonly kind: 'annotated'; readonly ctx: GuardContext; readonly findings: readonly Finding[] }
    | { readonly kind: 'findings'; readonly ctx: GuardContext; readonly findings: readonly Finding[] }
    | { readonly kind: 'upstream-error'; readonly error: Error }
    | { readonly kind: 'client-error'; readonly error: Error }
    | { readonly kind: 'upstream-closed' }
    | { readonly kind: 'client-closed' };

// ---------------------------------------------------------------------------
// Subclasses
// ---------------------------------------------------------------------------

/**
 * The SDK's capability assertions describe the *proxy's* declared capabilities,
 * which are meaningless here — toolwall declares nothing of its own, it relays
 * whatever the two real peers negotiated with each other. Left in place,
 * `assertNotificationCapability` would reject a perfectly valid
 * `notifications/message` relay because toolwall itself never claimed the
 * `logging` capability (`server/index.js`, `assertNotificationCapability`).
 *
 * Dropping the assertion is not a loss of a control: the real client's own
 * capability checks still run, one hop away, on the message we relay.
 */
class PassthroughServer extends Server {
    protected override assertCapabilityForMethod(): void {}
    protected override assertNotificationCapability(): void {}
    protected override assertRequestHandlerCapability(): void {}
    protected override assertTaskCapability(): void {}
    protected override assertTaskHandlerCapability(): void {}
}

class PassthroughClient extends Client {
    protected override assertCapabilityForMethod(): void {}
    protected override assertNotificationCapability(): void {}
    protected override assertRequestHandlerCapability(): void {}
    protected override assertTaskCapability(): void {}
    protected override assertTaskHandlerCapability(): void {}

    /**
     * Attach to the transport WITHOUT the SDK's automatic `initialize`
     * handshake.
     *
     * `Client.connect()` (`client/index.js`) overrides `Protocol.connect()`
     * purely to append `initialize` + `notifications/initialized`, and it hard-
     * codes `protocolVersion: LATEST_PROTOCOL_VERSION` and its own
     * `clientInfo`/`capabilities`. A proxy that let it run would replace the
     * real client's identity and capabilities with toolwall's, and would
     * synthesise an `InitializeResult` rather than relaying the server's —
     * including `instructions`, free-form natural language the client places in
     * its system prompt and a top-ranked injection surface
     * (`docs/RESEARCH-BRIEF.md` §1.5).
     *
     * So we call the grandparent directly. `Protocol.connect()` only installs
     * transport callbacks and calls `transport.start()`; the handshake is then
     * relayed verbatim in both directions like any other request.
     */
    async connectWithoutHandshake(transport: Transport): Promise<void> {
        const base = Protocol.prototype.connect as (this: PassthroughClient, transport: Transport) => Promise<void>;
        await base.call(this, transport);
    }
}

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

export interface ToolwallProxyOptions {
    /** Transport facing the trusted client (normally `StdioServerTransport`). */
    readonly clientTransport: Transport;
    /** Transport facing the untrusted server (from `createUpstreamStdioTransport`). */
    readonly upstreamTransport: Transport;
    /**
     * Stable per-connection identity of the upstream server. NOT
     * `serverInfo.name` (T-04). See `deriveServerId()` in `./spawn.js`, which
     * adapts a `SpawnSpec` onto the single implementation in
     * `../audit/identity.js` that the pin store also keys on. The two MUST agree
     * or every pin silently orphans.
     */
    readonly serverId: string;
    readonly era?: ProtocolEra;
    readonly guards?: GuardPipeline;
    readonly onEvent?: (event: ProxyEvent) => void;
    /** Override the effectively-infinite upstream request timeout. Rarely wanted. */
    readonly upstreamRequestTimeoutMs?: number;
}

// ---------------------------------------------------------------------------
// Proxy
// ---------------------------------------------------------------------------

export class ToolwallProxy {
    readonly serverId: string;
    readonly era: ProtocolEra;

    readonly #server: PassthroughServer;
    readonly #client: PassthroughClient;
    readonly #options: ToolwallProxyOptions;
    readonly #guards: GuardPipeline;
    readonly #timeoutMs: number;
    #started = false;
    #closed = false;
    #inflight = 0;

    constructor(options: ToolwallProxyOptions) {
        this.#options = options;
        this.serverId = options.serverId;
        this.era = options.era ?? DEFAULT_PROTOCOL_ERA;
        this.#guards = options.guards ?? new DefaultGuardPipeline();
        this.#timeoutMs = options.upstreamRequestTimeoutMs ?? NO_PROXY_TIMEOUT_MS;

        // Neither identity nor capability set below ever reaches the wire: we
        // relay the peers' own `initialize` request and result verbatim. They
        // exist because the SDK constructors require them.
        this.#server = new PassthroughServer({ name: 'toolwall', version: '0.0.0' }, { capabilities: {} });
        this.#client = new PassthroughClient({ name: 'toolwall', version: '0.0.0' }, { capabilities: {} });

        this.#detachDefaultHandlers();
        this.#installFallbacks();
        this.#installLifecycle();
    }

    /**
     * Handlers the SDK installs by default that would otherwise terminate a
     * message at the proxy instead of relaying it.
     *
     * KEPT (deliberately): `notifications/cancelled`. `Protocol._oncancel`
     * aborts the in-flight handler's `AbortController`; we thread that signal
     * into the outbound request, so the SDK emits a fresh
     * `notifications/cancelled` upstream carrying the *upstream* request id.
     * That gives correct id translation for free and, because
     * `_onrequest` checks `abortController.signal.aborted` before sending,
     * suppresses the stale response. Known fidelity cost: the SDK stringifies
     * the abort reason (`String(reason)` in `Protocol.request`'s `cancel`), so
     * a cancellation sent with no `reason` is relayed as `reason: "undefined"`.
     */
    #detachDefaultHandlers(): void {
        // Relay the handshake instead of answering it locally.
        this.#server.removeRequestHandler('initialize');
        this.#server.removeNotificationHandler('notifications/initialized');

        // Relay pings end to end rather than auto-ponging at the proxy: a ping
        // that never reaches the server does not prove the server is alive.
        this.#server.removeRequestHandler('ping');
        this.#client.removeRequestHandler('ping');

        // `Protocol._onprogress` looks the token up in `_progressHandlers` and,
        // finding nothing (we never pass `onprogress`), raises an error and
        // DROPS the notification. Removing the handler routes progress to the
        // fallback so it relays with its `progressToken` untouched.
        this.#server.removeNotificationHandler('notifications/progress');
        this.#client.removeNotificationHandler('notifications/progress');
    }

    #installFallbacks(): void {
        // client -> server
        this.#server.fallbackRequestHandler = async (request, extra) => this.#relayRequestUpstream(request, extra);
        this.#server.fallbackNotificationHandler = async notification => this.#relayNotification(notification, 'request');

        // server -> client. Under 2025-11-25 sampling/createMessage,
        // elicitation/create and roots/list are live server-initiated requests
        // (RESEARCH-BRIEF §3.1) and carry attacker-controlled natural language,
        // so this leg is attack surface, not plumbing.
        this.#client.fallbackRequestHandler = async (request, extra) => this.#relayRequestDownstream(request, extra);
        this.#client.fallbackNotificationHandler = async notification => this.#relayNotification(notification, 'response');
    }

    #installLifecycle(): void {
        const emit = this.#options.onEvent;
        this.#client.onerror = error => emit?.({ kind: 'upstream-error', error });
        this.#server.onerror = error => emit?.({ kind: 'client-error', error });
        this.#client.onclose = () => {
            emit?.({ kind: 'upstream-closed' });
            // The upstream is gone; there is nothing left to proxy. Tear the
            // client-facing side down so the real client sees a clean EOF
            // rather than a socket that accepts requests and never answers.
            if (!this.#closed) {
                void this.close();
            }
        };
        this.#server.onclose = () => {
            emit?.({ kind: 'client-closed' });
            if (!this.#closed) {
                void this.close();
            }
        };
    }

    /**
     * Connect upstream first, then accept the client. Ordering matters: a
     * request arriving before the upstream transport exists would be answered
     * with a "Not connected" error we invented.
     */
    async start(): Promise<void> {
        if (this.#started) {
            throw new Error('ToolwallProxy already started');
        }
        this.#started = true;
        await this.#client.connectWithoutHandshake(this.#options.upstreamTransport);
        await this.#server.connect(this.#options.clientTransport);
    }

    async close(): Promise<void> {
        if (this.#closed) {
            return;
        }
        this.#closed = true;
        const results = await Promise.allSettled([this.#server.close(), this.#client.close()]);
        const failure = results.find((r): r is PromiseRejectedResult => r.status === 'rejected');
        if (failure !== undefined) {
            const error = failure.reason instanceof Error ? failure.reason : new Error(String(failure.reason));
            this.#options.onEvent?.({ kind: 'upstream-error', error });
        }
    }

    // -----------------------------------------------------------------------
    // Relay
    // -----------------------------------------------------------------------

    #context(direction: GuardDirection, method: string): GuardContext {
        return { era: this.era, serverId: this.serverId, direction, method };
    }

    /**
     * Run the pipeline over one payload and turn the verdict into either a
     * payload to forward or a thrown `GuardBlockedError`.
     *
     * The `hasGuards` check is the transparency guarantee: with no guard
     * registered we never touch `payload`, so the caller forwards the identical
     * object reference.
     */
    async #applyGuards(payload: unknown, ctx: GuardContext): Promise<unknown> {
        if (!this.#guards.hasGuards(ctx.direction, ctx.method)) {
            return payload;
        }
        const outcome = await this.#guards.run(payload, ctx);
        const emit = this.#options.onEvent;
        switch (outcome.verdict.action) {
            case 'block':
                emit?.({ kind: 'blocked', ctx, code: outcome.verdict.code, findings: outcome.findings });
                throw new GuardBlockedError(outcome.verdict.code, outcome.findings, ctx);
            case 'annotate':
                emit?.({ kind: 'annotated', ctx, findings: outcome.findings });
                return outcome.payload;
            default:
                if (outcome.findings.length > 0) {
                    emit?.({ kind: 'findings', ctx, findings: outcome.findings });
                }
                return outcome.payload;
        }
    }

    async #relayRequestUpstream(request: JSONRPCRequest, extra: RequestHandlerExtra<never, never>): Promise<Result> {
        this.#inflight += 1;
        try {
            const requestCtx = this.#context('request', request.method);
            const params = await this.#applyGuards(request.params, requestCtx);

            let result: unknown;
            try {
                result = await this.#client.request(
                    buildOutboundRequest(request.method, params),
                    PassthroughResultSchema,
                    // Threading the handler's abort signal is what makes
                    // `notifications/cancelled` translate ids correctly. See
                    // `#detachDefaultHandlers`.
                    { signal: extra.signal, timeout: this.#timeoutMs }
                );
            } catch (error) {
                // Fail open on plumbing: relay the upstream's own error verbatim
                // rather than inventing one. A guard `block` cannot reach here —
                // it throws before the request is sent.
                throw RelayedRpcError.fromUpstream(error);
            }

            return (await this.#applyGuards(result, this.#context('response', request.method))) as Result;
        } finally {
            this.#inflight -= 1;
        }
    }

    async #relayRequestDownstream(request: JSONRPCRequest, extra: RequestHandlerExtra<never, never>): Promise<Result> {
        this.#inflight += 1;
        try {
            // A server->client request travels *towards the client*, so it is
            // inspected on the "response" leg: everything from the server is
            // attacker-controlled data (THREAT-MODEL §0).
            const outboundCtx = this.#context('response', request.method);
            const params = await this.#applyGuards(request.params, outboundCtx);

            let result: unknown;
            try {
                result = await this.#server.request(buildOutboundRequest(request.method, params), PassthroughResultSchema, {
                    signal: extra.signal,
                    timeout: this.#timeoutMs
                });
            } catch (error) {
                throw RelayedRpcError.fromUpstream(error);
            }

            // The client's answer is travelling towards the server: "request" leg.
            return (await this.#applyGuards(result, this.#context('request', request.method))) as Result;
        } finally {
            this.#inflight -= 1;
        }
    }

    async #relayNotification(notification: Notification, direction: GuardDirection): Promise<void> {
        const ctx = this.#context(direction, notification.method);
        let params: unknown;
        try {
            params = await this.#applyGuards(notification.params, ctx);
        } catch (error) {
            // A notification has no response, so a block is simply a drop. That
            // is still fail-closed: the payload does not reach the peer.
            if (error instanceof GuardBlockedError) {
                return;
            }
            throw error;
        }

        const outbound = buildOutboundRequest(notification.method, params);
        if (direction === 'request') {
            await this.#client.notification(outbound);
        } else {
            await this.#server.notification(outbound);
        }
    }

    // -----------------------------------------------------------------------
    // Test / diagnostic surface
    // -----------------------------------------------------------------------

    /** @internal exposed for tests and for the CLI's shutdown path. */
    get closed(): boolean {
        return this.#closed;
    }

    /** Requests currently relayed in either direction and awaiting a response. */
    get inflightRequests(): number {
        return this.#inflight;
    }

    /**
     * Close once no relayed request is still awaiting a response.
     *
     * The client's stdin reaching EOF means the client is gone, but requests it
     * already sent may still be in flight upstream. Tearing down immediately
     * drops those responses and makes the SDK log "response for an unknown
     * message ID". Drain first, up to `timeoutMs`, then close regardless — a
     * hung server must not hold the process open forever.
     */
    async closeWhenIdle(timeoutMs = 5_000, pollMs = 25): Promise<void> {
        const deadline = Date.now() + timeoutMs;
        while (this.#inflight > 0 && !this.#closed && Date.now() < deadline) {
            await new Promise<void>(resolve => {
                setTimeout(resolve, pollMs).unref();
            });
        }
        await this.close();
    }
}

/**
 * Rebuild `{ method, params }` for the outbound hop.
 *
 * `params` is omitted entirely when absent, so a request that arrived without a
 * `params` key does not gain `"params": undefined` (which `JSON.stringify`
 * drops, but which would still differ if the codec ever changed). `params` is
 * passed by reference — no clone — which is what keeps the untouched path free.
 *
 * The cast is the one place we tell TypeScript that a proxy relays methods the
 * SDK's `ClientRequest`/`ServerRequest` unions do not name. That is the whole
 * point of building on the fallback hooks: unknown and future methods forward.
 */
function buildOutboundRequest(method: string, params: unknown): { method: string; params?: Record<string, unknown> } {
    if (params === undefined) {
        return { method };
    }
    return { method, params: params as Record<string, unknown> };
}
