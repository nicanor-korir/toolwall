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

import type { Finding, GuardContext, GuardDirection, MessageCorrelation, ProtocolEra } from '../types/protocol.js';
import { DEFAULT_PROTOCOL_ERA, TOOLWALL_INTERNAL_ERROR, renderLocus, renderText, type Rendered } from '../types/protocol.js';
import type { GuardPipeline } from './pipeline.js';
import { DefaultGuardPipeline } from './pipeline.js';
import {
    ExchangeCorrelator,
    correlationForEmbedded,
    eraUsesMrtr,
    readInputRequests,
    readRequestState
} from './mrtr.js';
import {
    DEFAULT_RECONNECT_POLICY,
    ReconnectGate,
    UpstreamUnavailableError,
    backoffForAttempt,
    delay,
    isConnectionLoss,
    isReplayableMethod,
    resolveReconnectPolicy,
    totalBackoffMs,
    type ReconnectPolicy
} from './reconnect.js';

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

/**
 * A `MessageCorrelation` whose `correlationId` is known to be present —
 * contract **C-13**.
 *
 * `MessageCorrelation.correlationId` is optional in the public type so that a
 * caller outside the request path (a unit test, `provenanceObserver`) can build
 * one without inventing a pairing key. Inside this file it is not optional, and
 * this alias is what makes the compiler say so: every context the proxy hands a
 * guard carries an id a result can be matched back to its request with.
 */
type ProxyCorrelation = MessageCorrelation & { readonly correlationId: string };

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
 * `ruleId`, `severity`, `locus` and `remediation` are safe to forward. `message` and `evidence`
 * are NOT: they quote the payload that triggered the block, so on a `tools/list` drift they carry
 * the attacker's injected text verbatim — the very string the block exists to keep away from the
 * model. A JSON-RPC error goes to the LLM client, which routinely surfaces error text to the
 * model, so relaying them would hand the payload to its intended reader through the alarm about it.
 *
 * **`locus` and `remediation` are sanitized rather than trusted, and the original C-9 note that
 * called all four fields "written by toolwall" was wrong.** A locus is a JSON Pointer *into an
 * attacker-controlled payload*, so its path segments are names the untrusted side chose, and RFC
 * 6901 escapes only `~` and `/` — newlines and terminal control sequences pass straight through.
 * Red team round 2 proved the bypass end to end (`test/attacks/confirm-dialog-injection.test.ts`):
 * a `format: "uri"` property whose NAME carried fake dialog rows reached both the operator's
 * `/dev/tty` prompt and this function's output. `remediation` interpolates the same class of
 * value — a tool name, a denied hostname — for the good reason that a remediation which will not
 * name the thing to fix is useless. Both now go through `sanitizeLocus` / `sanitizeRenderedText`.
 *
 * The full finding, including the field-level diff a human needs, still goes to `onEvent`
 * (toolwall's stderr under the CLI) and to the audit log. Those are operator channels; this one
 * is not, and neither is sanitized there — an operator reading a log wants the bytes.
 */
export interface RedactedFinding {
    /**
     * Every text field is `Rendered` — a branded string obtainable only from a sanitizer in
     * `src/types/protocol.ts`. The fields were already sanitized here; typing them makes it
     * impossible to *stop* sanitizing them, which is the difference between the round-2 fix and a
     * guarantee. A future field added to this interface as `string` is a decision someone has to
     * make deliberately; one added as `Rendered` cannot be filled from a raw `Finding`.
     */
    readonly ruleId: Rendered;
    /**
     * Deliberately NOT `Rendered`: it is a closed union of five literals that toolwall defines, and
     * branding it would erase the union for every client that switches on it. A guard that emits a
     * severity outside the union is a type error at its own call site. It is still flattened before
     * it reaches a *terminal* (see `promptRow` in `guards/runtime/confirm.ts`), because a composed
     * third-party rule pack is JavaScript at runtime.
     */
    readonly severity: Finding['severity'];
    readonly locus: Rendered;
    readonly remediation: Rendered;
    readonly detail: Rendered;
}

const DETAIL_WITHHELD = renderText(
    "withheld from the client: it quotes the untrusted server's own text. The full finding, " +
        "including the field-level diff, is on toolwall's stderr and in the audit log.",
    600
);

export function redactFindingForClient(finding: Finding): RedactedFinding {
    return {
        // `ruleId` is namespaced by owner and composed rule packs supply their own, so it is not
        // ours either. One line, no control characters, like everything else here.
        ruleId: renderText(finding.ruleId, 120),
        severity: finding.severity,
        locus: renderLocus(finding.locus),
        remediation: renderText(finding.remediation, 600),
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
    | { readonly kind: 'client-closed' }
    // --- reconnection ------------------------------------------------------
    /** An attempt is about to be made. `buffered` is how many callers are parked. */
    | {
          readonly kind: 'upstream-reconnecting';
          readonly attempt: number;
          readonly maxAttempts: number;
          readonly buffered: number;
      }
    /** The new process passed re-verification and the buffer is about to be released. */
    | {
          readonly kind: 'upstream-reconnected';
          readonly attempt: number;
          readonly downtimeMs: number;
          readonly released: number;
      }
    /**
     * The new process came back as something that is **not** what was approved.
     * Terminal and deliberately not retried: retrying would be asking the
     * attacker to try again until we accept it.
     */
    | { readonly kind: 'upstream-reconnect-refused'; readonly findings: readonly Finding[]; readonly buffered: number }
    /** Retry budget spent. Every buffered caller is about to receive `-32603`. */
    | {
          readonly kind: 'upstream-reconnect-failed';
          readonly attempts: number;
          readonly error: Error;
          readonly buffered: number;
      };

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
    /**
     * Produces a **fresh** upstream transport for a reconnection attempt.
     *
     * Required for `reconnect.enabled`; without it there is nothing to reconnect
     * to and the policy resolves to disabled rather than pretending. Each call
     * MUST return a transport that has not been started — the proxy starts it.
     * Under stdio this means a new child process, which is why re-verification
     * is mandatory: the thing that comes back is not the thing that left.
     */
    readonly createUpstreamTransport?: () => Transport | Promise<Transport>;
    /** Reconnection and buffering. See `./reconnect.ts`. Off unless a factory is supplied. */
    readonly reconnect?: Partial<ReconnectPolicy>;
}

// ---------------------------------------------------------------------------
// Proxy
// ---------------------------------------------------------------------------

export class ToolwallProxy {
    readonly serverId: string;
    readonly era: ProtocolEra;

    readonly #server: PassthroughServer;
    readonly #options: ToolwallProxyOptions;
    readonly #guards: GuardPipeline;
    readonly #timeoutMs: number;
    readonly #reconnect: ReconnectPolicy;
    readonly #gate: ReconnectGate;
    readonly #correlator = new ExchangeCorrelator();

    /**
     * Replaced wholesale on every reconnect.
     *
     * The SDK's own `Protocol.connect()` error text recommends "a separate
     * Protocol instance per connection", and CVE-2026-25536 is what reusing one
     * across connections cost the SDK: message-id collisions and cross-client
     * response leakage (`docs/RESEARCH-BRIEF.md` §3.3). A fresh instance per
     * upstream process means no response handler, progress token, abort
     * controller or id counter from the dead process can be reached by the new
     * one. `#clientGeneration` fences late callbacks from the old instance.
     */
    #client: PassthroughClient;
    #clientGeneration = 0;

    #started = false;
    #closed = false;
    #inflight = 0;
    #reconnecting = false;

    /**
     * The handshake the real client performed, kept so it can be replayed to a
     * replacement process. Under `2025-11-25` a server that never saw
     * `initialize` has no `_clientCapabilities`, so it will refuse to send
     * sampling/elicitation/roots requests — the reconnected session would come
     * back subtly lamed rather than broken, which is worse. Under `2026-07-28`
     * there is no handshake and this stays empty.
     */
    #capturedInitialize: { readonly params: unknown } | undefined;
    #capturedInitialized = false;

    constructor(options: ToolwallProxyOptions) {
        this.#options = options;
        this.serverId = options.serverId;
        this.era = options.era ?? DEFAULT_PROTOCOL_ERA;
        this.#guards = options.guards ?? new DefaultGuardPipeline();
        this.#timeoutMs = options.upstreamRequestTimeoutMs ?? NO_PROXY_TIMEOUT_MS;
        this.#reconnect = resolveReconnectPolicy(options.reconnect, options.createUpstreamTransport !== undefined);
        this.#gate = new ReconnectGate(this.#reconnect);

        // Neither identity nor capability set below ever reaches the wire: we
        // relay the peers' own `initialize` request and result verbatim. They
        // exist because the SDK constructors require them.
        this.#server = new PassthroughServer({ name: 'toolwall', version: '0.0.0' }, { capabilities: {} });
        this.#client = this.#newUpstreamClient();

        this.#detachServerDefaultHandlers();
        this.#installServerFallbacks();
        this.#installServerLifecycle();
    }

    /** Build and fully wire a client-side `Protocol` for one upstream process. */
    #newUpstreamClient(): PassthroughClient {
        const client = new PassthroughClient({ name: 'toolwall', version: '0.0.0' }, { capabilities: {} });
        const generation = (this.#clientGeneration += 1);

        // Relay pings end to end rather than auto-ponging at the proxy: a ping
        // that never reaches the server does not prove the server is alive.
        client.removeRequestHandler('ping');
        // `Protocol._onprogress` looks the token up in `_progressHandlers` and,
        // finding nothing (we never pass `onprogress`), raises an error and
        // DROPS the notification. Removing the handler routes progress to the
        // fallback so it relays with its `progressToken` untouched.
        client.removeNotificationHandler('notifications/progress');

        // server -> client. Under 2025-11-25 sampling/createMessage,
        // elicitation/create and roots/list are live server-initiated requests
        // (RESEARCH-BRIEF §3.1) and carry attacker-controlled natural language,
        // so this leg is attack surface, not plumbing.
        client.fallbackRequestHandler = async (request, extra) => this.#relayRequestDownstream(request, extra);
        client.fallbackNotificationHandler = async notification => this.#relayNotification(notification, 'response');

        client.onerror = error => {
            if (generation !== this.#clientGeneration) return;
            this.#options.onEvent?.({ kind: 'upstream-error', error });
        };
        client.onclose = () => {
            // A callback from an instance we have already replaced says nothing
            // about the connection we are actually using.
            if (generation !== this.#clientGeneration) return;
            this.#onUpstreamClosed();
        };
        return client;
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
    #detachServerDefaultHandlers(): void {
        // Relay the handshake instead of answering it locally.
        this.#server.removeRequestHandler('initialize');
        this.#server.removeNotificationHandler('notifications/initialized');

        // Relay pings end to end rather than auto-ponging at the proxy: a ping
        // that never reaches the server does not prove the server is alive.
        this.#server.removeRequestHandler('ping');

        // See `#newUpstreamClient` for why progress must not be handled here.
        this.#server.removeNotificationHandler('notifications/progress');
    }

    #installServerFallbacks(): void {
        // client -> server
        this.#server.fallbackRequestHandler = async (request, extra) => this.#relayRequestUpstream(request, extra);
        this.#server.fallbackNotificationHandler = async notification => this.#relayNotification(notification, 'request');
    }

    #installServerLifecycle(): void {
        const emit = this.#options.onEvent;
        this.#server.onerror = error => emit?.({ kind: 'client-error', error });
        this.#server.onclose = () => {
            emit?.({ kind: 'client-closed' });
            if (!this.#closed) {
                void this.close();
            }
        };
    }

    /**
     * The upstream leg went away.
     *
     * With reconnection off this is the week-1 behaviour, unchanged: tear the
     * client-facing side down so the real client sees a clean EOF rather than a
     * socket that accepts requests and never answers. With reconnection on, the
     * client-facing side is left up and every caller parks on the gate.
     */
    #onUpstreamClosed(): void {
        this.#options.onEvent?.({ kind: 'upstream-closed' });
        if (this.#closed) {
            return;
        }
        if (!this.#reconnect.enabled) {
            void this.close();
            return;
        }
        if (this.#reconnecting) {
            // Our own teardown of a half-connected attempt. Already handled.
            return;
        }
        this.#gate.beginOutage();
        this.#reconnecting = true;
        void this.#reconnectLoop().finally(() => {
            this.#reconnecting = false;
        });
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
        // Anyone still parked on the gate is never getting an answer; say so
        // rather than leaving their promise pending for the process lifetime.
        this.#gate.fail(new UpstreamUnavailableError('shutting-down', 'toolwall is shutting down; the request was not delivered.'));
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

    /**
     * Build a `GuardContext`.
     *
     * `correlation` is a **required** parameter, not an optional one — contract
     * C-13. Every payload the proxy hands a guard belongs to some round trip, and
     * a leg that quietly passed `undefined` is precisely how a result stopped
     * being matchable to its request. Making the compiler ask the question at
     * every call site is the cheapest available guarantee that no leg is missed;
     * `test/integration/correlation.test.ts` checks the same thing at runtime,
     * across real traffic, because a future call site could still pass a
     * correlation whose id is empty.
     */
    #context(direction: GuardDirection, method: string, correlation: ProxyCorrelation): GuardContext {
        return { era: this.era, serverId: this.serverId, direction, method, correlation };
    }

    /**
     * Correlation for one client->server request.
     *
     * Under `2026-07-28` a request that echoes a `requestState` we issued is the
     * second half of an exchange whose first half we already inspected — and it
     * carries a **different JSON-RPC id**, so nothing else would link them. When
     * it is not a retry (or the era has no MRTR) this mints a fresh exchange id
     * so `correlation.exchangeId` is always present and a guard never has to
     * branch on its absence.
     *
     * `correlationId` is minted fresh in **both** arms. A retry is a new round
     * trip that continues an old exchange, so it keeps the `exchangeId` and takes
     * a new pairing key; reusing the pairing key would mean two live round trips
     * sharing one, which is the ambiguity C-13 exists to remove.
     */
    #correlateClientRequest(request: JSONRPCRequest): ProxyCorrelation {
        const correlationId = this.#correlator.mintCorrelationId();
        if (eraUsesMrtr(this.era)) {
            const retry = this.#correlator.correlateRetry(request.params);
            if (retry !== undefined) {
                return {
                    correlationId,
                    exchangeId: retry.exchangeId,
                    requestId: request.id,
                    requestStateHash: retry.requestStateHash,
                    isRetry: true
                };
            }
        }
        return { correlationId, exchangeId: this.#correlator.mint(), requestId: request.id };
    }

    /**
     * Correlation for a message toolwall relays or originates that is not a
     * client->server request: a notification in either direction, a server->client
     * request, and the synthetic re-verification traffic after a reconnect.
     *
     * A notification has no response leg and no JSON-RPC id, so its correlation
     * pairs with nothing. It is minted anyway: a guard that has to ask "is there
     * a correlation here?" before reading one has the branch C-13 was supposed to
     * delete, and "present but pairs with nothing" is a cheaper thing to reason
     * about than "sometimes absent".
     */
    #freshCorrelation(extra: Omit<MessageCorrelation, 'correlationId' | 'exchangeId'> = {}): ProxyCorrelation {
        return {
            correlationId: this.#correlator.mintCorrelationId(),
            exchangeId: this.#correlator.mint(),
            ...extra
        };
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
            const correlation = this.#correlateClientRequest(request);
            const requestCtx = this.#context('request', request.method, correlation);
            const params = await this.#applyGuards(request.params, requestCtx);

            // Capture the handshake AFTER the guards have had their say, so a
            // replay reproduces what was actually forwarded rather than what
            // arrived. Only what the client itself sent is ever replayed.
            if (request.method === 'initialize') {
                this.#capturedInitialize = { params };
            }

            const result = await this.#sendUpstream(request.method, params, extra.signal);
            const inspected = await this.#applyGuards(result, this.#context('response', request.method, correlation));
            return (await this.#liftInputRequests(inspected, request.method, correlation)) as Result;
        } finally {
            this.#inflight -= 1;
        }
    }

    /**
     * One upstream request, through the reconnect gate.
     *
     * Three distinct outcomes, and keeping them distinct is the point:
     *
     *  - the server answered (result or its own error) -> relayed verbatim;
     *  - the connection died and the method is safe to replay -> park, then
     *    reissue on the new process, which the caller never observes;
     *  - the connection died and the method is not safe to replay -> `-32603`
     *    saying so, because a `tools/call` whose response was lost has an
     *    execution status nobody knows and quietly running it twice is worse
     *    than an error the client can act on. See `./reconnect.ts`.
     */
    async #sendUpstream(method: string, params: unknown, signal: AbortSignal | undefined): Promise<unknown> {
        const options = signal === undefined ? { timeout: this.#timeoutMs } : { signal, timeout: this.#timeoutMs };

        try {
            await this.#gate.acquire(method, signal);
        } catch (error) {
            throw toRelayedError(error);
        }

        try {
            return await this.#client.request(buildOutboundRequest(method, params), PassthroughResultSchema, options);
        } catch (error) {
            if (!this.#reconnect.enabled || !isConnectionLoss(error)) {
                // Fail open on plumbing: relay the upstream's own error verbatim
                // rather than inventing one. A guard `block` cannot reach here —
                // it throws before the request is sent.
                throw RelayedRpcError.fromUpstream(error);
            }
            if (!isReplayableMethod(method, this.#reconnect.replayInFlight)) {
                throw new RelayedRpcError(
                    TOOLWALL_INTERNAL_ERROR,
                    `toolwall: the upstream MCP server closed the connection while ${method} was in flight. ` +
                        'Its execution status is unknown, so toolwall did not resend it. Reissue it if it is safe to repeat.',
                    { toolwall: { upstreamUnavailable: true, reason: 'not-replayable', method } }
                );
            }
            try {
                // Park until the replacement process is connected AND verified.
                await this.#gate.acquire(method, signal);
            } catch (gateError) {
                throw toRelayedError(gateError);
            }
            try {
                return await this.#client.request(buildOutboundRequest(method, params), PassthroughResultSchema, options);
            } catch (retryError) {
                throw RelayedRpcError.fromUpstream(retryError);
            }
        }
    }

    async #relayRequestDownstream(request: JSONRPCRequest, extra: RequestHandlerExtra<never, never>): Promise<Result> {
        this.#inflight += 1;
        try {
            // A server->client request travels *towards the client*, so it is
            // inspected on the "response" leg: everything from the server is
            // attacker-controlled data (THREAT-MODEL §0).
            const correlation = this.#freshCorrelation({ requestId: request.id });
            const outboundCtx = this.#context('response', request.method, correlation);
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
            return (await this.#applyGuards(result, this.#context('request', request.method, correlation))) as Result;
        } finally {
            this.#inflight -= 1;
        }
    }

    // -----------------------------------------------------------------------
    // MRTR (2026-07-28) — see `./mrtr.ts`
    // -----------------------------------------------------------------------

    /**
     * Route `InputRequiredResult.inputRequests` into the guard pipeline.
     *
     * Each embedded request is inspected as `("response", <embedded method>)`,
     * so a guard registered for `("response", "sampling/createMessage")` fires
     * on the live request under `2025-11-25` and on the embedded copy under
     * `2026-07-28` with no era knowledge of its own. `correlation.outerMethod`
     * and `correlation.inputRequestKey` say where it came from.
     *
     * The `requestState` accompanying the result is hashed and remembered so the
     * client's retry — which arrives under a **different JSON-RPC id** — is
     * recognised as the same exchange. The value itself is never parsed and
     * never rewritten; the whole result is forwarded by reference unless a guard
     * actually returned a replacement, in which case only the touched entries
     * are rebuilt.
     */
    async #liftInputRequests(result: unknown, outerMethod: string, correlation: ProxyCorrelation): Promise<unknown> {
        if (!eraUsesMrtr(this.era)) {
            return result;
        }
        const entries = readInputRequests(result);
        if (entries.length === 0) {
            return result;
        }

        const state = readRequestState(result);
        const requestStateHash = state === undefined ? undefined : this.#correlator.remember(state, correlation.exchangeId);

        let replacements: Map<string, unknown> | undefined;
        for (const entry of entries) {
            const ctx = this.#context(
                'response',
                entry.method,
                correlationForEmbedded({
                    correlationId: correlation.correlationId,
                    exchangeId: correlation.exchangeId,
                    outerMethod,
                    ...(correlation.requestId !== undefined ? { requestId: correlation.requestId } : {}),
                    inputRequestKey: entry.key,
                    ...(requestStateHash !== undefined ? { requestStateHash } : {})
                })
            );
            const inspected = await this.#applyGuards(entry.params, ctx);
            if (!Object.is(inspected, entry.params)) {
                replacements ??= new Map<string, unknown>();
                replacements.set(entry.key, inspected);
            }
        }

        if (replacements === undefined) {
            return result;
        }

        const source = result as Record<string, unknown>;
        const bag = source['inputRequests'] as Record<string, unknown>;
        const nextBag: Record<string, unknown> = {};
        for (const [key, value] of Object.entries(bag)) {
            if (replacements.has(key) && typeof value === 'object' && value !== null) {
                nextBag[key] = { ...(value as Record<string, unknown>), params: replacements.get(key) };
            } else {
                nextBag[key] = value;
            }
        }
        return { ...source, inputRequests: nextBag };
    }

    async #relayNotification(notification: Notification, direction: GuardDirection): Promise<void> {
        // C-13: a notification pairs with nothing, and still gets a correlation
        // id. See `#freshCorrelation`.
        const ctx = this.#context(direction, notification.method, this.#freshCorrelation());
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
            if (notification.method === 'notifications/initialized') {
                this.#capturedInitialized = true;
            }
            // Park with the requests so ordering survives an outage: a
            // notification that overtook the request it belongs to would be a
            // reordering, which the transparency rule forbids.
            try {
                await this.#gate.acquire(notification.method);
            } catch (error) {
                // A notification has no response, so there is nobody to tell.
                // Report it on the operator channel and drop it — which is what
                // a dropped connection does to a notification anyway.
                this.#options.onEvent?.({
                    kind: 'upstream-error',
                    error: error instanceof Error ? error : new Error(String(error))
                });
                return;
            }
            await this.#client.notification(outbound);
        } else {
            await this.#server.notification(outbound);
        }
    }

    // -----------------------------------------------------------------------
    // Reconnection — see `./reconnect.ts` for the policy and the reasoning
    // -----------------------------------------------------------------------

    /**
     * Retry, re-verify, release. Or fail every buffered caller with `-32603`.
     *
     * Two exits are terminal on purpose:
     *
     *  - **Retry budget spent.** Everything parked gets `-32603`, then the
     *    client leg closes so the client sees a clean EOF instead of a session
     *    that accepts requests and answers none.
     *  - **Re-verification blocked.** The replacement process is advertising
     *    something that is not what was approved. This is NOT retried: retrying
     *    is offering the attacker another go until we accept it. The buffer
     *    fails closed and the session ends.
     */
    async #reconnectLoop(): Promise<void> {
        const factory = this.#options.createUpstreamTransport;
        if (factory === undefined) {
            this.#gate.fail(new UpstreamUnavailableError('retries-exhausted', 'toolwall has no way to restart the upstream MCP server.'));
            await this.close();
            return;
        }

        let lastError: Error = new Error('the upstream MCP server closed the connection');

        for (let attempt = 0; attempt < this.#reconnect.maxAttempts; attempt++) {
            if (this.#closed) {
                this.#gate.fail(new UpstreamUnavailableError('shutting-down', 'toolwall is shutting down.'));
                return;
            }
            this.#options.onEvent?.({
                kind: 'upstream-reconnecting',
                attempt: attempt + 1,
                maxAttempts: this.#reconnect.maxAttempts,
                buffered: this.#gate.buffered
            });
            await delay(backoffForAttempt(this.#reconnect, attempt));
            if (this.#closed) {
                this.#gate.fail(new UpstreamUnavailableError('shutting-down', 'toolwall is shutting down.'));
                return;
            }

            try {
                this.#client = this.#newUpstreamClient();
                const transport = await factory();
                await this.#client.connectWithoutHandshake(transport);
                await this.#replayHandshake();
                await this.#reverifyAfterReconnect();

                this.#options.onEvent?.({
                    kind: 'upstream-reconnected',
                    attempt: attempt + 1,
                    downtimeMs: this.#gate.downtimeMs,
                    released: this.#gate.buffered
                });
                this.#gate.resume();
                return;
            } catch (error) {
                if (error instanceof GuardBlockedError) {
                    this.#options.onEvent?.({
                        kind: 'upstream-reconnect-refused',
                        findings: error.findings,
                        buffered: this.#gate.buffered
                    });
                    await this.#detachUpstream();
                    this.#gate.fail(
                        new UpstreamUnavailableError(
                            'reverification-failed',
                            'toolwall: the upstream MCP server restarted and its definitions no longer match what was approved, ' +
                                'so the buffered requests were not released.',
                            attempt + 1
                        )
                    );
                    // Drain before closing. `#gate.fail` only *rejects* the
                    // parked callers; their `-32603` still has to travel back
                    // through the handler chain and out of the client-facing
                    // transport. Closing in the same tick would swallow the
                    // explanation and leave the client with a bare EOF.
                    await this.closeWhenIdle(2_000);
                    return;
                }
                lastError = error instanceof Error ? error : new Error(String(error));
                await this.#detachUpstream();
            }
        }

        this.#options.onEvent?.({
            kind: 'upstream-reconnect-failed',
            attempts: this.#reconnect.maxAttempts,
            error: lastError,
            buffered: this.#gate.buffered
        });
        this.#gate.fail(
            new UpstreamUnavailableError(
                'retries-exhausted',
                `toolwall could not reach the upstream MCP server after ${this.#reconnect.maxAttempts} attempts ` +
                    `over ${totalBackoffMs(this.#reconnect)}ms: ${lastError.message}`,
                this.#reconnect.maxAttempts
            )
        );
        // Same reasoning as the refusal path above: let the `-32603`s reach the
        // client before the transport goes away.
        await this.closeWhenIdle(2_000);
    }

    /** Tear down a half-built attempt without letting its `onclose` restart the loop. */
    async #detachUpstream(): Promise<void> {
        try {
            await this.#client.close();
        } catch {
            // A transport that never started, or a process already gone. Either
            // way there is nothing to clean up and nothing to report.
        }
    }

    /**
     * Re-perform the client's handshake against the replacement process.
     *
     * `2025-11-25` only. The result is **not** relayed to the client — it
     * already has one, and inventing a second `InitializeResult` would be the
     * proxy speaking for a peer. It IS run through the `("response",
     * "initialize")` guards, because that result carries `instructions`, which
     * is a top-ranked injection surface (§1.5) and a pinned surface: a server
     * that came back with different instructions must be caught here, not after
     * the buffer is released.
     */
    async #replayHandshake(): Promise<void> {
        if (this.era !== '2025-11-25' || this.#capturedInitialize === undefined) {
            return;
        }
        const correlation = this.#freshCorrelation({ synthetic: true });
        const result = await this.#client.request(
            buildOutboundRequest('initialize', this.#capturedInitialize.params),
            PassthroughResultSchema,
            { timeout: this.#reconnect.reverifyTimeoutMs }
        );
        await this.#applyGuards(result, this.#context('response', 'initialize', correlation));
        if (this.#capturedInitialized) {
            await this.#client.notification({ method: 'notifications/initialized' });
        }
    }

    /**
     * **The security gate on reconnection.** Nothing buffered is released until
     * this returns.
     *
     * Step 1 marks the cached catalogue stale. `MetadataPinGuard` keeps
     * "what this connection is currently advertising" in memory, keyed by
     * `serverId` — which is derived from the launch spec and is therefore
     * *identical* across a restart, by design, so a routine restart does not
     * orphan every pin. Without this step the guard would happily verify a
     * `tools/call` against the catalogue the **previous process** advertised,
     * and a server that can arrange its own crash would get a definition swap
     * for free. Driving a synthetic `notifications/tools/list_changed` through
     * the pipeline uses the guard's existing, tested staleness path rather than
     * reaching across the module boundary for a private field.
     *
     * Step 2 re-lists and runs the result through the same
     * `("response", "tools/list")` guards a client-originated listing hits, so
     * drift in the replacement process is caught by the ordinary control on the
     * ordinary path. A block propagates out of here and fails the buffer closed.
     *
     * If the server cannot be listed at all, the catalogue stays stale — which
     * is not a bypass: `MetadataPinGuard` treats a stale catalogue as
     * unverifiable and applies the configured disposition. We log it and let the
     * guard decide, rather than inventing a second policy here.
     */
    async #reverifyAfterReconnect(): Promise<void> {
        if (!this.#reconnect.reverifyOnReconnect) {
            return;
        }
        const correlation = this.#freshCorrelation({ synthetic: true });

        // 1. invalidate whatever the previous process taught the guards.
        const staleCtx = this.#context('response', 'notifications/tools/list_changed', correlation);
        if (this.#guards.hasGuards(staleCtx.direction, staleCtx.method)) {
            await this.#guards.run({}, staleCtx);
        }

        // 2. re-list and verify against the pins.
        const listCtx = this.#context('response', 'tools/list', correlation);
        if (!this.#guards.hasGuards(listCtx.direction, listCtx.method)) {
            // Nothing is watching listings, so there is nothing to re-verify and
            // no reason to make the client wait for a request of our own.
            return;
        }
        let result: unknown;
        try {
            result = await this.#client.request({ method: 'tools/list' }, PassthroughResultSchema, {
                timeout: this.#reconnect.reverifyTimeoutMs
            });
        } catch (error) {
            this.#options.onEvent?.({
                kind: 'upstream-error',
                error: new Error(
                    `toolwall could not re-list tools after reconnecting, so the catalogue stays stale and calls ` +
                        `against it are unverifiable: ${error instanceof Error ? error.message : String(error)}`
                )
            });
            return;
        }
        await this.#applyGuards(result, listCtx);
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

    /** `connected` | `reconnecting` | `dead`. Always `connected` with reconnection off. */
    get linkState(): 'connected' | 'reconnecting' | 'dead' {
        return this.#gate.state;
    }

    /** Callers currently parked waiting for the upstream to come back. */
    get bufferedRequests(): number {
        return this.#gate.buffered;
    }

    /** The resolved reconnection policy, after defaults and the factory check. */
    get reconnectPolicy(): ReconnectPolicy {
        return this.#reconnect;
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
/**
 * Turn a gate rejection into something the client can read.
 *
 * `UpstreamUnavailableError` becomes `-32603` with a `data.toolwall` marker, so
 * a client can tell "toolwall could not deliver this" apart from "the server
 * returned an error" — the same distinction `GuardBlockedError` maintains.
 * Anything else is relayed as-is.
 */
function toRelayedError(error: unknown): RelayedRpcError {
    if (error instanceof UpstreamUnavailableError) {
        return new RelayedRpcError(error.code, error.message, {
            toolwall: { upstreamUnavailable: true, reason: error.reason, attempts: error.attempts }
        });
    }
    return RelayedRpcError.fromUpstream(error);
}

function buildOutboundRequest(method: string, params: unknown): { method: string; params?: Record<string, unknown> } {
    if (params === undefined) {
        return { method };
    }
    return { method, params: params as Record<string, unknown> };
}
