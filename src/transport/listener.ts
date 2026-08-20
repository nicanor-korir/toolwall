/**
 * The Streamable HTTP front door — toolwall's client-facing leg over HTTP.
 *
 * SHAPE
 * -----
 * ```
 *   [ MCP client ] --HTTP--> StreamableHttpListener --> ToolwallProxy --stdio--> [ server ]
 *                            \___ this file ___/         (guards run here)
 * ```
 *
 * It implements the SDK's `Transport`, so `assembleToolwall({ clientTransport })` takes it exactly
 * where it takes `StdioServerTransport`. Nothing about the guard stack changes: the same pipeline,
 * the same pin store, the same verdicts. What changes is who can talk to it, and that is the whole
 * reason this file is mostly about refusing requests.
 *
 * WHY THE SECURITY HERE IS THE FEATURE, NOT A WRAPPER AROUND IT
 * ------------------------------------------------------------
 * Opening a local HTTP port is the single riskiest thing a security tool can do, and the record on
 * this exact port is bad:
 *
 *  - **CVE-2025-66414** — the TypeScript SDK shipped `enableDnsRebindingProtection` defaulting to
 *    **false**, and the same default shipped simultaneously in the Python, Go, Java, Rust and Ruby
 *    SDKs. Verified against the tree vendored here, not recalled:
 *    `node_modules/@modelcontextprotocol/sdk/dist/esm/server/webStandardStreamableHttp.js:79`
 *    reads `options.enableDnsRebindingProtection ?? false`. So a server built the obvious way is
 *    reachable from any web page the user has open.
 *  - **CVE-2025-49596** — MCP Inspector, CVSS 9.4.
 *  - **CVE-2026-23744** — MCPJam, CVSS 9.8, exploited in the wild from February 2026.
 *
 * Both of the latter were *unauthenticated local endpoints reachable from a browser*. The spec
 * itself warns that a stdio proxy is an escalation path; a proxy that hands any local process the
 * ability to drive the server it is guarding has become one.
 *
 * So this listener, unconditionally and with no flag to turn any of it off:
 *
 *  1. **Binds `127.0.0.1`** unless an operator names another address, and says loudly when they do.
 *  2. **Validates `Origin` and `Host`** and answers **`403`** on either mismatch — before it looks
 *     at credentials, so a hostile page cannot use the auth response as an oracle.
 *  3. **Requires a bearer token on every request**, answers **`401`** without one, and generates a
 *     256-bit one at startup when the operator supplies none. There is deliberately **no
 *     `--listen-no-auth`**. An unauthenticated local control plane is the vulnerability class
 *     above, not a convenience.
 *  4. **Runs `verifyHeaderBodyAgreement` before the body reaches any guard**, answering `400` plus
 *     JSON-RPC `-32020 HeaderMismatch`. This is the Akamai header-confusion point applied to MCP:
 *     if policy is evaluated on `Mcp-Name` while execution follows `params.name`, the proxy has
 *     published an oracle rather than enforced a control. See `./headers.ts`.
 *  5. **Enforces the era's HTTP shape** — `2026-07-28` is POST-only and answers `405` to `GET` and
 *     `DELETE`, with no sessions and no resumability; `2025-11-25` keeps sessions and the standalone
 *     `GET` SSE stream. The difference is data (`HttpEraProfile`), not branches scattered here.
 *
 * TWO LANES, BECAUSE THE SDK IMPLEMENTS ONE REVISION AND WE SUPPORT TWO
 * ---------------------------------------------------------------------
 * `@modelcontextprotocol/sdk@1.30.0` implements `2025-11-25`: sessions, the standalone `GET` SSE
 * stream, `DELETE` termination, resumability. That lane delegates to its
 * `StreamableHTTPServerTransport`, because reimplementing a maintained SSE/session implementation
 * to prove a point is how you ship a subtly different one.
 *
 * The `2026-07-28` lane does **not** delegate, and the reason is a hard property of the SDK read
 * out of the vendored tree rather than guessed at: `webStandardStreamableHttp.js:174` throws
 * *"Stateless transport cannot be reused across requests"* the second time a transport with no
 * `sessionIdGenerator` handles anything. The SDK's stateless mode means one transport per HTTP
 * request, which cannot be the client-facing leg of a long-lived proxy session. The POST-only
 * shape is small enough to own: parse, hand to the pipeline, answer the matching id.
 *
 * WHAT THE 2026-07-28 LANE DOES NOT CARRY, SAID PLAINLY
 * ----------------------------------------------------
 * A server->client message that is not the answer to an in-flight POST — a relayed
 * `notifications/message`, a `notifications/progress`, a server-initiated request — has **nowhere
 * to go** on a POST-only endpoint with no SSE response stream. It is reported on the operator
 * channel as a `listener-error` and dropped. That is a real limitation and not a rounding error,
 * and it is stated here rather than discovered: under `2025-11-25` those messages ride the
 * standalone `GET` stream and are delivered normally, and `2025-11-25` is what every shipping
 * client speaks today. Carrying them under `2026-07-28` needs the POST response to become an SSE
 * stream keyed on `relatedRequestId`, which is the next piece of work on this file and is not
 * pretended to exist.
 *
 * WHAT IT DOES NOT DO
 * -------------------
 * No TLS. A listener bound to loopback and authenticated with a bearer token does not need it, and
 * terminating TLS here would invite binding it to a public interface, which is a posture toolwall
 * should not make easy. Put a reverse proxy in front if you need one, and understand that you are
 * then responsible for everything on this list that the reverse proxy now sees first.
 *
 * No OAuth. The spec's authorization framework is about a *server* authenticating its callers
 * across the internet; this is a loopback control plane for the process that spawned us, and a
 * shared secret is the honest primitive for that. Naming it "OAuth" would imply an identity model
 * that does not exist here.
 */

import { createServer, type IncomingMessage, type Server as HttpServer, type ServerResponse } from 'node:http';
import { randomUUID } from 'node:crypto';
import type { AddressInfo } from 'node:net';

import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import type { Transport, TransportSendOptions } from '@modelcontextprotocol/sdk/shared/transport.js';
import type { JSONRPCMessage, MessageExtraInfo, RequestId } from '@modelcontextprotocol/sdk/types.js';

import { DEFAULT_PROTOCOL_ERA, type ProtocolEra } from '../types/protocol.js';
import { hasMirroredPolicyHeaders, verifyHeaderBodyAgreement, type IncomingHeaders } from './headers.js';
import {
    DEFAULT_LISTEN_HOST,
    DEFAULT_MAX_BODY_BYTES,
    bearerTokenMatches,
    checkRequestOrigin,
    generateBearerToken,
    httpProfileForEra,
    isLoopbackHost,
    readBearerToken,
    readJsonBody,
    type HttpEraProfile
} from './http.js';

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

/**
 * What the listener reports to the operator channel.
 *
 * A refusal is reported with its rule id and status, never with the body that caused it: a
 * rejected request is attacker-shaped input, and echoing it into a log an operator reads is the
 * same mistake `redactFindingForClient` exists to avoid.
 */
export type ListenerEvent =
    | { readonly kind: 'listening'; readonly url: string; readonly era: ProtocolEra }
    | {
          readonly kind: 'rejected';
          readonly status: number;
          readonly ruleId: string;
          readonly message: string;
          readonly method: string;
          readonly path: string;
      }
    | { readonly kind: 'listener-error'; readonly error: Error };

export interface StreamableHttpListenerOptions {
    /** Protocol era. Decides the whole HTTP shape — see {@link HttpEraProfile}. */
    readonly era?: ProtocolEra;
    /** Interface to bind. Defaults to `127.0.0.1`; anything else is reported as a warning. */
    readonly host?: string;
    /** Port. `0` (the default) asks the OS for a free one, which the tests rely on. */
    readonly port?: number;
    /** Endpoint path. Anything else answers `404`. */
    readonly path?: string;
    /**
     * The bearer token clients must present. Generated when absent.
     *
     * There is no way to disable it. See the file header.
     */
    readonly token?: string;
    /** Extra web origins to accept, beyond loopback. Exact match on scheme+host+port. */
    readonly allowedOrigins?: readonly string[];
    readonly maxBodyBytes?: number;
    readonly onEvent?: (event: ListenerEvent) => void;
}

const DEFAULT_PATH = '/mcp';

// ---------------------------------------------------------------------------

export class StreamableHttpListener implements Transport {
    readonly era: ProtocolEra;
    readonly profile: HttpEraProfile;
    /** The bearer token this listener requires. Print it once; never write it to disk. */
    readonly token: string;
    readonly path: string;

    readonly #host: string;
    readonly #port: number;
    readonly #allowedOrigins: readonly string[];
    readonly #maxBodyBytes: number;
    readonly #onEvent: ((event: ListenerEvent) => void) | undefined;
    /**
     * The SDK transport, for the `2025-11-25` lane only. `undefined` under `2026-07-28`, where the
     * SDK's stateless mode is single-use and this file handles POST itself.
     */
    readonly #inner: StreamableHTTPServerTransport | undefined;
    /** `2026-07-28` lane: POSTs awaiting the response to the request they carried, keyed by id. */
    readonly #pending = new Map<string, ServerResponse>();
    readonly #http: HttpServer;

    #started = false;
    #closed = false;
    #address: AddressInfo | undefined;

    onclose?: () => void;
    onerror?: (error: Error) => void;
    onmessage?: <T extends JSONRPCMessage>(message: T, extra?: MessageExtraInfo) => void;

    /**
     * The `Mcp-Session-Id` the inner transport assigned, under the eras that have sessions.
     *
     * A plain property rather than a getter because `Transport` declares it `sessionId?: string`
     * and this tsconfig sets `exactOptionalPropertyTypes`, under which a getter returning
     * `string | undefined` is a different type from an optional `string`. It is mirrored from the
     * inner transport after each handled request, and stays absent under `2026-07-28`, which has
     * no sessions at all.
     */
    sessionId?: string;

    constructor(options: StreamableHttpListenerOptions = {}) {
        this.era = options.era ?? DEFAULT_PROTOCOL_ERA;
        this.profile = httpProfileForEra(this.era);
        this.token = options.token ?? generateBearerToken();
        this.path = options.path ?? DEFAULT_PATH;
        this.#host = options.host ?? DEFAULT_LISTEN_HOST;
        this.#port = options.port ?? 0;
        this.#allowedOrigins = options.allowedOrigins ?? [];
        this.#maxBodyBytes = options.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;
        this.#onEvent = options.onEvent;

        this.#inner = this.profile.usesSessions
            ? new StreamableHTTPServerTransport({
                  sessionIdGenerator: (): string => randomUUID(),
                  /*
                   * **The CVE-2025-66414 default, overridden explicitly.**
                   *
                   * The SDK reads `options.enableDnsRebindingProtection ?? false`
                   * (`webStandardStreamableHttp.js:79`), so a server built the obvious way ships the
                   * exact configuration the CVE describes. It is turned on here as defence in depth.
                   *
                   * Be precise about what that buys, because overstating it would be worse than
                   * leaving it off: the SDK's own check compares the `Host` header — **port
                   * included** — against `allowedHosts` by exact string match, and this listener
                   * defaults to port 0 so the authority is not known until the socket is bound.
                   * `allowedHosts` is therefore not passed, and with only `allowedOrigins` set the
                   * SDK's check covers `Origin` alone. **The `Host` half is done by
                   * `checkRequestOrigin` in `./http.ts`, which runs first and is stricter**: it
                   * refuses any non-loopback `Host` whether or not an allowlist was configured,
                   * which is the case the SDK cannot express.
                   */
                  enableDnsRebindingProtection: true,
                  ...(this.#allowedOrigins.length > 0 ? { allowedOrigins: [...this.#allowedOrigins] } : {})
              })
            : undefined;

        if (this.#inner !== undefined) {
            this.#inner.onmessage = (message, extra): void => {
                this.onmessage?.(message, extra);
            };
            this.#inner.onerror = (error): void => {
                this.onerror?.(error);
            };
            this.#inner.onclose = (): void => {
                this.onclose?.();
            };
        }

        this.#http = createServer((req, res) => {
            void this.#handle(req, res).catch((error: unknown) => {
                const err = error instanceof Error ? error : new Error(String(error));
                this.#emit({ kind: 'listener-error', error: err });
                this.onerror?.(err);
                if (!res.headersSent) {
                    this.#refuse(res, 500, 'toolwall/http.internal', 'Internal error.', req);
                }
            });
        });
        this.#http.on('error', (error: Error) => {
            this.#emit({ kind: 'listener-error', error });
            this.onerror?.(error);
        });
    }

    /** `http://host:port/path`, available once {@link start} has resolved. */
    get url(): string {
        const address = this.#address;
        if (address === undefined) {
            return `http://${this.#host}:${this.#port}${this.path}`;
        }
        const host = address.family === 'IPv6' ? `[${address.address}]` : address.address;
        return `http://${host}:${address.port}${this.path}`;
    }

    get port(): number {
        return this.#address?.port ?? this.#port;
    }

    /** True when this listener is reachable from outside the machine. The CLI says so loudly. */
    get boundBeyondLoopback(): boolean {
        return !isLoopbackHost(this.#host);
    }


    // --- Transport ---------------------------------------------------------

    async start(): Promise<void> {
        if (this.#started) {
            throw new Error('StreamableHttpListener already started');
        }
        this.#started = true;
        await this.#inner?.start();
        await new Promise<void>((resolve, reject) => {
            const onError = (error: Error): void => reject(error);
            this.#http.once('error', onError);
            this.#http.listen(this.#port, this.#host, () => {
                this.#http.removeListener('error', onError);
                this.#address = this.#http.address() as AddressInfo;
                this.#emit({ kind: 'listening', url: this.url, era: this.era });
                resolve();
            });
        });
    }

    /**
     * Deliver one message towards the client.
     *
     * Legacy lane: the SDK owns routing, including the standalone `GET` stream.
     *
     * POST-only lane: a result or an error is the answer to a POST that is still open, found by
     * JSON-RPC id. Anything else — a relayed notification, a server-initiated request — has no
     * channel on a POST-only endpoint and is reported rather than dropped in silence. See the
     * header: this is a stated limitation of that lane, not an oversight.
     */
    async send(message: JSONRPCMessage, options?: TransportSendOptions): Promise<void> {
        if (this.#inner !== undefined) {
            await this.#inner.send(message, options as { relatedRequestId?: RequestId } | undefined);
            return;
        }

        const record = message as unknown as Record<string, unknown>;
        const id = record['id'];
        const isAnswer = ('result' in record || 'error' in record) && (typeof id === 'string' || typeof id === 'number');
        if (!isAnswer) {
            const method = typeof record['method'] === 'string' ? (record['method'] as string) : 'a message';
            this.#emit({
                kind: 'listener-error',
                error: new Error(
                    `toolwall: ${method} could not be delivered. The ${this.era} Streamable HTTP transport is POST-only, ` +
                        'so a server->client message that is not the answer to an in-flight request has no channel. ' +
                        'Use --era 2025-11-25 over HTTP, or stdio, if this server sends notifications or sampling requests.'
                )
            });
            return;
        }

        const res = this.#pending.get(String(id));
        if (res === undefined) {
            // The POST went away (client disconnected, or the answer arrived twice). Nothing to
            // write to, and nothing that needs saying beyond verbose diagnostics.
            return;
        }
        this.#pending.delete(String(id));
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify(message));
    }

    async close(): Promise<void> {
        if (this.#closed) return;
        this.#closed = true;
        for (const [, res] of this.#pending) {
            if (!res.writableEnded) {
                res.end();
            }
        }
        this.#pending.clear();
        await this.#inner?.close();
        await new Promise<void>(resolve => {
            this.#http.close(() => resolve());
            // Sockets kept alive by a client that never disconnects would otherwise hold the
            // process open past the point the proxy considers itself shut down.
            this.#http.closeAllConnections?.();
        });
    }

    // --- Request handling --------------------------------------------------

    /**
     * The order of these checks is a security decision.
     *
     * Origin/Host first, before credentials, before the era shape, before the body: a hostile web
     * page must not be able to distinguish "wrong token" from "right token" by the shape of the
     * refusal, and it must not be able to reach body parsing at all. Path check is first of all
     * because a request to some other path is not addressed to us.
     */
    async #handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
        const path = (req.url ?? '/').split('?')[0] ?? '/';
        if (path !== this.path) {
            this.#refuse(res, 404, 'toolwall/http.unknown-path', `No MCP endpoint at ${path}.`, req);
            return;
        }

        // 1. DNS rebinding / cross-origin. 403, and never 401: this is not about credentials.
        const origin = checkRequestOrigin(req.headers, {
            allowedOrigins: this.#allowedOrigins,
            ...(this.#address !== undefined ? { boundAuthority: `${this.#host}:${this.#address.port}` } : {})
        });
        if (!origin.ok) {
            this.#refuse(res, origin.status, origin.ruleId, origin.message, req);
            return;
        }

        // 2. Authentication. There is no configuration in which this is skipped.
        if (!bearerTokenMatches(this.token, readBearerToken(req.headers))) {
            res.setHeader('WWW-Authenticate', 'Bearer realm="toolwall"');
            this.#refuse(
                res,
                401,
                'toolwall/http.unauthenticated',
                'A bearer token is required. toolwall prints the token for this session on stderr at startup.',
                req
            );
            return;
        }

        // 3. The era's HTTP shape. Under 2026-07-28 there is no GET stream and no session to
        //    DELETE, so both are 405 rather than being quietly accepted and doing nothing.
        const method = (req.method ?? 'GET').toUpperCase();
        if (!this.profile.allowedMethods.includes(method)) {
            res.setHeader('Allow', this.profile.allowedMethods.join(', '));
            this.#refuse(
                res,
                405,
                'toolwall/http.method-not-allowed',
                `${method} is not part of the ${this.era} Streamable HTTP transport. Allowed: ${this.profile.allowedMethods.join(', ')}.`,
                req
            );
            return;
        }

        if (method !== 'POST') {
            // Only reachable on the legacy lane: the POST-only profile already answered 405 above.
            await this.#inner?.handleRequest(req, res);
            this.#mirrorSessionId();
            return;
        }

        // 4. Body, bounded.
        const read = await readJsonBody(req, this.#maxBodyBytes);
        if (!read.ok) {
            this.#refuse(res, read.status, 'toolwall/http.body', read.message, req);
            return;
        }

        // 5. Header/body agreement — the reason `./headers.ts` exists.
        //
        //    Under a revision that mandates mirroring, every POST is checked. Under one that does
        //    not, the check runs only when the request actually carries a header a policy engine
        //    would read, and then refuses with -32022: we do not police headers whose correctness
        //    nothing requires, because trusting them is precisely the split this guards against.
        if (this.profile.requiresHeaderMirroring || hasMirroredPolicyHeaders(req.headers as IncomingHeaders)) {
            const check = verifyHeaderBodyAgreement(req.headers as IncomingHeaders, read.body, {
                requireValidatingRevision: true
            });
            if (!check.ok) {
                this.#emit({
                    kind: 'rejected',
                    status: check.httpStatus,
                    ruleId: check.violations[0]?.ruleId ?? 'toolwall/header-mismatch',
                    message: check.error.message,
                    method,
                    path
                });
                res.writeHead(check.httpStatus, { 'content-type': 'application/json' });
                res.end(
                    JSON.stringify({
                        jsonrpc: '2.0',
                        id: readJsonRpcId(read.body),
                        error: check.error
                    })
                );
                return;
            }
        }

        if (this.#inner !== undefined) {
            await this.#inner.handleRequest(req, res, read.body);
            this.#mirrorSessionId();
            return;
        }
        this.#handlePostOnly(read.body, res);
    }

    /**
     * The `2026-07-28` POST-only lane.
     *
     * One JSON-RPC message per POST. A request parks the `ServerResponse` under its id until
     * `send()` produces the answer; a notification or a response is `202 Accepted`, which is what
     * the revision specifies for a body that expects nothing back.
     *
     * Batches are refused rather than fanned out. `verifyHeaderBodyAgreement` already rejects one
     * — a single set of mirrored headers cannot honestly describe N messages — but this lane must
     * refuse them even when no mirrored header was sent, because parking N responses under one
     * HTTP response is a correlation problem with no correct answer.
     */
    #handlePostOnly(body: unknown, res: ServerResponse): void {
        if (Array.isArray(body)) {
            res.writeHead(400, { 'content-type': 'application/json' });
            res.end(
                JSON.stringify({
                    jsonrpc: '2.0',
                    id: null,
                    error: {
                        code: -32600,
                        message: 'toolwall: JSON-RPC batches are not part of the 2026-07-28 Streamable HTTP transport.',
                        data: { toolwall: { ruleId: 'toolwall/http.batch-refused', status: 400 } }
                    }
                })
            );
            return;
        }

        const record = (typeof body === 'object' && body !== null ? body : {}) as Record<string, unknown>;
        const id = record['id'];
        const isRequest = typeof record['method'] === 'string' && (typeof id === 'string' || typeof id === 'number');

        if (!isRequest) {
            res.writeHead(202).end();
            this.onmessage?.(body as JSONRPCMessage);
            return;
        }

        const key = String(id);
        this.#pending.set(key, res);
        res.on('close', () => {
            // The client hung up before the answer arrived. Forget the slot so a late `send()`
            // does not write to a dead socket, and so a client that abandons requests in a loop
            // cannot grow this map without bound.
            if (this.#pending.get(key) === res) {
                this.#pending.delete(key);
            }
        });
        this.onmessage?.(body as JSONRPCMessage);
    }

    #mirrorSessionId(): void {
        const id = this.#inner?.sessionId;
        if (id !== undefined) {
            this.sessionId = id;
        }
    }

    #refuse(res: ServerResponse, status: number, ruleId: string, message: string, req: IncomingMessage): void {
        this.#emit({
            kind: 'rejected',
            status,
            ruleId,
            message,
            method: (req.method ?? 'GET').toUpperCase(),
            path: (req.url ?? '/').split('?')[0] ?? '/'
        });
        if (res.headersSent) {
            res.end();
            return;
        }
        res.writeHead(status, { 'content-type': 'application/json' });
        // A JSON-RPC envelope even for transport-level refusals, because the peer is a JSON-RPC
        // client and an HTML error page from a proxy is how a client reports "the server is broken"
        // instead of "you were refused".
        res.end(
            JSON.stringify({
                jsonrpc: '2.0',
                id: null,
                error: { code: -32600, message: `toolwall: ${message}`, data: { toolwall: { ruleId, status } } }
            })
        );
    }

    #emit(event: ListenerEvent): void {
        this.#onEvent?.(event);
    }
}

/** The `id` of a single JSON-RPC message, so a `-32020` refusal can be addressed to it. */
function readJsonRpcId(body: unknown): string | number | null {
    if (typeof body !== 'object' || body === null || Array.isArray(body)) return null;
    const id = (body as Record<string, unknown>)['id'];
    return typeof id === 'string' || typeof id === 'number' ? id : null;
}
