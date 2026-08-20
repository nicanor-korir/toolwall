/**
 * Streamable HTTP — the era adapter, the security primitives, and the upstream leg.
 *
 * WHAT THIS BUYS, AND WHY IT IS NOT JUST "ANOTHER TRANSPORT"
 * ---------------------------------------------------------
 * Until this landed toolwall was stdio-only, and stdio-only means two things that are not
 * obvious from the outside:
 *
 *  1. **We could not proxy a remote MCP server at all.** Every hosted server speaks Streamable
 *     HTTP; a guardrail proxy that only speaks stdio guards only what runs on your laptop.
 *  2. **`./headers.ts` had no live consumer.** It is a complete, tested implementation of the
 *     2026-07-28 header/body agreement rules, and it validated nothing, because nothing in the
 *     product ever received an HTTP request. It was classified `exported-only` in
 *     `test/integration/wiring-completeness.test.ts` specifically so that fact had a test behind
 *     it rather than a comment. This module and `./listener.ts` are what make it live.
 *
 * THE TWO ERA SHAPES, WHICH ARE WIRE-INCOMPATIBLE
 * ----------------------------------------------
 * `docs/RESEARCH-BRIEF.md` §1.6 is explicit that these are not a version bump of one another:
 *
 * | | `2025-11-25` (legacy) | `2026-07-28` |
 * |---|---|---|
 * | POST | yes | yes, and **only** POST |
 * | GET (standalone SSE stream) | yes | **405** |
 * | DELETE (session termination) | yes | **405** |
 * | sessions (`Mcp-Session-Id`) | yes | none |
 * | resumability (`Last-Event-ID`) | yes | none |
 * | header/body mirroring | not required | **required**, and an intermediary must police it |
 *
 * The whole difference lives in {@link HttpEraProfile} so that the listener branches once, on a
 * data structure, rather than sprinkling `if (era === …)` through request handling — the same
 * era-adapter boundary `./mrtr.ts` keeps for MRTR.
 *
 * SECURITY POSTURE — NONE OF THIS IS OPTIONAL
 * -------------------------------------------
 * Three CVEs, all the same shape, all in the last eighteen months:
 *
 *  - **CVE-2025-66414** — the TypeScript SDK shipped DNS-rebinding protection **off by default**
 *    (`enableDnsRebindingProtection ?? false`, still the default in the `@modelcontextprotocol/sdk`
 *    1.30.0 tree vendored here — read, not assumed: `dist/esm/server/webStandardStreamableHttp.js:79`).
 *    The *same default shipped simultaneously in the Python, Go, Java, Rust and Ruby SDKs*, which
 *    is what tells you it is a specification-level design failure and not one library's bug.
 *  - **CVE-2025-49596** — MCP Inspector, CVSS 9.4. An unauthenticated local endpoint any web page
 *    could reach.
 *  - **CVE-2026-23744** — MCPJam, CVSS 9.8, exploited in the wild from February 2026. Same.
 *
 * A localhost listener is not a private one. A web page the user has open can issue requests to
 * `http://127.0.0.1:<port>` all day, and DNS rebinding turns an attacker-controlled name into a
 * loopback address so the browser believes it is same-origin. So:
 *
 *  - **Origin is validated and a mismatch is `403`** — {@link checkRequestOrigin}. Enabled always,
 *    never gated on a flag, and the SDK's own protection is *additionally* switched on explicitly
 *    in `./listener.ts` so the CVE default cannot be what ships.
 *  - **Loopback bind by default** — {@link DEFAULT_LISTEN_HOST}. Widening it is an explicit act
 *    with a warning attached.
 *  - **No unauthenticated local control plane** — every request carries a bearer token
 *    ({@link generateBearerToken}, {@link bearerTokenMatches}) and there is no flag to turn that
 *    off. We are a security tool; the spec warns stdio proxies about becoming an escalation path,
 *    and a listener that lets any local process drive the proxied server *is* that path.
 *
 * WHAT IS LIVE AND WHAT IS NOT — SAY IT PLAINLY
 * ---------------------------------------------
 * The **listener** half is live: `./listener.ts` is constructed by the CLI under `--listen` and is
 * the `clientTransport` the assembled proxy runs on, so `verifyHeaderBodyAgreement` runs on real
 * traffic.
 *
 * The **upstream** half ({@link createUpstreamHttpTransport}) is complete and is proven end to end
 * against a real HTTP MCP server in `test/integration/http.test.ts`, driving a real `ToolwallProxy`.
 * It is **not** reachable from `assembleToolwall()`, because that function takes a `SpawnSpec` and
 * builds a stdio child unconditionally, and `src/index.ts` belongs to the integrator. The additive
 * change it needs is one option — `ToolwallOptions.upstream?: { kind: "http"; url: string } |
 * { kind: "stdio"; spec: SpawnSpec }` — with `createUpstreamHttpTransport` supplying both the
 * transport and the `serverId` exactly as `createUpstreamStdioTransport` already does. Until that
 * lands, an embedder reaches it through `ToolwallProxy` directly. Do not let a README say toolwall
 * proxies remote servers out of the box before that option exists.
 */

import { randomBytes, timingSafeEqual } from 'node:crypto';
import type { IncomingHttpHeaders } from 'node:http';

import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';

import { deriveServerId } from '../audit/identity.js';
import type { ProtocolEra } from '../types/protocol.js';

// ---------------------------------------------------------------------------
// Era adapter
// ---------------------------------------------------------------------------

/**
 * Everything about an HTTP request that depends on which revision is being spoken.
 *
 * One structure so the listener asks the profile rather than asking the era. A future revision is
 * a new entry here and nothing else.
 */
export interface HttpEraProfile {
    readonly era: ProtocolEra;
    /** Whether `GET` opens a standalone SSE stream. `false` means `405`. */
    readonly allowsGetStream: boolean;
    /** Whether `DELETE` terminates a session. `false` means `405`. */
    readonly allowsDeleteSession: boolean;
    /** Whether the server assigns `Mcp-Session-Id`. */
    readonly usesSessions: boolean;
    /** Whether `Last-Event-ID` resumption exists. */
    readonly supportsResumability: boolean;
    /**
     * Whether this revision *obliges* the client to mirror body fields into headers, and therefore
     * whether an intermediary may police those headers at all (§1.7).
     */
    readonly requiresHeaderMirroring: boolean;
    /** Methods answered rather than refused. Everything else is `405` with this in `Allow`. */
    readonly allowedMethods: readonly string[];
}

const PROFILE_2025: HttpEraProfile = Object.freeze({
    era: '2025-11-25',
    allowsGetStream: true,
    allowsDeleteSession: true,
    usesSessions: true,
    supportsResumability: true,
    requiresHeaderMirroring: false,
    allowedMethods: Object.freeze(['POST', 'GET', 'DELETE'])
});

const PROFILE_2026: HttpEraProfile = Object.freeze({
    era: '2026-07-28',
    allowsGetStream: false,
    allowsDeleteSession: false,
    usesSessions: false,
    supportsResumability: false,
    requiresHeaderMirroring: true,
    allowedMethods: Object.freeze(['POST'])
});

export function httpProfileForEra(era: ProtocolEra): HttpEraProfile {
    return era === '2026-07-28' ? PROFILE_2026 : PROFILE_2025;
}

// ---------------------------------------------------------------------------
// Loopback and origin
// ---------------------------------------------------------------------------

/**
 * Where a listener binds unless an operator says otherwise.
 *
 * IPv4 loopback rather than `localhost`: a name resolves through whatever the host's resolver
 * says, and "whatever the resolver says" is the input an attacker controls in a rebinding attack.
 * A literal cannot be redirected.
 */
export const DEFAULT_LISTEN_HOST = '127.0.0.1';

/** Hostnames that name this machine and cannot be pointed elsewhere by a DNS answer. */
const LOOPBACK_LITERALS = new Set(['127.0.0.1', '::1', '0:0:0:0:0:0:0:1', 'localhost']);

/**
 * Is this host a loopback address?
 *
 * `localhost` is included because every real client uses it and refusing it makes the feature
 * unusable, but note it is a *name*: it is trusted here on the strength of the platform resolver,
 * which is why the default BIND address is the literal and why Origin is validated separately.
 * Any address in `127.0.0.0/8` counts — `127.0.0.1` is not the only loopback address, and a
 * check that only knew about it would be trivially sidestepped by `127.0.0.2`.
 */
export function isLoopbackHost(host: string): boolean {
    const bare = host.trim().toLowerCase().replace(/^\[|\]$/gu, '');
    if (LOOPBACK_LITERALS.has(bare)) {
        return true;
    }
    return /^127\.(?:\d{1,3})\.(?:\d{1,3})\.(?:\d{1,3})$/u.test(bare);
}

/** Split a `Host:`/`Origin:` authority into host and optional port, IPv6 literals included. */
export function splitAuthority(authority: string): { host: string; port: string | undefined } {
    const value = authority.trim();
    if (value.startsWith('[')) {
        const end = value.indexOf(']');
        if (end !== -1) {
            const host = value.slice(0, end + 1);
            const rest = value.slice(end + 1);
            return { host, port: rest.startsWith(':') ? rest.slice(1) : undefined };
        }
    }
    const colon = value.lastIndexOf(':');
    if (colon === -1) {
        return { host: value, port: undefined };
    }
    return { host: value.slice(0, colon), port: value.slice(colon + 1) };
}

export interface OriginCheckOptions {
    /**
     * Exact origins to accept, e.g. `https://app.example`. Compared byte-for-byte after lowercasing
     * the scheme and host — no suffix matching, because `https://evil-app.example` ends with
     * `app.example` and a suffix rule is how that becomes a bypass.
     */
    readonly allowedOrigins?: readonly string[];
    /** The `host:port` this listener is bound to, for the `Host` half of the check. */
    readonly boundAuthority?: string;
}

export type OriginCheck =
    | { readonly ok: true }
    | { readonly ok: false; readonly status: 403; readonly ruleId: string; readonly message: string };

/**
 * Validate `Origin` and `Host` — the DNS-rebinding control, contract-level, always on.
 *
 * Two headers, two different attacks, and both have to be checked:
 *
 *  - **`Origin`** says which web origin a browser is making this request *on behalf of*. A page on
 *    `https://evil.example` that fetches `http://127.0.0.1:9000/mcp` sends
 *    `Origin: https://evil.example`, and refusing it is what stops a visited web page from driving
 *    the user's MCP servers. A request with no `Origin` at all is not a browser request; it is
 *    accepted, because every legitimate MCP client is not a browser, and rejecting it would make
 *    the transport unusable while stopping nothing — the bearer token is what authorises those.
 *  - **`Host`** is what DNS rebinding manipulates: the attacker's name resolves to `127.0.0.1`
 *    after the TTL expires, so the browser now believes `http://evil.example:9000` *is* the
 *    listener and sends `Host: evil.example:9000` with no cross-origin restrictions. Requiring the
 *    `Host` header to name a loopback address (or the exact authority we bound to) refuses that,
 *    and it refuses it even when there is no `Origin` header at all.
 *
 * Returning `403` rather than `401` is deliberate: this is not "you did not authenticate", it is
 * "this request may not be made from there at all", and answering `401` would invite a browser to
 * retry with credentials.
 */
export function checkRequestOrigin(headers: IncomingHttpHeaders, options: OriginCheckOptions = {}): OriginCheck {
    const hostHeader = firstHeader(headers['host']);
    if (hostHeader !== undefined) {
        const { host } = splitAuthority(hostHeader);
        const boundMatches = options.boundAuthority !== undefined && hostHeader.toLowerCase() === options.boundAuthority.toLowerCase();
        if (!boundMatches && !isLoopbackHost(host)) {
            return {
                ok: false,
                status: 403,
                ruleId: 'toolwall/http.host-not-permitted',
                message:
                    `Host header ${JSON.stringify(hostHeader)} names neither this listener's bound address nor a loopback address. ` +
                    'That is the DNS-rebinding shape (CVE-2025-66414): a name the attacker controls, resolved to 127.0.0.1.'
            };
        }
    }

    const origin = firstHeader(headers['origin']);
    if (origin === undefined || origin === 'null') {
        // Not a browser request, or a browser that deliberately opaque-ified it. The bearer token
        // is what authorises this, not the absence of a header.
        return { ok: true };
    }

    const allowed = options.allowedOrigins ?? [];
    if (allowed.some(candidate => sameOrigin(candidate, origin))) {
        return { ok: true };
    }
    // A loopback origin is the one thing accepted without being named: it is another program on
    // this machine that has already been given the token, not a page on the open web.
    let parsed: URL;
    try {
        parsed = new URL(origin);
    } catch {
        return {
            ok: false,
            status: 403,
            ruleId: 'toolwall/http.origin-unparseable',
            message: `Origin ${JSON.stringify(origin)} is not a URL.`
        };
    }
    if (isLoopbackHost(parsed.hostname)) {
        return { ok: true };
    }
    return {
        ok: false,
        status: 403,
        ruleId: 'toolwall/http.origin-not-allowed',
        message:
            `Origin ${JSON.stringify(origin)} is not permitted. A web page cannot be allowed to drive this proxy: ` +
            'CVE-2025-49596 (MCP Inspector, CVSS 9.4) and CVE-2026-23744 (MCPJam, CVSS 9.8, exploited from Feb 2026) ' +
            'were both unauthenticated local endpoints reachable from a browser. Add --listen-allow-origin to permit one.'
    };
}

/** Exact origin comparison: scheme and host case-folded, port and path significant. */
function sameOrigin(a: string, b: string): boolean {
    try {
        const left = new URL(a);
        const right = new URL(b);
        return (
            left.protocol.toLowerCase() === right.protocol.toLowerCase() &&
            left.hostname.toLowerCase() === right.hostname.toLowerCase() &&
            left.port === right.port
        );
    } catch {
        return false;
    }
}

export function firstHeader(value: string | readonly string[] | undefined): string | undefined {
    if (typeof value === 'string') return value;
    if (Array.isArray(value)) return value[0];
    return undefined;
}

// ---------------------------------------------------------------------------
// Bearer authentication
// ---------------------------------------------------------------------------

/**
 * A fresh listener token.
 *
 * 256 bits from `randomBytes`, base64url so it survives a shell, a header and a copy-paste. It is
 * printed once on stderr at startup and never written to disk: a token in a file is a token in a
 * backup.
 */
export function generateBearerToken(): string {
    return randomBytes(32).toString('base64url');
}

/**
 * Constant-time bearer comparison.
 *
 * `timingSafeEqual` throws on a length mismatch, which would itself leak the length, so both sides
 * are hashed to a fixed width first — cheaper than the alternative of padding, and it removes the
 * throw. A local timing oracle is not the likeliest attack on a loopback listener; it is also not
 * a reason to write the comparison the wrong way.
 */
export function bearerTokenMatches(expected: string, presented: string | undefined): boolean {
    if (presented === undefined) return false;
    const a = Buffer.from(expected, 'utf8');
    const b = Buffer.from(presented, 'utf8');
    if (a.length !== b.length) {
        // Still compare something of equal length so the branch does not become the oracle.
        timingSafeEqual(a, a);
        return false;
    }
    return timingSafeEqual(a, b);
}

/** Read the bearer credential out of an `Authorization` header, or `undefined`. */
export function readBearerToken(headers: IncomingHttpHeaders): string | undefined {
    const raw = firstHeader(headers['authorization']);
    if (raw === undefined) return undefined;
    const match = /^Bearer[ \t]+(\S+)$/u.exec(raw.trim());
    return match?.[1];
}

// ---------------------------------------------------------------------------
// Body reading
// ---------------------------------------------------------------------------

/** Default cap on a POST body. A proxy that will buffer anything is a memory-exhaustion primitive. */
export const DEFAULT_MAX_BODY_BYTES = 4 * 1024 * 1024;

export type BodyRead =
    | { readonly ok: true; readonly body: unknown }
    | { readonly ok: false; readonly status: 400 | 413; readonly message: string };

/**
 * Read and parse a JSON body, bounded.
 *
 * The bound is enforced on bytes actually received rather than on `Content-Length`, because
 * `Content-Length` is a claim by the sender and the whole subject of this module is what happens
 * when two descriptions of one request disagree.
 */
export async function readJsonBody(
    stream: AsyncIterable<Buffer | string>,
    maxBytes: number = DEFAULT_MAX_BODY_BYTES
): Promise<BodyRead> {
    const chunks: Buffer[] = [];
    let total = 0;
    for await (const chunk of stream) {
        const buf = typeof chunk === 'string' ? Buffer.from(chunk, 'utf8') : chunk;
        total += buf.length;
        if (total > maxBytes) {
            return { ok: false, status: 413, message: `Request body exceeds ${maxBytes} bytes.` };
        }
        chunks.push(buf);
    }
    if (total === 0) {
        return { ok: false, status: 400, message: 'Request body is empty.' };
    }
    try {
        return { ok: true, body: JSON.parse(Buffer.concat(chunks).toString('utf8')) };
    } catch (error) {
        return { ok: false, status: 400, message: `Request body is not JSON: ${error instanceof Error ? error.message : String(error)}` };
    }
}

// ---------------------------------------------------------------------------
// Upstream leg
// ---------------------------------------------------------------------------

export class HttpUpstreamError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'HttpUpstreamError';
    }
}

export interface HttpUpstreamSpec {
    /** Absolute `http:` or `https:` URL of the remote MCP endpoint. */
    readonly url: string;
    /** Extra headers on every request — an `Authorization` for the remote server, typically. */
    readonly headers?: Readonly<Record<string, string>>;
    /**
     * Accept plaintext `http:` to a non-loopback host. Off by default and it should stay off:
     * every message on this leg is the traffic toolwall exists to inspect, and inspecting it after
     * an on-path attacker has rewritten it is not a control.
     */
    readonly allowInsecureHttp?: boolean;
}

export interface HttpUpstream {
    readonly transport: Transport;
    /** The identity the pin store and every `GuardContext` key on (T-04). */
    readonly serverId: string;
    readonly url: string;
    readonly warnings: readonly string[];
}

/**
 * Build the upstream leg for a remote Streamable HTTP MCP server.
 *
 * Mirrors `createUpstreamStdioTransport` deliberately, down to returning the `serverId` alongside
 * the transport: the pin store and the guards key on that value, and a caller that derived it
 * separately would be one refactor away from the Week-1 defect where two derivations disagreed and
 * every pin silently orphaned (`src/audit/identity.ts`).
 *
 * `deriveServerId` already understands an HTTP identity and hashes scheme, host, path and the
 * *names* of query parameters — never their values, which is where a hosted server puts a key.
 */
export function createUpstreamHttpTransport(spec: HttpUpstreamSpec): HttpUpstream {
    let url: URL;
    try {
        url = new URL(spec.url);
    } catch {
        throw new HttpUpstreamError(`toolwall: ${JSON.stringify(spec.url)} is not a URL.`);
    }
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
        throw new HttpUpstreamError(
            `toolwall: refusing to connect upstream over ${url.protocol}. Streamable HTTP is http: or https:.`
        );
    }

    const warnings: string[] = [];
    if (url.protocol === 'http:' && !isLoopbackHost(url.hostname)) {
        if (spec.allowInsecureHttp !== true) {
            throw new HttpUpstreamError(
                `toolwall: refusing to speak plaintext http: to ${url.host}. Every tool call and every result would ` +
                    'cross the network in the clear, and a guardrail applied to traffic an on-path attacker can rewrite ' +
                    'is not a guardrail. Use https:, or pass --upstream-allow-insecure-http if you own the path.'
            );
        }
        warnings.push(
            `upstream is plaintext http: to ${url.host}. toolwall inspects what the server sends; it cannot tell you ` +
                'whether that is what the server sent.'
        );
    }

    const transport = new StreamableHTTPClientTransport(url, {
        ...(spec.headers !== undefined ? { requestInit: { headers: { ...spec.headers } } } : {})
    });

    return {
        /*
         * The SDK is not compiled with `exactOptionalPropertyTypes`, so its transports declare
         * `sessionId: string | undefined` where the `Transport` interface it also publishes says
         * `sessionId?: string`. Identical at runtime, different to this tsconfig. The cast is the
         * tax for compiling stricter than the dependency, and it is confined to this one line.
         */
        transport: transport as unknown as Transport,
        serverId: deriveServerId({ transport: 'http', url: url.toString() }),
        url: url.toString(),
        warnings
    };
}
