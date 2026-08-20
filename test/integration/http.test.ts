/**
 * **Streamable HTTP, end to end, over a real socket.**
 *
 * Two things this file proves that nothing before it could:
 *
 *  1. **`src/transport/headers.ts` is on a live path.** It was classified `exported-only` in
 *     `test/integration/wiring-completeness.test.ts` — a complete, unit-tested control with no
 *     consumer — because toolwall had no HTTP front door for it to validate anything on. Every
 *     header/body case below goes through a real `fetch` to a real listener in front of a real
 *     spawned MCP server, so the `-32020 HeaderMismatch` path is exercised by traffic rather than
 *     by a unit test calling the validator directly.
 *  2. **toolwall can proxy a remote MCP server.** The last section drives a real `ToolwallProxy`
 *     whose upstream leg is Streamable HTTP against a real HTTP MCP server, with a guard registered,
 *     which is the capability the product did not have at all while it was stdio-only.
 *
 * The security assertions are not decoration. `Origin` validation, loopback binding and mandatory
 * authentication are the three things CVE-2025-66414 (DNS-rebinding protection off by default in
 * the TypeScript SDK *and simultaneously in the Python, Go, Java, Rust and Ruby SDKs*),
 * CVE-2025-49596 (MCP Inspector, CVSS 9.4) and CVE-2026-23744 (MCPJam, CVSS 9.8, exploited in the
 * wild from February 2026) were all about. A test that only covered the happy path would be
 * covering the least important thing this listener does.
 */

import { afterEach, describe, expect, it } from 'vitest';
import { createServer, request as httpRequest, type Server as HttpServer } from 'node:http';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { PassThrough } from 'node:stream';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import type { AddressInfo } from 'node:net';

import { Server as McpServer } from '@modelcontextprotocol/sdk/server/index.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';

import { assembleToolwall, type Toolwall } from '../../src/index.js';
import { AuditLog } from '../../src/audit/log.js';
import { PinStore } from '../../src/audit/manifest.js';
import { StreamableHttpListener } from '../../src/transport/listener.js';
import { createUpstreamHttpTransport, HttpUpstreamError, isLoopbackHost } from '../../src/transport/http.js';
import { mirroredHeadersForBody } from '../../src/transport/headers.js';
import { ToolwallProxy } from '../../src/transport/proxy.js';
import { DefaultGuardPipeline } from '../../src/transport/pipeline.js';
import { ALLOW, TOOLWALL_BLOCKED, type Guard, type GuardContext, type Verdict } from '../../src/types/protocol.js';
import { FIXTURE_SERVER } from './harness.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const CONCURRENT_SERVER = path.resolve(here, '../fixtures/concurrent-server.mjs');

// ---------------------------------------------------------------------------
// A toolwall whose CLIENT leg is HTTP
// ---------------------------------------------------------------------------

interface HttpPeer {
    readonly toolwall: Toolwall;
    readonly listener: StreamableHttpListener;
    readonly url: string;
    readonly token: string;
    close(): Promise<void>;
}

const cleanups: Array<() => Promise<void>> = [];

afterEach(async () => {
    while (cleanups.length > 0) {
        await cleanups.pop()?.();
    }
});

async function serveOverHttp(options: { era?: '2025-11-25' | '2026-07-28'; server?: string } = {}): Promise<HttpPeer> {
    const dir = await mkdtemp(path.join(tmpdir(), 'toolwall-http-'));
    const pins = await PinStore.open({ cwd: dir });
    const listener = new StreamableHttpListener({ era: options.era ?? '2026-07-28' });

    const toolwall = assembleToolwall({
        clientTransport: listener,
        spec: { command: process.execPath, args: [options.server ?? CONCURRENT_SERVER] },
        spawnPolicy: { allowedCommands: ['node'] },
        pins,
        audit: new AuditLog(),
        era: options.era ?? '2026-07-28',
        baseDir: dir,
        confirmationChannel: null,
        onUpstreamTransport: transport => {
            transport.stderr?.resume();
        }
    });
    toolwall.upstreamTransport.stderr?.resume();
    await toolwall.start();

    const peer: HttpPeer = {
        toolwall,
        listener,
        url: listener.url,
        token: listener.token,
        async close() {
            await toolwall.close();
            await rm(dir, { recursive: true, force: true }).catch(() => undefined);
        }
    };
    cleanups.push(() => peer.close());
    return peer;
}

/** A POST that mirrors its body into headers exactly as a conforming 2026-07-28 client would. */
async function post(
    peer: HttpPeer,
    body: Record<string, unknown>,
    overrides: Record<string, string> = {},
    era = '2026-07-28'
): Promise<Response> {
    return fetch(peer.url, {
        method: 'POST',
        headers: {
            'content-type': 'application/json',
            accept: 'application/json, text/event-stream',
            authorization: `Bearer ${peer.token}`,
            ...mirroredHeadersForBody(body, era),
            ...overrides
        },
        body: JSON.stringify(body)
    });
}

/**
 * A POST built with `node:http` rather than `fetch`.
 *
 * `fetch` refuses to set `Host` — it is a forbidden header name in the WHATWG spec and undici
 * enforces it — so the DNS-rebinding case cannot be expressed through it at all. A rebinding
 * attacker is not constrained by `fetch`'s rules: the browser writes the `Host` header itself,
 * naming the attacker's domain, because as far as it is concerned that IS the host. This helper
 * writes the request the way the attack actually arrives.
 */
function rawPost(
    peer: HttpPeer,
    headers: Record<string, string>,
    body: unknown
): Promise<{ status: number; body: string }> {
    return new Promise((resolve, reject) => {
        const payload = JSON.stringify(body);
        const req = httpRequest(
            {
                host: '127.0.0.1',
                port: peer.listener.port,
                path: peer.listener.path,
                method: 'POST',
                headers: {
                    'content-type': 'application/json',
                    accept: 'application/json, text/event-stream',
                    'content-length': Buffer.byteLength(payload),
                    ...headers
                }
            },
            res => {
                let text = '';
                res.setEncoding('utf8');
                res.on('data', chunk => {
                    text += chunk;
                });
                res.on('end', () => resolve({ status: res.statusCode ?? 0, body: text }));
            }
        );
        req.on('error', reject);
        req.end(payload);
    });
}

const INITIALIZE = {
    jsonrpc: '2.0',
    id: 1,
    method: 'initialize',
    params: { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'http-test', version: '1.0.0' } }
} as const;

async function handshakeOverHttp(peer: HttpPeer): Promise<void> {
    const res = await post(peer, { ...INITIALIZE });
    expect(res.status, await res.text().catch(() => '')).toBe(200);
    await post(peer, { jsonrpc: '2.0', method: 'notifications/initialized' });
}

// ---------------------------------------------------------------------------

describe('Streamable HTTP listener · 2026-07-28, the POST-only shape', () => {
    it('proxies a real MCP server end to end over HTTP', async () => {
        const peer = await serveOverHttp();
        await handshakeOverHttp(peer);

        const listed = await post(peer, { jsonrpc: '2.0', id: 2, method: 'tools/list' });
        expect(listed.status).toBe(200);
        const body = (await listed.json()) as { result?: { tools?: Array<{ name: string }> } };
        expect(body.result?.tools?.map(t => t.name)).toContain('slow_echo');

        const called = await post(peer, {
            jsonrpc: '2.0',
            id: 3,
            method: 'tools/call',
            params: { name: 'slow_echo', arguments: { tag: 'over-http' } }
        });
        expect(called.status).toBe(200);
        expect(JSON.stringify(await called.json())).toContain('echo:over-http');
    });

    it('answers 202 to a notification, because there is nothing to answer with', async () => {
        const peer = await serveOverHttp();
        await handshakeOverHttp(peer);
        const res = await post(peer, { jsonrpc: '2.0', method: 'notifications/cancelled', params: { requestId: 99 } });
        expect(res.status).toBe(202);
    });

    it('answers 405 to GET and DELETE, which this revision does not define', async () => {
        const peer = await serveOverHttp();
        for (const method of ['GET', 'DELETE']) {
            const res = await fetch(peer.url, { method, headers: { authorization: `Bearer ${peer.token}` } });
            expect(res.status, method).toBe(405);
            expect(res.headers.get('allow')).toBe('POST');
            const body = (await res.json()) as { error?: { data?: { toolwall?: { ruleId?: string } } } };
            expect(body.error?.data?.toolwall?.ruleId).toBe('toolwall/http.method-not-allowed');
        }
    });

    it('answers 404 for a path that is not the endpoint', async () => {
        const peer = await serveOverHttp();
        const res = await fetch(`http://127.0.0.1:${peer.listener.port}/not-mcp`, {
            method: 'POST',
            headers: { authorization: `Bearer ${peer.token}` }
        });
        expect(res.status).toBe(404);
    });

    it('refuses a JSON-RPC batch, which one set of mirrored headers cannot describe', async () => {
        const peer = await serveOverHttp();
        await handshakeOverHttp(peer);
        const res = await fetch(peer.url, {
            method: 'POST',
            headers: {
                'content-type': 'application/json',
                accept: 'application/json, text/event-stream',
                authorization: `Bearer ${peer.token}`,
                'MCP-Protocol-Version': '2026-07-28'
            },
            body: JSON.stringify([{ jsonrpc: '2.0', id: 9, method: 'tools/list' }])
        });
        expect(res.status).toBe(400);
    });
});

describe('Streamable HTTP listener · the header/body agreement is LIVE (-32020)', () => {
    it('rejects Mcp-Name disagreeing with params.name, and the tool never runs', async () => {
        const peer = await serveOverHttp();
        await handshakeOverHttp(peer);

        // The Akamai header-confusion shape: policy would read `plain`, execution would run
        // `slow_echo`. A proxy that authorised on the header and forwarded the body has published
        // an oracle for how to phrase a bypass.
        const res = await post(
            peer,
            { jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'slow_echo', arguments: { tag: 'x' } } },
            { 'Mcp-Name': 'plain' }
        );
        expect(res.status).toBe(400);
        const body = (await res.json()) as { error?: { code?: number; data?: { toolwall?: { headerMismatch?: boolean } } } };
        expect(body.error?.code).toBe(-32020);
        expect(body.error?.data?.toolwall?.headerMismatch).toBe(true);
        // The body it refused is not echoed back: a refusal must not become an oracle either.
        expect(JSON.stringify(body)).not.toContain('slow_echo');
    });

    it('rejects Mcp-Method disagreeing with the body method', async () => {
        const peer = await serveOverHttp();
        await handshakeOverHttp(peer);
        const res = await post(peer, { jsonrpc: '2.0', id: 5, method: 'tools/list' }, { 'Mcp-Method': 'ping' });
        expect(res.status).toBe(400);
        expect(((await res.json()) as { error: { code: number } }).error.code).toBe(-32020);
    });

    it('decodes the =?base64?…?= sentinel before comparing, and only the exact sentinel', async () => {
        const peer = await serveOverHttp();
        await handshakeOverHttp(peer);

        // A tool name that cannot travel raw in an HTTP field. `mirroredHeadersForBody` encodes it,
        // and the listener must decode before comparing or every non-ASCII name is a false 400.
        const awkward = 'echo ünïcode';
        const body = {
            jsonrpc: '2.0',
            id: 6,
            method: 'tools/call',
            params: { name: awkward, arguments: {} }
        };
        const headers = mirroredHeadersForBody(body, '2026-07-28');
        expect(headers['Mcp-Name']).toMatch(/^=\?base64\?[A-Za-z0-9+/]+={0,2}\?=$/u);

        // Agreement holds: this reaches the server (which answers "ok" for an unknown tool name),
        // rather than being refused at the door.
        const ok = await post(peer, body);
        expect(ok.status).toBe(200);

        // And a sentinel that decodes to something ELSE is a mismatch, not a pass.
        const tampered = await post(peer, body, {
            'Mcp-Name': `=?base64?${Buffer.from('echo other', 'utf8').toString('base64')}?=`
        });
        expect(tampered.status).toBe(400);
        expect(((await tampered.json()) as { error: { code: number } }).error.code).toBe(-32020);
    });

    it('refuses to police mirrored headers under a revision that does not mandate them (-32022)', async () => {
        // The spec's direct mandate on intermediaries: verify that the declared revision requires
        // header/body validation, and REJECT rather than trusting unvalidated headers. Under
        // 2025-11-25 a client owes no mirroring at all, so an `Mcp-Name` is decoration an attacker
        // writes for free.
        const peer = await serveOverHttp({ era: '2025-11-25' });
        const res = await fetch(peer.url, {
            method: 'POST',
            headers: {
                'content-type': 'application/json',
                accept: 'application/json, text/event-stream',
                authorization: `Bearer ${peer.token}`,
                'MCP-Protocol-Version': '2025-11-25',
                'Mcp-Method': 'tools/call',
                'Mcp-Name': 'plain'
            },
            body: JSON.stringify({ jsonrpc: '2.0', id: 7, method: 'tools/call', params: { name: 'plain', arguments: {} } })
        });
        expect(res.status).toBe(400);
        expect(((await res.json()) as { error: { code: number } }).error.code).toBe(-32022);
    });

    it('leaves a legacy request that mirrors nothing alone, and does not 405 its GET', async () => {
        const peer = await serveOverHttp({ era: '2025-11-25' });
        // No mirrored policy headers: judged on the body alone, as that revision intends.
        const res = await fetch(peer.url, {
            method: 'POST',
            headers: {
                'content-type': 'application/json',
                accept: 'application/json, text/event-stream',
                authorization: `Bearer ${peer.token}`,
                'MCP-Protocol-Version': '2025-11-25'
            },
            body: JSON.stringify({ ...INITIALIZE })
        });
        expect(res.status).toBe(200);

        // GET is part of the 2025-11-25 shape, so toolwall's era gate must not be what refuses it.
        const get = await fetch(peer.url, {
            method: 'GET',
            headers: { authorization: `Bearer ${peer.token}`, accept: 'text/event-stream' }
        });
        const ruleId = await get
            .clone()
            .json()
            .then((b: unknown) => (b as { error?: { data?: { toolwall?: { ruleId?: string } } } }).error?.data?.toolwall?.ruleId)
            .catch(() => undefined);
        expect(ruleId).not.toBe('toolwall/http.method-not-allowed');
        get.body?.cancel().catch(() => undefined);
    });
});

describe('Streamable HTTP listener · the CVE surface', () => {
    it('binds loopback by default', async () => {
        const peer = await serveOverHttp();
        expect(peer.listener.boundBeyondLoopback).toBe(false);
        expect(isLoopbackHost(new URL(peer.url).hostname)).toBe(true);
    });

    it('answers 403 to a cross-origin request — CVE-2025-66414 shipped this OFF by default', async () => {
        const peer = await serveOverHttp();
        const res = await post(peer, { ...INITIALIZE }, { Origin: 'https://evil.example' });
        expect(res.status).toBe(403);
        const body = (await res.json()) as { error?: { data?: { toolwall?: { ruleId?: string } } } };
        expect(body.error?.data?.toolwall?.ruleId).toBe('toolwall/http.origin-not-allowed');
    });

    it('checks Origin BEFORE credentials, so the refusal is not an auth oracle', async () => {
        const peer = await serveOverHttp();
        const res = await fetch(peer.url, {
            method: 'POST',
            headers: { 'content-type': 'application/json', Origin: 'https://evil.example' },
            body: JSON.stringify({ ...INITIALIZE })
        });
        // No Authorization header at all, and the answer is still 403 rather than 401: a hostile
        // page learns nothing about whether it guessed the token.
        expect(res.status).toBe(403);
    });

    it('answers 403 to a rebound Host header even with a valid token', async () => {
        const peer = await serveOverHttp();
        const body = { ...INITIALIZE };
        const res = await rawPost(
            peer,
            {
                authorization: `Bearer ${peer.token}`,
                ...mirroredHeadersForBody(body, '2026-07-28'),
                // The rebinding signature: the socket is loopback, the name in the request is not.
                host: 'evil.example'
            },
            body
        );
        expect(res.status).toBe(403);
        expect(
            (JSON.parse(res.body) as { error: { data: { toolwall: { ruleId: string } } } }).error.data.toolwall.ruleId
        ).toBe('toolwall/http.host-not-permitted');

        // The control is on the NAME, not on some property of the connection: the identical request
        // naming a loopback host is served.
        const ok = await rawPost(
            peer,
            { authorization: `Bearer ${peer.token}`, ...mirroredHeadersForBody(body, '2026-07-28'), host: `127.0.0.1:${peer.listener.port}` },
            body
        );
        expect(ok.status).toBe(200);
    });

    it('accepts an origin an operator explicitly allowed, and still refuses its neighbours', async () => {
        const dir = await mkdtemp(path.join(tmpdir(), 'toolwall-http-'));
        const listener = new StreamableHttpListener({ era: '2026-07-28', allowedOrigins: ['https://app.example'] });
        const toolwall = assembleToolwall({
            clientTransport: listener,
            spec: { command: process.execPath, args: [CONCURRENT_SERVER] },
            spawnPolicy: { allowedCommands: ['node'] },
            pins: await PinStore.open({ cwd: dir }),
            audit: new AuditLog(),
            era: '2026-07-28',
            baseDir: dir,
            confirmationChannel: null,
            onUpstreamTransport: t => t.stderr?.resume()
        });
        toolwall.upstreamTransport.stderr?.resume();
        await toolwall.start();
        cleanups.push(async () => {
            await toolwall.close();
            await rm(dir, { recursive: true, force: true }).catch(() => undefined);
        });
        const peer: HttpPeer = { toolwall, listener, url: listener.url, token: listener.token, close: async () => {} };

        expect((await post(peer, { ...INITIALIZE }, { Origin: 'https://app.example' })).status).toBe(200);
        // Suffix matching would accept this. Exact comparison does not, which is the point.
        expect((await post(peer, { ...INITIALIZE, id: 2 }, { Origin: 'https://evil-app.example' })).status).toBe(403);
    });

    it('refuses every unauthenticated request — there is no flag that turns this off', async () => {
        const peer = await serveOverHttp();

        const none = await fetch(peer.url, {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ ...INITIALIZE })
        });
        expect(none.status).toBe(401);
        expect(none.headers.get('www-authenticate')).toContain('Bearer');

        const wrong = await post(peer, { ...INITIALIZE }, { authorization: 'Bearer not-the-token' });
        expect(wrong.status).toBe(401);

        // A token of the right length but the wrong bytes, so the comparison itself is exercised
        // rather than the length check in front of it.
        const nearMiss = `${peer.token.slice(0, -1)}${peer.token.endsWith('A') ? 'B' : 'A'}`;
        expect((await post(peer, { ...INITIALIZE }, { authorization: `Bearer ${nearMiss}` })).status).toBe(401);
    });

    it('generates a token nobody configured, so "no auth" is not reachable by omission', async () => {
        const a = new StreamableHttpListener();
        const b = new StreamableHttpListener();
        expect(a.token.length).toBeGreaterThanOrEqual(40);
        expect(a.token).not.toBe(b.token);
    });
});

// ---------------------------------------------------------------------------
// Upstream leg: toolwall in front of a REMOTE MCP server
// ---------------------------------------------------------------------------

/** A real MCP server on a real HTTP socket, built on the SDK's own Streamable HTTP transport. */
async function startRemoteMcpServer(): Promise<{ url: string; close(): Promise<void> }> {
    const mcp = new McpServer({ name: 'remote-fixture', version: '1.0.0' }, { capabilities: { tools: {} } });
    mcp.setRequestHandler(ListToolsRequestSchema, () => ({
        tools: [
            {
                name: 'remote_echo',
                description: 'Echoes over HTTP.',
                inputSchema: { type: 'object', properties: { text: { type: 'string' } }, required: ['text'] }
            },
            {
                name: 'remote_forbidden',
                description: 'Must never execute in the guard test.',
                inputSchema: { type: 'object', properties: {} }
            }
        ]
    }));
    mcp.setRequestHandler(CallToolRequestSchema, request => ({
        content: [{ type: 'text' as const, text: `remote:${String(request.params.arguments?.['text'] ?? request.params.name)}` }]
    }));

    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: () => 'remote-session' });
    await mcp.connect(transport);

    const http: HttpServer = createServer((req, res) => {
        void transport.handleRequest(req, res);
    });
    await new Promise<void>(resolve => http.listen(0, '127.0.0.1', () => resolve()));
    const address = http.address() as AddressInfo;
    return {
        url: `http://127.0.0.1:${address.port}/mcp`,
        async close() {
            await transport.close().catch(() => undefined);
            await new Promise<void>(resolve => {
                http.close(() => resolve());
                http.closeAllConnections?.();
            });
        }
    };
}

describe('Streamable HTTP upstream · toolwall in front of a REMOTE server', () => {
    it('proxies a remote MCP server, with a guard on the request leg', async () => {
        const remote = await startRemoteMcpServer();
        cleanups.push(() => remote.close());

        const upstream = createUpstreamHttpTransport({ url: remote.url });
        // The identity the pin store keys on comes from the URL, not from `serverInfo.name` (T-04).
        expect(upstream.serverId).toMatch(/^srv_[0-9a-f]{32}$/u);
        expect(upstream.warnings).toEqual([]);

        const blocked: GuardContext[] = [];
        const guard: Guard = {
            name: 'remote-blocker',
            inspect(payload: unknown, ctx: GuardContext): Verdict {
                if ((payload as { name?: string } | undefined)?.name === 'remote_forbidden') {
                    blocked.push(ctx);
                    return {
                        action: 'block',
                        code: TOOLWALL_BLOCKED,
                        findings: [
                            {
                                ruleId: 'test/remote-blocked',
                                severity: 'high',
                                message: 'blocked',
                                locus: '/name',
                                remediation: 'nothing'
                            }
                        ]
                    };
                }
                return ALLOW;
            }
        };
        const guards = new DefaultGuardPipeline();
        guards.register({ direction: 'request', method: 'tools/call', guard });

        const toProxy = new PassThrough();
        const fromProxy = new PassThrough();
        const lines: Array<Record<string, unknown>> = [];
        let buffer = '';
        fromProxy.on('data', chunk => {
            buffer += String(chunk);
            for (;;) {
                const idx = buffer.indexOf('\n');
                if (idx === -1) break;
                const raw = buffer.slice(0, idx).trim();
                buffer = buffer.slice(idx + 1);
                if (raw.length > 0) lines.push(JSON.parse(raw) as Record<string, unknown>);
            }
        });

        const proxy = new ToolwallProxy({
            clientTransport: new StdioServerTransport(toProxy, fromProxy),
            upstreamTransport: upstream.transport,
            serverId: upstream.serverId,
            guards
        });
        await proxy.start();
        cleanups.push(() => proxy.close());

        const send = (message: Record<string, unknown>): void => {
            toProxy.write(`${JSON.stringify(message)}\n`);
        };
        const waitFor = async (id: number): Promise<Record<string, unknown>> => {
            const deadline = Date.now() + 10_000;
            for (;;) {
                const found = lines.find(l => l['id'] === id && ('result' in l || 'error' in l));
                if (found !== undefined) return found;
                if (Date.now() > deadline) throw new Error(`timed out waiting for id ${id}; saw ${JSON.stringify(lines)}`);
                await new Promise<void>(resolve => setTimeout(resolve, 20));
            }
        };

        send({ ...INITIALIZE });
        await waitFor(1);
        send({ jsonrpc: '2.0', method: 'notifications/initialized' });

        send({ jsonrpc: '2.0', id: 2, method: 'tools/list' });
        const listed = await waitFor(2);
        expect(JSON.stringify(listed)).toContain('remote_echo');

        send({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'remote_echo', arguments: { text: 'hi' } } });
        expect(JSON.stringify(await waitFor(3))).toContain('remote:hi');

        // And a guard verdict is enforced on the HTTP leg exactly as on stdio: the block happens
        // before the request is sent, so the remote server never sees it.
        send({ jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'remote_forbidden', arguments: {} } });
        const refused = await waitFor(4);
        expect(refused['error']).toBeDefined();
        expect(blocked).toHaveLength(1);
    });

    it('refuses plaintext http: to a non-loopback host unless told otherwise', () => {
        expect(() => createUpstreamHttpTransport({ url: 'http://mcp.example.com/mcp' })).toThrow(HttpUpstreamError);
        const allowed = createUpstreamHttpTransport({ url: 'http://mcp.example.com/mcp', allowInsecureHttp: true });
        expect(allowed.warnings.join(' ')).toContain('plaintext');
        expect(() => createUpstreamHttpTransport({ url: 'ftp://mcp.example.com/mcp' })).toThrow(HttpUpstreamError);
        expect(() => createUpstreamHttpTransport({ url: 'not a url' })).toThrow(HttpUpstreamError);
    });

    it('derives one identity per endpoint, and query VALUES never enter it', () => {
        const a = createUpstreamHttpTransport({ url: 'https://mcp.example.com/mcp?key=SECRET-A' });
        const b = createUpstreamHttpTransport({ url: 'https://mcp.example.com/mcp?key=SECRET-B' });
        const c = createUpstreamHttpTransport({ url: 'https://other.example.com/mcp' });
        expect(a.serverId).toBe(b.serverId);
        expect(a.serverId).not.toBe(c.serverId);
    });
});

describe('the stdio path is untouched', () => {
    it('still proxies the original fixture server over stdio with no HTTP anywhere in it', async () => {
        const dir = await mkdtemp(path.join(tmpdir(), 'toolwall-stdio-'));
        const toProxy = new PassThrough();
        const fromProxy = new PassThrough();
        const seen: string[] = [];
        fromProxy.on('data', chunk => seen.push(String(chunk)));

        const toolwall = assembleToolwall({
            clientTransport: new StdioServerTransport(toProxy, fromProxy),
            spec: { command: process.execPath, args: [FIXTURE_SERVER] },
            spawnPolicy: { allowedCommands: ['node'] },
            pins: await PinStore.open({ cwd: dir }),
            audit: new AuditLog(),
            baseDir: dir,
            confirmationChannel: null,
            onUpstreamTransport: t => t.stderr?.resume()
        });
        toolwall.upstreamTransport.stderr?.resume();
        await toolwall.start();
        cleanups.push(async () => {
            await toolwall.close();
            await rm(dir, { recursive: true, force: true }).catch(() => undefined);
        });

        toProxy.write(`${JSON.stringify({ ...INITIALIZE })}\n`);
        const deadline = Date.now() + 10_000;
        for (;;) {
            if (seen.join('').includes('"id":1')) break;
            if (Date.now() > deadline) throw new Error(`stdio handshake never came back: ${seen.join('')}`);
            await new Promise<void>(resolve => setTimeout(resolve, 20));
        }
        expect(seen.join('')).toContain('toolwall-test-downstream');
    });
});
