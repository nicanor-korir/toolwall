/**
 * ROUND 3 · the HTTP listener (`--listen`) — the highest-value target in the tree.
 *
 * CVE-2025-49596 (MCP Inspector, CVSS 9.4) and CVE-2026-23744 (MCPJam, CVSS 9.8, exploited in the
 * wild from Feb 2026) were the same bug twice: an unauthenticated local HTTP endpoint that any web
 * page the user had open could drive. `src/transport/listener.ts` claims to close that class with
 * Origin+Host validation (403), loopback bind, an always-on 256-bit bearer token (401), header/body
 * agreement (400 + -32020), and an era-shaped method allowlist (405) — in that order, with
 * **Origin deliberately before credentials so a refusal cannot be an auth oracle**.
 *
 * Everything here drives a REAL listener on a REAL socket with real sockets and real `fetch`.
 * Nothing is mocked.
 *
 * Owning module: src/transport/listener.ts + src/transport/http.ts.
 */
import { afterEach, describe, expect, it } from 'vitest';
import { connect } from 'node:net';

import { StreamableHttpListener } from '../../src/transport/listener.js';

const listeners: StreamableHttpListener[] = [];

afterEach(async () => {
    for (const l of listeners.splice(0)) await l.close().catch(() => undefined);
});

const TOKEN = 'test-token-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

async function boot(options: Partial<ConstructorParameters<typeof StreamableHttpListener>[0]> = {}): Promise<StreamableHttpListener> {
    const l = new StreamableHttpListener({ token: TOKEN, ...options });
    listeners.push(l);
    await l.start();
    return l;
}

const CALL_BODY = { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'read_file', arguments: { path: '/etc/passwd' } } };

async function post(l: StreamableHttpListener, headers: Record<string, string>, body: unknown = CALL_BODY, path?: string): Promise<Response> {
    return fetch(`http://127.0.0.1:${l.port}${path ?? l.path}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', ...headers },
        body: JSON.stringify(body)
    });
}

/** Raw HTTP over a socket, so a test can send things `fetch` refuses to (no Host, duplicates). */
function raw(port: number, request: string): Promise<string> {
    return new Promise((resolve, reject) => {
        const socket = connect(port, '127.0.0.1', () => socket.write(request));
        let out = '';
        socket.setTimeout(4000, () => { socket.destroy(); resolve(out); });
        socket.on('data', c => { out += c.toString(); });
        socket.on('end', () => resolve(out));
        socket.on('close', () => resolve(out));
        socket.on('error', reject);
    });
}
const statusOf = (response: string): number => Number(/^HTTP\/1\.[01] (\d{3})/u.exec(response)?.[1] ?? 0);

// ---------------------------------------------------------------------------

describe('Round 3 · the Origin-before-credentials ordering claim', () => {
    it('HELD — a hostile web origin gets 403 whether the token is absent, wrong, or CORRECT', async () => {
        const l = await boot();
        const evil = { origin: 'https://evil.example' };

        const noToken = await post(l, evil);
        const wrongToken = await post(l, { ...evil, authorization: 'Bearer not-the-token' });
        const rightToken = await post(l, { ...evil, authorization: `Bearer ${TOKEN}` });

        // All three identical: the response shape reveals nothing about the credential.
        expect([noToken.status, wrongToken.status, rightToken.status]).toStrictEqual([403, 403, 403]);
        // And no WWW-Authenticate, which would invite a browser to retry with credentials.
        expect(rightToken.headers.get('www-authenticate')).toBeNull();
    });

    it('HELD — the 401 lane is only reachable from an origin that already passed the 403 gate', async () => {
        const l = await boot();
        expect((await post(l, {})).status).toBe(401); // no Origin at all = not a browser
        expect((await post(l, { authorization: 'Bearer wrong' })).status).toBe(401);
        expect((await post(l, { origin: `http://localhost:3000` })).status).toBe(401); // loopback origin
    });

    it('HELD — a valid token from a hostile origin cannot reach body parsing at all', async () => {
        const l = await boot();
        // Body is deliberately unparseable. A 400 would prove the body was read despite the origin.
        const response = await fetch(`http://127.0.0.1:${l.port}${l.path}`, {
            method: 'POST',
            headers: { 'content-type': 'application/json', origin: 'https://evil.example', authorization: `Bearer ${TOKEN}` },
            body: '{ this is not json'
        });
        expect(response.status).toBe(403);
    });
});

describe('Round 3 · credential handling', () => {
    it('HELD — duplicate Authorization is deterministic (first wins) and cannot be used to smuggle', async () => {
        const l = await boot();
        // Measured, not assumed: node's HTTP parser DISCARDS repeated `authorization` (it is on the
        // no-join list), so the FIRST value wins. Both orderings are therefore deterministic and
        // neither lets a second header override the first — there is no request-smuggling seam here.
        const goodFirst = await raw(
            l.port,
            `POST ${l.path} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer ${TOKEN}\r\nAuthorization: Bearer evil\r\n` +
                `Accept: application/json, text/event-stream\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}`
        );
        const evilFirst = await raw(
            l.port,
            `POST ${l.path} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer evil\r\nAuthorization: Bearer ${TOKEN}\r\n` +
                `Accept: application/json, text/event-stream\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}`
        );
        expect(statusOf(goodFirst)).not.toBe(401); // first value is the real token
        expect(statusOf(evilFirst)).toBe(401); // appending the real token afterwards does NOT help
    });

    it('HELD — a duplicated Mcp-Name is joined by node and then fails the body comparison', async () => {
        const l = await boot({ era: '2026-07-28' });
        // node joins non-authorization duplicates with ", ", so `single()` sees one value "a, b"
        // rather than a repeat. The `header-repeated` rule is therefore unreachable over node's
        // parser — but the joined value cannot equal the body's name, so it still fails closed.
        const body = JSON.stringify(CALL_BODY);
        const response = await raw(
            l.port,
            `POST ${l.path} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer ${TOKEN}\r\n` +
                `Mcp-Protocol-Version: 2026-07-28\r\nMcp-Method: tools/call\r\nMcp-Name: read_file\r\nMcp-Name: evil_tool\r\n` +
                `Accept: application/json, text/event-stream\r\nContent-Type: application/json\r\n` +
                `Content-Length: ${Buffer.byteLength(body)}\r\nConnection: close\r\n\r\n${body}`
        );
        expect(statusOf(response)).toBe(400);
    });

    it('HELD — header NAME casing is irrelevant (Node lowercases), so case games buy nothing', async () => {
        const l = await boot();
        const response = await raw(
            l.port,
            `POST ${l.path} HTTP/1.1\r\nHost: 127.0.0.1\r\nAUTHORIZATION: Bearer ${TOKEN}\r\n` +
                `Content-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}`
        );
        // Authenticated: it got past 401 to the body/era stage rather than being refused.
        expect(statusOf(response)).not.toBe(401);
    });

    it('NOTE — the scheme token is case-SENSITIVE, so RFC-legal `bearer` is refused (fails closed)', async () => {
        const l = await boot();
        const response = await raw(
            l.port,
            `POST ${l.path} HTTP/1.1\r\nHost: 127.0.0.1\r\nauthorization: bearer ${TOKEN}\r\n` +
                `Content-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}`
        );
        // RFC 7235 says the scheme is case-insensitive. Refusing is a COMPATIBILITY bug, not a
        // security one — it errs closed. Recorded so nobody "fixes" it into a loose matcher.
        expect(statusOf(response)).toBe(401);
    });
});

describe('Round 3 · DNS rebinding / Host handling', () => {
    it('HELD — a rebound attacker hostname in Host is 403 even with the correct token', async () => {
        const l = await boot();
        const response = await raw(
            l.port,
            `POST ${l.path} HTTP/1.1\r\nHost: evil.example:${l.port}\r\nAuthorization: Bearer ${TOKEN}\r\n` +
                `Content-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}`
        );
        expect(statusOf(response)).toBe(403);
    });

    it('BOUNDARY — omitting Host entirely skips the Host check, but the bearer token still refuses', async () => {
        const l = await boot();
        // HTTP/1.0 has no mandatory Host. `checkRequestOrigin` only tests Host when present, so this
        // path skips the rebinding control. It is NOT a browser-reachable bypass: every browser
        // sends Host, so a rebinding attacker cannot omit it. Auth is what actually stops this.
        const noAuth = await raw(l.port, `POST ${l.path} HTTP/1.0\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}`);
        expect(statusOf(noAuth)).toBe(401);

        const withAuth = await raw(
            l.port,
            `POST ${l.path} HTTP/1.0\r\nAuthorization: Bearer ${TOKEN}\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}`
        );
        // Got past both gates with no Host header at all — documents the skip precisely.
        expect(statusOf(withAuth)).not.toBe(403);
        expect(statusOf(withAuth)).not.toBe(401);
    });

    it('HELD — Origin spoofs that merely CONTAIN a loopback literal are refused', async () => {
        const l = await boot();
        for (const origin of [
            'http://127.0.0.1.evil.example',
            'http://localhost.evil.example',
            'https://evil.example/127.0.0.1',
            'http://evil.example#127.0.0.1',
            'http://127.0.0.1@evil.example'
        ]) {
            expect((await post(l, { origin, authorization: `Bearer ${TOKEN}` })).status, origin).toBe(403);
        }
    });

    it('NOTE — `Origin: null` is accepted by design; only the bearer token stands behind it', async () => {
        const l = await boot();
        // A sandboxed iframe or a data: URL page sends `Origin: null`. It is treated as "not a
        // browser request". That is a documented choice, and the token is the control that holds.
        expect((await post(l, { origin: 'null' })).status).toBe(401);
        expect((await post(l, { origin: 'null', authorization: `Bearer ${TOKEN}` })).status).not.toBe(403);
    });
});

describe('Round 3 · era lane confusion', () => {
    it('HELD — the 2026-07-28 POST-only lane answers 405 to GET and DELETE, after auth', async () => {
        const l = await boot({ era: '2026-07-28' });
        for (const method of ['GET', 'DELETE']) {
            const response = await fetch(`http://127.0.0.1:${l.port}${l.path}`, { method, headers: { authorization: `Bearer ${TOKEN}` } });
            expect(response.status, method).toBe(405);
            expect(response.headers.get('allow')).toBe('POST');
        }
    });

    it('HELD — a client cannot talk itself onto the other lane: the era is fixed at construction', async () => {
        // Claiming 2025-11-25 in the header on a 2026 listener does not restore GET.
        const l = await boot({ era: '2026-07-28' });
        const response = await fetch(`http://127.0.0.1:${l.port}${l.path}`, {
            method: 'GET',
            headers: { authorization: `Bearer ${TOKEN}`, 'mcp-protocol-version': '2025-11-25' }
        });
        expect(response.status).toBe(405);
    });

    it('HELD — a legacy-lane header/body SPLIT is refused rather than policed on trust', async () => {
        const l = await boot({ era: '2025-11-25' });
        // `Mcp-Name` claims a benign tool; the body calls another. Under 2025-11-25 mirroring is not
        // mandated, so toolwall refuses to police it (-32022) rather than authorising the header.
        const response = await post(l, { authorization: `Bearer ${TOKEN}`, 'mcp-name': 'list_files', 'mcp-protocol-version': '2025-11-25' });
        expect(response.status).toBe(400);
        expect((await response.json() as { error: { code: number } }).error.code).toBe(-32022);
    });

    it('HELD — the base64 sentinel is decoded before comparison, so it cannot smuggle a split', async () => {
        const l = await boot({ era: '2026-07-28' });
        // Mcp-Method says `tools/list` (encoded); the body says `tools/call`. Decoding is what makes
        // this detectable at all — a proxy comparing raw bytes would see two unequal opaque strings
        // and might treat the header as authoritative.
        const encoded = `=?base64?${Buffer.from('tools/list', 'utf8').toString('base64')}?=`;
        const response = await post(l, {
            authorization: `Bearer ${TOKEN}`,
            'mcp-protocol-version': '2026-07-28',
            'mcp-method': encoded
        });
        expect(response.status).toBe(400);
        const body = await response.json() as { error: { code: number; data: { toolwall: { violations: string[] } } } };
        expect(body.error.code).toBe(-32020);
        expect(body.error.data.toolwall.violations).toContain('toolwall/header-body-method-mismatch');
    });

    it('HELD — a matching sentinel-encoded header is accepted, proving the decode is real', async () => {
        const l = await boot({ era: '2026-07-28' });
        // Stand in for the proxy: answer whatever reaches the transport, so the POST completes.
        l.onmessage = (message): void => {
            const id = (message as unknown as { id?: unknown }).id;
            void l.send({ jsonrpc: '2.0', id, result: { ok: true } } as never);
        };
        const encoded = `=?base64?${Buffer.from('tools/call', 'utf8').toString('base64')}?=`;
        const response = await post(l, {
            authorization: `Bearer ${TOKEN}`,
            'mcp-protocol-version': '2026-07-28',
            'mcp-method': encoded,
            'mcp-name': 'read_file'
        });
        // Header and body agree once decoded, so the request is carried rather than refused.
        expect(response.status).toBe(200);
    });
});

describe('Round 3 · path handling', () => {
    it('NOTE — the path check runs before Origin, so 404-vs-403 distinguishes the endpoint path', async () => {
        const l = await boot();
        const evil = { origin: 'https://evil.example' };
        expect((await post(l, evil, CALL_BODY, '/not-the-mcp-path')).status).toBe(404);
        expect((await post(l, evil, CALL_BODY, l.path)).status).toBe(403);
        // Severity: informational only. A cross-origin `fetch` gets an opaque response and cannot
        // read either status, and any local process that can read them needs no oracle — it can
        // simply be told the path. Recorded because the file's own comment claims Origin is first.
    });
});
