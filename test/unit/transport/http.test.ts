/**
 * Unit tests for the Streamable HTTP primitives.
 *
 * `test/integration/http.test.ts` drives these through a real socket, which is what proves they
 * are wired. This file is for the cases a live request cannot easily express — an IPv6 authority,
 * a `127.0.0.2` loopback address, a body that exceeds the cap — and for the ones where the exact
 * boundary matters more than the plumbing around it.
 */

import { describe, expect, it } from 'vitest';
import { Readable } from 'node:stream';

import {
    DEFAULT_LISTEN_HOST,
    bearerTokenMatches,
    checkRequestOrigin,
    generateBearerToken,
    httpProfileForEra,
    isLoopbackHost,
    readBearerToken,
    readJsonBody,
    splitAuthority
} from '../../../src/transport/http.js';

describe('the era profile is the whole 2025-11-25 / 2026-07-28 difference', () => {
    it('makes 2026-07-28 POST-only, sessionless and non-resumable', () => {
        const p = httpProfileForEra('2026-07-28');
        expect(p.allowedMethods).toEqual(['POST']);
        expect(p.allowsGetStream).toBe(false);
        expect(p.allowsDeleteSession).toBe(false);
        expect(p.usesSessions).toBe(false);
        expect(p.supportsResumability).toBe(false);
        // The half that matters to `headers.ts`: only this revision obliges a client to mirror,
        // and only a mirroring revision may be policed on its headers.
        expect(p.requiresHeaderMirroring).toBe(true);
    });

    it('keeps the legacy shape for 2025-11-25', () => {
        const p = httpProfileForEra('2025-11-25');
        expect(p.allowedMethods).toEqual(['POST', 'GET', 'DELETE']);
        expect(p.usesSessions).toBe(true);
        expect(p.supportsResumability).toBe(true);
        expect(p.requiresHeaderMirroring).toBe(false);
    });
});

describe('loopback detection', () => {
    it('defaults to the IPv4 literal, not a name a resolver could redirect', () => {
        expect(DEFAULT_LISTEN_HOST).toBe('127.0.0.1');
    });

    it('accepts the whole 127.0.0.0/8 block, not just 127.0.0.1', () => {
        // A check that only knew 127.0.0.1 would be sidestepped by binding or naming 127.0.0.2,
        // which is just as loopback and just as reachable from a browser.
        for (const host of ['127.0.0.1', '127.0.0.2', '127.1.2.3', '::1', '[::1]', 'localhost', 'LOCALHOST']) {
            expect(isLoopbackHost(host), host).toBe(true);
        }
    });

    it('rejects everything else, including names that merely look local', () => {
        for (const host of ['evil.example', 'localhost.evil.example', '0.0.0.0', '10.0.0.1', '127.0.0.1.evil.example']) {
            expect(isLoopbackHost(host), host).toBe(false);
        }
    });

    it('splits an authority, IPv6 literals included', () => {
        expect(splitAuthority('127.0.0.1:8099')).toEqual({ host: '127.0.0.1', port: '8099' });
        expect(splitAuthority('example.com')).toEqual({ host: 'example.com', port: undefined });
        expect(splitAuthority('[::1]:9000')).toEqual({ host: '[::1]', port: '9000' });
        expect(splitAuthority('[::1]')).toEqual({ host: '[::1]', port: undefined });
    });
});

describe('Origin and Host validation — the DNS-rebinding control', () => {
    const ok = (headers: Record<string, string>, allowed: string[] = []): boolean =>
        checkRequestOrigin(headers, { allowedOrigins: allowed }).ok;

    it('accepts a request with no Origin, because that is not a browser', () => {
        expect(ok({ host: '127.0.0.1:9000' })).toBe(true);
    });

    it('accepts an opaque Origin of "null" the same way', () => {
        expect(ok({ host: '127.0.0.1:9000', origin: 'null' })).toBe(true);
    });

    it('refuses a Host that names anything but loopback', () => {
        const result = checkRequestOrigin({ host: 'evil.example:9000' });
        expect(result.ok).toBe(false);
        expect(result.ok === false && result.status).toBe(403);
        expect(result.ok === false && result.ruleId).toBe('toolwall/http.host-not-permitted');
    });

    it('accepts the exact authority the listener bound to, even when it is not loopback', () => {
        // An operator who deliberately binds a LAN address still needs their own requests served;
        // what must not be accepted is a name they did not bind.
        expect(checkRequestOrigin({ host: '10.0.0.5:9000' }, { boundAuthority: '10.0.0.5:9000' }).ok).toBe(true);
        expect(checkRequestOrigin({ host: 'evil.example:9000' }, { boundAuthority: '10.0.0.5:9000' }).ok).toBe(false);
    });

    it('refuses a web Origin that was not allowed', () => {
        const result = checkRequestOrigin({ host: '127.0.0.1:9000', origin: 'https://evil.example' });
        expect(result.ok === false && result.status).toBe(403);
        expect(result.ok === false && result.ruleId).toBe('toolwall/http.origin-not-allowed');
    });

    it('accepts a loopback Origin without it having to be named', () => {
        expect(ok({ host: '127.0.0.1:9000', origin: 'http://localhost:5173' })).toBe(true);
        expect(ok({ host: '127.0.0.1:9000', origin: 'http://127.0.0.1:3000' })).toBe(true);
    });

    it('compares an allowed origin exactly — no suffix matching, ever', () => {
        expect(ok({ host: '127.0.0.1:9000', origin: 'https://app.example' }, ['https://app.example'])).toBe(true);
        // Every one of these ends with, starts with or otherwise resembles the allowed value.
        expect(ok({ host: '127.0.0.1:9000', origin: 'https://evil-app.example' }, ['https://app.example'])).toBe(false);
        expect(ok({ host: '127.0.0.1:9000', origin: 'https://app.example.evil.com' }, ['https://app.example'])).toBe(false);
        expect(ok({ host: '127.0.0.1:9000', origin: 'http://app.example' }, ['https://app.example'])).toBe(false);
        expect(ok({ host: '127.0.0.1:9000', origin: 'https://app.example:8443' }, ['https://app.example'])).toBe(false);
    });

    it('refuses an Origin that is not a URL rather than falling through', () => {
        const result = checkRequestOrigin({ host: '127.0.0.1:9000', origin: 'not a url' });
        expect(result.ok === false && result.ruleId).toBe('toolwall/http.origin-unparseable');
    });
});

describe('bearer tokens', () => {
    it('generates a distinct 256-bit token every time', () => {
        const tokens = new Set(Array.from({ length: 32 }, () => generateBearerToken()));
        expect(tokens.size).toBe(32);
        for (const token of tokens) {
            // base64url of 32 bytes.
            expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/u);
        }
    });

    it('matches only the exact token, and survives a length mismatch without throwing', () => {
        const token = generateBearerToken();
        expect(bearerTokenMatches(token, token)).toBe(true);
        expect(bearerTokenMatches(token, `${token}x`)).toBe(false);
        expect(bearerTokenMatches(token, token.slice(0, -1))).toBe(false);
        expect(bearerTokenMatches(token, '')).toBe(false);
        expect(bearerTokenMatches(token, undefined)).toBe(false);
    });

    it('reads the credential out of an Authorization header, and only a Bearer one', () => {
        expect(readBearerToken({ authorization: 'Bearer abc123' })).toBe('abc123');
        expect(readBearerToken({ authorization: '  Bearer\tabc123  ' })).toBe('abc123');
        expect(readBearerToken({ authorization: 'Basic abc123' })).toBeUndefined();
        expect(readBearerToken({ authorization: 'Bearer' })).toBeUndefined();
        expect(readBearerToken({})).toBeUndefined();
    });
});

describe('body reading is bounded', () => {
    const stream = (chunks: string[]): AsyncIterable<Buffer> => Readable.from(chunks.map(c => Buffer.from(c, 'utf8')));

    it('parses a JSON body', async () => {
        const read = await readJsonBody(stream(['{"a":', '1}']));
        expect(read.ok && read.body).toEqual({ a: 1 });
    });

    it('refuses a body over the cap, counting bytes received rather than Content-Length', async () => {
        // Content-Length is a claim by the sender; this module exists because two descriptions of
        // one request can disagree.
        const read = await readJsonBody(stream(['x'.repeat(100)]), 64);
        expect(read.ok).toBe(false);
        expect(read.ok === false && read.status).toBe(413);
    });

    it('refuses an empty body and a non-JSON body with 400', async () => {
        expect((await readJsonBody(stream([]))).ok).toBe(false);
        const bad = await readJsonBody(stream(['{not json']));
        expect(bad.ok === false && bad.status).toBe(400);
    });
});
