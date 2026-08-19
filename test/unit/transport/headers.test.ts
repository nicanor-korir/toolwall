/**
 * Header/body agreement — the header-confusion cases, stated as attacks.
 *
 * Every "mismatch" case below is a request that a proxy policing `Mcp-Method` /
 * `Mcp-Name` would authorise while the backend executed something else. That is
 * the Akamai header-confusion shape applied to MCP, and the spec's answer is
 * `400` + `-32020 HeaderMismatch`.
 */
import { describe, expect, it } from 'vitest';

import {
    HEADER_VALIDATING_REVISIONS,
    decodeMirroredHeaderValue,
    encodeMirroredHeaderValue,
    mirroredHeadersForBody,
    needsSentinel,
    verifyHeaderBodyAgreement
} from '../../../src/transport/headers.js';
import { MCP_HEADER_MISMATCH, MCP_UNSUPPORTED_PROTOCOL_VERSION } from '../../../src/types/protocol.js';

const CURRENT = HEADER_VALIDATING_REVISIONS[0] as string;

const callBody = (name: string, args: Record<string, unknown> = {}): Record<string, unknown> => ({
    jsonrpc: '2.0',
    id: 1,
    method: 'tools/call',
    params: { name, arguments: args }
});

const headersFor = (body: Record<string, unknown>, overrides: Record<string, string | string[]> = {}): Record<string, string | string[]> => ({
    ...mirroredHeadersForBody(body, CURRENT),
    ...overrides
});

describe('the mirrored headers must agree with the body', () => {
    it('accepts a request whose headers were built from its own body', () => {
        const body = callBody('read_file', { path: '/tmp/x' });
        const result = verifyHeaderBodyAgreement(headersFor(body), body);
        expect(result.ok).toBe(true);
        if (result.ok) {
            expect(result.method).toBe('tools/call');
            expect(result.name).toBe('read_file');
            expect(result.protocolVersion).toBe(CURRENT);
        }
    });

    it('rejects the tool-name split: policy reads the header, the server runs the body', () => {
        // The attack in one object. A gateway allowlisting `read_file` lets this
        // through; the backend deletes everything.
        const body = callBody('delete_everything');
        const result = verifyHeaderBodyAgreement(headersFor(body, { 'Mcp-Name': 'read_file' }), body);
        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.code).toBe(MCP_HEADER_MISMATCH);
            expect(result.httpStatus).toBe(400);
            expect(result.violations.map(v => v.ruleId)).toContain('toolwall/header-body-name-mismatch');
        }
    });

    it('rejects the method split', () => {
        const body = callBody('anything');
        const result = verifyHeaderBodyAgreement(headersFor(body, { 'Mcp-Method': 'tools/list' }), body);
        expect(result.ok).toBe(false);
        if (!result.ok) expect(result.violations.map(v => v.ruleId)).toContain('toolwall/header-body-method-mismatch');
    });

    it('rejects a protocol-version split, which would put policy and execution on different revisions', () => {
        const body = {
            jsonrpc: '2.0',
            id: 1,
            method: 'tools/call',
            params: { name: 'x', _meta: { 'io.modelcontextprotocol/protocolVersion': '2025-11-25' } }
        };
        const result = verifyHeaderBodyAgreement(
            { 'MCP-Protocol-Version': CURRENT, 'Mcp-Method': 'tools/call', 'Mcp-Name': 'x' },
            body
        );
        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.code).toBe(MCP_HEADER_MISMATCH);
            expect(result.violations.map(v => v.ruleId)).toContain('toolwall/header-body-protocol-version-mismatch');
        }
    });

    it('rejects a repeated header rather than picking one of the values', () => {
        const body = callBody('read_file');
        const result = verifyHeaderBodyAgreement(headersFor(body, { 'Mcp-Name': ['read_file', 'delete_everything'] }), body);
        expect(result.ok).toBe(false);
        if (!result.ok) expect(result.violations.map(v => v.ruleId)).toContain('toolwall/header-repeated');
    });

    it('rejects an absent Mcp-Method on a request: absence must not be a way to skip validation', () => {
        const body = callBody('read_file');
        const headers = headersFor(body);
        delete headers['Mcp-Method'];
        const result = verifyHeaderBodyAgreement(headers, body);
        expect(result.ok).toBe(false);
        if (!result.ok) expect(result.violations.map(v => v.ruleId)).toContain('toolwall/header-method-absent');
    });

    it('rejects an Mcp-Name sent for a method that mirrors none', () => {
        const body = { jsonrpc: '2.0', id: 1, method: 'tools/list' };
        const result = verifyHeaderBodyAgreement(
            { 'MCP-Protocol-Version': CURRENT, 'Mcp-Method': 'tools/list', 'Mcp-Name': 'anything-i-like' },
            body
        );
        expect(result.ok).toBe(false);
        if (!result.ok) expect(result.violations.map(v => v.ruleId)).toContain('toolwall/header-name-unexpected');
    });

    it('rejects a batch body: one header set cannot honestly describe N messages', () => {
        const result = verifyHeaderBodyAgreement({ 'MCP-Protocol-Version': CURRENT, 'Mcp-Method': 'tools/call' }, [
            callBody('a'),
            callBody('b')
        ]);
        expect(result.ok).toBe(false);
        if (!result.ok) expect(result.violations.map(v => v.ruleId)).toContain('toolwall/header-batch-unvalidatable');
    });

    it('mirrors resources/read onto params.uri, not params.name', () => {
        const body = { jsonrpc: '2.0', id: 1, method: 'resources/read', params: { uri: 'file:///etc/hosts' } };
        expect(verifyHeaderBodyAgreement(headersFor(body), body).ok).toBe(true);
        const split = verifyHeaderBodyAgreement(headersFor(body, { 'Mcp-Name': 'file:///tmp/safe' }), body);
        expect(split.ok).toBe(false);
    });
});

describe('the protocol-version gate: refuse to police headers nobody had to mirror', () => {
    it('rejects a revision that does not require header-body validation', () => {
        const body = callBody('read_file');
        const result = verifyHeaderBodyAgreement(
            { 'MCP-Protocol-Version': '2025-11-25', 'Mcp-Method': 'tools/call', 'Mcp-Name': 'read_file' },
            body
        );
        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.code).toBe(MCP_UNSUPPORTED_PROTOCOL_VERSION);
            expect(result.violations.map(v => v.ruleId)).toContain('toolwall/header-revision-does-not-validate');
        }
    });

    it('rejects an absent MCP-Protocol-Version', () => {
        const body = callBody('read_file');
        const result = verifyHeaderBodyAgreement({ 'Mcp-Method': 'tools/call', 'Mcp-Name': 'read_file' }, body);
        expect(result.ok).toBe(false);
        if (!result.ok) expect(result.code).toBe(MCP_UNSUPPORTED_PROTOCOL_VERSION);
    });

    it('can be told to stop gating, and then still enforces agreement', () => {
        const body = callBody('read_file');
        const ok = verifyHeaderBodyAgreement(
            { 'MCP-Protocol-Version': '2025-11-25', 'Mcp-Method': 'tools/call', 'Mcp-Name': 'read_file' },
            body,
            { requireValidatingRevision: false }
        );
        expect(ok.ok).toBe(true);
        const split = verifyHeaderBodyAgreement(
            { 'MCP-Protocol-Version': '2025-11-25', 'Mcp-Method': 'tools/call', 'Mcp-Name': 'other' },
            body,
            { requireValidatingRevision: false }
        );
        expect(split.ok).toBe(false);
    });
});

describe('the =?base64?…?= sentinel', () => {
    it('round-trips a value that cannot travel raw', () => {
        for (const value of ['tool with spaces', 'ünïcode', 'tab\there', 'emoji 🙂']) {
            expect(needsSentinel(value)).toBe(true);
            const encoded = encodeMirroredHeaderValue(value);
            expect(encoded.startsWith('=?base64?')).toBe(true);
            const decoded = decodeMirroredHeaderValue(encoded);
            expect(decoded.ok && decoded.value).toBe(value);
        }
    });

    it('leaves a printable-ASCII value alone', () => {
        expect(encodeMirroredHeaderValue('read_file')).toBe('read_file');
        const decoded = decodeMirroredHeaderValue('read_file');
        expect(decoded.ok && decoded.encoded).toBe(false);
    });

    it('is decoded before comparison, so an encoded header matches a raw body value', () => {
        const body = callBody('tool with spaces');
        const result = verifyHeaderBodyAgreement(headersFor(body), body);
        expect(result.ok).toBe(true);
        if (result.ok) expect(result.name).toBe('tool with spaces');
    });

    it('treats =?BASE64?…?= as a literal — the markers are case-sensitive', () => {
        // The evasion: a lenient proxy decodes it and sees `read_file`; a strict
        // backend does not, and sees the literal. Two readings of one request.
        const payload = Buffer.from('read_file', 'utf8').toString('base64');
        const decoded = decodeMirroredHeaderValue(`=?BASE64?${payload}?=`);
        expect(decoded.ok && decoded.encoded).toBe(false);
        expect(decoded.ok && decoded.value).toBe(`=?BASE64?${payload}?=`);

        const body = callBody('read_file');
        const result = verifyHeaderBodyAgreement(headersFor(body, { 'Mcp-Name': `=?BASE64?${payload}?=` }), body);
        expect(result.ok).toBe(false);
    });

    it('rejects a malformed sentinel instead of falling back to the raw string', () => {
        const bad = decodeMirroredHeaderValue('=?base64?not base64!?=');
        expect(bad.ok).toBe(false);

        const body = callBody('read_file');
        const result = verifyHeaderBodyAgreement(headersFor(body, { 'Mcp-Name': '=?base64?%%%?=' }), body);
        expect(result.ok).toBe(false);
        if (!result.ok) expect(result.violations.map(v => v.ruleId)).toContain('toolwall/header-sentinel-malformed');
    });

    it('accepts exactly one spelling per value: canonical, padded base64', () => {
        // "read_file" is 9 bytes, so its base64 needs no padding.
        const canonical = decodeMirroredHeaderValue('=?base64?cmVhZF9maWxl?=');
        expect(canonical.ok && canonical.value).toBe('read_file');

        // "read_filef" is 10 bytes and its canonical form carries `==`.
        expect(Buffer.from('read_filef', 'utf8').toString('base64')).toBe('cmVhZF9maWxlZg==');
        expect(decodeMirroredHeaderValue('=?base64?cmVhZF9maWxlZg==?=').ok).toBe(true);

        // The same bytes spelled without padding: accepted by Node, rejected
        // here. Two accepted spellings is two hops reading one header two ways.
        const unpadded = decodeMirroredHeaderValue('=?base64?cmVhZF9maWxlZg?=');
        expect(unpadded.ok).toBe(false);
        if (!unpadded.ok) expect(unpadded.reason).toContain('canonical');
    });
});

describe('Mcp-Param-{Name}', () => {
    it('accepts a param header that matches the argument', () => {
        const body = callBody('read_file', { path: '/tmp/x' });
        const result = verifyHeaderBodyAgreement(headersFor(body, { 'Mcp-Param-path': '/tmp/x' }), body);
        expect(result.ok).toBe(true);
        if (result.ok) expect(result.params['path']).toBe('/tmp/x');
    });

    it('rejects a param header that disagrees with the argument', () => {
        const body = callBody('read_file', { path: '/etc/shadow' });
        const result = verifyHeaderBodyAgreement(headersFor(body, { 'Mcp-Param-path': '/tmp/harmless' }), body);
        expect(result.ok).toBe(false);
        if (!result.ok) expect(result.violations.map(v => v.ruleId)).toContain('toolwall/header-body-param-mismatch');
    });

    it('rejects a param header naming an argument that is not there', () => {
        const body = callBody('read_file', { path: '/tmp/x' });
        const result = verifyHeaderBodyAgreement(headersFor(body, { 'Mcp-Param-target': 'anything' }), body);
        expect(result.ok).toBe(false);
        if (!result.ok) expect(result.violations.map(v => v.ruleId)).toContain('toolwall/header-param-unresolvable');
    });

    it('rejects a case-ambiguous param header rather than choosing an argument', () => {
        // HTTP header names are case-insensitive, MCP argument names are not.
        const body = callBody('read_file', { path: '/tmp/a', Path: '/tmp/b' });
        const result = verifyHeaderBodyAgreement(headersFor(body, { 'Mcp-Param-path': '/tmp/a' }), body);
        expect(result.ok).toBe(false);
        if (!result.ok) expect(result.violations.map(v => v.ruleId)).toContain('toolwall/header-param-unresolvable');
    });
});

describe('the error toolwall writes back', () => {
    it('names the rules but does not echo the offending values', () => {
        const body = callBody('delete_everything');
        const result = verifyHeaderBodyAgreement(headersFor(body, { 'Mcp-Name': 'read_file' }), body);
        expect(result.ok).toBe(false);
        if (!result.ok) {
            const serialized = JSON.stringify(result.error);
            expect(serialized).not.toContain('delete_everything');
            expect(serialized).not.toContain('read_file');
            expect(result.error.data.toolwall.violations).toContain('toolwall/header-body-name-mismatch');
        }
    });
});
