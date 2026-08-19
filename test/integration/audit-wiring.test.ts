/**
 * Contract C-2, end to end.
 *
 * Dev 1's `{ action: "allow" }` carries no findings, so the records a runtime guard produces on
 * the allow path — "this subschema was NOT enforced", "this regex was refused and the argument
 * was NOT validated against it", "a symlink was traversed but stayed in root" — have nowhere to
 * ride back on the verdict. Dev 3 emits them to an injected `AuditSink` instead. C-2 makes
 * connecting that sink the integrator's job: unwired, every one of those records is discarded,
 * and a gap in our own coverage becomes invisible rather than merely non-blocking.
 *
 * These tests assert the wire exists by driving traffic through the assembled proxy and reading
 * what actually landed in `src/audit/log.ts`.
 */
import { readFile, stat } from 'node:fs/promises';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { AuditLog } from '../../src/audit/log.js';

import { POISONED_SERVER, RUGPULL_SERVER, connectAssembled, errorOf, type AssembledPeer } from './harness.js';

const peers: AssembledPeer[] = [];
afterEach(async () => {
    for (const peer of peers.splice(0)) await peer.close().catch(() => undefined);
});

describe('C-2 · informational findings from an `allow` verdict reach src/audit/', () => {
    it('records what a guard could NOT check, on a call it allowed', async () => {
        // Pinning off => the pin store is empty => `SchemaGuard` has no pinned definition to
        // enforce. At `balanced` that is non-blocking (blocking a call because of OUR gap is an
        // outage, not security), so the only place the gap can surface is the audit sink.
        const peer = await connectAssembled({ enable: { pinning: false } });
        peers.push(peer);

        await peer.handshake();
        await peer.call('tools/list');
        const call = await peer.call('tools/call', { name: 'echo', arguments: { text: 'hi' } });

        expect(errorOf(call)).toBeUndefined();
        expect(call.value['result']).toStrictEqual({ content: [{ type: 'text', text: 'hi' }] });
        // The verdict was `allow` — no `blocked` and no `annotated` event exists to carry this.
        expect(peer.events.filter(e => e.kind === 'blocked' || e.kind === 'annotated')).toHaveLength(0);

        const informational = peer.audit.records.filter(r => r.kind === 'finding');
        expect(informational.length).toBeGreaterThan(0);
        const ruleIds = informational.flatMap(r => (r.findings ?? []).map(f => f.ruleId));
        expect(ruleIds).toContain('toolwall/schema.definition-unavailable');

        const record = informational.find(r => (r.findings ?? []).some(f => f.ruleId === 'toolwall/schema.definition-unavailable'));
        expect(record?.method).toBe('tools/call');
        expect(record?.direction).toBe('request');
        expect(record?.serverId).toBe(peer.toolwall.serverId);
        // Severity `low`: a limitation of ours, recorded, never used to justify a block.
        expect(record?.findings?.[0]?.severity).toBe('low');
    });

    it('records blocks with the FULL finding, not the redacted copy the client gets', async () => {
        const peer = await connectAssembled({ server: RUGPULL_SERVER, serverArgs: ['--variant', 'prose'] });
        peers.push(peer);
        await peer.handshake();
        await peer.call('tools/list');
        await peer.call('tools/list'); // drift

        const blocked = peer.audit.records.filter(r => r.kind === 'blocked');
        expect(blocked).toHaveLength(1);
        const drift = blocked[0]?.findings?.find(f => f.ruleId === 'toolwall/pin-drift');
        // The operator channel keeps the diff. The client channel does not — see
        // `redactFindingForClient` in src/transport/proxy.ts.
        expect(drift?.message).toContain('~ /description');
        expect(drift?.evidence?.['changedPaths']).toStrictEqual(['/description']);
        expect(blocked[0]?.detail?.['code']).toBe(-32600);
    });

    it('records every pin-engine state change and the spawn itself', async () => {
        const peer = await connectAssembled({ server: POISONED_SERVER });
        peers.push(peer);
        await peer.handshake();
        await peer.call('tools/list');

        // T-07: the spec asks stdio proxies to log all transport usage. Names only for the
        // environment; values are never written anywhere.
        const spawn = peer.audit.records.filter(r => r.kind === 'spawn');
        expect(spawn).toHaveLength(1);
        expect(spawn[0]?.detail?.['command']).toBe(process.execPath);
        // Names only, values never. PATH is inherited by every child, so its VALUE is exactly
        // what a "log the environment" bug would leak: its NAME must be present and its value
        // must not. (`command` and `cwd` are logged deliberately — they are what we executed,
        // and they are the T-07 record the spec asks stdio proxies to keep.)
        const envKeys = spawn[0]?.detail?.['envKeys'] as string[];
        expect(envKeys).toContain('PATH');
        const pathValue = process.env['PATH'];
        expect(pathValue).toBeDefined();
        expect(JSON.stringify(spawn[0])).not.toContain(pathValue as string);

        const pinEvents = peer.audit.records.filter(r => r.kind === 'pin');
        expect(pinEvents.map(r => r.detail?.['subject']).sort()).toStrictEqual([
            'instructions',
            'safe_addition_calculator'
        ]);
    });
});

describe('the audit log is append-only and hash-chained', () => {
    it('chains records, and reports the first link that does not verify', () => {
        const log = new AuditLog({ now: () => new Date('2026-08-19T00:00:00.000Z') });
        log.record({ kind: 'lifecycle', serverId: 'srv_a', detail: { event: 'started' } });
        log.record({ kind: 'blocked', serverId: 'srv_a', method: 'tools/call', detail: { code: -32600 } });
        log.record({ kind: 'lifecycle', serverId: 'srv_a', detail: { event: 'client-closed' } });

        expect(log.length).toBe(3);
        expect(log.records[0]?.previousHash).toBeNull();
        expect(log.records[1]?.previousHash).toBe(log.records[0]?.hash);
        expect(log.verifyChain()).toStrictEqual({ ok: true });

        // Keyless: this detects modification, it does not prevent forgery. Someone who can write
        // the file can recompute the chain. Rewriting a record in place is what it catches.
        const tampered = log.records as unknown as Array<Record<string, unknown>>;
        tampered[1] = { ...tampered[1], detail: { code: 0 } };
        const result = log.verifyChain();
        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.firstBadIndex).toBe(1);
            expect(result.reason).toBe('record hash does not match its contents');
        }
    });

    it('appends to a local file, owner-only, with no network path anywhere', async () => {
        const peer = await connectAssembled({ enable: { pinning: false } });
        peers.push(peer);
        // A second log writing to disk, sharing this session's temp dir.
        const log = new AuditLog({ cwd: peer.dir, file: 'audit.jsonl' });
        log.record({ kind: 'lifecycle', serverId: 'srv_a', detail: { event: 'started' } });
        log.record({ kind: 'lifecycle', serverId: 'srv_a', detail: { event: 'client-closed' } });
        await log.flush();

        const path = join(peer.dir, 'audit.jsonl');
        const lines = (await readFile(path, 'utf8')).trim().split('\n');
        expect(lines).toHaveLength(2);
        const first = JSON.parse(lines[0] as string) as { seq: number; previousHash: null; hash: string };
        const second = JSON.parse(lines[1] as string) as { seq: number; previousHash: string };
        expect(first.seq).toBe(1);
        expect(second.previousHash).toBe(first.hash);

        if (process.platform !== 'win32') {
            expect((await stat(path)).mode & 0o777).toBe(0o600);
        }
    });
});
