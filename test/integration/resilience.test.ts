/**
 * Failure modes, through the assembled product.
 *
 * toolwall sits in the middle of somebody's editor session. The controls are worth nothing if the
 * proxy hangs, crashes or wedges the client when the upstream misbehaves — a security tool that
 * takes the session down is a security tool that gets uninstalled. Every case below is measured
 * against a direct connection where "what should happen" is otherwise a matter of opinion.
 *
 * Covered: upstream killed mid-flight, malformed framing from the client, a payload shape the
 * JSON-RPC schema rejects, a hostile payload shape (deep nesting, T-08), an upstream error, and a
 * restart of the same server against a persisted pin store.
 */
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { PinStore } from '../../src/audit/manifest.js';

import { RUGPULL_SERVER, connectAssembled, connectDirect, errorOf, findingsOf, type AssembledPeer } from './harness.js';

const peers: AssembledPeer[] = [];
const closeAll = async (): Promise<void> => {
    for (const peer of peers.splice(0)) await peer.close().catch(() => undefined);
};

const settle = (ms = 300): Promise<void> => new Promise(resolve => setTimeout(resolve, ms));

describe('the client session degrades gracefully, never silently', () => {
    it('an upstream killed mid-request tears the client side down cleanly instead of hanging', async () => {
        const peer = await connectAssembled();
        peers.push(peer);
        try {
            await peer.handshake();
            await peer.call('tools/list');

            const pid = peer.toolwall.upstreamTransport.pid;
            expect(pid).toBeTypeOf('number');

            // `hang` blocks until cancelled, so this request is genuinely in flight.
            peer.send({ jsonrpc: '2.0', id: 99, method: 'tools/call', params: { name: 'hang', arguments: {} } });
            await settle(250);
            process.kill(pid as number, 'SIGKILL');
            await settle(600);

            // What actually happens, stated rather than wished for: the in-flight request gets no
            // response — the upstream that owed it one no longer exists — and toolwall closes the
            // client-facing leg so the client sees a clean EOF and fails its own pending requests.
            // The failure mode we must not have is a socket that stays open and answers nothing.
            expect(peer.out.lines.some(l => l.value['id'] === 99)).toBe(false);
            expect(peer.toolwall.proxy.closed).toBe(true);
            expect(peer.events.map(e => e.kind)).toContain('upstream-closed');
            expect(peer.events.map(e => e.kind)).toContain('client-closed');

            // The audit log says why the session ended.
            const lifecycle = peer.audit.records.filter(r => r.kind === 'lifecycle');
            expect(lifecycle.map(r => r.detail?.['event'])).toContain('upstream-closed');
        } finally {
            await closeAll();
        }
    });

    it('malformed framing from the client is reported and survived, not fatal', async () => {
        const peer = await connectAssembled();
        peers.push(peer);
        try {
            await peer.handshake();
            await peer.call('tools/list');

            peer.sendRaw('{not json at all\n');
            await settle(200);

            expect(peer.toolwall.proxy.closed).toBe(false);
            expect(peer.events.filter(e => e.kind === 'client-error').length).toBeGreaterThan(0);

            // Still fully functional afterwards.
            const ok = await peer.call('tools/call', { name: 'echo', arguments: { text: 'still alive' } });
            expect(ok.value['result']).toStrictEqual({ content: [{ type: 'text', text: 'still alive' }] });
        } finally {
            await closeAll();
        }
    });

    it('a params shape the JSON-RPC schema rejects behaves exactly as it does without the proxy', async () => {
        // `{"params": "not-an-object"}` fails `JSONRPCMessageSchema` in the SDK's own ReadBuffer,
        // which discards the message before any handler sees it, so no response is ever sent.
        // That is the SDK's behaviour on every peer's read path, not something toolwall
        // introduces — measured here against a direct connection rather than asserted.
        const direct = connectDirect();
        const peer = await connectAssembled();
        peers.push(peer);
        try {
            direct.send({
                jsonrpc: '2.0',
                id: 1,
                method: 'initialize',
                params: { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'p', version: '1' } }
            });
            await direct.out.waitForId(1);
            direct.send({ jsonrpc: '2.0', method: 'notifications/initialized' });
            direct.send({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: 'not-an-object' });

            await peer.handshake();
            peer.send({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: 'not-an-object' });
            await settle(400);

            expect(direct.out.lines.some(l => l.value['id'] === 2)).toBe(false);
            expect(peer.out.lines.some(l => l.value['id'] === 2)).toBe(false);

            // Both peers keep serving.
            direct.send({ jsonrpc: '2.0', id: 3, method: 'tools/list' });
            expect(errorOf(await direct.out.waitForId(3))).toBeUndefined();
            expect(errorOf(await peer.call('tools/list'))).toBeUndefined();
        } finally {
            await direct.close();
            await closeAll();
        }
    });

    it('a deeply nested argument payload is blocked at the proxy (T-08), not forwarded', async () => {
        const peer = await connectAssembled();
        peers.push(peer);
        try {
            await peer.handshake();
            await peer.call('tools/list');

            // 200 levels. `balanced` allows 32; the bound exists so an oversized/deeply-nested
            // payload is a rejected request rather than a proxy-side stack or CPU problem.
            let deep: Record<string, unknown> = {};
            const root = deep;
            for (let i = 0; i < 200; i++) {
                const next: Record<string, unknown> = {};
                deep['n'] = next;
                deep = next;
            }

            const blocked = await peer.call('tools/call', {
                name: 'echo',
                arguments: { text: 'x', deep: root }
            });
            expect(errorOf(blocked)?.code).toBe(-32600);
            expect(findingsOf(blocked).map(f => f.ruleId)).toContain('toolwall/bounds.depth');

            // The server never saw it, and the session continues.
            const calls = await peer.call('tools/call', { name: 'calls', arguments: {} });
            const log = JSON.parse((calls.value['result'] as { content: Array<{ text: string }> }).content[0]!.text) as string[];
            expect(log).not.toContain('echo');
        } finally {
            await closeAll();
        }
    });

    it('an upstream error is relayed with its code, message and data intact through the guard stack', async () => {
        const peer = await connectAssembled();
        peers.push(peer);
        try {
            await peer.handshake();
            await peer.call('tools/list');
            const boom = await peer.call('tools/call', { name: 'boom', arguments: {} });
            const error = errorOf(boom);
            expect(error?.code).toBe(-32602);
            expect(error?.message).toContain('boom happened');
            expect(error?.data).toStrictEqual({ detail: 'structured error data', n: 42 });
            // Not a toolwall block: `data.toolwall` is absent, so a client can tell the two apart.
            expect((error?.data as Record<string, unknown>)['toolwall']).toBeUndefined();
        } finally {
            await closeAll();
        }
    });

    it('a restarted server is verified against the pins from the previous session, not re-adopted', async () => {
        // The upstream going away and coming back is routine (editor reload, server crash-loop).
        // If a restart re-ran trust-on-first-use, the rug-pull control would reset itself every
        // time the server bounced — which an attacker can cause on demand.
        //
        // Note the assertion this test hangs on. Comparing hashes is NOT enough: the second
        // session sees the same clean definition, so a store that silently failed to load would
        // re-adopt it and produce the identical hash. Only "no `pinned` event, a `verified` event
        // instead" distinguishes "loaded and checked" from "forgot and trusted again".
        const dir = await mkdtemp(join(tmpdir(), 'toolwall-restart-'));
        try {
            const first = await connectAssembled({
                server: RUGPULL_SERVER,
                serverArgs: ['--variant', 'prose'],
                dir,
                pins: await PinStore.open({ cwd: dir })
            });
            peers.push(first);
            await first.handshake();
            await first.call('tools/list');
            const serverId = first.toolwall.serverId;
            const pinnedHash = first.pins.get(serverId, 'tool', 'add')?.hash;
            expect(pinnedHash).toBeDefined();
            await first.pins.flush();
            await first.close();
            peers.length = 0;

            const reopened = await PinStore.open({ cwd: dir });
            expect(reopened.list().map(p => `${p.kind}:${p.subject}`).sort()).toStrictEqual([
                'server:instructions',
                'tool:add'
            ]);

            const second = await connectAssembled({
                server: RUGPULL_SERVER,
                serverArgs: ['--variant', 'prose'],
                dir,
                pins: reopened
            });
            peers.push(second);

            // Same launch spec => same identity => the pins written last session are reachable.
            expect(second.toolwall.serverId).toBe(serverId);
            await second.handshake();

            // The fixture's own counter restarted, so its first listing is clean again — and it is
            // VERIFIED against the existing pin rather than adopted anew.
            expect(errorOf(await second.call('tools/list'))).toBeUndefined();
            expect(second.pins.get(serverId, 'tool', 'add')?.hash).toBe(pinnedHash);
            expect(second.pinEvents.filter(e => e.kind === 'pinned')).toHaveLength(0);
            expect(second.pinEvents.filter(e => e.kind === 'verified').map(e => e.subject).sort()).toStrictEqual([
                'add',
                'instructions'
            ]);

            // And the mutation on the second listing is still caught after the restart.
            expect(errorOf(await second.call('tools/list'))?.code).toBe(-32600);
        } finally {
            await closeAll();
            await rm(dir, { recursive: true, force: true }).catch(() => undefined);
        }
    });
});
