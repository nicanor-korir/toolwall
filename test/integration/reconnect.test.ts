/**
 * Zero-downtime reconnection, through the assembled product.
 *
 * Real child processes, really killed, really respawned. The fixture remembers
 * how many times it has been launched, so "the server that came back" can be a
 * genuinely different server from the one that left — which is what a restart
 * is, and what an attacker who can crash a server gets to exploit.
 *
 * Two things are being proved here and they pull in opposite directions:
 *
 *   1. **The session survives.** A blip must not take the user's editor down.
 *   2. **The restart is not a bypass.** The replacement process is re-verified
 *      against the pin store *before* one buffered request is released, and a
 *      replacement that no longer matches what was approved fails the buffer
 *      closed rather than serving it.
 *
 * If only (1) held we would have shipped a rug-pull delivery mechanism.
 */
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { PassThrough } from 'node:stream';
import { join } from 'node:path';

import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { describe, expect, it } from 'vitest';

import { ToolwallProxy, type ProxyEvent } from '../../src/transport/proxy.js';
import { createUpstreamStdioTransport } from '../../src/transport/spawn.js';

import { RESTARTING_SERVER, connectAssembled, errorOf, type AssembledPeer } from './harness.js';

const peers: AssembledPeer[] = [];
const dirs: string[] = [];

const closeAll = async (): Promise<void> => {
    for (const peer of peers.splice(0)) await peer.close().catch(() => undefined);
    for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true }).catch(() => undefined);
};

const stateDir = async (): Promise<string> => {
    const dir = await mkdtemp(join(tmpdir(), 'toolwall-restart-state-'));
    dirs.push(dir);
    return dir;
};

const settle = (ms: number): Promise<void> => new Promise(resolve => setTimeout(resolve, ms));

/** Poll until `predicate` holds. Used for teardown, which is deliberately drain-then-close. */
async function eventually(predicate: () => boolean, what: string, timeoutMs = 5_000): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
        if (predicate()) return;
        await settle(20);
    }
    throw new Error(`timed out waiting for ${what}`);
}

/** Wait until an event of `kind` has been observed, so tests do not race the outage. */
async function waitForEvent(peer: AssembledPeer, kind: ProxyEvent['kind'], timeoutMs = 8_000): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
        if (peer.events.some(e => e.kind === kind)) return;
        await settle(10);
    }
    throw new Error(`timed out waiting for ${kind}; saw [${peer.events.map(e => e.kind).join(', ')}]`);
}

const killUpstream = (peer: AssembledPeer): number => {
    const pid = peer.toolwall.currentUpstreamTransport.pid;
    expect(pid).toBeTypeOf('number');
    process.kill(pid as number, 'SIGKILL');
    return pid as number;
};

const textOf = (line: { value: Record<string, unknown> }): string =>
    ((line.value['result'] as { content: Array<{ text: string }> }).content[0] as { text: string }).text;

// ---------------------------------------------------------------------------

describe('an upstream blip buffers instead of ending the session', () => {
    it('respawns the server, re-verifies it, and answers the request that arrived while it was gone', async () => {
        const state = await stateDir();
        const peer = await connectAssembled({
            server: RESTARTING_SERVER,
            serverArgs: ['--state', state],
            // Slow the first attempt down so the request below is genuinely
            // buffered rather than racing a reconnect that already finished.
            reconnect: { backoffMs: [400, 600, 1200] }
        });
        peers.push(peer);
        try {
            await peer.handshake();
            await peer.call('tools/list');
            expect(textOf(await peer.call('tools/call', { name: 'gen', arguments: {} }))).toBe('1');

            const oldPid = killUpstream(peer);
            await waitForEvent(peer, 'upstream-reconnecting');
            expect(peer.toolwall.proxy.linkState).toBe('reconnecting');

            // Sent while there is no upstream at all. This is the whole feature.
            const buffered = peer.call('tools/call', { name: 'gen', arguments: {} });
            await settle(50);
            expect(peer.toolwall.proxy.bufferedRequests).toBeGreaterThan(0);

            const answer = await buffered;
            expect(errorOf(answer)).toBeUndefined();
            // Generation 2: it really was answered by the replacement process.
            expect(textOf(answer)).toBe('2');
            expect(peer.toolwall.currentUpstreamTransport.pid).not.toBe(oldPid);

            expect(peer.toolwall.proxy.closed).toBe(false);
            expect(peer.toolwall.proxy.linkState).toBe('connected');
            expect(peer.events.map(e => e.kind)).toContain('upstream-reconnected');

            // And the session keeps working afterwards.
            expect(errorOf(await peer.call('tools/list'))).toBeUndefined();
        } finally {
            await closeAll();
        }
    }, 30_000);

    it('re-verifies the replacement against the existing pins rather than re-adopting it', async () => {
        // The same distinction `resilience.test.ts` draws for a restarted
        // session, applied to an automatic reconnect: comparing hashes is not
        // enough, because a store that silently forgot would re-adopt the same
        // clean definition and produce the same hash. Only "verified, never
        // pinned again" separates "checked" from "forgot and trusted anew".
        const state = await stateDir();
        const peer = await connectAssembled({
            server: RESTARTING_SERVER,
            serverArgs: ['--state', state],
            reconnect: { backoffMs: [300, 600, 1200] }
        });
        peers.push(peer);
        try {
            await peer.handshake();
            await peer.call('tools/list');
            const pinnedHash = peer.pins.get(peer.toolwall.serverId, 'tool', 'add')?.hash;
            expect(pinnedHash).toBeDefined();

            const pinnedBefore = peer.pinEvents.filter(e => e.kind === 'pinned').length;
            expect(pinnedBefore).toBeGreaterThan(0);

            killUpstream(peer);
            await waitForEvent(peer, 'upstream-reconnected');

            // toolwall listed the new process ITSELF, before releasing anything.
            expect(peer.pinEvents.filter(e => e.kind === 'pinned')).toHaveLength(pinnedBefore);
            expect(peer.pinEvents.filter(e => e.kind === 'verified').map(e => e.subject)).toContain('add');
            expect(peer.pins.get(peer.toolwall.serverId, 'tool', 'add')?.hash).toBe(pinnedHash);
        } finally {
            await closeAll();
        }
    }, 30_000);

    it('replays the handshake, so a server->client request still works after the reconnect', async () => {
        // Under 2025-11-25 a server that never saw `initialize` has no recorded
        // client capabilities and the SDK refuses to let it send sampling at
        // all. A session that came back unable to sample would be a subtler
        // failure than one that died.
        const state = await stateDir();
        const peer = await connectAssembled({
            server: RESTARTING_SERVER,
            serverArgs: ['--state', state],
            reconnect: { backoffMs: [300, 600, 1200] }
        });
        peers.push(peer);
        try {
            await peer.handshake();
            await peer.call('tools/list');

            killUpstream(peer);
            await waitForEvent(peer, 'upstream-reconnected');

            // The replacement asks US to sample; answer it like a real client.
            const asked = peer.call('tools/call', { name: 'ask', arguments: {} });
            const sampling = await peer.out.waitForMethod('sampling/createMessage');
            peer.send({
                jsonrpc: '2.0',
                id: sampling.value['id'],
                result: { role: 'assistant', content: { type: 'text', text: 'pong' }, model: 'test' }
            });
            const done = await asked;
            expect(errorOf(done)).toBeUndefined();
            expect(textOf(done)).toContain('pong');
        } finally {
            await closeAll();
        }
    }, 30_000);
});

describe('a reconnect is not a path around a guard', () => {
    it('REFUSES to resume when the replacement process advertises something that was not approved', async () => {
        // `--poison-after 1`: generation 1 is clean and gets pinned, generation 2
        // serves a poisoned description. The serverId is derived from the launch
        // spec, so it is IDENTICAL across the restart by design — which is
        // exactly why the in-memory catalogue must be invalidated and re-listed
        // rather than inherited.
        const state = await stateDir();
        const peer = await connectAssembled({
            server: RESTARTING_SERVER,
            serverArgs: ['--state', state, '--poison-after', '1'],
            reconnect: { backoffMs: [300, 600, 1200] }
        });
        peers.push(peer);
        try {
            await peer.handshake();
            await peer.call('tools/list');
            expect(peer.pins.get(peer.toolwall.serverId, 'tool', 'add')).toBeDefined();

            killUpstream(peer);
            await waitForEvent(peer, 'upstream-reconnecting');

            const buffered = peer.call('tools/call', { name: 'add', arguments: { a: 1, b: 2 } });
            const answer = await buffered;

            const error = errorOf(answer);
            expect(error?.code).toBe(-32603);
            const data = error?.data as { toolwall?: { upstreamUnavailable?: boolean; reason?: string } };
            expect(data?.toolwall?.upstreamUnavailable).toBe(true);
            expect(data?.toolwall?.reason).toBe('reverification-failed');

            // The refusal is loud on the operator channel, and it names drift.
            const refused = peer.events.filter(e => e.kind === 'upstream-reconnect-refused');
            expect(refused).toHaveLength(1);
            expect(peer.pinEvents.filter(e => e.kind === 'drift').map(e => e.subject)).toContain('add');

            // The pin was never quietly updated to the poisoned definition.
            const stored = peer.pins.get(peer.toolwall.serverId, 'tool', 'add');
            expect(JSON.stringify(stored?.definition)).not.toContain('Ignore previous instructions');

            // And it is not retried: retrying is offering the attacker another go.
            expect(peer.events.filter(e => e.kind === 'upstream-reconnecting')).toHaveLength(1);
            // The session ends — after the -32603s have been flushed, not before.
            await eventually(() => peer.toolwall.proxy.closed, 'the proxy to close after refusing');
        } finally {
            await closeAll();
        }
    }, 30_000);
});

describe('what happens to a request that was already on the wire', () => {
    it('does not silently re-run a tools/call whose execution status is unknown', async () => {
        const state = await stateDir();
        const peer = await connectAssembled({
            server: RESTARTING_SERVER,
            serverArgs: ['--state', state],
            reconnect: { backoffMs: [200, 600, 1200] }
        });
        peers.push(peer);
        try {
            await peer.handshake();
            await peer.call('tools/list');

            // Genuinely in flight when the process dies.
            const inflight = peer.call('tools/call', { name: 'slow', arguments: { ms: 5000 } });
            await settle(150);
            killUpstream(peer);

            const answer = await inflight;
            const error = errorOf(answer);
            expect(error?.code).toBe(-32603);
            expect(error?.message).toContain('execution status is unknown');
            expect((error?.data as { toolwall?: { reason?: string } })?.toolwall?.reason).toBe('not-replayable');

            // The client got a real answer and the session lived on.
            await waitForEvent(peer, 'upstream-reconnected');
            expect(peer.toolwall.proxy.closed).toBe(false);
            expect(textOf(await peer.call('tools/call', { name: 'gen', arguments: {} }))).toBe('2');
        } finally {
            await closeAll();
        }
    }, 30_000);

    it('does re-run it when the operator has explicitly accepted at-least-once delivery', async () => {
        const state = await stateDir();
        const peer = await connectAssembled({
            server: RESTARTING_SERVER,
            serverArgs: ['--state', state],
            reconnect: { backoffMs: [200, 600, 1200], replayInFlight: 'all' }
        });
        peers.push(peer);
        try {
            await peer.handshake();
            await peer.call('tools/list');

            const inflight = peer.call('tools/call', { name: 'slow', arguments: { ms: 300 } });
            await settle(120);
            killUpstream(peer);

            const answer = await inflight;
            expect(errorOf(answer)).toBeUndefined();
            expect(textOf(answer)).toBe('slept 300');
            expect(peer.events.map(e => e.kind)).toContain('upstream-reconnected');
        } finally {
            await closeAll();
        }
    }, 30_000);
});

describe('when the server cannot be brought back at all', () => {
    it('answers every buffered caller with -32603 and then closes cleanly', async () => {
        // Driven at the transport level so the failure is deterministic: the
        // factory refuses to build a replacement, which is what a server whose
        // binary has been removed or whose port is taken looks like from here.
        const state = await stateDir();
        const upstream = createUpstreamStdioTransport(
            { command: process.execPath, args: [RESTARTING_SERVER, '--state', state] },
            { allowedCommands: ['node'] }
        );
        const toProxy = new PassThrough();
        const fromProxy = new PassThrough();
        const lines: Array<Record<string, unknown>> = [];
        let buffer = '';
        fromProxy.on('data', (chunk: Buffer) => {
            buffer += chunk.toString();
            for (;;) {
                const idx = buffer.indexOf('\n');
                if (idx === -1) break;
                const raw = buffer.slice(0, idx);
                buffer = buffer.slice(idx + 1);
                if (raw.trim().length > 0) lines.push(JSON.parse(raw) as Record<string, unknown>);
            }
        });

        const events: ProxyEvent[] = [];
        const proxy = new ToolwallProxy({
            clientTransport: new StdioServerTransport(toProxy, fromProxy),
            upstreamTransport: upstream.transport,
            serverId: upstream.serverId,
            createUpstreamTransport: () => {
                throw new Error('respawn refused by the test');
            },
            // Slow enough that the request below is genuinely parked rather
            // than arriving after the budget is already spent.
            reconnect: { enabled: true, maxAttempts: 3, backoffMs: [400, 400, 400] },
            onEvent: event => events.push(event)
        });
        upstream.transport.stderr?.resume();
        await proxy.start();

        const waitForId = async (id: number, timeoutMs = 8_000): Promise<Record<string, unknown>> => {
            const deadline = Date.now() + timeoutMs;
            for (;;) {
                const found = lines.find(l => l['id'] === id && ('result' in l || 'error' in l));
                if (found !== undefined) return found;
                if (Date.now() > deadline) {
                    throw new Error(`timed out waiting for id ${id}; saw ${JSON.stringify(lines)}`);
                }
                await settle(20);
            }
        };

        try {
            toProxy.write(
                `${JSON.stringify({
                    jsonrpc: '2.0',
                    id: 0,
                    method: 'initialize',
                    params: { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 't', version: '1' } }
                })}\n`
            );
            await waitForId(0);
            toProxy.write(`${JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' })}\n`);

            toProxy.write(`${JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' })}\n`);
            await waitForId(1);

            const pid = upstream.transport.pid as number;
            process.kill(pid, 'SIGKILL');
            await settle(80);

            toProxy.write(`${JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list' })}\n`);
            const failure = await waitForId(2);
            const error = failure['error'] as { code: number; message: string; data?: unknown };
            expect(error.code).toBe(-32603);
            expect(error.message).toContain('could not reach the upstream MCP server');
            expect((error.data as { toolwall?: { reason?: string } })?.toolwall?.reason).toBe('retries-exhausted');

            const failed = events.filter(e => e.kind === 'upstream-reconnect-failed');
            expect(failed).toHaveLength(1);
            expect(events.filter(e => e.kind === 'upstream-reconnecting')).toHaveLength(3);
            await eventually(() => proxy.closed, 'the proxy to close after exhausting its retries');
        } finally {
            await proxy.close();
            await closeAll();
        }
    }, 30_000);
});
