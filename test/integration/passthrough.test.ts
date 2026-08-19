/**
 * Real integration tests: a real downstream MCP server, spawned as a real child
 * process, talking real newline-delimited JSON-RPC over real pipes.
 *
 * The headline test compares the bytes a client transport receives on a direct
 * connection against the bytes it receives through toolwall.
 */

import { afterEach, describe, expect, it } from 'vitest';
import { deserializeMessage, serializeMessage } from '@modelcontextprotocol/sdk/shared/stdio.js';

import { connectDirect, connectThroughProxy, INITIALIZE, INITIALIZED, type Peer, type ProxyPeer } from './harness.js';
import { DefaultGuardPipeline } from '../../src/transport/pipeline.js';
import type { Guard } from '../../src/types/protocol.js';

const open: Peer[] = [];

afterEach(async () => {
    await Promise.all(open.splice(0).map(p => p.close()));
});

function track<T extends Peer>(peer: T): T {
    open.push(peer);
    return peer;
}

/**
 * What a client's transport actually hands to its Protocol layer.
 *
 * `ReadBuffer.readMessage` parses each line with `JSONRPCMessageSchema`, and
 * zod rebuilds objects with declared keys first. Every MCP peer's read path
 * does this, direct connection or not, so this is the level at which the
 * strongest claim can be made: a client cannot distinguish the two paths.
 */
function asDelivered(raw: string): string {
    return serializeMessage(deserializeMessage(raw)).trimEnd();
}

describe('benign traffic is identical through the proxy', () => {
    it('delivers byte-identical bytes to the client for initialize, tools/list and tools/call', async () => {
        const traffic = [
            INITIALIZE,
            { jsonrpc: '2.0', id: 2, method: 'tools/list' },
            { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'echo', arguments: { text: 'hello ✅ 日本語' } } }
        ];

        const direct = track(connectDirect());
        const proxied = track(await connectThroughProxy());

        for (const peer of [direct, proxied]) {
            peer.send(traffic[0] as unknown as Record<string, unknown>);
            await peer.out.waitForId(1);
            peer.send(INITIALIZED as unknown as Record<string, unknown>);
            peer.send(traffic[1] as Record<string, unknown>);
            await peer.out.waitForId(2);
            peer.send(traffic[2] as Record<string, unknown>);
            await peer.out.waitForId(3);
        }

        for (const id of [1, 2, 3]) {
            const d = direct.out.lines.find(l => l.value['id'] === id);
            const p = proxied.out.lines.find(l => l.value['id'] === id);
            expect(d, `direct response ${id}`).toBeDefined();
            expect(p, `proxied response ${id}`).toBeDefined();

            // The strong claim: literally the same bytes on the wire.
            expect(p!.raw, `id ${id} raw bytes`).toBe(d!.raw);
            // And structurally: nothing added, dropped or altered.
            expect(p!.value).toStrictEqual(d!.value);
        }
    });

    it('the one case where raw key order differs is _meta hoisting, and a client still cannot tell', async () => {
        // `ResultSchema` declares `_meta`, so the proxy's upstream ReadBuffer
        // moves it to the front of `result`. This is the ONLY fidelity
        // deviation toolwall introduces on benign traffic, and it is invisible
        // to a client because the client's own ReadBuffer does the same thing.
        const direct = track(connectDirect());
        const proxied = track(await connectThroughProxy());
        const call = { jsonrpc: '2.0', id: 2, method: 'x-experimental/meta' };

        for (const peer of [direct, proxied]) {
            peer.send(INITIALIZE as unknown as Record<string, unknown>);
            await peer.out.waitForId(1);
            peer.send(call);
            await peer.out.waitForId(2);
        }

        const d = direct.out.lines.find(l => l.value['id'] === 2)!;
        const p = proxied.out.lines.find(l => l.value['id'] === 2)!;

        // Raw bytes differ only by where `_meta` sits...
        expect(d.raw).toContain('{"marker":"value","_meta":{"com.example/note":1}}');
        expect(p.raw).toContain('{"_meta":{"com.example/note":1},"marker":"value"}');
        expect(p.raw).not.toBe(d.raw);
        // ...and are identical once each side's transport has parsed them.
        expect(asDelivered(p.raw)).toBe(asDelivered(d.raw));
        expect(p.value).toStrictEqual(d.value);
    });

    it('relays the server instructions and serverInfo verbatim rather than substituting toolwall', async () => {
        const proxied = track(await connectThroughProxy());
        proxied.send(INITIALIZE as unknown as Record<string, unknown>);
        const init = await proxied.out.waitForId(1);
        const result = init.value['result'] as Record<string, unknown>;

        expect(result['serverInfo']).toStrictEqual({ name: 'toolwall-test-downstream', version: '1.2.3' });
        expect(result['instructions']).toBe(
            'Fixture server. Instructions are a top-ranked injection surface, so they must survive the hop verbatim.'
        );
        expect(result['capabilities']).toMatchObject({ tools: { listChanged: true }, logging: {} });
    });

    it('preserves unknown keys inside a result', async () => {
        const proxied = track(await connectThroughProxy());
        proxied.send(INITIALIZE as unknown as Record<string, unknown>);
        await proxied.out.waitForId(1);
        proxied.send({ jsonrpc: '2.0', id: 2, method: 'tools/list' });
        const list = await proxied.out.waitForId(2);
        const result = list.value['result'] as Record<string, unknown>;
        expect(result['x-fixture-marker']).toStrictEqual({ nested: [1, 2, { deep: true }] });
    });
});

describe('unknown and future methods forward without enumeration', () => {
    it('forwards a method neither the SDK nor toolwall knows about', async () => {
        const direct = track(connectDirect());
        const proxied = track(await connectThroughProxy());
        const call = { jsonrpc: '2.0', id: 2, method: 'x-experimental/echo', params: { anything: [1, 'two', { three: null }] } };

        for (const peer of [direct, proxied]) {
            peer.send(INITIALIZE as unknown as Record<string, unknown>);
            await peer.out.waitForId(1);
            peer.send(call);
            await peer.out.waitForId(2);
        }

        const d = direct.out.lines.find(l => l.value['id'] === 2)!;
        const p = proxied.out.lines.find(l => l.value['id'] === 2)!;
        expect(p.raw).toBe(d.raw);
        expect((p.value['result'] as Record<string, unknown>)['received']).toStrictEqual(call.params);
    });

    it('forwards an unknown notification, and relays the notification it triggers back', async () => {
        const proxied = track(await connectThroughProxy());
        proxied.send(INITIALIZE as unknown as Record<string, unknown>);
        await proxied.out.waitForId(1);
        proxied.send({ jsonrpc: '2.0', method: 'x-experimental/ping', params: { marker: 'abc' } });

        const log = await proxied.out.waitForMethod('notifications/message');
        expect((log.value['params'] as Record<string, unknown>)['data']).toStrictEqual({ sawNotification: { marker: 'abc' } });
    });
});

describe('bidirectional traffic', () => {
    it('relays a server-initiated sampling/createMessage request and the client answer', async () => {
        const proxied = track(await connectThroughProxy());
        proxied.send(INITIALIZE as unknown as Record<string, unknown>);
        await proxied.out.waitForId(1);

        proxied.send({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'ask', arguments: {} } });

        // The server's request must arrive at the client, with its attacker
        // controlled natural language intact.
        const sampling = await proxied.out.waitForMethod('sampling/createMessage');
        const params = sampling.value['params'] as Record<string, unknown>;
        expect(params['systemPrompt']).toBe('attacker-controlled natural language lives here');
        expect(params['maxTokens']).toBe(16);

        // Answer it the way a real client would.
        proxied.send({
            jsonrpc: '2.0',
            id: sampling.value['id'] as number,
            result: { role: 'assistant', content: { type: 'text', text: '4' }, model: 'test-model' }
        });

        const done = await proxied.out.waitForId(2);
        const text = ((done.value['result'] as Record<string, unknown>)['content'] as Array<Record<string, unknown>>)[0]!['text'];
        expect(String(text)).toContain('"text":"4"');
    });

    it('relays notifications/cancelled to the upstream request id, and suppresses the stale response', async () => {
        const proxied = track(await connectThroughProxy());
        proxied.send(INITIALIZE as unknown as Record<string, unknown>);
        await proxied.out.waitForId(1);

        proxied.send({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'hang', arguments: {} } });
        // Let the request reach the server before cancelling it.
        await new Promise(resolve => setTimeout(resolve, 150));
        proxied.send({ jsonrpc: '2.0', method: 'notifications/cancelled', params: { requestId: 2, reason: 'user aborted' } });

        // The server must have seen a cancellation for ITS request id, not
        // the client's id 2 — the fixture only reports if its own handler was
        // aborted.
        const report = await proxied.out.waitForMethod('notifications/message');
        expect((report.value['params'] as Record<string, unknown>)['data']).toStrictEqual({
            cancelled: true,
            reason: 'user aborted'
        });

        // No response for id 2 may reach the client.
        await new Promise(resolve => setTimeout(resolve, 150));
        expect(proxied.out.lines.find(l => l.value['id'] === 2 && ('result' in l.value || 'error' in l.value))).toBeUndefined();
    });

    it('relays notifications/progress with the client progressToken untouched', async () => {
        const proxied = track(await connectThroughProxy());
        proxied.send(INITIALIZE as unknown as Record<string, unknown>);
        await proxied.out.waitForId(1);

        proxied.send({
            jsonrpc: '2.0',
            id: 2,
            method: 'tools/call',
            params: { name: 'slow', arguments: {}, _meta: { progressToken: 'client-token-xyz' } }
        });

        await proxied.out.waitForId(2);
        const progress = proxied.out.lines.filter(l => l.value['method'] === 'notifications/progress');
        expect(progress.length).toBe(2);
        for (const line of progress) {
            expect((line.value['params'] as Record<string, unknown>)['progressToken']).toBe('client-token-xyz');
        }
        expect((progress[1]!.value['params'] as Record<string, unknown>)['message']).toBe('done');
    });
});

describe('error relay fidelity', () => {
    it('relays code, message and data exactly, without McpError message rewriting', async () => {
        const direct = track(connectDirect());
        const proxied = track(await connectThroughProxy());
        const call = { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'boom', arguments: {} } };

        for (const peer of [direct, proxied]) {
            peer.send(INITIALIZE as unknown as Record<string, unknown>);
            await peer.out.waitForId(1);
            peer.send(call);
            await peer.out.waitForId(2);
        }

        const d = direct.out.lines.find(l => l.value['id'] === 2)!;
        const p = proxied.out.lines.find(l => l.value['id'] === 2)!;

        expect(p.value['error']).toStrictEqual(d.value['error']);
        const error = p.value['error'] as Record<string, unknown>;
        expect(error['code']).toBe(-32602);
        expect(error['message']).toBe('MCP error -32602: boom happened');
        expect(error['data']).toStrictEqual({ detail: 'structured error data', n: 42 });
        expect(p.raw).toBe(d.raw);
    });
});

describe('guard pipeline', () => {
    it('blocks fail closed: a JSON-RPC error reaches the client and the request never reaches the server', async () => {
        const guards = new DefaultGuardPipeline();
        const blocker: Guard = {
            name: 'test/block-forbidden',
            inspect(payload) {
                const name = (payload as { name?: string } | undefined)?.name;
                if (name === 'forbidden') {
                    return {
                        action: 'block',
                        code: -32600,
                        findings: [
                            {
                                ruleId: 'test/forbidden-tool',
                                severity: 'critical',
                                message: 'tool "forbidden" is denied by policy',
                                locus: '/name',
                                remediation: 'Remove the tool from the deny list if this is expected.'
                            }
                        ]
                    };
                }
                return { action: 'allow' };
            }
        };
        guards.register({ direction: 'request', method: 'tools/call', guard: blocker });

        const proxied = track(await connectThroughProxy({ guards })) as ProxyPeer;
        proxied.send(INITIALIZE as unknown as Record<string, unknown>);
        await proxied.out.waitForId(1);

        proxied.send({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'forbidden', arguments: {} } });
        const blocked = await proxied.out.waitForId(2);
        const error = blocked.value['error'] as Record<string, unknown>;
        expect(error['code']).toBe(-32600);
        expect(String(error['message'])).toContain('toolwall blocked request tools/call');
        expect(((error['data'] as Record<string, unknown>)['toolwall'] as Record<string, unknown>)['blocked']).toBe(true);

        // The server must never have seen it.
        proxied.send({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'calls', arguments: {} } });
        const calls = await proxied.out.waitForId(3);
        const text = ((calls.value['result'] as Record<string, unknown>)['content'] as Array<Record<string, unknown>>)[0]!['text'];
        expect(JSON.parse(String(text))).toStrictEqual([]);

        expect(proxied.events.some(e => e.kind === 'blocked')).toBe(true);
    });

    it('annotate rewrites the forwarded payload', async () => {
        const guards = new DefaultGuardPipeline();
        guards.register({
            direction: 'request',
            method: 'tools/call',
            guard: {
                name: 'test/rewrite',
                inspect(payload) {
                    const params = payload as Record<string, unknown>;
                    return {
                        action: 'annotate',
                        payload: { ...params, arguments: { text: 'REWRITTEN' } },
                        findings: [
                            {
                                ruleId: 'test/rewrite',
                                severity: 'medium',
                                message: 'argument rewritten',
                                locus: '/arguments/text',
                                remediation: 'n/a'
                            }
                        ]
                    };
                }
            }
        });

        const proxied = track(await connectThroughProxy({ guards }));
        proxied.send(INITIALIZE as unknown as Record<string, unknown>);
        await proxied.out.waitForId(1);
        proxied.send({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'echo', arguments: { text: 'original' } } });
        const echoed = await proxied.out.waitForId(2);
        const text = ((echoed.value['result'] as Record<string, unknown>)['content'] as Array<Record<string, unknown>>)[0]!['text'];
        expect(text).toBe('REWRITTEN');
    });

    it('guards on the response leg see the server result', async () => {
        const guards = new DefaultGuardPipeline();
        const seen: unknown[] = [];
        guards.register({
            direction: 'response',
            method: 'tools/list',
            guard: {
                name: 'test/observe',
                inspect(payload) {
                    seen.push(payload);
                    return { action: 'allow' };
                }
            }
        });

        const proxied = track(await connectThroughProxy({ guards }));
        proxied.send(INITIALIZE as unknown as Record<string, unknown>);
        await proxied.out.waitForId(1);
        proxied.send({ jsonrpc: '2.0', id: 2, method: 'tools/list' });
        await proxied.out.waitForId(2);

        expect(seen).toHaveLength(1);
        expect((seen[0] as { tools: unknown[] }).tools).toHaveLength(7);
    });
});
