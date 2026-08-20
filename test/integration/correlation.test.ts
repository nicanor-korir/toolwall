/**
 * **Contract C-13, closed: a result is matched to its own request under concurrency.**
 *
 * The gap, as C-13 stated it: `GuardContext` carried no per-exchange id, so a `tools/call` RESULT
 * did not say which call produced it. `ResultGuard` correlated by popping a per-server queue of
 * outbound calls and matching a result to "the single call in flight"; with more than one
 * outstanding it declined to guess, emitted `toolwall/result.uncorrelated` (`info`) and skipped
 * `outputSchema` enforcement and the ATPA sequence check entirely.
 *
 * Declining to guess was the right call — enforcing one tool's `outputSchema` against another
 * tool's result is worse than not enforcing it. But it meant **concurrent workloads silently got
 * reduced coverage**, and concurrency is the ordinary shape of an agent driving several tools at
 * once, not an exotic one.
 *
 * `MessageCorrelation.correlationId` closes it. `ToolwallProxy` mints one per request/response
 * round trip and puts the same value on both legs, so pairing needs no inference at all.
 *
 * ## Why this file is an integration test and not a unit test
 *
 * The claim is about the TRANSPORT's behaviour across two legs of real traffic, and the failure
 * mode is a leg that quietly gets no correlation. A unit test that builds a `GuardContext` by hand
 * asserts the shape of a literal it wrote itself. So everything below runs a real `ToolwallProxy`
 * against a real child process (`test/fixtures/concurrent-server.mjs`) that answers **out of
 * order**: five calls with descending delays come back in reverse, with all five in flight.
 *
 * ## What is proved here, and what is left to Dev 3
 *
 * Proved here: the transport now supplies everything needed to pair a result with its request, and
 * the algorithm that uses it works on real interleaved traffic — including the ATPA sequence with
 * unrelated calls between the error and the retry. `CorrelatingProbe` below is that algorithm,
 * written as the reference `ResultGuard` can adopt.
 *
 * Not changed here: `ResultGuard` itself (`src/guards/runtime/`, Dev 3). `QueueProbe` reproduces
 * its current correlation exactly, and the tests that run it record what it misses today — so
 * these are measurements of a live defect, not a description of one.
 */

import { describe, expect, it } from 'vitest';

import { DefaultGuardPipeline } from '../../src/transport/pipeline.js';
import { ALLOW, correlationIdOf, type Guard, type GuardContext, type Verdict } from '../../src/types/protocol.js';
import { connectThroughProxy, type ProxyPeer } from './harness.js';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const here = path.dirname(fileURLToPath(import.meta.url));
const CONCURRENT_SERVER = path.resolve(here, '../fixtures/concurrent-server.mjs');

const INITIALIZE = {
    jsonrpc: '2.0' as const,
    method: 'initialize',
    params: {
        protocolVersion: '2025-11-25',
        capabilities: {},
        clientInfo: { name: 'correlation-test', version: '1.0.0' }
    }
};

interface ToolCallParams {
    readonly name: string;
    readonly arguments?: Record<string, unknown>;
}

const asRecord = (v: unknown): Record<string, unknown> | undefined =>
    typeof v === 'object' && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : undefined;

/** Concatenate a result's text content, as `ResultGuard.collectText` does for the ATPA match. */
function collectText(result: unknown): string {
    const record = asRecord(result);
    const content = record?.['content'];
    if (!Array.isArray(content)) return '';
    return content
        .map(part => {
            const p = asRecord(part);
            return typeof p?.['text'] === 'string' ? (p['text'] as string) : '';
        })
        .join('\n');
}

// ---------------------------------------------------------------------------
// Probes
// ---------------------------------------------------------------------------

interface Pairing {
    readonly correlationId: string;
    readonly tool: string;
    readonly requestTag: string | undefined;
    readonly resultTag: string | undefined;
}

/**
 * Records every context the proxy builds, so the guarantee can be checked rather than assumed.
 */
class ContextRecorder implements Guard {
    readonly name = 'context-recorder';
    readonly seen: GuardContext[] = [];

    inspect(_payload: unknown, ctx: GuardContext): Verdict {
        this.seen.push(ctx);
        return ALLOW;
    }
}

/**
 * **The reference correlation, written against `correlationId`.**
 *
 * This is the shape `ResultGuard` can adopt, and it is deliberately boring: a `Map` keyed on the
 * id the transport supplies, with no inference, no ordering assumption and no ambiguity to resolve.
 *
 * The ATPA half has a second change, and it is NOT a correlation fix — it is what correlation makes
 * possible. `ResultGuard` keeps one `lastError` slot per SERVER and lets the next call on that
 * server consume it, whatever tool that call names. Interleave one unrelated `plain` call between
 * a `flaky` error and the `flaky` retry and the record is gone before the retry is inspected. Here
 * the record is keyed by TOOL, which is only sound because the result can now be attributed to the
 * tool that produced it: under the queue, a `flaky` error arriving with other calls in flight was
 * recorded against `toolName: ""` and matched nothing afterwards.
 */
class CorrelatingProbe implements Guard {
    readonly name = 'correlating-probe';
    readonly pairings: Pairing[] = [];
    readonly atpaHits: string[] = [];
    readonly missingId: GuardContext[] = [];
    /** Highest number of `tools/call` round trips open at once. 1 would make this file vacuous. */
    maxInFlight = 0;

    readonly #pending = new Map<string, { tool: string; argumentKeys: string[]; tag: string | undefined }>();
    readonly #lastErrorByTool = new Map<string, { text: string; argumentKeys: string[] }>();

    inspect(payload: unknown, ctx: GuardContext): Verdict {
        const id = correlationIdOf(ctx);
        if (id === undefined) {
            this.missingId.push(ctx);
            return ALLOW;
        }
        if (ctx.method !== 'tools/call') return ALLOW;

        if (ctx.direction === 'request') {
            const params = (asRecord(payload) ?? {}) as unknown as ToolCallParams;
            const args = asRecord(params.arguments) ?? {};
            const argumentKeys = Object.keys(args);

            // ATPA: does this call retry a tool that just failed, adding an argument that failure
            // named? Keyed by tool, so unrelated traffic in between cannot consume the record.
            const prior = this.#lastErrorByTool.get(params.name);
            if (prior !== undefined) {
                this.#lastErrorByTool.delete(params.name);
                const added = argumentKeys.filter(k => !prior.argumentKeys.includes(k));
                const namedInError = added.filter(k => prior.text.includes(k));
                if (namedInError.length > 0) {
                    this.atpaHits.push(`${params.name}:${namedInError.join(',')}`);
                }
            }

            this.#pending.set(id, {
                tool: params.name,
                argumentKeys,
                tag: typeof args['tag'] === 'string' ? (args['tag'] as string) : undefined
            });
            this.maxInFlight = Math.max(this.maxInFlight, this.#pending.size);
            return ALLOW;
        }

        const call = this.#pending.get(id);
        this.#pending.delete(id);
        if (call === undefined) return ALLOW;

        const structured = asRecord(asRecord(payload)?.['structuredContent']);
        this.pairings.push({
            correlationId: id,
            tool: call.tool,
            requestTag: call.tag,
            resultTag: typeof structured?.['tag'] === 'string' ? (structured['tag'] as string) : undefined
        });

        if (asRecord(payload)?.['isError'] === true) {
            this.#lastErrorByTool.set(call.tool, {
                text: collectText(payload),
                argumentKeys: call.argumentKeys
            });
        }
        return ALLOW;
    }
}

/**
 * `ResultGuard`'s correlation as it stands today, reproduced exactly (`#correlate`, and the single
 * per-server `lastError` slot consumed by the next call whatever it is).
 *
 * It is here so the tests below measure a live defect instead of describing one: run the same
 * traffic through both probes and the difference is the coverage C-13 was costing.
 */
class QueueProbe implements Guard {
    readonly name = 'queue-probe';
    readonly pairings: Pairing[] = [];
    readonly atpaHits: string[] = [];
    /** Results the queue refused to correlate — `toolwall/result.uncorrelated` in the real guard. */
    uncorrelated = 0;

    readonly #queue: Array<{ tool: string; argumentKeys: string[]; tag: string | undefined }> = [];
    #lastError: { toolName: string; text: string; argumentKeys: string[] } | undefined;

    inspect(payload: unknown, ctx: GuardContext): Verdict {
        if (ctx.method !== 'tools/call') return ALLOW;

        if (ctx.direction === 'request') {
            const params = (asRecord(payload) ?? {}) as unknown as ToolCallParams;
            const args = asRecord(params.arguments) ?? {};
            const argumentKeys = Object.keys(args);

            const prior = this.#lastError;
            this.#lastError = undefined; // consumed by the next call, whatever it is
            if (prior !== undefined && prior.toolName === params.name) {
                const added = argumentKeys.filter(k => !prior.argumentKeys.includes(k));
                const namedInError = added.filter(k => prior.text.includes(k));
                if (namedInError.length > 0) {
                    this.atpaHits.push(`${params.name}:${namedInError.join(',')}`);
                }
            }

            this.#queue.push({
                tool: params.name,
                argumentKeys,
                tag: typeof args['tag'] === 'string' ? (args['tag'] as string) : undefined
            });
            return ALLOW;
        }

        // `#correlate`: one in flight is unambiguous, more than one is not.
        let call: { tool: string; argumentKeys: string[]; tag: string | undefined } | undefined;
        if (this.#queue.length === 1) {
            call = this.#queue.shift();
        } else if (this.#queue.length > 1) {
            this.#queue.shift();
            this.uncorrelated += 1;
        }
        if (call === undefined) {
            return ALLOW;
        }

        const structured = asRecord(asRecord(payload)?.['structuredContent']);
        this.pairings.push({
            correlationId: correlationIdOf(ctx) ?? '',
            tool: call.tool,
            requestTag: call.tag,
            resultTag: typeof structured?.['tag'] === 'string' ? (structured['tag'] as string) : undefined
        });

        if (asRecord(payload)?.['isError'] === true) {
            this.#lastError = { toolName: call.tool, text: collectText(payload), argumentKeys: call.argumentKeys };
        }
        return ALLOW;
    }
}

// ---------------------------------------------------------------------------
// Harness helpers
// ---------------------------------------------------------------------------

function pipelineWith(...guards: Guard[]): DefaultGuardPipeline {
    const pipeline = new DefaultGuardPipeline();
    for (const guard of guards) {
        pipeline.register({ direction: 'request', method: 'tools/call', guard });
        pipeline.register({ direction: 'response', method: 'tools/call', guard });
    }
    return pipeline;
}

async function handshake(peer: ProxyPeer, id: number): Promise<void> {
    peer.send({ ...INITIALIZE, id });
    await peer.out.waitForId(id);
    peer.send({ jsonrpc: '2.0', method: 'notifications/initialized' });
}

// ---------------------------------------------------------------------------

describe('C-13 · every GuardContext the transport builds carries a correlation id', () => {
    it('populates it on BOTH legs of a request, and on notifications and server->client traffic', async () => {
        const recorder = new ContextRecorder();
        const pipeline = new DefaultGuardPipeline();
        // Wildcards on purpose: the question is whether ANY leg is missed, so nothing may be
        // excluded by the registration itself.
        pipeline.register({ direction: 'request', method: '*', guard: recorder });
        pipeline.register({ direction: 'response', method: '*', guard: recorder });

        const peer = await connectThroughProxy({ server: CONCURRENT_SERVER, guards: pipeline });
        try {
            await handshake(peer, 1);
            peer.send({ jsonrpc: '2.0', id: 2, method: 'tools/list' });
            await peer.out.waitForId(2);
            peer.send({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'plain', arguments: {} } });
            await peer.out.waitForId(3);
        } finally {
            await peer.close();
        }

        // initialize (both legs), notifications/initialized, tools/list (both legs),
        // tools/call (both legs) — every one of them.
        expect(recorder.seen.length).toBeGreaterThanOrEqual(6);
        const withoutId = recorder.seen.filter(ctx => correlationIdOf(ctx) === undefined);
        expect(
            withoutId.map(c => `${c.direction} ${c.method}`),
            'a leg with no correlation id is a leg on which a result cannot be paired with its request'
        ).toEqual([]);

        // Distinct per round trip, and identical across the two legs of one round trip.
        const requests = recorder.seen.filter(c => c.direction === 'request' && c.method === 'tools/call');
        const responses = recorder.seen.filter(c => c.direction === 'response' && c.method === 'tools/call');
        expect(requests).toHaveLength(1);
        expect(responses).toHaveLength(1);
        expect(correlationIdOf(responses[0] as GuardContext)).toBe(correlationIdOf(requests[0] as GuardContext));

        // The notification leg gets one too, and it is not shared with the request around it.
        const notification = recorder.seen.find(c => c.method === 'notifications/initialized');
        expect(correlationIdOf(notification as GuardContext)).toBeTruthy();
        expect(correlationIdOf(notification as GuardContext)).not.toBe(correlationIdOf(requests[0] as GuardContext));
    });
});

describe('C-13 · several overlapping tools/calls, each result matched to its own request', () => {
    it('pairs five out-of-order results with the five calls that produced them', async () => {
        const probe = new CorrelatingProbe();
        const queue = new QueueProbe();
        const peer = await connectThroughProxy({
            server: CONCURRENT_SERVER,
            guards: pipelineWith(probe, queue)
        });

        // Descending delays: the LAST call answers FIRST. Nothing about arrival order carries any
        // information about which call a result belongs to, which is the whole point.
        const calls = [
            { id: 10, tag: 't1', delayMs: 250 },
            { id: 11, tag: 't2', delayMs: 200 },
            { id: 12, tag: 't3', delayMs: 150 },
            { id: 13, tag: 't4', delayMs: 100 },
            { id: 14, tag: 't5', delayMs: 50 }
        ];

        try {
            await handshake(peer, 1);
            for (const c of calls) {
                peer.send({
                    jsonrpc: '2.0',
                    id: c.id,
                    method: 'tools/call',
                    params: { name: 'slow_echo', arguments: { tag: c.tag, delayMs: c.delayMs } }
                });
            }
            for (const c of calls) {
                await peer.out.waitForId(c.id);
            }
        } finally {
            await peer.close();
        }

        // The premise: they really were concurrent, and they really did come back reversed. If
        // either of these fails the rest of the file is measuring sequential traffic.
        expect(probe.maxInFlight, 'the fixture must actually hold several calls open at once').toBe(5);
        const arrivalOrder = peer.out.lines
            .filter(l => typeof l.value['id'] === 'number' && (l.value['id'] as number) >= 10 && 'result' in l.value)
            .map(l => l.value['id']);
        expect(arrivalOrder).toEqual([14, 13, 12, 11, 10]);

        // THE assertion. Every result carried the tag of the call that asked for it.
        expect(probe.pairings).toHaveLength(5);
        for (const pairing of probe.pairings) {
            expect(pairing.resultTag, `result for ${pairing.correlationId} paired with the wrong call`).toBe(
                pairing.requestTag
            );
        }
        expect(new Set(probe.pairings.map(p => p.correlationId)).size, 'ids must be unique per round trip').toBe(5);
        expect(probe.pairings.map(p => p.requestTag).sort()).toEqual(['t1', 't2', 't3', 't4', 't5']);

        // And the measurement of what it was costing: the queue correlated ONE of the five and
        // refused the other four, which in `ResultGuard` is four `toolwall/result.uncorrelated`
        // findings and four results whose `outputSchema` was not enforced.
        expect(queue.uncorrelated).toBe(4);
        expect(queue.pairings).toHaveLength(1);
    });
});

describe('C-13 · an ATPA sequence interleaved with unrelated traffic', () => {
    it('still ties the retry to the error that solicited it, and the queue does not', async () => {
        const probe = new CorrelatingProbe();
        const queue = new QueueProbe();
        const peer = await connectThroughProxy({
            server: CONCURRENT_SERVER,
            guards: pipelineWith(probe, queue)
        });

        try {
            await handshake(peer, 1);

            // A slow unrelated call left OPEN across the whole sequence, so the ATPA error result
            // arrives with another call in flight — the condition under which the queue records the
            // error against no tool at all.
            peer.send({
                jsonrpc: '2.0',
                id: 20,
                method: 'tools/call',
                params: { name: 'slow_echo', arguments: { tag: 'background', delayMs: 400 } }
            });

            // The ATPA error. Its text names `debug_context`, an argument `flaky`'s schema never
            // declares.
            peer.send({
                jsonrpc: '2.0',
                id: 21,
                method: 'tools/call',
                params: { name: 'flaky', arguments: { query: 'select 1' } }
            });
            const errored = await peer.out.waitForId(21);
            expect(JSON.stringify(errored.value)).toContain('E_MISSING_CONTEXT');

            // Unrelated traffic BETWEEN the error and the retry. This is what a single per-server
            // `lastError` slot cannot survive.
            peer.send({ jsonrpc: '2.0', id: 22, method: 'tools/call', params: { name: 'plain', arguments: {} } });
            await peer.out.waitForId(22);
            peer.send({ jsonrpc: '2.0', id: 23, method: 'tools/list' });
            await peer.out.waitForId(23);

            // The retry, carrying the argument the error string asked for.
            peer.send({
                jsonrpc: '2.0',
                id: 24,
                method: 'tools/call',
                params: { name: 'flaky', arguments: { query: 'select 1', debug_context: 'ssh-rsa AAAA...' } }
            });
            await peer.out.waitForId(24);
            await peer.out.waitForId(20);
        } finally {
            await peer.close();
        }

        expect(
            probe.atpaHits,
            'the retry adds an argument the previous error named and the pinned schema does not declare'
        ).toEqual(['flaky:debug_context']);

        // The defect, measured. Two independent reasons the queue misses it, and correlation is
        // what removes the first: the error result arrived with `slow_echo` still in flight, so it
        // was never attributed to `flaky`; and the interleaved `plain` call would have consumed the
        // record even if it had been.
        expect(queue.atpaHits).toEqual([]);
        expect(queue.uncorrelated).toBeGreaterThan(0);
    });
});
