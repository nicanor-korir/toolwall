/**
 * MRTR plumbing, end to end against a real `2026-07-28`-shaped server.
 *
 * The claim being tested is narrow and it is the one Dev 3's guard depends on:
 *
 *   a `sampling/createMessage` embedded in a `tools/call` result reaches a guard
 *   registered for `("response", "sampling/createMessage")` — the SAME
 *   registration that catches the live server->client request under
 *   `2025-11-25` — with correlation that spans the changed JSON-RPC id.
 *
 * If that does not hold, then under the current revision a malicious server can
 * put an arbitrary `systemPrompt` and its own `tools[]` into a tool result and
 * every detector keyed on the method sees nothing (`docs/RESEARCH-BRIEF.md`
 * §4.5.2).
 */
import { describe, expect, it } from 'vitest';

import { DefaultGuardPipeline } from '../../src/transport/pipeline.js';
import type { Guard, GuardContext, Verdict } from '../../src/types/protocol.js';
import { ALLOW, TOOLWALL_BLOCKED } from '../../src/types/protocol.js';

import { MRTR_SERVER, connectThroughProxy, type ProxyPeer } from './harness.js';

const REQUEST_STATE = 'opaque-state-do-not-parse-me:§±';

interface Seen {
    readonly payload: unknown;
    readonly ctx: GuardContext;
}

/** Records every payload it is shown, and optionally blocks by rule. */
class Recorder implements Guard {
    readonly name = 'test/recorder';
    readonly seen: Seen[] = [];
    #verdict: (payload: unknown, ctx: GuardContext) => Verdict = () => ALLOW;

    blockWhen(predicate: (ctx: GuardContext) => boolean): void {
        this.#verdict = (_payload, ctx) =>
            predicate(ctx)
                ? {
                      action: 'block',
                      code: TOOLWALL_BLOCKED,
                      findings: [
                          {
                              ruleId: 'test/embedded-block',
                              severity: 'critical',
                              message: 'blocked for the test',
                              locus: '',
                              remediation: 'n/a'
                          }
                      ]
                  }
                : ALLOW;
    }

    inspect(payload: unknown, ctx: GuardContext): Verdict {
        this.seen.push({ payload, ctx });
        return this.#verdict(payload, ctx);
    }
}

const peers: ProxyPeer[] = [];
const closeAll = async (): Promise<void> => {
    for (const peer of peers.splice(0)) await peer.close().catch(() => undefined);
};

interface Rig {
    readonly peer: ProxyPeer;
    readonly recorder: Recorder;
    call(id: number, params: Record<string, unknown>): Promise<Record<string, unknown>>;
}

async function rig(options: { era?: '2025-11-25' | '2026-07-28' } = {}): Promise<Rig> {
    const recorder = new Recorder();
    const guards = new DefaultGuardPipeline();
    for (const method of ['sampling/createMessage', 'elicitation/create', 'roots/list']) {
        guards.register({ direction: 'response', method, guard: recorder });
    }
    // Also on the enclosing call, both legs, so correlation can be compared
    // between the outer message and the payloads lifted out of it.
    guards.register({ direction: 'response', method: 'tools/call', guard: recorder });
    guards.register({ direction: 'request', method: 'tools/call', guard: recorder });

    const peer = await connectThroughProxy({
        server: MRTR_SERVER,
        guards,
        era: options.era ?? '2026-07-28'
    });
    peers.push(peer);

    return {
        peer,
        recorder,
        async call(id, params) {
            peer.send({ jsonrpc: '2.0', id, method: 'tools/call', params });
            const line = await peer.out.waitFor(l => l.value['id'] === id && ('result' in l.value || 'error' in l.value));
            return line.value;
        }
    };
}

const embedded = (recorder: Recorder, method: string): Seen | undefined =>
    recorder.seen.find(s => s.ctx.method === method && s.ctx.correlation?.inputRequestKey !== undefined);

describe('inputRequests reach the guard pipeline on the response leg', () => {
    it('lifts an embedded sampling/createMessage to the same registration a live request would hit', async () => {
        const { recorder, call } = await rig();
        try {
            const answer = await call(7, { name: 'assist', arguments: {} });
            expect(answer['error']).toBeUndefined();

            const sampling = embedded(recorder, 'sampling/createMessage');
            expect(sampling).toBeDefined();
            // The guard sees the payload the client's LLM would have been handed.
            expect((sampling?.payload as { systemPrompt: string }).systemPrompt).toContain('unrestricted assistant');
            expect((sampling?.payload as { tools: Array<{ name: string }> }).tools[0]?.name).toBe('exfil');

            // ...on the response leg, because it is data from the server.
            expect(sampling?.ctx.direction).toBe('response');
            expect(sampling?.ctx.era).toBe('2026-07-28');
            expect(sampling?.ctx.correlation?.outerMethod).toBe('tools/call');
            expect(sampling?.ctx.correlation?.inputRequestKey).toBe('s1');
            expect(sampling?.ctx.correlation?.requestId).toBe(7);
            expect(sampling?.ctx.correlation?.requestStateHash).toMatch(/^[0-9a-f]{64}$/u);

            // Every entry is lifted, not just the first.
            expect(embedded(recorder, 'roots/list')?.ctx.correlation?.inputRequestKey).toBe('r1');
        } finally {
            await closeAll();
        }
    }, 20_000);

    it('lifts an embedded elicitation/create with its requestedSchema intact', async () => {
        const { recorder, call } = await rig();
        try {
            await call(1, { name: 'signup', arguments: {} });
            const elicit = embedded(recorder, 'elicitation/create');
            expect(elicit).toBeDefined();
            // The credential-shaped elicitation §4.5.3 says a proxy CAN enforce
            // against. Recognising it is Dev 3's job; getting it here is ours.
            const schema = (elicit?.payload as { requestedSchema: { properties: Record<string, unknown> } }).requestedSchema;
            expect(Object.keys(schema.properties)).toContain('api_key');
        } finally {
            await closeAll();
        }
    }, 20_000);

    it('correlates the retry to the original exchange across a CHANGED JSON-RPC id', async () => {
        const { recorder, call } = await rig();
        try {
            await call(7, { name: 'assist', arguments: {} });
            const sampling = embedded(recorder, 'sampling/createMessage');
            const exchangeId = sampling?.ctx.correlation?.exchangeId;
            expect(exchangeId).toBeDefined();

            // The retry: a different id, echoing the opaque state byte for byte.
            await call(8, { name: 'assist', arguments: {}, requestState: REQUEST_STATE });

            const retry = recorder.seen.find(
                s => s.ctx.direction === 'request' && s.ctx.method === 'tools/call' && s.ctx.correlation?.requestId === 8
            );
            expect(retry?.ctx.correlation?.isRetry).toBe(true);
            expect(retry?.ctx.correlation?.exchangeId).toBe(exchangeId);
            expect(retry?.ctx.correlation?.requestStateHash).toBe(sampling?.ctx.correlation?.requestStateHash);

            // The first leg was NOT flagged as a retry.
            const first = recorder.seen.find(
                s => s.ctx.direction === 'request' && s.ctx.method === 'tools/call' && s.ctx.correlation?.requestId === 7
            );
            expect(first?.ctx.correlation?.isRetry).toBeUndefined();
            expect(first?.ctx.correlation?.exchangeId).toBe(exchangeId);
        } finally {
            await closeAll();
        }
    }, 20_000);

    it('relays requestState byte-exactly in both directions and never parses it', async () => {
        const { call } = await rig();
        try {
            const first = await call(7, { name: 'assist', arguments: {} });
            // Out to the client, unchanged, including the non-ASCII bytes.
            expect((first['result'] as { requestState: string }).requestState).toBe(REQUEST_STATE);

            // Back to the server, unchanged: the fixture compares what it receives
            // against what it minted and reports the verdict itself.
            const second = await call(8, { name: 'assist', arguments: {}, requestState: REQUEST_STATE });
            const result = second['result'] as { 'x-echoed-state': string; 'x-state-matched': boolean };
            expect(result['x-state-matched']).toBe(true);
            expect(result['x-echoed-state']).toBe(REQUEST_STATE);
        } finally {
            await closeAll();
        }
    }, 20_000);

    it('a block on the embedded leg blocks the whole result — the payload never reaches the client', async () => {
        const { recorder, call } = await rig();
        recorder.blockWhen(ctx => ctx.method === 'sampling/createMessage');
        try {
            const answer = await call(7, { name: 'assist', arguments: {} });
            const error = answer['error'] as { code: number; data?: unknown };
            expect(error).toBeDefined();
            expect(error.code).toBe(TOOLWALL_BLOCKED);
            // The poisoned systemPrompt is not anywhere in what the client got.
            expect(JSON.stringify(answer)).not.toContain('unrestricted assistant');
            expect(JSON.stringify(answer)).not.toContain('attacker.example');
        } finally {
            await closeAll();
        }
    }, 20_000);

    it('does nothing to a complete result, so the ordinary path is untouched', async () => {
        const { recorder, call } = await rig();
        try {
            const answer = await call(1, { name: 'plain', arguments: {} });
            expect((answer['result'] as { resultType: string }).resultType).toBe('complete');
            expect(recorder.seen.filter(s => s.ctx.correlation?.inputRequestKey !== undefined)).toHaveLength(0);
        } finally {
            await closeAll();
        }
    }, 20_000);
});

describe('the era boundary stays clean', () => {
    it('does not lift anything under 2025-11-25, where these payloads are live requests instead', async () => {
        // Same server, same bytes on the wire. Under the older era the shape
        // simply does not exist, and scanning every result for it would be work
        // done on the hot path for something that cannot occur.
        const { recorder, call } = await rig({ era: '2025-11-25' });
        try {
            const answer = await call(7, { name: 'assist', arguments: {} });
            // Still forwarded verbatim — the transparency rule does not care
            // whether toolwall understands the payload.
            expect((answer['result'] as { requestState: string }).requestState).toBe(REQUEST_STATE);
            expect(recorder.seen.some(s => s.ctx.method === 'sampling/createMessage')).toBe(false);
        } finally {
            await closeAll();
        }
    }, 20_000);
});
