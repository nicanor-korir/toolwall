/**
 * The reconnect gate and its policy, in isolation.
 *
 * The end-to-end behaviour — real child process, real crash, real re-verification
 * against the pin store — is `test/integration/reconnect.test.ts`. This file
 * pins the buffer's own invariants: ordering, bounds, cancellation, and the
 * replay classification that decides whether an in-flight request may be
 * resent.
 */
import { describe, expect, it } from 'vitest';

import {
    DEFAULT_RECONNECT_POLICY,
    REPLAYABLE_READ_ONLY_METHODS,
    ReconnectGate,
    UpstreamUnavailableError,
    backoffForAttempt,
    isConnectionLoss,
    isReplayableMethod,
    resolveReconnectPolicy,
    totalBackoffMs
} from '../../../src/transport/reconnect.js';
import { TOOLWALL_INTERNAL_ERROR } from '../../../src/types/protocol.js';

const policy = (over: Partial<typeof DEFAULT_RECONNECT_POLICY> = {}): typeof DEFAULT_RECONNECT_POLICY =>
    resolveReconnectPolicy({ enabled: true, ...over }, true);

describe('the policy the brief asks for', () => {
    it('is 3 attempts spread over roughly two seconds', () => {
        const resolved = policy();
        expect(resolved.maxAttempts).toBe(3);
        expect(totalBackoffMs(resolved)).toBeGreaterThanOrEqual(1500);
        expect(totalBackoffMs(resolved)).toBeLessThanOrEqual(2500);
    });

    it('refuses to be enabled without something to reconnect to', () => {
        expect(resolveReconnectPolicy({ enabled: true }, false).enabled).toBe(false);
        expect(resolveReconnectPolicy({ enabled: true }, true).enabled).toBe(true);
    });

    it('repeats the last backoff entry when more attempts than entries are configured', () => {
        const resolved = policy({ maxAttempts: 5, backoffMs: [10, 20] });
        expect([0, 1, 2, 3, 4].map(i => backoffForAttempt(resolved, i))).toStrictEqual([10, 20, 20, 20, 20]);
    });

    it('re-verifies on reconnect by default', () => {
        expect(DEFAULT_RECONNECT_POLICY.reverifyOnReconnect).toBe(true);
    });
});

describe('which in-flight requests may be resent', () => {
    it('never resends tools/call by default: its execution status is unknown', () => {
        expect(isReplayableMethod('tools/call', 'read-only-methods')).toBe(false);
        expect(REPLAYABLE_READ_ONLY_METHODS).not.toContain('tools/call');
    });

    it('resends listing and read methods, whose re-execution is observationally free', () => {
        for (const method of ['tools/list', 'resources/read', 'prompts/get', 'initialize', 'server/discover']) {
            expect(isReplayableMethod(method, 'read-only-methods')).toBe(true);
        }
    });

    it('does not resend a method it has never heard of', () => {
        // Forward-compatibility cuts the other way here: an unknown future
        // method might do anything, so "unknown" means "do not repeat it".
        expect(isReplayableMethod('x-experimental/launch-missiles', 'read-only-methods')).toBe(false);
    });

    it('honours the explicit opt-in and opt-out', () => {
        expect(isReplayableMethod('tools/call', 'all')).toBe(true);
        expect(isReplayableMethod('tools/list', 'none')).toBe(false);
    });
});

describe('recognising a lost connection', () => {
    it('separates "the connection went away" from "the server answered with an error"', () => {
        expect(isConnectionLoss(new Error('Not connected'))).toBe(true);
        expect(isConnectionLoss(new Error('boom happened'))).toBe(false);
        expect(isConnectionLoss('a string')).toBe(false);
    });
});

describe('ReconnectGate', () => {
    it('costs nothing while the link is healthy', async () => {
        const gate = new ReconnectGate(policy());
        await expect(gate.acquire('tools/call')).resolves.toBeUndefined();
        expect(gate.buffered).toBe(0);
        expect(gate.state).toBe('connected');
    });

    it('parks callers during an outage and releases them in arrival order', async () => {
        const gate = new ReconnectGate(policy());
        gate.beginOutage();

        const released: string[] = [];
        const waits = ['a', 'b', 'c'].map(name => gate.acquire(name).then(() => released.push(name)));
        await Promise.resolve();
        expect(gate.buffered).toBe(3);

        gate.resume();
        await Promise.all(waits);
        // A client that issued a then b still gets a dispatched first.
        expect(released).toStrictEqual(['a', 'b', 'c']);
        expect(gate.buffered).toBe(0);
    });

    it('answers -32603 to everything parked when the retry budget is spent', async () => {
        const gate = new ReconnectGate(policy());
        gate.beginOutage();
        const parked = gate.acquire('tools/call');
        await Promise.resolve();

        gate.fail(new UpstreamUnavailableError('retries-exhausted', 'gone', 3));
        await expect(parked).rejects.toThrow(UpstreamUnavailableError);
        await parked.catch((error: UpstreamUnavailableError) => {
            expect(error.code).toBe(TOOLWALL_INTERNAL_ERROR);
            expect(error.reason).toBe('retries-exhausted');
            expect(error.attempts).toBe(3);
        });
    });

    it('refuses new callers once dead rather than parking them forever', async () => {
        const gate = new ReconnectGate(policy());
        gate.beginOutage();
        gate.fail(new UpstreamUnavailableError('retries-exhausted', 'gone'));
        await expect(gate.acquire('tools/list')).rejects.toThrow(UpstreamUnavailableError);
    });

    it('is bounded: an enthusiastic client plus a dead server is not a memory sink (T-08)', async () => {
        const gate = new ReconnectGate(policy({ maxBufferedRequests: 2 }));
        gate.beginOutage();
        const a = gate.acquire('a');
        const b = gate.acquire('b');
        await Promise.resolve();
        expect(gate.buffered).toBe(2);

        await expect(gate.acquire('c')).rejects.toMatchObject({ reason: 'buffer-full' });

        gate.resume();
        await Promise.all([a, b]);
    });

    it('drops a caller that gave up, so a cancelled request is not dispatched to the new server', async () => {
        const gate = new ReconnectGate(policy());
        gate.beginOutage();
        const controller = new AbortController();
        const parked = gate.acquire('tools/call', controller.signal);
        await Promise.resolve();
        expect(gate.buffered).toBe(1);

        controller.abort();
        await expect(parked).rejects.toThrow(UpstreamUnavailableError);
        expect(gate.buffered).toBe(0);

        // And resuming does not resurrect it.
        gate.resume();
        expect(gate.buffered).toBe(0);
    });

    it('rejects immediately for a signal that was already aborted', async () => {
        const gate = new ReconnectGate(policy());
        gate.beginOutage();
        await expect(gate.acquire('m', AbortSignal.abort())).rejects.toThrow(UpstreamUnavailableError);
    });

    it('reports how long the outage has been running', async () => {
        const gate = new ReconnectGate(policy());
        expect(gate.downtimeMs).toBe(0);
        gate.beginOutage();
        await new Promise(resolve => setTimeout(resolve, 20));
        expect(gate.downtimeMs).toBeGreaterThanOrEqual(10);
        gate.resume();
        expect(gate.downtimeMs).toBe(0);
    });
});
