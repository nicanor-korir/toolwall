import { describe, expect, it, vi } from 'vitest';

import { ANY_METHOD, DefaultGuardPipeline } from '../../../src/transport/pipeline.js';
import type { Finding, Guard, GuardContext, Verdict } from '../../../src/types/protocol.js';

const CTX: GuardContext = { era: '2025-11-25', serverId: 'stdio:test', direction: 'request', method: 'tools/call' };

function finding(overrides: Partial<Finding> = {}): Finding {
    return {
        ruleId: 'test/rule',
        severity: 'high',
        message: 'something',
        locus: '/name',
        remediation: 'do something',
        ...overrides
    };
}

function guard(name: string, verdict: Verdict | ((payload: unknown) => Verdict)): Guard {
    return { name, inspect: payload => (typeof verdict === 'function' ? verdict(payload) : verdict) };
}

describe('transparency fast path', () => {
    it('reports no guards for an unregistered pair', () => {
        const pipeline = new DefaultGuardPipeline();
        expect(pipeline.hasGuards('request', 'tools/call')).toBe(false);

        pipeline.register({ direction: 'request', method: 'tools/call', guard: guard('g', { action: 'allow' }) });
        expect(pipeline.hasGuards('request', 'tools/call')).toBe(true);
        expect(pipeline.hasGuards('response', 'tools/call')).toBe(false);
        expect(pipeline.hasGuards('request', 'tools/list')).toBe(false);
    });

    it('returns the identical payload reference when nothing matched', async () => {
        const pipeline = new DefaultGuardPipeline();
        const payload = { name: 'echo' };
        const outcome = await pipeline.run(payload, CTX);
        expect(outcome.payload).toBe(payload);
        expect(outcome.mutated).toBe(false);
        expect(outcome.verdict.action).toBe('allow');
    });

    it('returns the identical payload reference when every guard allows', async () => {
        const pipeline = new DefaultGuardPipeline();
        pipeline.register({ direction: 'request', method: 'tools/call', guard: guard('a', { action: 'allow' }) });
        pipeline.register({ direction: 'request', method: 'tools/call', guard: guard('b', { action: 'allow' }) });
        const payload = { name: 'echo' };
        const outcome = await pipeline.run(payload, CTX);
        expect(outcome.payload).toBe(payload);
        expect(outcome.mutated).toBe(false);
    });

    it('honours wildcard registration', () => {
        const pipeline = new DefaultGuardPipeline();
        pipeline.register({ direction: 'response', method: ANY_METHOD, guard: guard('w', { action: 'allow' }) });
        expect(pipeline.hasGuards('response', 'anything/at/all')).toBe(true);
        expect(pipeline.hasGuards('request', 'anything/at/all')).toBe(false);
    });
});

describe('verdict precedence: block > confirm > annotate > allow', () => {
    it('short-circuits on block and does not run later guards', async () => {
        const later = vi.fn(() => ({ action: 'allow' }) as Verdict);
        const pipeline = new DefaultGuardPipeline();
        pipeline.register({
            direction: 'request',
            method: 'tools/call',
            guard: guard('blocker', { action: 'block', code: -32600, findings: [finding()] })
        });
        pipeline.register({ direction: 'request', method: 'tools/call', guard: { name: 'later', inspect: later } });

        const outcome = await pipeline.run({}, CTX);
        expect(outcome.verdict.action).toBe('block');
        expect(later).not.toHaveBeenCalled();
    });

    it('a later allow cannot relax an earlier block', async () => {
        const pipeline = new DefaultGuardPipeline();
        pipeline.register({
            direction: 'request',
            method: 'tools/call',
            guard: guard('blocker', { action: 'block', code: -32600, findings: [finding()] })
        });
        pipeline.register({ direction: 'request', method: 'tools/call', guard: guard('permissive', { action: 'allow' }) });
        expect((await pipeline.run({}, CTX)).verdict.action).toBe('block');
    });

    it('confirm outranks annotate', async () => {
        const pipeline = new DefaultGuardPipeline({ confirmationProvider: { confirm: async () => false } });
        pipeline.register({
            direction: 'request',
            method: 'tools/call',
            guard: guard('annotator', { action: 'annotate', payload: { changed: true }, findings: [finding()] })
        });
        pipeline.register({ direction: 'request', method: 'tools/call', guard: guard('confirmer', { action: 'confirm', findings: [finding()] }) });
        expect((await pipeline.run({}, CTX)).verdict.action).toBe('block');
    });

    it('threads an annotated payload into the next guard', async () => {
        const seen: unknown[] = [];
        const pipeline = new DefaultGuardPipeline();
        pipeline.register({
            direction: 'request',
            method: 'tools/call',
            guard: guard('first', { action: 'annotate', payload: { step: 1 }, findings: [] })
        });
        pipeline.register({
            direction: 'request',
            method: 'tools/call',
            guard: guard('second', payload => {
                seen.push(payload);
                return { action: 'allow' };
            })
        });

        const outcome = await pipeline.run({ step: 0 }, CTX);
        expect(seen).toStrictEqual([{ step: 1 }]);
        expect(outcome.mutated).toBe(true);
        expect(outcome.payload).toStrictEqual({ step: 1 });
        expect(outcome.verdict.action).toBe('annotate');
    });
});

describe('fail closed', () => {
    it('turns a guard that throws into a block', async () => {
        const onGuardError = vi.fn();
        const pipeline = new DefaultGuardPipeline({ onGuardError });
        pipeline.register({
            direction: 'request',
            method: 'tools/call',
            guard: {
                name: 'crasher',
                inspect() {
                    throw new Error('regex exploded');
                }
            }
        });

        const outcome = await pipeline.run({}, CTX);
        expect(outcome.verdict.action).toBe('block');
        expect(outcome.findings.map(f => f.ruleId)).toContain('toolwall/guard-crashed');
        expect(outcome.findings[0]?.severity).toBe('critical');
        expect(onGuardError).toHaveBeenCalledOnce();
    });

    it('blocks a confirm verdict when no confirmation provider is wired', async () => {
        const pipeline = new DefaultGuardPipeline();
        pipeline.register({ direction: 'request', method: 'tools/call', guard: guard('c', { action: 'confirm', findings: [finding()] }) });
        const outcome = await pipeline.run({}, CTX);
        expect(outcome.verdict.action).toBe('block');
        expect(outcome.findings.map(f => f.ruleId)).toContain('toolwall/no-confirmation-provider');
    });

    it('blocks when the human declines, and forwards when they approve', async () => {
        const declining = new DefaultGuardPipeline({ confirmationProvider: { confirm: async () => false } });
        const approving = new DefaultGuardPipeline({ confirmationProvider: { confirm: async () => true } });
        for (const pipeline of [declining, approving]) {
            pipeline.register({ direction: 'request', method: 'tools/call', guard: guard('c', { action: 'confirm', findings: [finding()] }) });
        }
        expect((await declining.run({}, CTX)).verdict.action).toBe('block');
        expect((await approving.run({}, CTX)).verdict.action).toBe('allow');
    });

    it('blocks when the confirmation provider itself throws', async () => {
        const pipeline = new DefaultGuardPipeline({
            confirmationProvider: {
                confirm: async () => {
                    throw new Error('tty gone');
                }
            }
        });
        pipeline.register({ direction: 'request', method: 'tools/call', guard: guard('c', { action: 'confirm', findings: [finding()] }) });
        expect((await pipeline.run({}, CTX)).verdict.action).toBe('block');
    });
});

describe('error codes', () => {
    it('rewrites a block code that lands in the MCP-reserved range', async () => {
        // -32020..-32099 are reserved for the spec; implementations MUST NOT
        // invent codes there (RESEARCH-BRIEF §1.9).
        const pipeline = new DefaultGuardPipeline();
        pipeline.register({
            direction: 'request',
            method: 'tools/call',
            guard: guard('g', { action: 'block', code: -32050, findings: [finding()] })
        });
        const outcome = await pipeline.run({}, CTX);
        expect(outcome.verdict).toMatchObject({ action: 'block', code: -32600 });
    });

    it('passes a legitimate code straight through', async () => {
        const pipeline = new DefaultGuardPipeline();
        pipeline.register({
            direction: 'request',
            method: 'tools/call',
            guard: guard('g', { action: 'block', code: -32603, findings: [finding()] })
        });
        expect((await pipeline.run({}, CTX)).verdict).toMatchObject({ code: -32603 });
    });

    it('rewrites a non-integer code', async () => {
        const pipeline = new DefaultGuardPipeline();
        pipeline.register({
            direction: 'request',
            method: 'tools/call',
            guard: guard('g', { action: 'block', code: Number.NaN, findings: [finding()] })
        });
        expect((await pipeline.run({}, CTX)).verdict).toMatchObject({ code: -32600 });
    });
});

describe('findings accumulate across guards', () => {
    it('collects findings from every guard that ran', async () => {
        const pipeline = new DefaultGuardPipeline();
        pipeline.register({
            direction: 'request',
            method: 'tools/call',
            guard: guard('a', { action: 'annotate', payload: {}, findings: [finding({ ruleId: 'a' })] })
        });
        pipeline.register({
            direction: 'request',
            method: 'tools/call',
            guard: guard('b', { action: 'block', code: -32600, findings: [finding({ ruleId: 'b' })] })
        });
        const outcome = await pipeline.run({}, CTX);
        expect(outcome.findings.map(f => f.ruleId)).toStrictEqual(['a', 'b']);
    });

    it('runs exact-method guards before wildcard guards', async () => {
        const order: string[] = [];
        const pipeline = new DefaultGuardPipeline();
        pipeline.register({
            direction: 'request',
            method: ANY_METHOD,
            guard: guard('wildcard', () => {
                order.push('wildcard');
                return { action: 'allow' };
            })
        });
        pipeline.register({
            direction: 'request',
            method: 'tools/call',
            guard: guard('exact', () => {
                order.push('exact');
                return { action: 'allow' };
            })
        });
        await pipeline.run({}, CTX);
        expect(order).toStrictEqual(['exact', 'wildcard']);
    });
});
