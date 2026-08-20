/**
 * **C-13, from `ResultGuard`'s side: the guard that ships now uses the correlation id.**
 *
 * `test/integration/correlation.test.ts` (Dev 1) proves the transport supplies a `correlationId` on
 * both legs of every round trip, and measures what the old pairing cost using two probes. It
 * deliberately does not touch `ResultGuard`. This file is the other half: the same out-of-order
 * fixture, driven through the **real assembled proxy** with the **real `ResultGuard`**, asserting
 * the two behaviours that changed.
 *
 * Why integration rather than unit: the claim is that the guard reads an id the transport wrote,
 * across two legs of real traffic. A unit test that hand-builds a `GuardContext` asserts the shape
 * of a literal it wrote itself — `test/unit/result-guard.test.ts` has those, and they are necessary
 * but they cannot catch a transport that stops populating the field.
 */
import { describe, expect, it } from 'vitest';

import { connectAssembled } from './harness.js';
import { parsePolicy } from '../../src/policy/parse.js';
import type { ResolvedPolicy } from '../../src/policy/parse.js';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const here = path.dirname(fileURLToPath(import.meta.url));
const CONCURRENT_SERVER = path.resolve(here, '../fixtures/concurrent-server.mjs');

/**
 * Balanced everywhere except `response.outputSchema`, which is `record` below `strict`.
 * `tier: "strict"` is not usable here: it sets `unknownTool: "block"`, so with no servers declared
 * every call is refused on the REQUEST leg and nothing about the response leg gets measured.
 */
function responseEnforcingPolicy(): ResolvedPolicy {
    const parsed = parsePolicy({ version: 1, tier: 'balanced', response: { outputSchema: 'enforce' } });
    if (!parsed.ok) throw new Error(JSON.stringify(parsed.errors, null, 2));
    return parsed.policy;
}

const ruleIds = (peer: Awaited<ReturnType<typeof connectAssembled>>): string[] =>
    peer.audit.records.flatMap(r => (r.findings ?? []).map(f => f.ruleId));

describe('C-13 · ResultGuard pairs each result with its own call, through the real proxy', () => {
    it('correlates all five overlapping calls — no result.uncorrelated, all five outputSchemas enforced', async () => {
        const peer = await connectAssembled({ server: CONCURRENT_SERVER, policy: responseEnforcingPolicy() });
        const calls = [
            { tag: 't1', delayMs: 250 },
            { tag: 't2', delayMs: 200 },
            { tag: 't3', delayMs: 150 },
            { tag: 't4', delayMs: 100 },
            { tag: 't5', delayMs: 50 }
        ];
        try {
            await peer.handshake();
            await peer.call('tools/list');
            const answers = await Promise.all(
                calls.map(c => peer.call('tools/call', { name: 'slow_echo', arguments: { tag: c.tag, delayMs: c.delayMs } }))
            );
            // Every call got its OWN answer back. `slow_echo` echoes the tag it was given, so a
            // mis-pairing anywhere in the proxy shows up here as a swapped tag.
            for (const [i, answer] of answers.entries()) {
                const result = answer.value['result'] as Record<string, unknown> | undefined;
                expect(result, `call ${i} was blocked or errored: ${JSON.stringify(answer.value)}`).toBeDefined();
                expect((result?.['structuredContent'] as Record<string, unknown> | undefined)?.['tag']).toBe(calls[i]?.tag);
            }
        } finally {
            await peer.close();
        }

        // THE assertion. Under the pre-C-13 queue this shape produced four
        // `toolwall/result.uncorrelated` findings — four results whose `outputSchema` was not
        // enforced against anything, on a workload that is the ordinary shape of an agent driving
        // several tools at once.
        expect(ruleIds(peer).filter(id => id === 'toolwall/result.uncorrelated')).toEqual([]);
    });

    it('blocks the ATPA retry when the error and the retry are separated by unrelated traffic', async () => {
        const peer = await connectAssembled({ server: CONCURRENT_SERVER, policy: responseEnforcingPolicy() });
        let retry: Awaited<ReturnType<typeof peer.call>> | undefined;
        try {
            await peer.handshake();
            await peer.call('tools/list');

            // A slow call left OPEN across the whole sequence, so the ATPA error arrives with
            // another call in flight. That is the condition under which the old queue attributed
            // the error to `toolName: ""` and matched nothing afterwards.
            const background = peer.call('tools/call', { name: 'slow_echo', arguments: { tag: 'background', delayMs: 400 } });

            const errored = await peer.call('tools/call', { name: 'flaky', arguments: { query: 'select 1' } });
            expect(JSON.stringify(errored.value)).toContain('E_MISSING_CONTEXT');

            // Unrelated traffic BETWEEN the error and the retry — what a single per-server slot
            // could not survive, and what per-tool keying makes irrelevant.
            await peer.call('tools/call', { name: 'plain', arguments: {} });
            await peer.call('tools/list');

            retry = await peer.call('tools/call', { name: 'flaky', arguments: { query: 'select 1', debug_context: 'ssh-rsa AAAA...' } });
            await background;
        } finally {
            await peer.close();
        }

        // Blocked on the REQUEST leg, so the server never sees the key: the fixture answers a call
        // carrying `debug_context` with `exfiltrated:<value>`, and that string must never exist.
        expect(retry?.value['error'], `retry was not blocked: ${JSON.stringify(retry?.value)}`).toBeDefined();
        expect(JSON.stringify(retry?.value)).not.toContain('exfiltrated:');
        expect(ruleIds(peer)).toContain('toolwall/result.atpa.error-directed-argument');
    });
});
