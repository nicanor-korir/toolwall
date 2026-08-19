/**
 * MRTR primitives — the `2026-07-28` era adapter, tested in isolation.
 *
 * The integration-level question ("does the guard actually see it?") is
 * `test/integration/mrtr.test.ts`. This file pins the parsing and correlation
 * rules that file depends on.
 */
import { describe, expect, it } from 'vitest';

import {
    ExchangeCorrelator,
    INPUT_REQUIRED,
    MRTR_EMBEDDED_METHODS,
    eraUsesMrtr,
    hashRequestState,
    isInputRequired,
    readInputRequests,
    readRequestState,
    readResultType
} from '../../../src/transport/mrtr.js';

const inputRequired = (requests: Record<string, unknown>, requestState?: string): Record<string, unknown> => ({
    resultType: INPUT_REQUIRED,
    inputRequests: requests,
    ...(requestState === undefined ? {} : { requestState })
});

describe('resultType', () => {
    it('treats an absent resultType as "complete", per the schema', () => {
        expect(readResultType({ content: [] })).toBe('complete');
        expect(readResultType(undefined)).toBe('complete');
        expect(isInputRequired({ content: [] })).toBe(false);
    });

    it('reports an unrecognised resultType verbatim rather than flattening it', () => {
        expect(readResultType({ resultType: 'something_future' })).toBe('something_future');
    });
});

describe('lifting inputRequests', () => {
    it('lifts each entry with its key, method, params and a pointer that resolves', () => {
        const result = inputRequired({
            k1: { method: 'sampling/createMessage', params: { systemPrompt: 'injected' } },
            k2: { method: 'elicitation/create', params: { message: 'your API key please' } }
        });
        const entries = readInputRequests(result);
        expect(entries.map(e => e.method)).toStrictEqual(['sampling/createMessage', 'elicitation/create']);
        expect(entries[0]?.locus).toBe('/inputRequests/k1/params');
        expect(entries[0]?.params).toStrictEqual({ systemPrompt: 'injected' });
    });

    it('escapes RFC 6901 characters in a server-assigned key', () => {
        const entries = readInputRequests(inputRequired({ 'a/b~c': { method: 'roots/list', params: {} } }));
        expect(entries[0]?.locus).toBe('/inputRequests/a~1b~0c/params');
    });

    it('lifts nothing from a complete result, so the common path does no work', () => {
        expect(readInputRequests({ content: [{ type: 'text', text: 'hi' }] })).toStrictEqual([]);
        // Even with the bag present: without `input_required` there is nothing to lift.
        expect(readInputRequests({ inputRequests: { k: { method: 'roots/list' } } })).toStrictEqual([]);
    });

    it('skips an entry it cannot name rather than guessing at one', () => {
        // Routing attacker data to a guard registered under the wrong name is
        // worse than not routing it: it would be inspected by the wrong rules.
        const entries = readInputRequests(
            inputRequired({ good: { method: 'roots/list', params: {} }, bad: { params: {} }, alsoBad: 'nope' })
        );
        expect(entries.map(e => e.key)).toStrictEqual(['good']);
    });

    it('names the three methods that exist only inside inputRequests', () => {
        expect([...MRTR_EMBEDDED_METHODS].sort()).toStrictEqual([
            'elicitation/create',
            'roots/list',
            'sampling/createMessage'
        ]);
    });
});

describe('requestState', () => {
    it('is read from params.requestState and from the reserved _meta key', () => {
        expect(readRequestState({ requestState: 'abc' })).toBe('abc');
        expect(readRequestState({ _meta: { 'io.modelcontextprotocol/requestState': 'xyz' } })).toBe('xyz');
        expect(readRequestState({ requestState: 42 })).toBeUndefined();
        expect(readRequestState('not an object')).toBeUndefined();
    });

    it('is hashed, never parsed — the same bytes always give the same link', () => {
        const state = '{"iat":1,"sub":"looks-like-json-but-we-do-not-look"}';
        expect(hashRequestState(state)).toBe(hashRequestState(state));
        expect(hashRequestState(state)).toHaveLength(64);
        expect(hashRequestState(state)).not.toContain('looks-like-json');
    });
});

describe('ExchangeCorrelator', () => {
    it('links a retry to the exchange that issued the requestState, across a changed JSON-RPC id', () => {
        const correlator = new ExchangeCorrelator();
        const exchangeId = correlator.mint();
        correlator.remember('opaque-state', exchangeId);

        // The retry is a DIFFERENT JSON-RPC message with a different id; the
        // echoed state is the only thing tying the two together.
        const linked = correlator.correlateRetry({ name: 'add', requestState: 'opaque-state' });
        expect(linked?.exchangeId).toBe(exchangeId);
        expect(linked?.requestStateHash).toBe(hashRequestState('opaque-state'));
    });

    it('says "no link" rather than guessing when the state was never issued here', () => {
        const correlator = new ExchangeCorrelator();
        correlator.remember('mine', correlator.mint());
        expect(correlator.correlateRetry({ requestState: 'someone-elses' })).toBeUndefined();
        expect(correlator.correlateRetry({})).toBeUndefined();
    });

    it('mints distinct ids', () => {
        const correlator = new ExchangeCorrelator();
        const ids = new Set(Array.from({ length: 1000 }, () => correlator.mint()));
        expect(ids.size).toBe(1000);
    });

    it('is bounded, so a server that never retries cannot grow the proxy without limit (T-08)', () => {
        const correlator = new ExchangeCorrelator(8);
        for (let i = 0; i < 100; i++) {
            correlator.remember(`state-${i}`, correlator.mint());
        }
        expect(correlator.size).toBe(8);
        // The oldest are gone; the newest still correlate.
        expect(correlator.correlateRetry({ requestState: 'state-0' })).toBeUndefined();
        expect(correlator.correlateRetry({ requestState: 'state-99' })).toBeDefined();
    });

    it('keeps a live exchange alive when it is re-remembered', () => {
        const correlator = new ExchangeCorrelator(4);
        const keep = correlator.mint();
        correlator.remember('keep', keep);
        for (let i = 0; i < 3; i++) correlator.remember(`filler-${i}`, correlator.mint());
        correlator.remember('keep', keep); // second round trip on the same exchange
        for (let i = 3; i < 6; i++) correlator.remember(`filler-${i}`, correlator.mint());
        expect(correlator.correlateRetry({ requestState: 'keep' })?.exchangeId).toBe(keep);
    });
});

describe('era gating', () => {
    it('applies only to 2026-07-28; under 2025-11-25 these payloads are live requests already', () => {
        expect(eraUsesMrtr('2026-07-28')).toBe(true);
        expect(eraUsesMrtr('2025-11-25')).toBe(false);
    });
});
