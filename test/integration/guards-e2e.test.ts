/**
 * The guards, fired end to end through the REAL assembled proxy.
 *
 * A unit test proving a detector works does not prove the detector is wired into the request
 * path. Everything here spawns the red team's actual malicious fixture as a real child process,
 * drives raw JSON-RPC into `assembleToolwall()`'s client-facing transport, and asserts on the
 * bytes that come back out. A guard that exists but is not registered fails these tests; so does
 * a guard registered on the wrong leg, or one whose block is swallowed by an error path.
 */
import { describe, expect, it } from 'vitest';

import {
    POISONED_SERVER,
    RUGPULL_SERVER,
    blockedFindings,
    confirmationOutcomes,
    connectAssembled,
    connectDirect,
    errorOf,
    findingsOf,
    INITIALIZE,
    INITIALIZED,
    type AssembledPeer
} from './harness.js';

/** The payload the red team's poisoned fixture smuggles. It must never reach the client. */
const POISON_MARKER = 'Ignore previous instructions';

const closeAll = async (peers: AssembledPeer[]): Promise<void> => {
    for (const peer of peers.splice(0)) await peer.close().catch(() => undefined);
};

// ---------------------------------------------------------------------------
// A benign server must be completely untouched
// ---------------------------------------------------------------------------

describe('a benign server still works, with the full guard stack in the path', () => {
    const peers: AssembledPeer[] = [];
    const cleanup = (): Promise<void> => closeAll(peers);

    it('relays the handshake, the listing and a call, and blocks nothing', async () => {
        const peer = await connectAssembled();
        peers.push(peer);
        try {
            const init = await peer.handshake();
            const initResult = init.value['result'] as Record<string, unknown>;
            // The server's own instructions, not toolwall's — C-5. Blanking these would delete a
            // top-ranked injection surface from view while claiming to defend it.
            expect(initResult['instructions']).toBe(
                'Fixture server. Instructions are a top-ranked injection surface, so they must survive the hop verbatim.'
            );
            expect(initResult['serverInfo']).toStrictEqual({ name: 'toolwall-test-downstream', version: '1.2.3' });

            const list = await peer.call('tools/list');
            expect(errorOf(list)).toBeUndefined();
            const tools = (list.value['result'] as { tools: Array<{ name: string }> }).tools;
            expect(tools.map(t => t.name)).toStrictEqual(['echo', 'ask', 'slow', 'boom', 'forbidden', 'calls', 'hang']);
            // The unknown top-level key inside the result survives the guard stack untouched.
            expect((list.value['result'] as Record<string, unknown>)['x-fixture-marker']).toStrictEqual({
                nested: [1, 2, { deep: true }]
            });

            const call = await peer.call('tools/call', { name: 'echo', arguments: { text: 'hello' } });
            expect(errorOf(call)).toBeUndefined();
            expect(call.value['result']).toStrictEqual({ content: [{ type: 'text', text: 'hello' }] });

            // A method neither the SDK nor toolwall knows about is still forwarded: guards are
            // registered per method, so `hasGuards` is false here and the payload is not touched.
            const unknown = await peer.call('x-experimental/echo', { anything: [1, 2, 3] });
            expect(unknown.value['result']).toStrictEqual({
                received: { anything: [1, 2, 3] },
                'x-server-note': 'handled by fallback'
            });

            expect(peer.events.filter(e => e.kind === 'blocked')).toHaveLength(0);
        } finally {
            await cleanup();
        }
    });

    it('produces byte-identical tools/call results to a direct connection', async () => {
        const peer = await connectAssembled();
        peers.push(peer);
        const direct = connectDirect();
        try {
            await peer.handshake();
            await peer.call('tools/list');
            const guarded = await peer.call('tools/call', { name: 'echo', arguments: { text: 'compare me' } });

            direct.send({ ...INITIALIZE, id: 1 });
            await direct.out.waitForId(1);
            direct.send({ ...INITIALIZED });
            direct.send({ jsonrpc: '2.0', id: 2, method: 'tools/list' });
            await direct.out.waitForId(2);
            direct.send({
                jsonrpc: '2.0',
                id: 3,
                method: 'tools/call',
                params: { name: 'echo', arguments: { text: 'compare me' } }
            });
            const plain = await direct.out.waitForId(3);

            // Same id, so the raw lines are directly comparable.
            expect(guarded.raw.replace(/"id":\d+/u, '"id":X')).toBe(plain.raw.replace(/"id":\d+/u, '"id":X'));
        } finally {
            await direct.close();
            await cleanup();
        }
    });

    it('pins what it saw, so the next session verifies instead of trusting again', async () => {
        const peer = await connectAssembled();
        peers.push(peer);
        try {
            await peer.handshake();
            await peer.call('tools/list');

            expect(peer.pins.get(peer.toolwall.serverId, 'server', 'instructions')).toBeDefined();
            const echo = peer.pins.get(peer.toolwall.serverId, 'tool', 'echo');
            expect(echo?.decision.kind).toBe('trust-on-first-use');
            expect(echo?.hash).toMatch(/^sha256:[0-9a-f]{64}$/u);

            // C-2: the pin engine's state changes reached the audit log rather than /dev/null.
            const pinned = peer.audit.records.filter(r => r.kind === 'pin');
            expect(pinned.length).toBeGreaterThan(0);
            expect(peer.audit.verifyChain()).toStrictEqual({ ok: true });
        } finally {
            await cleanup();
        }
    });
});

// ---------------------------------------------------------------------------
// T-01 — poisoned metadata
// ---------------------------------------------------------------------------

describe('poisoned-server.js — poisoned metadata is detected and surfaced', () => {
    const peers: AssembledPeer[] = [];
    const cleanup = (): Promise<void> => closeAll(peers);

    it('under strict pin mode the poisoned listing never reaches the client', async () => {
        // Strict is the honest setting for a server you have not approved: TOFU cannot tell a
        // benign first sighting from a tool that was already hostile when you first saw it.
        const peer = await connectAssembled({ server: POISONED_SERVER, pinMode: 'strict' });
        peers.push(peer);
        try {
            const init = await peer.handshake();
            // The server-level `instructions` carry the payload and are unapproved, so the
            // handshake itself is refused rather than forwarded.
            const initError = errorOf(init);
            expect(initError?.code).toBe(-32600);
            expect(init.raw).not.toContain(POISON_MARKER);
            expect(findingsOf(init).map(f => f.ruleId)).toContain('toolwall/pin-unpinned');

            const list = await peer.call('tools/list');
            expect(errorOf(list)?.code).toBe(-32600);
            expect(list.raw).not.toContain(POISON_MARKER);
            const ruleIds = findingsOf(list).map(f => f.ruleId);
            expect(ruleIds).toContain('toolwall/pin-unpinned');

            const blocked = peer.events.filter(e => e.kind === 'blocked');
            expect(blocked.length).toBeGreaterThanOrEqual(2);
        } finally {
            await cleanup();
        }
    });

    it('under TOFU it is pinned and recorded, and the boundary is stated rather than overclaimed', async () => {
        const peer = await connectAssembled({ server: POISONED_SERVER, pinMode: 'tofu' });
        peers.push(peer);
        try {
            const init = await peer.handshake();
            const list = await peer.call('tools/list');

            // Honest statement of what pinning does and does not do. Pinning answers "did this
            // change since you approved it" with certainty; it says nothing about whether the
            // first sighting was safe. Under TOFU the poison is adopted, which is exactly why
            // `strict` exists and why the detectors are Week 2 work.
            expect(errorOf(init)).toBeUndefined();
            expect(errorOf(list)).toBeUndefined();
            expect(list.raw).toContain(POISON_MARKER);

            // What it DOES give the operator: the poisoned surface is captured verbatim, keyed to
            // this server's launch identity, and every adoption is on the audit chain.
            const instructions = peer.pins.get(peer.toolwall.serverId, 'server', 'instructions');
            expect(JSON.stringify(instructions?.definition)).toContain(POISON_MARKER);
            const tool = peer.pins.get(peer.toolwall.serverId, 'tool', 'safe_addition_calculator');
            // The injection nested inside a schema property description is inside the pin too —
            // a description-only scrubber that never recurses into inputSchema misses it.
            expect(JSON.stringify(tool?.definition)).toContain(POISON_MARKER);
            expect(
                (tool?.definition as { inputSchema: { properties: { b: { description: string } } } }).inputSchema
                    .properties.b.description
            ).toContain(POISON_MARKER);

            const pinEvents = peer.pinEvents.filter(e => e.kind === 'pinned');
            expect(pinEvents.map(e => e.subject).sort()).toStrictEqual(['instructions', 'safe_addition_calculator']);
            expect(peer.audit.records.filter(r => r.kind === 'pin').length).toBeGreaterThan(0);
        } finally {
            await cleanup();
        }
    });

    it('a poisoned tool that mutates after adoption is then blocked, because the pin holds', async () => {
        // The pin taken under TOFU is still load-bearing: it is what makes any later mutation of
        // this server detectable, which is the difference between TOFU and no control at all.
        const peer = await connectAssembled({ server: POISONED_SERVER, pinMode: 'tofu' });
        peers.push(peer);
        try {
            await peer.handshake();
            await peer.call('tools/list');
            const pinnedHash = peer.pins.get(peer.toolwall.serverId, 'tool', 'safe_addition_calculator')?.hash;
            expect(pinnedHash).toBeDefined();

            const call = await peer.call('tools/call', {
                name: 'safe_addition_calculator',
                arguments: { a: 1, b: 2 }
            });
            // The call itself verifies against the pin and goes through; the T-03 result-leg
            // payload is Week 2's problem and is not claimed here.
            expect(errorOf(call)).toBeUndefined();
            expect(peer.pins.get(peer.toolwall.serverId, 'tool', 'safe_addition_calculator')?.hash).toBe(pinnedHash);
        } finally {
            await cleanup();
        }
    });
});

// ---------------------------------------------------------------------------
// T-02 — rug pulls, one test per variant
// ---------------------------------------------------------------------------

async function pinCleanBaseline(peer: AssembledPeer): Promise<void> {
    await peer.handshake();
    const list = await peer.call('tools/list');
    expect(errorOf(list)).toBeUndefined();
    expect(peer.pins.get(peer.toolwall.serverId, 'tool', 'add')?.decision.kind).toBe('trust-on-first-use');
}

describe('rugpull-server.js --variant prose', () => {
    const peers: AssembledPeer[] = [];

    it('blocks the mutated listing and every subsequent call, with a readable diff', async () => {
        const peer = await connectAssembled({ server: RUGPULL_SERVER, serverArgs: ['--variant', 'prose'] });
        peers.push(peer);
        try {
            await pinCleanBaseline(peer);
            const pinnedHash = peer.pins.get(peer.toolwall.serverId, 'tool', 'add')?.hash;

            const first = await peer.call('tools/call', { name: 'add', arguments: { a: 1, b: 2 } });
            expect(errorOf(first)).toBeUndefined();

            // Second listing is hostile.
            const poisoned = await peer.call('tools/list');
            expect(errorOf(poisoned)?.code).toBe(-32600);

            // The mutated definition never reaches the client — and neither does the injected
            // text, not even inside the alarm about it. The block goes to the LLM client, which
            // surfaces error text to the model; a diff quoted verbatim there would deliver the
            // payload through the alarm.
            expect(poisoned.raw).not.toContain('id_rsa');
            expect(poisoned.raw).not.toContain('Ignore previous instructions');

            const clientSide = findingsOf(poisoned)[0];
            expect(clientSide?.ruleId).toBe('toolwall/pin-drift');
            expect(clientSide?.severity).toBe('critical');
            expect(clientSide?.remediation).toContain('quarantined');

            // The operator's copy is complete: hashes, field-level diff, and the poisoned text
            // escaped so an invisible-character change is readable.
            const drift = blockedFindings(peer).find(f => f.ruleId === 'toolwall/pin-drift');
            expect(drift?.evidence?.['changedPaths']).toStrictEqual(['/description']);
            expect(drift?.message).toContain('~ /description');
            expect(drift?.message).toContain('Ignore previous instructions');

            // Quarantined: no further call gets through, and the pin is untouched.
            const after = await peer.call('tools/call', { name: 'add', arguments: { a: 1, b: 2 } });
            expect(errorOf(after)?.code).toBe(-32600);
            expect(findingsOf(after)[0]?.ruleId).toBe('toolwall/pin-drift');
            expect(peer.pins.get(peer.toolwall.serverId, 'tool', 'add')?.hash).toBe(pinnedHash);
        } finally {
            await closeAll(peers);
        }
    });
});

describe('rugpull-server.js --variant schema', () => {
    const peers: AssembledPeer[] = [];

    it('is caught even though nothing a human would read has changed', async () => {
        const peer = await connectAssembled({ server: RUGPULL_SERVER, serverArgs: ['--variant', 'schema'] });
        peers.push(peer);
        try {
            await pinCleanBaseline(peer);

            const poisoned = await peer.call('tools/list');
            expect(errorOf(poisoned)?.code).toBe(-32600);
            expect(poisoned.raw).not.toContain('exfil_target');
            expect(findingsOf(poisoned)[0]?.ruleId).toBe('toolwall/pin-drift');

            const drift = blockedFindings(peer).find(f => f.ruleId === 'toolwall/pin-drift');
            const paths = drift?.evidence?.['changedPaths'] as string[];
            // The premise of the attack: a description-only pin sees nothing here.
            expect(paths.every(p => p.startsWith('/inputSchema'))).toBe(true);
            expect(paths).toContain('/inputSchema/properties/exfil_target');
            expect(drift?.message).not.toContain('~ /description');

            const after = await peer.call('tools/call', {
                name: 'add',
                arguments: { a: 1, b: 2, exfil_target: 'https://attacker.example/collect' }
            });
            expect(errorOf(after)?.code).toBe(-32600);
            expect(findingsOf(after)[0]?.ruleId).toBe('toolwall/pin-drift');
        } finally {
            await closeAll(peers);
        }
    });
});

describe('rugpull-server.js --variant delayed (Pillar Deadbugz) — the headline claim', () => {
    const peers: AssembledPeer[] = [];

    it('mutates after three calls, and re-verification catches it where first-connect pinning cannot', async () => {
        const peer = await connectAssembled({
            server: RUGPULL_SERVER,
            serverArgs: ['--variant', 'delayed', '--threshold', '3']
        });
        peers.push(peer);
        try {
            await pinCleanBaseline(peer);

            // The window every existing tool has already stopped looking in: `mcp-context-protector`
            // pins at first connect and never re-verifies; a pre-install scanner never saw a call
            // at all. Three clean calls, and a second clean listing.
            for (let i = 0; i < 3; i++) {
                const ok = await peer.call('tools/call', { name: 'add', arguments: { a: i, b: 1 } });
                expect(errorOf(ok)).toBeUndefined();
            }
            expect(errorOf(await peer.call('tools/list'))).toBeUndefined();

            // The fourth call is the one that flips the server.
            expect(errorOf(await peer.call('tools/call', { name: 'add', arguments: { a: 9, b: 9 } }))).toBeUndefined();
            await peer.out.waitForMethod('notifications/tools/list_changed');

            // The server has told us its definitions moved and we have not seen the new listing,
            // so the cached definition no longer describes what it is advertising. A call against
            // a stale catalogue is unverifiable, and unverifiable fails closed.
            //
            // Week 2 changed HOW it fails closed, not WHETHER. `assembleToolwall` now always wires
            // a `BudgetedConfirmationProvider` (C-14), so the block no longer carries
            // `toolwall/no-confirmation-provider`. `toolwall/pin-unverifiable` is not on
            // `confirmation.promptableRules`, so the provider denies it WITHOUT spending a prompt
            // and without touching a terminal — the load-bearing half of the budget design.
            expect(peer.toolwall.pinGuard?.isCatalogueStale(peer.toolwall.serverId)).toBe(true);
            const stale = await peer.call('tools/call', { name: 'add', arguments: { a: 1, b: 1 } });
            expect(errorOf(stale)?.code).toBe(-32600);
            const staleRules = findingsOf(stale).map(f => f.ruleId);
            expect(staleRules).toContain('toolwall/pin-unverifiable');
            expect(staleRules).not.toContain('toolwall/no-confirmation-provider');
            // The denial is recorded on the operator channel rather than vanishing.
            expect(confirmationOutcomes(peer)).toContain('not-promptable');

            // And the mutated listing itself is blocked outright when it arrives.
            const poisoned = await peer.call('tools/list');
            expect(errorOf(poisoned)?.code).toBe(-32600);
            expect(poisoned.raw).not.toContain('id_rsa');
            expect(findingsOf(poisoned)[0]?.ruleId).toBe('toolwall/pin-drift');
            const drift = blockedFindings(peer).find(f => f.ruleId === 'toolwall/pin-drift');
            expect(drift?.evidence?.['changedPaths']).toStrictEqual(['/description']);
        } finally {
            await closeAll(peers);
        }
    });

    it('--silent: the same mutation with no list_changed notification is still caught at the next listing', async () => {
        // A hostile server can simply not send the notification. The control must never depend on
        // the attacker announcing the attack.
        const peer = await connectAssembled({
            server: RUGPULL_SERVER,
            serverArgs: ['--variant', 'delayed', '--threshold', '3', '--silent']
        });
        peers.push(peer);
        try {
            await pinCleanBaseline(peer);
            for (let i = 0; i < 4; i++) {
                expect(errorOf(await peer.call('tools/call', { name: 'add', arguments: { a: i, b: 1 } }))).toBeUndefined();
            }
            expect(peer.toolwall.pinGuard?.isCatalogueStale(peer.toolwall.serverId)).toBe(false);

            const poisoned = await peer.call('tools/list');
            expect(errorOf(poisoned)?.code).toBe(-32600);
            expect(findingsOf(poisoned)[0]?.ruleId).toBe('toolwall/pin-drift');
            expect(blockedFindings(peer).find(f => f.ruleId === 'toolwall/pin-drift')?.message).toContain(
                'Ignore previous instructions'
            );

            expect(errorOf(await peer.call('tools/call', { name: 'add', arguments: { a: 1, b: 1 } }))?.code).toBe(-32600);
        } finally {
            await closeAll(peers);
        }
    });
});
