/**
 * The seam that decides whether pinning works at all.
 *
 * `MetadataPinGuard` looks a pin up by `GuardContext.serverId`, which the **transport** derives
 * from the spawn spec. `PinStore` stores pins under the id the **pin store's** caller derived.
 * Week 1 shipped two independent implementations of `deriveServerId` that produced different
 * strings for the same spec. Nothing failed, because nothing had wired them together yet.
 *
 * Had that reached the assembled pipeline, the failure would have been invisible in exactly the
 * wrong way: `store.get(ctx.serverId, ...)` returns `undefined`, `pinIfAbsent` adopts the live
 * definition under trust-on-first-use, and every call is "verified" against a pin created one
 * millisecond earlier from whatever the server just said. The rug-pull control would report
 * success while defending nothing.
 *
 * These tests exist so that can never regress silently.
 */
import { resolve } from 'node:path';

import { describe, expect, it } from 'vitest';

import { deriveServerId as deriveFromIdentity } from '../../src/audit/identity.js';
import { deriveServerId as deriveFromManifest } from '../../src/audit/manifest.js';
import {
    createUpstreamStdioTransport,
    deriveServerId as deriveFromSpawn,
    serverIdentityForSpawn,
    type SpawnSpec
} from '../../src/transport/spawn.js';

const SPECS: ReadonlyArray<{ readonly label: string; readonly spec: SpawnSpec }> = [
    { label: 'command only', spec: { command: 'node' } },
    { label: 'command + args', spec: { command: 'node', args: ['server.js'] } },
    { label: 'explicit cwd', spec: { command: 'node', args: ['server.js'], cwd: '/tmp' } },
    { label: 'relative cwd', spec: { command: 'node', args: ['server.js'], cwd: './fixtures' } },
    { label: 'explicit env', spec: { command: 'node', args: ['s.js'], env: { API_BASE: 'https://a.example' } } },
    { label: 'passthrough env', spec: { command: 'node', args: ['s.js'], passthroughEnv: ['GITHUB_TOKEN'] } },
    {
        label: 'env + passthrough + cwd',
        spec: {
            command: 'python3',
            args: ['-m', 'server'],
            cwd: '/srv/app',
            env: { API_BASE: 'https://a.example' },
            passthroughEnv: ['GITHUB_TOKEN', 'OPENAI_API_KEY']
        }
    }
];

describe('one deriveServerId, or every pin in the field orphans', () => {
    it.each(SPECS)('transport-derived === manifest-derived for $label', ({ spec }) => {
        const fromTransport = deriveFromSpawn(spec);
        const fromManifest = deriveFromManifest(serverIdentityForSpawn(spec));
        expect(fromTransport).toBe(fromManifest);
        expect(fromTransport).toMatch(/^srv_[0-9a-f]{32}$/u);
    });

    it('the manifest re-export and the identity module are literally the same function', () => {
        expect(deriveFromManifest).toBe(deriveFromIdentity);
    });

    it('the id the transport hands the proxy is the id the pin store would compute', () => {
        // This is the actual production path: `createUpstreamStdioTransport` produces the
        // `serverId` that `ToolwallProxy` puts in every `GuardContext`.
        const spec: SpawnSpec = { command: process.execPath, args: ['server.js'], cwd: resolve('.') };
        const built = createUpstreamStdioTransport(spec);
        expect(built.serverId).toBe(deriveFromManifest(serverIdentityForSpawn(spec)));
    });
});

describe('structure is identity, secrets are not', () => {
    const base: SpawnSpec = { command: 'node', args: ['s.js'], env: { TOKEN: 'v1' } };

    it('a rotated credential does not change the id', () => {
        // If it did, every pin for this server would disappear on the next key rotation and the
        // next tools/list would be trusted on first use again — a rug-pull window opened by
        // routine ops.
        expect(deriveFromSpawn({ ...base, env: { TOKEN: 'v2-rotated' } })).toBe(deriveFromSpawn(base));
    });

    it('a renamed variable DOES change the id', () => {
        expect(deriveFromSpawn({ ...base, env: { OTHER_TOKEN: 'v1' } })).not.toBe(deriveFromSpawn(base));
    });

    it('a variable passed through by name contributes, without toolwall ever holding its value', () => {
        const withPassthrough: SpawnSpec = { command: 'node', args: ['s.js'], passthroughEnv: ['TOKEN'] };
        // Same *name* as `base.env`, supplied by a different mechanism: same identity.
        expect(deriveFromSpawn(withPassthrough)).toBe(deriveFromSpawn(base));
    });

    it('an absent cwd is absent, not process.cwd()', () => {
        // Folding it in would make the identity depend on the directory the client happened to
        // be launched from, so starting Claude Desktop from elsewhere would orphan every pin.
        const noCwd = deriveFromSpawn({ command: 'node', args: ['s.js'] });
        const explicit = deriveFromSpawn({ command: 'node', args: ['s.js'], cwd: process.cwd() });
        expect(noCwd).not.toBe(explicit);
        expect(noCwd).toBe(deriveFromSpawn({ command: 'node', args: ['s.js'] }));
    });

    it('never reads serverInfo: the function takes exactly one argument, the launch spec', () => {
        expect(deriveFromSpawn.length).toBe(1);
        expect(deriveFromManifest.length).toBe(1);
    });
});
