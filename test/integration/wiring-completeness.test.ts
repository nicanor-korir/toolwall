/**
 * **The anti-recurrence test. Contract C-22.**
 *
 * Three weeks running, a module has shipped complete, unit-tested, exported from its barrel — and
 * dead. Week 2 it was the entire response leg (`ResultGuard`, `UnicodeHygieneGuard`,
 * `AtrAdvisoryGuard`): implemented, green, and never registered. Week 3 it was
 * `src/policy/infer.ts` and `src/audit/provenance.ts`: 2,448 lines, not imported by `src/index.ts`
 * at all. In every case nothing failed, because **a module nobody imports raises no error and a
 * guard nobody registers reports nothing.**
 *
 * C-17 fixed the instance: `assembleToolwall()` throws if `ResultGuard`'s registration count is
 * not the six C-12 requires. That is a good check and it generalises to nothing — it knows about
 * one guard. This file is the general form, and it is a test rather than a convention because a
 * convention has now failed three times.
 *
 * ## The rule
 *
 * Every module under `src/guards/`, `src/policy/` and `src/audit/` must be classified below, and
 * the classification must be TRUE of the code:
 *
 * | status | what it claims | what is verified |
 * |---|---|---|
 * | `assembled` | it runs in the shipped path | import-reachable from `src/index.ts`, a symbol of it appears inside `assembleToolwall()`, and it is on the public export surface |
 * | `opt-in` | it runs only when an operator asks | all of the above, PLUS the option that enables it exists in `src/index.ts` |
 * | `support` | it is a library the above depend on | import-reachable from `src/index.ts` |
 * | `barrel` | it only re-exports | contains no runtime logic |
 * | `exported-only` | **it has no consumer in the shipped path** | on the public export surface, and the reason it has no consumer is written down |
 *
 * `exported-only` exists so that "built but nothing calls it" has to be an explicit, argued claim
 * rather than something a reader has to discover with `grep`. `src/transport/headers.ts` is the
 * one module in that state today: it validates the MCP 2026-07-28 header/body agreement rules, and
 * there is no HTTP listener yet for it to validate anything on.
 *
 * A new file under those directories fails this suite until somebody classifies it. A module that
 * is neither wired nor declared opt-in fails it. A module that claims `assembled` but is not
 * referenced from the assembly function fails it. **`infer.ts` and `provenance.ts` would have
 * failed the reachability check on the day they landed**, which is the whole point.
 *
 * What this does NOT claim: that a reachable module is *correct*, or that a registered guard is
 * registered on the right leg. `test/integration/response-guards-e2e.test.ts` and
 * `test/integration/inference-provenance-e2e.test.ts` are what prove behaviour. This file proves
 * only that there is nothing on disk that the product silently forgot.
 */
import { describe, expect, it } from 'vitest';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const here = path.dirname(fileURLToPath(import.meta.url));
const SRC = path.resolve(here, '../../src');
const ENTRY = path.join(SRC, 'index.ts');

/** Directories whose contents are capability modules and therefore have to be accounted for. */
const CAPABILITY_DIRS = ['guards', 'policy', 'audit', 'transport'];

type Status = 'assembled' | 'opt-in' | 'support' | 'barrel' | 'exported-only';

interface Classification {
    readonly status: Status;
    /** Why this classification is the honest one. Read by a human, not by the test. */
    readonly reason: string;
    /**
     * `opt-in` only: the `ToolwallOptions` field an operator sets to turn this on. Asserted to
     * exist in `src/index.ts`, so "opt-in" cannot quietly mean "unreachable".
     */
    readonly enabledBy?: string;
}

/**
 * The manifest. Adding a module means adding a line here and making the line true.
 *
 * Ordered by directory, not by importance.
 */
const MANIFEST: Record<string, Classification> = {
    // --- audit ------------------------------------------------------------
    'audit/log.ts': {
        status: 'assembled',
        reason: 'the C-2 sink. `assembleToolwall` constructs it and every guard writes findings through `audit.sink()`.'
    },
    'audit/manifest.ts': {
        status: 'assembled',
        reason: 'the pin store. C-1 makes it load-bearing: it is what `PinnedToolDefinitionSource` reads.'
    },
    'audit/identity.ts': {
        status: 'support',
        reason: 'the ONE server-identity derivation. `spawn.ts` and `manifest.ts` both adapt to it — that single source is itself the fix for a Week-1 defect where two derivations disagreed.'
    },
    'audit/provenance.ts': {
        status: 'opt-in',
        reason: 'T-09. It is the only code in the product that can make a network request, so it is off unless an operator names the flag, and offline unless they name --verify-provenance specifically.',
        enabledBy: 'options.provenance'
    },

    // --- policy -----------------------------------------------------------
    'policy/parse.ts': {
        status: 'assembled',
        reason: '`defaultPolicy()` is the policy `assembleToolwall` falls back to when no file is given.'
    },
    'policy/infer.ts': {
        status: 'assembled',
        reason: 'the inferred capability policy, default-ON. It wraps the base policy in `assembleToolwall` and is what makes the capability layer enforce anything at day zero (0/17 -> 15/17 with no policy file).'
    },
    'policy/contract.ts': {
        status: 'support',
        reason: 'the Guard / Finding / ToolDefinitionSource interfaces every module is written against. Types plus the shared block code.'
    },
    'policy/schema.ts': {
        status: 'support',
        reason: 'the policy document shape and the tier presets, consumed by parse.ts.'
    },
    'policy/roles.ts': {
        status: 'support',
        reason: 'binds capability roles to schema LOCATIONS. Used by capability-guard.ts and by infer.ts; it is the reason neither of them inspects argument values.'
    },
    'policy/containment.ts': {
        status: 'support',
        reason: 'canonical, symlink-resolved path containment. Used by capability-guard.ts and by infer.ts to canonicalize inferred roots.'
    },
    'policy/egress.ts': {
        status: 'support',
        reason: 'egress evaluation, called from capability-guard.ts on every url/host role target.'
    },
    'policy/hosts.ts': {
        status: 'support',
        reason: 'host allowlist matching, used by egress.ts and by infer.ts (ANY_HOST).'
    },
    'policy/annotations.ts': {
        status: 'support',
        reason: 'reads ToolAnnotations as a signal, never as authorization. Called from capability-guard.ts.'
    },
    'policy/credentials.ts': {
        status: 'support',
        reason: 'credential-shaped elicitation detection, called from result-guard.ts.'
    },
    'policy/index.ts': {
        status: 'barrel',
        reason: 're-export only. The package entry point reaches these symbols directly from their own modules, so this barrel is a convenience for callers inside src/ and carries no logic of its own.'
    },

    // --- guards/metadata --------------------------------------------------
    'guards/metadata/drift.ts': {
        status: 'assembled',
        reason: '`MetadataPinGuard` — registered on the four pinned response methods AND on every tools/call request.'
    },
    'guards/metadata/unicode.ts': {
        status: 'assembled',
        reason: '`UnicodeHygieneGuard` — registered on the ten response methods that carry server-authored text.'
    },
    'guards/metadata/canonicalize.ts': {
        status: 'support',
        reason: 'the hash the pin store keys on. Called from drift.ts.'
    },
    'guards/metadata/diff.ts': {
        status: 'support',
        reason: 'renders what changed between a pin and a live definition. Called from drift.ts.'
    },
    'guards/metadata/surface.ts': {
        status: 'support',
        reason: 'extracts the pinnable surface out of a listing payload. Called from drift.ts and unicode.ts.'
    },
    'guards/metadata/rules.ts': {
        status: 'opt-in',
        reason: 'the advisory agent-threat-rules detector. Measured 0/8 catch on the enforce lane and 5/8 at 6.5% FP on alert, so it is never constructed by assembleToolwall — the caller hands in a pre-built scanner or it does not exist.',
        enabledBy: 'options.atr'
    },
    'guards/metadata/index.ts': {
        status: 'barrel',
        reason: 're-export only. The metadata guards are reached from src/index.ts through their own modules; this barrel exists for callers inside src/ and carries no logic of its own.'
    },

    // --- guards/runtime ---------------------------------------------------
    'guards/runtime/schema-guard.ts': {
        status: 'assembled',
        reason: '`SchemaGuard` — registered on tools/call request, validating against the PINNED definition (C-1).'
    },
    'guards/runtime/capability-guard.ts': {
        status: 'assembled',
        reason: '`CapabilityGuard` — registered on tools/call request. Filesystem containment and egress, and the home of the fused measure/proto walk.'
    },
    'guards/runtime/result-guard.ts': {
        status: 'assembled',
        reason: '`ResultGuard` — six registrations, and the count is asserted at assembly time (C-12).'
    },
    'guards/runtime/confirm.ts': {
        status: 'assembled',
        reason: 'the ONE BudgetedConfirmationProvider per session (C-14). A per-call provider would have an infinite budget.'
    },
    'guards/runtime/json-schema.ts': {
        status: 'support',
        reason: 'the JSON Schema validator, used by schema-guard.ts and result-guard.ts.'
    },
    // --- transport --------------------------------------------------------
    'transport/proxy.ts': {
        status: 'assembled',
        reason: '`ToolwallProxy` — the thing in the middle. Every guard verdict is applied here and every finding a client sees is redacted here.'
    },
    'transport/pipeline.ts': {
        status: 'assembled',
        reason: '`DefaultGuardPipeline` — the (direction, method) registration table. Its hasGuards() fast path is the transparency guarantee for every method nothing is registered on.'
    },
    'transport/spawn.ts': {
        status: 'assembled',
        reason: 'T-07 spawn hardening plus the upstream transport. Validation runs before anything is executed, and again for every process a reconnect spawns.'
    },
    'transport/reconnect.ts': {
        status: 'support',
        reason: 'the reconnect gate and replay policy. Enabled by default, but owned by proxy.ts rather than by the assembly function — assembleToolwall only hands it `{ enabled: true, ...options.reconnect }`. A reconnected server is always re-verified against the pin store before a buffered request is released.'
    },
    'transport/mrtr.ts': {
        status: 'support',
        reason: 'reads MRTR inputRequests and result types out of a payload. Called from proxy.ts (#liftInputRequests) and result-guard.ts.'
    },
    'transport/headers.ts': {
        status: 'exported-only',
        reason: 'HTTP header/body agreement for the 2026-07-28 revision. toolwall ships a stdio transport only, so there is no HTTP listener for this to validate on and it has NO live consumer. It is exported, unit-tested and honest about being unused; the README says so under "What toolwall does NOT do".'
    },

    'guards/runtime/index.ts': {
        status: 'barrel',
        reason: 're-export only, and it IS on the public export surface: src/index.ts re-exports SchemaGuard, CapabilityGuard and measure through it.'
    }
};

// ---------------------------------------------------------------------------
// Facts about the code, computed rather than asserted
// ---------------------------------------------------------------------------

function walk(dir: string, out: string[] = []): string[] {
    for (const entry of readdirSync(dir)) {
        const p = path.join(dir, entry);
        if (statSync(p).isDirectory()) walk(p, out);
        else if (p.endsWith('.ts')) out.push(p);
    }
    return out;
}

/** Every capability module on disk, as a `guards/runtime/x.ts`-style key. */
const modulesOnDisk = CAPABILITY_DIRS.flatMap(d => walk(path.join(SRC, d)))
    .map(f => path.relative(SRC, f).split(path.sep).join('/'))
    .sort();

/** Resolve a relative ESM specifier (`./x.js`) against an importing file, to a `.ts` path. */
function resolveSpecifier(fromFile: string, specifier: string): string {
    const rel = specifier.replace(/\.js$/u, '.ts');
    const abs = path.resolve(path.dirname(fromFile), rel);
    return abs.endsWith('.ts') ? abs : `${abs}.ts`;
}

/**
 * Everything transitively imported by `src/index.ts`.
 *
 * This is the check that would have caught both Week-3 modules on the day they landed: neither
 * appeared anywhere in this set, so no test, no type error and no lint rule had anything to say.
 */
function reachableFromEntry(): Set<string> {
    const seen = new Set<string>();
    const stack = [ENTRY];
    while (stack.length > 0) {
        const file = stack.pop() as string;
        if (seen.has(file)) continue;
        seen.add(file);
        let source: string;
        try {
            source = readFileSync(file, 'utf8');
        } catch {
            continue; // a specifier that does not resolve to a file is not a module we own
        }
        for (const m of source.matchAll(/(?:from|import)\s+['"](\.[^'"]+)['"]/gu)) {
            stack.push(resolveSpecifier(file, m[1] as string));
        }
    }
    return seen;
}

const reachable = reachableFromEntry();
const entrySource = readFileSync(ENTRY, 'utf8');

/**
 * The body of `assembleToolwall()`, as text.
 *
 * Text rather than a parsed AST on purpose: the question is "does the assembly function mention
 * this module's surface at all", and a substring search cannot be fooled into a false PASS by a
 * module that is genuinely absent. A false pass is the only failure mode that matters here.
 */
const assemblyBody = (() => {
    const start = entrySource.indexOf('export function assembleToolwall');
    const end = entrySource.indexOf('\nfunction recordProxyEvent', start);
    expect(start, 'assembleToolwall() must exist in src/index.ts').toBeGreaterThan(-1);
    expect(end, 'the assembly function must end before recordProxyEvent').toBeGreaterThan(start);
    return entrySource.slice(start, end);
})();

function exportedNames(moduleKey: string): string[] {
    const source = readFileSync(path.join(SRC, moduleKey), 'utf8');
    return [...source.matchAll(/export (?:async )?(?:function|class|const|interface|type|enum) (\w+)/gu)].map(m => m[1] as string);
}

/** Does `src/index.ts` re-export this module's surface, directly or through one barrel? */
function isPubliclyExported(moduleKey: string): boolean {
    const abs = path.join(SRC, moduleKey);
    for (const m of entrySource.matchAll(/export\s+(?:type\s+)?(?:\*|\{[^}]*\})\s+from\s+['"](\.[^'"]+)['"]/gu)) {
        const target = resolveSpecifier(ENTRY, m[1] as string);
        if (target === abs) return true;
        // One level of barrel: `export { CapabilityGuard } from './guards/runtime/index.js'`.
        let barrel: string;
        try {
            barrel = readFileSync(target, 'utf8');
        } catch {
            continue;
        }
        for (const b of barrel.matchAll(/from\s+['"](\.[^'"]+)['"]/gu)) {
            if (resolveSpecifier(target, b[1] as string) === abs) return true;
        }
    }
    return false;
}

// ---------------------------------------------------------------------------

describe('C-22 · every capability module is either wired or declared opt-in', () => {
    it('accounts for every module on disk — a new one fails until it is classified', () => {
        const unclassified = modulesOnDisk.filter(m => MANIFEST[m] === undefined);
        expect(
            unclassified,
            'These modules under src/guards, src/policy or src/audit are not classified in this file. ' +
                'Add each to MANIFEST as "assembled" (it runs in assembleToolwall), "opt-in" (an operator ' +
                'turns it on, and say what turns it on), "support" (a library the wired modules use) or ' +
                '"barrel". A module that is none of those is dead code, and dead code that looks like a ' +
                'security control is worse than no control.'
        ).toEqual([]);
    });

    it('has no stale manifest entries', () => {
        const missing = Object.keys(MANIFEST).filter(m => !modulesOnDisk.includes(m));
        expect(missing, 'these manifest entries name files that no longer exist').toEqual([]);
    });

    it('every non-barrel module is import-reachable from src/index.ts', () => {
        // THE check. `src/policy/infer.ts` and `src/audit/provenance.ts` both failed exactly this
        // for the whole of Week 3 while their unit tests were green.
        const unreachable = Object.entries(MANIFEST)
            .filter(([, c]) => c.status !== 'barrel')
            .map(([m]) => m)
            .filter(m => !reachable.has(path.join(SRC, m)));
        expect(
            unreachable,
            'Nothing in src/index.ts imports these, transitively, so no code path in the shipped ' +
                'product can reach them. They are dead however good their unit tests are.'
        ).toEqual([]);
    });

    it('every "assembled" and "opt-in" module is actually referenced by assembleToolwall()', () => {
        const failures: string[] = [];
        for (const [module, c] of Object.entries(MANIFEST)) {
            if (c.status !== 'assembled' && c.status !== 'opt-in') continue;
            const names = exportedNames(module);
            const hit = names.some(n => new RegExp(`\\b${n}\\b`, 'u').test(assemblyBody));
            if (!hit) failures.push(`${module} (exports: ${names.slice(0, 6).join(', ')})`);
        }
        expect(
            failures,
            'These claim to run in the shipped path, but assembleToolwall() never names any of their ' +
                'exports. Either wire them or reclassify them honestly.'
        ).toEqual([]);
    });

    it('every "opt-in" module names the option that enables it, and that option exists', () => {
        for (const [module, c] of Object.entries(MANIFEST)) {
            if (c.status !== 'opt-in') continue;
            expect(c.enabledBy, `${module} is opt-in but does not say what enables it`).toBeTruthy();
            expect(
                entrySource.includes(c.enabledBy as string),
                `${module} claims to be enabled by \`${c.enabledBy}\`, but that does not appear in src/index.ts. ` +
                    '"Opt-in" must never be a polite word for "unreachable".'
            ).toBe(true);
        }
    });

    it('every "assembled" and "opt-in" module is on the public export surface', () => {
        const hidden = Object.entries(MANIFEST)
            .filter(([, c]) => c.status === 'assembled' || c.status === 'opt-in' || c.status === 'exported-only')
            .map(([m]) => m)
            .filter(m => !isPubliclyExported(m));
        expect(
            hidden,
            'src/index.ts does not re-export these, directly or through their barrel. An embedder cannot ' +
                'reach them, and the omission is the same one that hid infer.ts and provenance.ts.'
        ).toEqual([]);
    });

    it('every module carries a reason, and barrels really are barrels', () => {
        for (const [module, c] of Object.entries(MANIFEST)) {
            expect(c.reason.length, `${module} needs a reason a human can read`).toBeGreaterThan(20);
            if (c.status !== 'barrel') continue;
            const source = readFileSync(path.join(SRC, module), 'utf8');
            const code = source
                .replace(/\/\*[\s\S]*?\*\//gu, '')
                .replace(/^\s*\/\/.*$/gmu, '')
                .split('\n')
                .map(l => l.trim())
                .filter(l => l.length > 0);
            const notReExports = code.filter(l => !/^export\s/u.test(l) && !/^\}\s*from\s/u.test(l) && !/^[\w,{} ]+$/u.test(l));
            expect(notReExports, `${module} is classified as a barrel but contains runtime code`).toEqual([]);
        }
    });

    it('an "exported-only" module really has no consumer, so the claim cannot rot into a lie', () => {
        // The inverse of every other check here. If somebody wires `headers.ts` into the proxy, the
        // classification stops being true and this fails — which is the correct outcome, because
        // "no live consumer" is a sentence the README puts in front of users.
        for (const [module, c] of Object.entries(MANIFEST)) {
            if (c.status !== 'exported-only') continue;
            const abs = path.join(SRC, module);
            const importers = [...reachable]
                .filter(f => f !== abs && f !== ENTRY)
                .filter(f => {
                    let src: string;
                    try {
                        src = readFileSync(f, 'utf8');
                    } catch {
                        return false;
                    }
                    return [...src.matchAll(/from\s+['"](\.[^'"]+)['"]/gu)].some(m => resolveSpecifier(f, m[1] as string) === abs);
                })
                .map(f => path.relative(SRC, f));
            expect(
                importers,
                `${module} is classified "exported-only" — no consumer in the shipped path — but these modules import it. ` +
                    'Reclassify it as `support` or `assembled` and update the README, which currently tells users it is unused.'
            ).toEqual([]);
        }
    });

    it('the C-17 assembly-time assertion is still there — the instance fix, not just the general one', () => {
        // A generalisation that quietly replaced the specific check would be a regression: this one
        // fails at STARTUP rather than in a test run, which is the stronger of the two.
        expect(assemblyBody).toContain('contract C-12');
        expect(assemblyBody).toMatch(/throw new Error\(/u);
    });
});
