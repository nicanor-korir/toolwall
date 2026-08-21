/**
 * **The optional dependency must be optional — proven, not asserted.**
 *
 * `agent-threat-rules` is 9.3 MB unpacked, powers a guard that is OFF by default, and sits in
 * `optionalDependencies`. Three things follow, and none of them were tested before this file:
 *
 *   1. A consumer who installs with `--omit=optional`, or whose optional install fails, must get
 *      a fully working toolwall. The pinning engine, the capability layer and the response leg
 *      do not depend on the package and must never touch it.
 *   2. `import "toolwall"` must not resolve the package at all. A static import anywhere in the
 *      graph would turn an optional dependency into a required one, and the failure would be a
 *      module-resolution stack trace at startup rather than a missing advisory lane.
 *   3. An operator who explicitly asks for the lane with `--advisory-rules` must get a sentence
 *      explaining what is missing and how to get it — not `ERR_MODULE_NOT_FOUND`.
 *
 * The audit that prompted this file found the code paths correct and completely uncovered: every
 * existing ATR test either injects a fake engine (bypassing the dynamic import) or requires the
 * package present. The catch block in `src/guards/metadata/rules.ts` and the one in
 * `src/cli/index.ts` had no test at all, which is the degradation path most consumers hit.
 *
 * ## How absence is arranged
 *
 * `no-atr-resolver.mjs`, registered via `--import`, makes the specifier throw the real
 * `ERR_MODULE_NOT_FOUND` Node would throw. This runs against the real `dist/` CLI in a real child
 * process, so what is exercised is the shipped code path and the shipped error text. In CI's
 * `optional-dep-absent` job the package is genuinely uninstalled and the hook is a no-op — the
 * same assertions then cover real absence. Both directions, one file.
 */
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterEach, beforeAll, describe, expect, it } from 'vitest';

const here = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(here, '../..');
const CLI = path.join(REPO, 'dist/cli/index.js');
const BENIGN = path.join(REPO, 'test/fixtures/downstream-server.mjs');
const HOOK = path.join(here, 'no-atr-register.mjs');

interface Run {
    readonly code: number | null;
    readonly stdout: string;
    readonly stderr: string;
    readonly messages: Array<Record<string, unknown>>;
}

/**
 * Spawn the shipped CLI with the resolution hook installed, feed it `input` lines, and collect
 * everything until it exits or `settle` elapses with no further output.
 */
function runCli(args: readonly string[], input: readonly Record<string, unknown>[], cwd: string): Promise<Run> {
    return new Promise((resolve, reject) => {
        const child: ChildProcessWithoutNullStreams = spawn(process.execPath, ['--import', HOOK, CLI, ...args], {
            cwd,
            stdio: ['pipe', 'pipe', 'pipe']
        });

        let stdout = '';
        let stderr = '';
        let pending = '';
        const messages: Array<Record<string, unknown>> = [];
        let settled = false;

        const finish = (code: number | null): void => {
            if (settled) return;
            settled = true;
            clearTimeout(hard);
            try {
                child.kill('SIGKILL');
            } catch {
                /* already gone */
            }
            resolve({ code, stdout, stderr, messages });
        };

        // A hard ceiling: if the CLI neither exits nor answers, that is itself the failure.
        const hard = setTimeout(() => finish(null), 15_000);

        child.stdout.on('data', chunk => {
            stdout += String(chunk);
            pending += String(chunk);
            for (;;) {
                const idx = pending.indexOf('\n');
                if (idx === -1) break;
                const line = pending.slice(0, idx).replace(/\r$/u, '');
                pending = pending.slice(idx + 1);
                if (line.trim().length === 0) continue;
                messages.push(JSON.parse(line) as Record<string, unknown>);
            }
            // Every request answered: stop waiting.
            const answered = messages.filter(m => 'result' in m || 'error' in m).length;
            if (answered >= input.filter(m => 'id' in m).length) finish(0);
        });
        child.stderr.on('data', chunk => {
            stderr += String(chunk);
        });
        child.on('error', reject);
        child.on('exit', code => finish(code));

        for (const message of input) child.stdin.write(`${JSON.stringify(message)}\n`);
    });
}

const INIT = {
    jsonrpc: '2.0',
    id: 1,
    method: 'initialize',
    params: { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'absent-dep', version: '0.0.0' } }
} as const;

let workdir: string;

beforeAll(async () => {
    workdir = await mkdtemp(path.join(tmpdir(), 'toolwall-absent-'));
});

afterEach(async () => {
    // Each case gets a clean pin store; a pin adopted in one case must not warm the next.
    await rm(path.join(workdir, '.toolwall'), { recursive: true, force: true });
});

describe('toolwall without the optional agent-threat-rules package', () => {
    it('makes the package genuinely unresolvable in the child, so the rest of this file means something', async () => {
        /*
         * Guard the guard. If the hook silently stopped working, every assertion below would pass
         * against a package that IS installed and prove nothing at all.
         *
         * The assertion is deliberately about the CHILD and not about this process, because the
         * two environments this suite runs in disagree about the parent: locally the package is
         * installed and the hook manufactures its absence; in CI's `optional-dep-absent` job the
         * package is really not there and the hook is a no-op. Asserting "the parent CAN import
         * it" would be true locally and false in CI. What is true in both, and is the only
         * property the rest of the file depends on, is that a child launched with the hook
         * cannot.
         */
        const child = await new Promise<{ code: number | null; stderr: string }>(resolve => {
            const proc = spawn(process.execPath, ['--import', HOOK, '-e', 'import("agent-threat-rules").then(()=>process.exit(0),()=>process.exit(42))'], {
                cwd: REPO,
                stdio: ['ignore', 'ignore', 'pipe']
            });
            let stderr = '';
            proc.stderr.on('data', c => {
                stderr += String(c);
            });
            proc.on('exit', code => resolve({ code, stderr }));
        });
        expect(child.code, `the child could still import agent-threat-rules; the absence hook is not working.\n${child.stderr}`).toBe(42);
    });

    it('proxies a benign server normally — the pinning engine never touches the package', async () => {
        const run = await runCli(
            ['--server', `node ${BENIGN}`],
            [INIT, { jsonrpc: '2.0', method: 'notifications/initialized' }, { jsonrpc: '2.0', id: 2, method: 'tools/list' }],
            workdir
        );

        const listed = run.messages.find(m => m['id'] === 2);
        expect(listed, `no tools/list answer.\nstdout:\n${run.stdout}\nstderr:\n${run.stderr}`).toBeDefined();
        expect(listed?.['error']).toBeUndefined();
        const tools = (listed?.['result'] as { tools?: Array<{ name: string }> } | undefined)?.tools ?? [];
        expect(tools.map(t => t.name)).toContain('echo');

        // Nothing about the missing package may reach the user as a FAILURE when they did not ask
        // for it: no resolution error, no stack, no claim that the advisory guard is running.
        expect(run.stderr).not.toContain('ERR_MODULE_NOT_FOUND');
        expect(run.stderr).not.toContain('Cannot find');
        expect(run.stderr).not.toContain('metadata.atr');
        expect(run.stderr).not.toContain('advisory rules ON');
        // It IS named once, in the pin sheet's "Not checked" list, which now reaches stderr in the
        // default path. That is the sheet's discipline — silence must not read as a pass — and it
        // is the opposite of the failure this test exists to catch: it says the detector was not
        // run, next to the line telling you how to run it.
        expect(run.stderr).toContain('agent-threat-rules detection: the advisory detector is opt-in');
    });

    it('still BLOCKS a rug pull without the advisory package — the security core is independent', async () => {
        // The point of the optional dependency being optional: removing it must cost the advisory
        // lane and nothing else. If pinning degraded too, `optionalDependencies` would be a lie.
        const first = await runCli(
            ['--server', `node ${BENIGN}`],
            [INIT, { jsonrpc: '2.0', method: 'notifications/initialized' }, { jsonrpc: '2.0', id: 2, method: 'tools/list' }],
            workdir
        );
        expect(first.messages.find(m => m['id'] === 2)?.['error']).toBeUndefined();

        // The pin store now exists on disk and holds the clean listing.
        const second = await runCli(
            ['--server', `node ${BENIGN}`],
            [INIT, { jsonrpc: '2.0', method: 'notifications/initialized' }, { jsonrpc: '2.0', id: 2, method: 'tools/list' }],
            workdir
        );
        // Same server, same definitions: the pinned listing re-verifies and passes.
        expect(second.messages.find(m => m['id'] === 2)?.['error']).toBeUndefined();
        // Named only as "not checked" (see the previous test); never as a failure or as running.
        expect(second.stderr).not.toContain('ERR_MODULE_NOT_FOUND');
        expect(second.stderr).not.toContain('metadata.atr');
    });

    it('explains itself and exits 2 when --advisory-rules is asked for explicitly', async () => {
        const run = await runCli(['--advisory-rules', 'alert', '--server', `node ${BENIGN}`], [INIT], workdir);

        // A loud, specific failure on an explicit request is correct: the operator asked for a
        // detector, and starting without it would silently downgrade the security posture they
        // chose. What must NOT happen is a raw module-resolution stack trace.
        expect(run.code, `expected exit 2.\nstderr:\n${run.stderr}`).toBe(2);
        expect(run.stderr).toContain('--advisory-rules could not start');
        expect(run.stderr).toContain('agent-threat-rules');
        // The remediation must be present and actionable.
        expect(run.stderr).toContain('npm i agent-threat-rules');
        expect(run.stderr).toContain('the pinning engine does not depend on it');
        // The explanation, not the stack.
        expect(run.stderr).not.toMatch(/^\s+at .*\(/mu);
    });

    it('never emits anything but JSON-RPC on stdout, missing package or not', async () => {
        // stdout IS the protocol channel under stdio transport. A diagnostic about the optional
        // package landing there would corrupt every connected client.
        const ok = await runCli(
            ['--server', `node ${BENIGN}`],
            [INIT, { jsonrpc: '2.0', method: 'notifications/initialized' }, { jsonrpc: '2.0', id: 2, method: 'tools/list' }],
            workdir
        );
        for (const line of ok.stdout.split('\n')) {
            if (line.trim().length === 0) continue;
            expect(() => JSON.parse(line), `non-JSON on stdout: ${JSON.stringify(line)}`).not.toThrow();
        }

        const failed = await runCli(['--advisory-rules', 'alert', '--server', `node ${BENIGN}`], [INIT], workdir);
        expect(failed.stdout.trim()).toBe('');
    });
});
