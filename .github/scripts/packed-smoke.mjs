/**
 * Smoke test for the PACKED artifact, run from a scratch project that has toolwall installed
 * from its tarball and knows nothing about this repository's layout.
 *
 * Why this is not a vitest file: everything in `test/` runs with the repo's `node_modules` and
 * its `dist/` on disk. That combination cannot detect an incomplete `files` list, a `bin` that
 * is not executable, or an `exports` map that resolves only because a relative path happened to
 * work. Those bugs are invisible from inside the repo and fatal on first install, so they have
 * to be checked from outside it.
 *
 * Run by `.github/workflows/ci.yml` (job `package`) with cwd = the scratch consumer project and
 * GITHUB_WORKSPACE = the repo checkout, which is used ONLY to locate a fixture MCP server to
 * proxy. The toolwall under test is resolved through the consumer project's node_modules.
 */
import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';
import path from 'node:path';
import process from 'node:process';

const workspace = process.env['GITHUB_WORKSPACE'];
if (workspace === undefined) {
    throw new Error('GITHUB_WORKSPACE is not set; this script expects to run in CI.');
}

// Resolve the INSTALLED toolwall, not the repo. If `files` or `exports` is wrong, this throws
// here with a clear message rather than failing mysteriously later.
const require = createRequire(path.join(process.cwd(), 'index.js'));
const cli = require.resolve('toolwall/package.json');
const pkg = require('toolwall/package.json');
const installedRoot = path.dirname(cli);
const binRelative = typeof pkg.bin === 'string' ? pkg.bin : pkg.bin?.['toolwall'];
if (binRelative === undefined) {
    throw new Error('the installed package.json declares no `toolwall` bin entry');
}
const binPath = path.resolve(installedRoot, binRelative);

// The package must also be importable as a library through its `exports` map.
const lib = await import('toolwall');
for (const symbol of ['assembleToolwall', 'ToolwallProxy', 'PinStore']) {
    if (typeof lib[symbol] === 'undefined') {
        throw new Error(`the installed package does not export ${symbol} through its exports map`);
    }
}

const fixture = path.join(workspace, 'test/fixtures/downstream-server.mjs');

/** Speak real JSON-RPC to the packed binary over stdio and return the tools it lists. */
function proxyAndList() {
    return new Promise((resolve, reject) => {
        const child = spawn(process.execPath, [binPath, '--server', `node ${fixture}`], {
            cwd: process.cwd(),
            stdio: ['pipe', 'pipe', 'pipe']
        });

        let out = '';
        let err = '';
        let pending = '';
        const lines = [];

        const timer = setTimeout(() => {
            child.kill('SIGKILL');
            reject(new Error(`timed out.\nstdout:\n${out}\nstderr:\n${err}`));
        }, 30_000);

        child.stdout.on('data', chunk => {
            out += String(chunk);
            pending += String(chunk);
            for (;;) {
                const idx = pending.indexOf('\n');
                if (idx === -1) break;
                const line = pending.slice(0, idx).replace(/\r$/u, '');
                pending = pending.slice(idx + 1);
                if (line.trim().length === 0) continue;
                // Under stdio transport stdout IS the protocol channel. A banner here is a bug.
                let parsed;
                try {
                    parsed = JSON.parse(line);
                } catch {
                    clearTimeout(timer);
                    child.kill('SIGKILL');
                    reject(new Error(`non-JSON line on stdout, which corrupts every MCP client: ${JSON.stringify(line)}`));
                    return;
                }
                lines.push(parsed);
                const listed = lines.find(l => l.id === 2 && (l.result !== undefined || l.error !== undefined));
                if (listed !== undefined) {
                    clearTimeout(timer);
                    child.stdin.end();
                    child.kill('SIGTERM');
                    resolve({ listed, stderr: err });
                }
            }
        });
        child.stderr.on('data', chunk => {
            err += String(chunk);
        });
        child.on('error', e => {
            clearTimeout(timer);
            reject(e);
        });

        const send = m => child.stdin.write(`${JSON.stringify(m)}\n`);
        send({
            jsonrpc: '2.0',
            id: 1,
            method: 'initialize',
            params: {
                protocolVersion: '2025-11-25',
                capabilities: {},
                clientInfo: { name: 'packed-smoke', version: '0.0.0' }
            }
        });
        send({ jsonrpc: '2.0', method: 'notifications/initialized' });
        send({ jsonrpc: '2.0', id: 2, method: 'tools/list' });
    });
}

const { listed, stderr } = await proxyAndList();
if (listed.error !== undefined) {
    throw new Error(`tools/list through the packed CLI failed: ${JSON.stringify(listed.error)}`);
}
const tools = listed.result?.tools;
if (!Array.isArray(tools) || tools.length === 0) {
    throw new Error(`tools/list returned no tools through the packed CLI: ${JSON.stringify(listed.result)}`);
}
const names = tools.map(t => t.name);
for (const expected of ['echo', 'rows']) {
    if (!names.includes(expected)) {
        throw new Error(`the packed CLI did not relay the "${expected}" tool. Got: ${names.join(', ')}`);
    }
}

process.stdout.write(`packed artifact OK: bin=${binPath}\n`);
process.stdout.write(`  exports map resolves assembleToolwall / ToolwallProxy / PinStore\n`);
process.stdout.write(`  proxied tools/list relayed ${tools.length} tools: ${names.join(', ')}\n`);
process.stdout.write(`  stdout carried JSON-RPC only\n`);
if (stderr.trim().length > 0) {
    process.stdout.write(`  (stderr, informational)\n${stderr.trim().split('\n').map(l => `    ${l}`).join('\n')}\n`);
}
