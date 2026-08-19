/**
 * toolwall latency benchmark — `npm run bench`.
 *
 * Measures the round-trip latency of a real `tools/call` against a real MCP server child
 * process, three ways:
 *
 *   direct    the client's transport talks to the server. No proxy in the path. The baseline.
 *   proxy     through `ToolwallProxy` with ZERO guards registered. Isolates transport cost.
 *   guarded   through the fully assembled product: `assembleToolwall()` with the metadata pin
 *             guard, schema guard and capability guard on `tools/call`, plus the audit log.
 *
 * "Added latency" is the difference between the same percentile of two configurations. That is
 * the number the 5ms budget is about, and it is what gets reported — pass or fail. Absolute
 * percentiles are printed alongside so the delta can be sanity-checked rather than trusted.
 *
 * It benchmarks `dist/`, not `src/`, so what is measured is what ships.
 *
 * Method notes, stated so the numbers can be argued with:
 *   - Sequential requests, one in flight at a time. Concurrency would measure the event loop.
 *   - Every configuration talks to the same fixture server binary with the same arguments.
 *   - The guarded run performs `initialize` and `tools/list` first, so the pin store is warm and
 *     the measured calls are the steady state a real session spends its life in: two map lookups
 *     and a string compare per call, not a canonicalize.
 *   - Warmup iterations are discarded to skip JIT and first-call allocation.
 *   - The child process is respawned per configuration, never shared.
 *
 * ## Two payload sizes, because Week 2 put work on the RESULT
 *
 * Week 1 measured request-leg guards only, so a tiny echo was a fair probe. `ResultGuard` (C-12)
 * now runs on every `tools/call`, `resources/read` and `prompts/get` RESULT: `measure()` walks the
 * payload (bounded at 200k nodes) and `hasProtoKey()` walks it again. That cost scales with the
 * result, and a 9-byte echo would hide it entirely.
 *
 * So both sizes are measured:
 *   small   a 9-byte echo   — the Week-1 probe, kept for comparability with the C-11 table.
 *   large   a 64 KiB echo   — a realistic `read_file` / query result, where the response-leg walk
 *                             is actually doing work.
 * A guard cost that only appears in the `large` row is still a real cost; reporting only `small`
 * would be choosing the flattering number.
 */

import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { PassThrough } from 'node:stream';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import process from 'node:process';

import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

import { PinStore, ToolwallProxy, assembleToolwall, createUpstreamStdioTransport } from '../dist/index.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const FIXTURE = path.resolve(here, '../test/fixtures/downstream-server.mjs');

const ITERATIONS = Number(process.env['TOOLWALL_BENCH_N'] ?? 1000);
const WARMUP = Number(process.env['TOOLWALL_BENCH_WARMUP'] ?? 100);
const BUDGET_MS = 5;

// ---------------------------------------------------------------------------
// Minimal JSON-RPC client over a duplex pair
// ---------------------------------------------------------------------------

interface Wire {
    send(message: Record<string, unknown>): void;
    onLine(handler: (value: Record<string, unknown>) => void): void;
    close(): Promise<void>;
}

function lineReader(handler: (value: Record<string, unknown>) => void): (chunk: Buffer | string) => void {
    let buffer = '';
    return chunk => {
        buffer += chunk.toString();
        for (;;) {
            const idx = buffer.indexOf('\n');
            if (idx === -1) break;
            const raw = buffer.slice(0, idx).replace(/\r$/u, '');
            buffer = buffer.slice(idx + 1);
            if (raw.length > 0) handler(JSON.parse(raw) as Record<string, unknown>);
        }
    };
}

class Rpc {
    #nextId = 1;
    readonly #pending = new Map<number, (value: Record<string, unknown>) => void>();
    readonly #wire: Wire;

    constructor(wire: Wire) {
        this.#wire = wire;
        wire.onLine(value => {
            const id = value['id'];
            if (typeof id === 'number') {
                const resolve = this.#pending.get(id);
                if (resolve !== undefined) {
                    this.#pending.delete(id);
                    resolve(value);
                }
            }
        });
    }

    request(method: string, params?: Record<string, unknown>): Promise<Record<string, unknown>> {
        const id = this.#nextId++;
        return new Promise(resolve => {
            this.#pending.set(id, resolve);
            this.#wire.send({ jsonrpc: '2.0', id, method, ...(params === undefined ? {} : { params }) });
        });
    }

    notify(method: string, params?: Record<string, unknown>): void {
        this.#wire.send({ jsonrpc: '2.0', method, ...(params === undefined ? {} : { params }) });
    }

    close(): Promise<void> {
        return this.#wire.close();
    }
}

// ---------------------------------------------------------------------------
// Configurations
// ---------------------------------------------------------------------------

function directWire(): Wire {
    const child: ChildProcessWithoutNullStreams = spawn(process.execPath, [FIXTURE], {
        stdio: ['pipe', 'pipe', 'pipe']
    });
    child.stderr.resume();
    let onLine: (value: Record<string, unknown>) => void = () => undefined;
    child.stdout.on('data', lineReader(value => onLine(value)));
    return {
        send: message => child.stdin.write(`${JSON.stringify(message)}\n`),
        onLine: handler => {
            onLine = handler;
        },
        close: async () => {
            child.stdin.end();
            child.kill('SIGTERM');
            await new Promise<void>(resolve => {
                child.once('close', () => resolve());
                setTimeout(resolve, 2000).unref();
            });
        }
    };
}

/** Through `ToolwallProxy` with no guards registered: transport cost only. */
async function bareProxyWire(): Promise<Wire> {
    const upstream = createUpstreamStdioTransport({ command: process.execPath, args: [FIXTURE] }, { allowedCommands: ['node'] });
    upstream.transport.stderr?.resume();

    const toProxy = new PassThrough();
    const fromProxy = new PassThrough();
    let onLine: (value: Record<string, unknown>) => void = () => undefined;
    fromProxy.on('data', lineReader(value => onLine(value)));

    const proxy = new ToolwallProxy({
        clientTransport: new StdioServerTransport(toProxy, fromProxy),
        upstreamTransport: upstream.transport,
        serverId: upstream.serverId
    });
    await proxy.start();

    return {
        send: message => toProxy.write(`${JSON.stringify(message)}\n`),
        onLine: handler => {
            onLine = handler;
        },
        close: () => proxy.close()
    };
}

/** The whole product, exactly as `assembleToolwall()` builds it for the CLI. */
async function guardedWire(): Promise<Wire> {
    const toProxy = new PassThrough();
    const fromProxy = new PassThrough();
    let onLine: (value: Record<string, unknown>) => void = () => undefined;
    fromProxy.on('data', lineReader(value => onLine(value)));

    const toolwall = assembleToolwall({
        clientTransport: new StdioServerTransport(toProxy, fromProxy),
        spec: { command: process.execPath, args: [FIXTURE] },
        spawnPolicy: { allowedCommands: ['node'] },
        // In-memory: the pin store is not written during the measured window, and a disk write
        // would be measuring the filesystem rather than toolwall.
        pins: await PinStore.open({ path: path.join(here, '.bench-pins-not-written.json') })
    });
    toolwall.upstreamTransport.stderr?.resume();
    await toolwall.start();

    return {
        send: message => toProxy.write(`${JSON.stringify(message)}\n`),
        onLine: handler => {
            onLine = handler;
        },
        close: () => toolwall.close()
    };
}

// ---------------------------------------------------------------------------
// Measurement
// ---------------------------------------------------------------------------

const INIT_PARAMS = {
    protocolVersion: '2025-11-25',
    capabilities: {},
    clientInfo: { name: 'toolwall-bench', version: '0.0.0' }
};

/** The two payload sizes. `text` comes back verbatim in the result, so it sizes both legs. */
const WORKLOADS = [
    { name: 'small', text: 'benchmark' },
    { name: 'large', text: 'x'.repeat(64 * 1024) }
] as const;

type WorkloadName = (typeof WORKLOADS)[number]['name'];

async function measure(label: string, makeWire: () => Wire | Promise<Wire>): Promise<Record<WorkloadName, number[]>> {
    const rpc = new Rpc(await makeWire());
    try {
        await rpc.request('initialize', INIT_PARAMS);
        rpc.notify('notifications/initialized');
        // Warm the pin store: a real session lists once and then calls thousands of times.
        await rpc.request('tools/list');

        const out = {} as Record<WorkloadName, number[]>;
        for (const workload of WORKLOADS) {
            const params = { name: 'echo', arguments: { text: workload.text } };
            for (let i = 0; i < WARMUP; i++) await rpc.request('tools/call', params);

            const samples: number[] = new Array<number>(ITERATIONS);
            for (let i = 0; i < ITERATIONS; i++) {
                const start = process.hrtime.bigint();
                const response = await rpc.request('tools/call', params);
                const end = process.hrtime.bigint();
                if (response['error'] !== undefined) {
                    throw new Error(
                        `${label}/${workload.name}: the benchmarked call was rejected: ${JSON.stringify(response['error'])}`
                    );
                }
                samples[i] = Number(end - start) / 1e6;
            }
            out[workload.name] = samples;
        }
        return out;
    } finally {
        await rpc.close();
    }
}

function percentile(sorted: readonly number[], p: number): number {
    if (sorted.length === 0) return Number.NaN;
    const idx = Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1));
    return sorted[idx] as number;
}

interface Stats {
    readonly label: string;
    readonly p50: number;
    readonly p95: number;
    readonly p99: number;
    readonly mean: number;
    readonly max: number;
}

function summarize(label: string, samples: number[]): Stats {
    const sorted = [...samples].sort((a, b) => a - b);
    return {
        label,
        p50: percentile(sorted, 50),
        p95: percentile(sorted, 95),
        p99: percentile(sorted, 99),
        mean: samples.reduce((a, b) => a + b, 0) / samples.length,
        max: sorted[sorted.length - 1] as number
    };
}

const ms = (n: number): string => n.toFixed(3).padStart(8);

const added = (a: Stats, b: Stats): Stats => ({
    label: `${b.label} - ${a.label}`,
    p50: b.p50 - a.p50,
    p95: b.p95 - a.p95,
    p99: b.p99 - a.p99,
    mean: b.mean - a.mean,
    max: b.max - a.max
});

async function main(): Promise<void> {
    process.stderr.write(
        `toolwall latency benchmark\n` +
            `  node        ${process.version} on ${process.platform}/${process.arch}\n` +
            `  iterations  ${ITERATIONS} per workload (after ${WARMUP} warmup)\n` +
            `  method      sequential tools/call, one in flight, same fixture server per config\n` +
            `  workloads   ${WORKLOADS.map(w => `${w.name} (${w.text.length}B echoed)`).join(', ')}\n\n`
    );

    const raw = {
        direct: await measure('direct', directWire),
        bare: await measure('proxy', bareProxyWire),
        guarded: await measure('guarded', guardedWire)
    };

    let worstAddedP99 = Number.NEGATIVE_INFINITY;

    for (const workload of WORKLOADS) {
        const direct = summarize('direct', raw.direct[workload.name]);
        const bare = summarize('proxy (0 guards)', raw.bare[workload.name]);
        const guarded = summarize('guarded (full stack)', raw.guarded[workload.name]);

        process.stdout.write(`\n== workload: ${workload.name} (${workload.text.length} B echoed) ==\n`);
        process.stdout.write(`config                      p50       p95       p99      mean       max\n`);
        for (const s of [direct, bare, guarded]) {
            process.stdout.write(`${s.label.padEnd(20)}${ms(s.p50)}  ${ms(s.p95)}  ${ms(s.p99)}  ${ms(s.mean)}  ${ms(s.max)}\n`);
        }

        process.stdout.write(`\nadded latency (same percentile, config minus baseline)\n`);
        for (const s of [added(direct, bare), added(direct, guarded), added(bare, guarded)]) {
            process.stdout.write(`${s.label.padEnd(40)}p50 ${ms(s.p50)}  p95 ${ms(s.p95)}  p99 ${ms(s.p99)}\n`);
        }

        const addedP99 = guarded.p99 - direct.p99;
        if (addedP99 > worstAddedP99) worstAddedP99 = addedP99;
        process.stdout.write(`\n${workload.name}: added p99 = ${addedP99.toFixed(3)}ms\n`);
    }

    const verdict = worstAddedP99 <= BUDGET_MS ? 'WITHIN' : 'OVER';
    process.stdout.write(
        `\nbudget: sub-${BUDGET_MS}ms p99 added overhead, full guard stack vs a direct connection\n` +
            `result: ${worstAddedP99.toFixed(3)}ms (worst workload) — ${verdict} budget\n`
    );
    if (worstAddedP99 > BUDGET_MS) {
        process.exitCode = 1;
    }
}

await main();
