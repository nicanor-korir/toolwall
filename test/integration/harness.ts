/**
 * Integration harness.
 *
 * Both peers here are real: a real child process speaking real newline
 * delimited JSON-RPC over real pipes, and a real `StdioServerTransport` on the
 * client-facing side of the proxy. Nothing in this file pretends to be a
 * transport.
 *
 * The client-facing side uses `PassThrough` streams rather than the test
 * process's own stdio for one reason only: so the test can read the exact bytes
 * the proxy writes. `StdioServerTransport` is the same class the CLI uses, with
 * the same codec.
 */

import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { PassThrough } from 'node:stream';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

import { AuditLog } from '../../src/audit/log.js';
import { PinStore } from '../../src/audit/manifest.js';
import type { PinEvent } from '../../src/guards/metadata/drift.js';
import type { ResolvedPolicy } from '../../src/policy/parse.js';
import { assembleToolwall, type GuardToggles, type Toolwall } from '../../src/index.js';
import { ToolwallProxy, type ProxyEvent } from '../../src/transport/proxy.js';
import { createUpstreamStdioTransport } from '../../src/transport/spawn.js';
import type { GuardPipeline } from '../../src/transport/pipeline.js';

const here = path.dirname(fileURLToPath(import.meta.url));
export const FIXTURE_SERVER = path.resolve(here, '../fixtures/downstream-server.mjs');
export const POISONED_SERVER = path.resolve(here, '../fixtures/malicious/poisoned-server.js');
export const RUGPULL_SERVER = path.resolve(here, '../fixtures/malicious/rugpull-server.js');

export interface JsonRpcLine {
    readonly raw: string;
    readonly value: Record<string, unknown>;
}

/** Collects newline-delimited JSON from a stream, exposing raw bytes and parsed values. */
class LineCollector {
    readonly lines: JsonRpcLine[] = [];
    #buffer = '';
    #waiters: Array<() => void> = [];

    feed(chunk: Buffer | string): void {
        this.#buffer += chunk.toString();
        for (;;) {
            const idx = this.#buffer.indexOf('\n');
            if (idx === -1) {
                break;
            }
            const raw = this.#buffer.slice(0, idx).replace(/\r$/u, '');
            this.#buffer = this.#buffer.slice(idx + 1);
            if (raw.length === 0) {
                continue;
            }
            this.lines.push({ raw, value: JSON.parse(raw) as Record<string, unknown> });
        }
        const waiters = this.#waiters;
        this.#waiters = [];
        for (const w of waiters) {
            w();
        }
    }

    /** Waits until `predicate` matches a line, returning it. */
    async waitFor(predicate: (line: JsonRpcLine) => boolean, timeoutMs = 10_000): Promise<JsonRpcLine> {
        const deadline = Date.now() + timeoutMs;
        for (;;) {
            const found = this.lines.find(predicate);
            if (found !== undefined) {
                return found;
            }
            const remaining = deadline - Date.now();
            if (remaining <= 0) {
                throw new Error(`Timed out waiting for a line. Saw:\n${this.lines.map(l => l.raw).join('\n')}`);
            }
            await new Promise<void>(resolve => {
                const timer = setTimeout(resolve, Math.min(remaining, 50));
                this.#waiters.push(() => {
                    clearTimeout(timer);
                    resolve();
                });
            });
        }
    }

    /** Waits for the response to a given JSON-RPC id. */
    waitForId(id: number | string, timeoutMs?: number): Promise<JsonRpcLine> {
        return this.waitFor(line => line.value['id'] === id && ('result' in line.value || 'error' in line.value), timeoutMs);
    }

    waitForMethod(method: string, timeoutMs?: number): Promise<JsonRpcLine> {
        return this.waitFor(line => line.value['method'] === method, timeoutMs);
    }
}

export interface Peer {
    send(message: Record<string, unknown>): void;
    readonly out: LineCollector;
    close(): Promise<void>;
}

/** A direct connection to the fixture server: no proxy in the path. */
export function connectDirect(): Peer {
    const child: ChildProcessWithoutNullStreams = spawn(process.execPath, [FIXTURE_SERVER], {
        stdio: ['pipe', 'pipe', 'pipe']
    });
    const out = new LineCollector();
    child.stdout.on('data', chunk => out.feed(chunk));
    child.stderr.resume();

    return {
        send(message) {
            child.stdin.write(`${JSON.stringify(message)}\n`);
        },
        out,
        async close() {
            child.stdin.end();
            child.kill('SIGTERM');
            await new Promise<void>(resolve => {
                if (child.exitCode !== null || child.signalCode !== null) {
                    resolve();
                    return;
                }
                child.once('close', () => resolve());
                setTimeout(resolve, 2000).unref();
            });
        }
    };
}

export interface ProxyPeer extends Peer {
    readonly proxy: ToolwallProxy;
    readonly events: ProxyEvent[];
}

/** A connection to the fixture server through a real ToolwallProxy. */
export async function connectThroughProxy(options: { guards?: GuardPipeline } = {}): Promise<ProxyPeer> {
    const upstream = createUpstreamStdioTransport({ command: process.execPath, args: [FIXTURE_SERVER] }, { allowedCommands: ['node'] });

    const toProxy = new PassThrough();
    const fromProxy = new PassThrough();
    const out = new LineCollector();
    fromProxy.on('data', chunk => out.feed(chunk));

    const events: ProxyEvent[] = [];
    const proxy = new ToolwallProxy({
        clientTransport: new StdioServerTransport(toProxy, fromProxy),
        upstreamTransport: upstream.transport,
        serverId: upstream.serverId,
        ...(options.guards !== undefined ? { guards: options.guards } : {}),
        onEvent: event => events.push(event)
    });

    upstream.transport.stderr?.resume();
    await proxy.start();

    return {
        send(message) {
            toProxy.write(`${JSON.stringify(message)}\n`);
        },
        out,
        proxy,
        events,
        async close() {
            await proxy.close();
        }
    };
}

// ---------------------------------------------------------------------------
// The assembled product
// ---------------------------------------------------------------------------

/**
 * A connection to a real MCP server through the **fully assembled** toolwall — the same
 * `assembleToolwall()` the CLI calls, with the real pin store, real guards and real audit log.
 *
 * This is the distinction the mandate turns on: `test/unit/*` proves each detector works;
 * nothing there proves a detector is *reachable from the request path*. Everything below drives
 * raw JSON-RPC into the client-facing transport and reads what comes back out, so a guard that
 * is implemented but not registered fails these tests.
 */
export interface AssembledPeer extends Peer {
    readonly toolwall: Toolwall;
    readonly events: ProxyEvent[];
    readonly pinEvents: PinEvent[];
    readonly audit: AuditLog;
    readonly pins: PinStore;
    /** Temp directory holding this session's pin store. Removed by `close()`. */
    readonly dir: string;
    /** Write raw bytes to the client-facing transport, framing and all. For malformed input. */
    sendRaw(bytes: string): void;
    /** Send a request and await its response line. Ids are allocated automatically. */
    call(method: string, params?: Record<string, unknown>): Promise<JsonRpcLine>;
    /** `initialize` + `notifications/initialized`, relayed end to end. */
    handshake(): Promise<JsonRpcLine>;
}

export interface AssembledOptions {
    /** Path to the server script. Defaults to the benign fixture. */
    readonly server?: string;
    readonly serverArgs?: readonly string[];
    readonly policy?: ResolvedPolicy;
    readonly pinMode?: 'tofu' | 'strict';
    readonly onUnverifiable?: 'block' | 'confirm' | 'allow';
    readonly enable?: GuardToggles;
    /** Reuse an existing store (to prove pins survive a restart). A temp one is made otherwise. */
    readonly pins?: PinStore;
    /** Reuse an existing temp dir alongside `pins`. */
    readonly dir?: string;
}

export async function connectAssembled(options: AssembledOptions = {}): Promise<AssembledPeer> {
    const dir = options.dir ?? (await mkdtemp(path.join(tmpdir(), 'toolwall-e2e-')));
    const ownsDir = options.dir === undefined;
    const pins = options.pins ?? (await PinStore.open({ cwd: dir }));
    const audit = new AuditLog();

    const toProxy = new PassThrough();
    const fromProxy = new PassThrough();
    const out = new LineCollector();
    fromProxy.on('data', chunk => out.feed(chunk));

    const events: ProxyEvent[] = [];
    const pinEvents: PinEvent[] = [];

    const toolwall = assembleToolwall({
        clientTransport: new StdioServerTransport(toProxy, fromProxy),
        spec: {
            command: process.execPath,
            args: [options.server ?? FIXTURE_SERVER, ...(options.serverArgs ?? [])]
        },
        spawnPolicy: { allowedCommands: ['node'] },
        pins,
        audit,
        ...(options.policy !== undefined ? { policy: options.policy } : {}),
        ...(options.pinMode !== undefined ? { pinMode: options.pinMode } : {}),
        ...(options.onUnverifiable !== undefined ? { onUnverifiable: options.onUnverifiable } : {}),
        ...(options.enable !== undefined ? { enable: options.enable } : {}),
        baseDir: dir,
        onEvent: event => events.push(event),
        onPinEvent: event => pinEvents.push(event)
    });

    toolwall.upstreamTransport.stderr?.resume();
    await toolwall.start();

    let nextId = 1;
    const send = (message: Record<string, unknown>): void => {
        toProxy.write(`${JSON.stringify(message)}\n`);
    };

    return {
        send,
        sendRaw: bytes => {
            toProxy.write(bytes);
        },
        out,
        toolwall,
        events,
        pinEvents,
        audit,
        pins,
        dir,
        async call(method, params) {
            const id = nextId++;
            send({ jsonrpc: '2.0', id, method, ...(params === undefined ? {} : { params }) });
            return out.waitForId(id);
        },
        async handshake() {
            const id = nextId++;
            send({ ...INITIALIZE, id });
            const result = await out.waitForId(id);
            send({ ...INITIALIZED });
            return result;
        },
        async close() {
            await toolwall.close();
            if (ownsDir) {
                await rm(dir, { recursive: true, force: true }).catch(() => undefined);
            }
        }
    };
}

/** The JSON-RPC `error` object from a response line, or `undefined` if it succeeded. */
export function errorOf(line: JsonRpcLine): { code: number; message: string; data?: unknown } | undefined {
    const error = line.value['error'];
    if (error === undefined || error === null || typeof error !== 'object') return undefined;
    return error as { code: number; message: string; data?: unknown };
}

/**
 * The findings toolwall attached to a blocked response, as the CLIENT sees them.
 *
 * Deliberately redacted — see `redactFindingForClient` in `src/transport/proxy.ts`. `message`
 * and `evidence` quote the untrusted server's own text and are not on this channel. Read them
 * from `peer.events` or `peer.audit` instead, which is where an operator reads them.
 */
export function findingsOf(line: JsonRpcLine): Array<{ ruleId: string; severity: string; locus: string; remediation: string; detail: string }> {
    const error = errorOf(line);
    const data = error?.data as { toolwall?: { findings?: unknown } } | undefined;
    const findings = data?.toolwall?.findings;
    return Array.isArray(findings) ? (findings as Array<{ ruleId: string; severity: string; locus: string; remediation: string; detail: string }>) : [];
}

/** The unredacted findings from a `blocked` proxy event — the operator-facing channel. */
export function blockedFindings(peer: AssembledPeer): Array<{ ruleId: string; severity: string; message: string; evidence?: Record<string, unknown> }> {
    return peer.events
        .filter((e): e is Extract<ProxyEvent, { kind: 'blocked' }> => e.kind === 'blocked')
        .flatMap(e => [...e.findings]) as Array<{ ruleId: string; severity: string; message: string; evidence?: Record<string, unknown> }>;
}

/** The handshake, byte for byte identical on both paths. */
export const INITIALIZE = {
    jsonrpc: '2.0',
    id: 1,
    method: 'initialize',
    params: {
        protocolVersion: '2025-11-25',
        capabilities: { sampling: {}, roots: { listChanged: true }, elicitation: {} },
        clientInfo: { name: 'toolwall-integration-test', version: '9.9.9' }
    }
} as const;

export const INITIALIZED = { jsonrpc: '2.0', method: 'notifications/initialized' } as const;
