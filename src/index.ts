/**
 * toolwall — the assembled product.
 *
 * The three module areas are built against interfaces and know nothing about each other. This
 * file is where they become one thing: transport + metadata guards + runtime guards + audit,
 * wired in an order that is itself a security decision.
 *
 * ```
 *  [ trusted client ] --stdio--> ToolwallProxy --stdio--> [ untrusted MCP server ]
 *                                     |
 *                        DefaultGuardPipeline
 *                                     |
 *      response leg                   |                 request leg
 *      -----------                    |                 -----------
 *      initialize        -> pin       |   tools/call  -> 1. MetadataPinGuard  (identity)
 *      server/discover   -> pin       |                  2. SchemaGuard       (contract)
 *      tools/list        -> pin       |                  3. CapabilityGuard   (authority)
 *      .../list_changed  -> pin       |
 *                                     v
 *                                 AuditLog  (hash-chained; C-2 sink)
 * ```
 *
 * ## Why that order on `tools/call`, specifically
 *
 * 1. **`MetadataPinGuard` first.** If the tool definition no longer matches the one that was
 *    approved, nothing downstream is meaningful: the schema the other guards would enforce, the
 *    annotations the capability guard would read, and the description the model acted on are all
 *    attacker-controlled as of this moment. Identity is checked before content (T-02, rank 1).
 * 2. **`SchemaGuard` second, reading the PINNED definition — contract C-1.** This is the
 *    security-critical wire in this file. `SchemaGuard` takes a `ToolDefinitionSource`; the one
 *    it gets is `PinnedToolDefinitionSource`, backed by the pin store. If it validated against
 *    the live `tools/list` instead, an attacker would widen their own schema first and their
 *    hostile arguments would become "valid" — the rug pull would legalise its own payload.
 *    `test/integration/schema-pin-binding.test.ts` runs that exact attack both ways.
 * 3. **`CapabilityGuard` last.** It is the only one that touches the filesystem (`lstat` while
 *    resolving symlinks segment by segment), so it runs only on calls the two cheap deterministic
 *    checks already accepted.
 *
 * The pipeline short-circuits on the first `block`, so this order also means the finding a user
 * sees names the most fundamental problem rather than a downstream symptom of it.
 *
 * ## What is NOT registered, and why that matters
 *
 * Guards are registered per `(direction, method)`, never with `ANY_METHOD`. `GuardPipeline`'s
 * `hasGuards()` fast path then returns false for every other method — `prompts/*`,
 * `resources/*`, `ping`, `sampling/createMessage`, unknown and future methods — and the proxy
 * forwards the payload object by reference with no inspection, no clone and no re-serialization.
 * That is the transparency guarantee, and it is also why the measured overhead on non-`tools/*`
 * traffic is indistinguishable from the guard-free transport.
 */

import type { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';

import { AuditLog } from './audit/log.js';
import { PinStore } from './audit/manifest.js';
import { MetadataPinGuard, type PinEvent } from './guards/metadata/drift.js';
import { CapabilityGuard } from './guards/runtime/capability-guard.js';
import { SchemaGuard } from './guards/runtime/schema-guard.js';
import type { ToolDefinition, ToolDefinitionSource } from './policy/contract.js';
import { defaultPolicy, type ResolvedPolicy } from './policy/parse.js';
import { DefaultGuardPipeline } from './transport/pipeline.js';
import { ToolwallProxy, type ProxyEvent } from './transport/proxy.js';
import type { ReconnectPolicy } from './transport/reconnect.js';
import {
    createUpstreamStdioTransport,
    type SpawnAudit,
    type SpawnPolicy,
    type SpawnSpec
} from './transport/spawn.js';
import type { ConfirmationProvider, ProtocolEra } from './types/protocol.js';
import { DEFAULT_PROTOCOL_ERA } from './types/protocol.js';

// ---------------------------------------------------------------------------
// C-1 · The pinned tool definition source
// ---------------------------------------------------------------------------

const isRecord = (v: unknown): v is Record<string, unknown> =>
    typeof v === 'object' && v !== null && !Array.isArray(v);

/**
 * The `ToolDefinitionSource` the runtime guards enforce against — contract **C-1**.
 *
 * It reads `PinRecord.definition`: the detached, NFC-normalized copy of the tool surface that
 * was hashed and approved. Never the live `tools/list`. The distinction is the whole control:
 *
 *   pinned:  { a: number, b: number }, required [a, b]
 *   live:    { a: number, b: number, exfil_target: string }, required [a, b, exfil_target]
 *
 * Validating `{ a, b, exfil_target: "https://attacker.example/collect" }` against the live
 * schema says "valid" — the attacker declared the parameter they are about to abuse. Validating
 * against the pinned schema says "undeclared property". T-02 is therefore a dependency of T-05,
 * not a parallel feature (`docs/ARCHITECTURE.md` C-1).
 *
 * A pin whose stored definition is not a usable tool object returns `undefined` rather than a
 * guess, which routes into `SchemaGuard`'s `requireKnownSchema` decision: recorded at
 * `balanced`, fail-closed at `strict`. Guessing here would be inventing a contract.
 */
export class PinnedToolDefinitionSource implements ToolDefinitionSource {
    readonly #store: PinStore;

    constructor(store: PinStore) {
        this.#store = store;
    }

    get(serverId: string, toolName: string): ToolDefinition | undefined {
        const record = this.#store.get(serverId, 'tool', toolName);
        if (record === undefined) return undefined;
        const definition = record.definition;
        if (!isRecord(definition)) return undefined;
        if (typeof definition['name'] !== 'string') return undefined;
        if (!isRecord(definition['inputSchema'])) return undefined;
        return definition as unknown as ToolDefinition;
    }
}

// ---------------------------------------------------------------------------
// Assembly
// ---------------------------------------------------------------------------

/** Which guards to register. All default to `true`; setting one false turns that control off. */
export interface GuardToggles {
    readonly pinning?: boolean;
    readonly schema?: boolean;
    readonly capability?: boolean;
}

export interface ToolwallOptions {
    /** Transport facing the trusted client (`StdioServerTransport` under the CLI). */
    readonly clientTransport: Transport;
    /** What to spawn upstream. Validated for T-07 before anything is executed. */
    readonly spec: SpawnSpec;
    readonly spawnPolicy?: SpawnPolicy;
    readonly era?: ProtocolEra;
    /** Security state. Open it with `PinStore.open()`; this function never writes it. */
    readonly pins: PinStore;
    /** Capability policy. Defaults to the `balanced` tier preset with no policy file. */
    readonly policy?: ResolvedPolicy;
    /** Destination for C-2 records and for blocked/annotated events. Defaults to memory only. */
    readonly audit?: AuditLog;
    readonly pinMode?: 'tofu' | 'strict';
    readonly onUnverifiable?: 'block' | 'confirm' | 'allow';
    /** Base directory for resolving relative path arguments (C-7: one base, not per-argument). */
    readonly baseDir?: string;
    /** Override the derived identity. Do this only if you know why; see `src/audit/identity.ts`. */
    readonly serverId?: string;
    /** Resolves `confirm` verdicts (T-06). Absent means `confirm` fails closed. */
    readonly confirmationProvider?: ConfirmationProvider;
    readonly onEvent?: (event: ProxyEvent) => void;
    readonly onPinEvent?: (event: PinEvent) => void;
    readonly enable?: GuardToggles;
    readonly upstreamRequestTimeoutMs?: number;
    /**
     * Zero-downtime reconnection. **Enabled by default** — this is the week-2
     * reliability deliverable, and a security proxy that takes the editor
     * session down whenever the server it is watching bounces gets uninstalled.
     *
     * Pass `{ enabled: false }` for the week-1 behaviour (upstream close tears
     * the client leg down immediately). See `src/transport/reconnect.ts` for the
     * retry schedule, the buffer bound and the replay semantics, and
     * `ToolwallProxy.#reverifyAfterReconnect` for why a reconnect cannot be a
     * path around a guard.
     */
    readonly reconnect?: Partial<ReconnectPolicy>;
    /**
     * Called with each upstream transport as it is created, including the
     * replacements a reconnect builds.
     *
     * A reconnect spawns a **new child process with a new stderr pipe**, so a
     * caller that attached a stderr relay to the first transport would go
     * quiet after the first restart. This is how it re-attaches.
     */
    readonly onUpstreamTransport?: (transport: StdioClientTransport) => void;
}

export interface Toolwall {
    readonly proxy: ToolwallProxy;
    readonly serverId: string;
    readonly era: ProtocolEra;
    readonly pins: PinStore;
    readonly audit: AuditLog;
    /** `undefined` when pinning is disabled. */
    readonly pinGuard: MetadataPinGuard | undefined;
    readonly tools: ToolDefinitionSource;
    /** The T-07 spawn record. `pid` is null until `start()`. */
    readonly spawnAudit: SpawnAudit;
    /**
     * The upstream transport, exposed for two things only: reading `pid` after `start()`, and
     * relaying the child's `stderr`. It is piped rather than inherited so the child can never
     * write to OUR stdout, which under stdio transport is the protocol channel.
     *
     * This is the transport for the FIRST upstream process. A reconnect builds a new one; use
     * `onUpstreamTransport` to follow it, or `currentUpstreamTransport` to read the live one.
     */
    readonly upstreamTransport: StdioClientTransport;
    /** The upstream transport currently in use, which a reconnect replaces. */
    readonly currentUpstreamTransport: StdioClientTransport;
    /** Names of the guards actually registered, for a startup banner that does not lie. */
    readonly registeredGuards: readonly string[];
    start(): Promise<void>;
    close(): Promise<void>;
    closeWhenIdle(timeoutMs?: number): Promise<void>;
}

/** Response-leg methods whose payload carries a pinnable surface, across both eras. */
const PINNED_RESPONSE_METHODS = [
    'initialize',
    'server/discover',
    'tools/list',
    'notifications/tools/list_changed'
] as const;

/**
 * Build the whole product: spawn-hardened upstream transport, guard pipeline, proxy, audit.
 *
 * Throws `SpawnPolicyError` before anything is executed if the spawn spec fails T-07 validation.
 * Nothing is spawned and no transport is started until `start()` is awaited.
 */
export function assembleToolwall(options: ToolwallOptions): Toolwall {
    const era = options.era ?? DEFAULT_PROTOCOL_ERA;
    const policy = options.policy ?? defaultPolicy();
    const audit = options.audit ?? new AuditLog();
    const enable = options.enable ?? {};

    const upstream = createUpstreamStdioTransport(options.spec, options.spawnPolicy ?? {});
    const serverId = options.serverId ?? upstream.serverId;

    audit.record({
        kind: 'spawn',
        serverId,
        detail: {
            command: upstream.audit.command,
            args: upstream.audit.args,
            cwd: upstream.audit.cwd,
            // Names only. Values are never written anywhere.
            envKeys: upstream.audit.envKeys,
            warnings: upstream.audit.warnings.map(w => w.ruleId)
        }
    });

    const tools = new PinnedToolDefinitionSource(options.pins);
    const sink = audit.sink();

    const pipeline = new DefaultGuardPipeline({
        ...(options.confirmationProvider !== undefined
            ? { confirmationProvider: options.confirmationProvider }
            : {}),
        onGuardError: (guardName, ctx, error) => {
            audit.record({
                kind: 'lifecycle',
                serverId: ctx.serverId,
                method: ctx.method,
                direction: ctx.direction,
                detail: {
                    event: 'guard-crashed',
                    guard: guardName,
                    error: error instanceof Error ? error.message : String(error)
                }
            });
        }
    });

    const registeredGuards: string[] = [];

    // --- metadata guards (Dev 2) ------------------------------------------
    let pinGuard: MetadataPinGuard | undefined;
    if (enable.pinning !== false) {
        pinGuard = new MetadataPinGuard({
            store: options.pins,
            era,
            ...(options.pinMode !== undefined ? { mode: options.pinMode } : {}),
            ...(options.onUnverifiable !== undefined ? { onUnverifiable: options.onUnverifiable } : {}),
            onEvent: (event: PinEvent) => {
                audit.record({
                    kind: 'pin',
                    serverId: event.serverId,
                    detail: {
                        event: event.kind,
                        pinKind: event.pinKind,
                        subject: event.subject,
                        message: event.message
                    }
                });
                options.onPinEvent?.(event);
            }
        });
        for (const method of PINNED_RESPONSE_METHODS) {
            pipeline.register({ direction: 'response', method, guard: pinGuard });
        }
        // The point of the whole product: re-verified before EVERY tools/call, not at connect.
        pipeline.register({ direction: 'request', method: 'tools/call', guard: pinGuard });
        registeredGuards.push(pinGuard.name);
    }

    // --- runtime guards (Dev 3) -------------------------------------------
    if (enable.schema !== false) {
        // C-1: `tools` is the PIN STORE, never the live listing.
        const schemaGuard = new SchemaGuard({ policy, tools, audit: sink });
        pipeline.register({ direction: 'request', method: 'tools/call', guard: schemaGuard });
        registeredGuards.push(schemaGuard.name);
    }

    if (enable.capability !== false) {
        const capabilityGuard = new CapabilityGuard({
            policy,
            tools,
            ...(options.baseDir !== undefined ? { baseDir: options.baseDir } : {}),
            audit: sink
        });
        pipeline.register({ direction: 'request', method: 'tools/call', guard: capabilityGuard });
        registeredGuards.push(capabilityGuard.name);
    }

    options.onUpstreamTransport?.(upstream.transport);
    let currentUpstream = upstream.transport;

    /**
     * Respawn for a reconnection attempt.
     *
     * `createUpstreamStdioTransport` re-runs `validateSpawnSpec` every time, so the T-07
     * argument-level controls are enforced on the replacement process too and not only on the
     * first one. Every restart is also recorded, which is the spec's "log all stdio transport
     * usage" obligation applied to the case where the process count is not one.
     */
    const createUpstreamTransport = (): StdioClientTransport => {
        const next = createUpstreamStdioTransport(options.spec, options.spawnPolicy ?? {});
        audit.record({
            kind: 'spawn',
            serverId,
            detail: {
                command: next.audit.command,
                args: next.audit.args,
                cwd: next.audit.cwd,
                envKeys: next.audit.envKeys,
                warnings: next.audit.warnings.map(w => w.ruleId),
                reason: 'reconnect'
            }
        });
        currentUpstream = next.transport;
        options.onUpstreamTransport?.(next.transport);
        return next.transport;
    };

    const proxy = new ToolwallProxy({
        clientTransport: options.clientTransport,
        upstreamTransport: upstream.transport,
        createUpstreamTransport,
        // Enabled by default; `{ enabled: false }` restores the week-1 behaviour.
        reconnect: { enabled: true, ...(options.reconnect ?? {}) },
        serverId,
        era,
        guards: pipeline,
        ...(options.upstreamRequestTimeoutMs !== undefined
            ? { upstreamRequestTimeoutMs: options.upstreamRequestTimeoutMs }
            : {}),
        onEvent: (event: ProxyEvent) => {
            recordProxyEvent(audit, serverId, event);
            options.onEvent?.(event);
        }
    });

    return {
        proxy,
        serverId,
        era,
        pins: options.pins,
        audit,
        pinGuard,
        tools,
        spawnAudit: upstream.audit,
        upstreamTransport: upstream.transport,
        get currentUpstreamTransport(): StdioClientTransport {
            return currentUpstream;
        },
        registeredGuards,
        start: () => proxy.start(),
        close: () => proxy.close(),
        closeWhenIdle: (timeoutMs?: number) =>
            timeoutMs === undefined ? proxy.closeWhenIdle() : proxy.closeWhenIdle(timeoutMs)
    };
}

function recordProxyEvent(audit: AuditLog, serverId: string, event: ProxyEvent): void {
    switch (event.kind) {
        case 'blocked':
            audit.record({
                kind: 'blocked',
                serverId: event.ctx.serverId,
                method: event.ctx.method,
                direction: event.ctx.direction,
                findings: event.findings,
                detail: { code: event.code }
            });
            return;
        case 'annotated':
            audit.record({
                kind: 'annotated',
                serverId: event.ctx.serverId,
                method: event.ctx.method,
                direction: event.ctx.direction,
                findings: event.findings
            });
            return;
        case 'findings':
            audit.record({
                kind: 'finding',
                serverId: event.ctx.serverId,
                method: event.ctx.method,
                direction: event.ctx.direction,
                findings: event.findings
            });
            return;
        case 'upstream-error':
        case 'client-error':
            audit.record({
                kind: 'lifecycle',
                serverId,
                detail: { event: event.kind, error: event.error.message }
            });
            return;
        case 'upstream-closed':
        case 'client-closed':
            audit.record({ kind: 'lifecycle', serverId, detail: { event: event.kind } });
            return;
        case 'upstream-reconnecting':
            audit.record({
                kind: 'lifecycle',
                serverId,
                detail: { event: event.kind, attempt: event.attempt, maxAttempts: event.maxAttempts, buffered: event.buffered }
            });
            return;
        case 'upstream-reconnected':
            audit.record({
                kind: 'lifecycle',
                serverId,
                detail: { event: event.kind, attempt: event.attempt, downtimeMs: event.downtimeMs, released: event.released }
            });
            return;
        case 'upstream-reconnect-refused':
            // The severe one: the process that came back is not the one that was approved.
            audit.record({
                kind: 'blocked',
                serverId,
                method: 'tools/list',
                direction: 'response',
                findings: event.findings,
                detail: { event: event.kind, buffered: event.buffered }
            });
            return;
        case 'upstream-reconnect-failed':
            audit.record({
                kind: 'lifecycle',
                serverId,
                detail: { event: event.kind, attempts: event.attempts, buffered: event.buffered, error: event.error.message }
            });
            return;
        default: {
            const exhaustive: never = event;
            void exhaustive;
        }
    }
}

// ---------------------------------------------------------------------------
// Public surface
// ---------------------------------------------------------------------------

export { AuditLog } from './audit/log.js';
export type { AuditEntry, AuditRecord, AuditRecordKind, AuditLogOptions } from './audit/log.js';
export { PinStore, PinConflictError, PinStoreIntegrityError, DEFAULT_PIN_FILE } from './audit/manifest.js';
export type { PinRecord, PinDecision, PinDecisionKind, PinFilter, PinStoreOptions } from './audit/manifest.js';
export { deriveServerId } from './audit/identity.js';
export type { ServerIdentity, StdioServerIdentity, HttpServerIdentity } from './audit/identity.js';

export { MetadataPinGuard } from './guards/metadata/drift.js';
export type { DriftReport, MetadataPinGuardOptions, PinEvent, PinEventKind } from './guards/metadata/drift.js';
export { CANONICALIZATION_VERSION, canonicalize, canonicalizeAndHash } from './guards/metadata/canonicalize.js';

export { SchemaGuard, CapabilityGuard } from './guards/runtime/index.js';
export { parsePolicy, defaultPolicy } from './policy/parse.js';
export type { ResolvedPolicy, ParseResult, PolicyError } from './policy/parse.js';
export type { AuditSink, ToolDefinition, ToolDefinitionSource } from './policy/contract.js';
export type { StrictnessTier } from './policy/schema.js';

export { ToolwallProxy, GuardBlockedError, RelayedRpcError } from './transport/proxy.js';
export type { ProxyEvent, ToolwallProxyOptions } from './transport/proxy.js';
export {
    DEFAULT_RECONNECT_POLICY,
    ReconnectGate,
    UpstreamUnavailableError,
    REPLAYABLE_READ_ONLY_METHODS,
    isReplayableMethod,
    resolveReconnectPolicy,
    totalBackoffMs
} from './transport/reconnect.js';
export type { ReconnectPolicy, ReplayPolicy, LinkState } from './transport/reconnect.js';
export {
    ExchangeCorrelator,
    MRTR_EMBEDDED_METHODS,
    INPUT_REQUIRED,
    eraUsesMrtr,
    hashRequestState,
    isInputRequired,
    readInputRequests,
    readRequestState,
    readResultType
} from './transport/mrtr.js';
export type { EmbeddedInputRequest, ResultType } from './transport/mrtr.js';
export {
    HEADER_METHOD,
    HEADER_NAME,
    HEADER_PARAM_PREFIX,
    HEADER_PROTOCOL_VERSION,
    HEADER_VALIDATING_REVISIONS,
    META_PROTOCOL_VERSION,
    decodeMirroredHeaderValue,
    encodeMirroredHeaderValue,
    mirroredHeadersForBody,
    needsSentinel,
    verifyHeaderBodyAgreement
} from './transport/headers.js';
export type { HeaderCheck, HeaderCheckOptions, HeaderViolation, IncomingHeaders } from './transport/headers.js';
export { DefaultGuardPipeline, ANY_METHOD } from './transport/pipeline.js';
export type { GuardPipeline, GuardRegistration, PipelineOutcome } from './transport/pipeline.js';
export {
    createUpstreamStdioTransport,
    validateSpawnSpec,
    SpawnPolicyError,
    describeInheritedEnvironment,
    serverIdentityForSpawn
} from './transport/spawn.js';
export type { SpawnSpec, SpawnPolicy, SpawnAudit, SpawnViolation } from './transport/spawn.js';

export * from './types/protocol.js';
