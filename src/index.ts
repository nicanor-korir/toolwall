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
 *      initialize        -> pin,uni,atr |  tools/call  -> 1. MetadataPinGuard  (identity)
 *      server/discover   -> pin,uni,atr |                 2. SchemaGuard       (contract)
 *      tools/list        -> pin,uni,atr |                 3. CapabilityGuard   (authority + egress)
 *      .../list_changed  -> pin         |                 4. ResultGuard       (ATPA sequence)
 *      tools/call        -> result      |
 *      resources/read    -> result      |
 *      prompts/get       -> result,uni  |
 *      elicitation/create-> result,uni  |
 *      sampling/create.. -> result,uni  |
 *      prompts/list      -> uni         |
 *      resources/list    -> uni         |
 *      resources/templates/list -> uni  |
 *      completion/complete      -> uni  |
 *                                     v
 *                                 AuditLog  (hash-chained; C-2 sink)
 * ```
 *
 * `uni` = `UnicodeHygieneGuard`, `atr` = `AtrAdvisoryGuard` (opt-in; never constructed unless the
 * operator hands in a scanner).
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
 * 3. **`CapabilityGuard` third.** It is the only one that touches the filesystem (`lstat` while
 *    resolving symlinks segment by segment), so it runs only on calls the two cheap deterministic
 *    checks already accepted. It is also where **egress** is enforced: `policy.egressFor()` plus
 *    the per-tool `network` grant, intersected (C-16).
 * 4. **`ResultGuard` last on the request leg.** Contract **C-12**: this registration is where the
 *    guard learns which tool a result belongs to and where the ATPA sequence check runs. Omitting
 *    it silently disables `outputSchema` enforcement AND ATPA with no error. It is last because
 *    the pipeline short-circuits on a block, so a call the three guards above rejected never gets
 *    recorded as "in flight" for a result that will never arrive.
 *
 * The pipeline short-circuits on the first `block`, so this order also means the finding a user
 * sees names the most fundamental problem rather than a downstream symptom of it.
 *
 * ## The response leg — contracts C-12 and C-13
 *
 * `ResultGuard` gets **six** registrations (three result methods + two server->client request
 * methods on the response leg, per C-4, + the request-leg `tools/call` above). `UnicodeHygieneGuard`
 * gets the ten response methods that carry server-authored text.
 *
 * Per **C-13**, `ToolwallProxy.#liftInputRequests` routes an MRTR `inputRequests` entry into the
 * pipeline as `("response", <embedded method>)`. So the `("response", "sampling/createMessage")`
 * and `("response", "elicitation/create")` registrations fire on the live 2025-11-25 server->client
 * request AND on the 2026-07-28 copy embedded in a `tools/call` result, with no era branch in any
 * guard. `roots/list` is deliberately left unregistered: it carries no server-authored text and
 * `ResultGuard` has no check for it — the outer `("response", "tools/call")` registration already
 * records every MRTR input request, `roots/list` included.
 *
 * ## What is NOT registered, and why that matters
 *
 * Guards are registered per `(direction, method)`, never with `ANY_METHOD`. `GuardPipeline`'s
 * `hasGuards()` fast path then returns false for every other method — `ping`, `roots/list`,
 * `resources/subscribe`, `logging/setLevel`, unknown and future methods — and the proxy forwards
 * the payload object by reference with no inspection, no clone and no re-serialization. That is
 * the transparency guarantee.
 *
 * Note honestly what the Week-2 registrations cost on the hot path: every `tools/call`,
 * `resources/read` and `prompts/get` RESULT now walks `measure()` (bounded at 200k nodes) and
 * `hasProtoKey()` instead of being forwarded by reference, and every listing walks `scanSurface()`.
 * That is new per-result work Week 1 never benchmarked. `bench/latency.ts` measures it and
 * `docs/ARCHITECTURE.md` C-11 records the numbers.
 */

import type { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';

import { AuditLog } from './audit/log.js';
import { DEFAULT_PIN_SCOPE, PinStore, type PinScope } from './audit/manifest.js';
import { MetadataPinGuard, type PinEvent } from './guards/metadata/drift.js';
import { AtrAdvisoryGuard, ATR_GUARD_RESPONSE_METHODS, type AtrMode, type AtrScanner } from './guards/metadata/rules.js';
import { UnicodeHygieneGuard, UNICODE_GUARD_RESPONSE_METHODS } from './guards/metadata/unicode.js';
import { CapabilityGuard } from './guards/runtime/capability-guard.js';
import {
    BudgetedConfirmationProvider,
    ttyChannel,
    type ConfirmationChannel,
    type ConfirmationRecord
} from './guards/runtime/confirm.js';
import { ResultGuard, RESULT_METHODS, SERVER_REQUEST_METHODS } from './guards/runtime/result-guard.js';
import { SchemaGuard } from './guards/runtime/schema-guard.js';
import type { Finding, GuardContext, ToolDefinition, ToolDefinitionSource } from './policy/contract.js';
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
 *
 * ## Scope — the gap Dev 2 flagged, and how far this closes it
 *
 * Pins are keyed on `(serverId, scope, kind, subject)`. `PinStore.get()` defaults `scope` to
 * `DEFAULT_PIN_SCOPE`, so before this class took a scope it could only ever read the default one.
 * That is correct **today**, because scope keying is opt-in and nothing sets a non-default scope —
 * but the moment an operator enables it, every lookup here would return `undefined` and every call
 * would route into `requireKnownSchema`. Fail-safe rather than fail-open, and still a schema layer
 * that has quietly stopped enforcing anything.
 *
 * Two halves, because the scope arrives from two different places:
 *
 *  - **Per session.** A stdio server is launched with one credential and keeps it for the life of
 *    the process, so `assembleToolwall({ pinScope })` sets `defaultScope` here and
 *    `resolveScope` on `MetadataPinGuard` from the same value. The two sides of C-1 cannot drift.
 *  - **Per call.** `get()` takes an explicit `scope` that overrides the session default. No guard
 *    passes it yet: `GuardContext` has no authorization field (the additive `authorizationScope?`
 *    Dev 2 requested of Dev 1 in `MetadataPinGuardOptions.resolveScope`). When it lands, the
 *    guards forward `ctx.authorizationScope` and nothing here changes.
 */
export class PinnedToolDefinitionSource implements ToolDefinitionSource {
    readonly #store: PinStore;
    readonly #defaultScope: PinScope;

    constructor(store: PinStore, defaultScope: PinScope = DEFAULT_PIN_SCOPE) {
        this.#store = store;
        this.#defaultScope = defaultScope;
    }

    /** The authorization scope this source reads when a caller does not name one. */
    get defaultScope(): PinScope {
        return this.#defaultScope;
    }

    get(serverId: string, toolName: string, scope?: PinScope): ToolDefinition | undefined {
        const record = this.#store.get(serverId, 'tool', toolName, scope ?? this.#defaultScope);
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

/**
 * Which guards to register. All default to `true`; setting one false turns that control off.
 *
 * There is deliberately no `atr` flag. The advisory `agent-threat-rules` detector is enabled by
 * handing in a scanner (`ToolwallOptions.atr`), never by a boolean — see the note there.
 */
export interface GuardToggles {
    readonly pinning?: boolean;
    readonly schema?: boolean;
    readonly capability?: boolean;
    /** `ResultGuard` — the whole response leg: bounds, `outputSchema`, ATPA, MRTR, elicitation. */
    readonly result?: boolean;
    /** `UnicodeHygieneGuard` — invisible-character and ANSI rejection on server metadata. */
    readonly unicode?: boolean;
}

/** How the advisory `agent-threat-rules` detector is turned on. See {@link ToolwallOptions.atr}. */
export interface AtrOptions {
    /**
     * A loaded scanner. Build it with `await AtrScanner.create()` — it is async, it reads ~780 YAML
     * files, and `agent-threat-rules` is an OPTIONAL dependency that may not be installed.
     */
    readonly scanner: AtrScanner;
    /** Default `"advisory"`: findings reach the audit log, the verdict stays `allow`. */
    readonly mode?: AtrMode;
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
    /**
     * Resolves `confirm` verdicts (T-06).
     *
     * Absent, one `BudgetedConfirmationProvider` is built here — **once per session**, per contract
     * C-14, because the budget is per instance and a per-call provider would have an infinite one.
     * Supply your own only to replace that policy wholesale.
     */
    readonly confirmationProvider?: ConfirmationProvider;
    /**
     * The interactive channel the default `BudgetedConfirmationProvider` prompts on.
     *
     * Omitted, `ttyChannel()` is used: `/dev/tty`, never stdout (C-3). It returns `undefined` when
     * there is no controlling terminal, and that value is passed through unchanged — an absent
     * channel is the fail-closed path, not an error (C-14).
     *
     * Pass `null` to state explicitly that this session has no interactive channel. Non-interactive
     * embedders should do that rather than relying on `/dev/tty` being absent: a test runner or a
     * daemon started from a terminal can still open it, and a guard that blocks for two minutes
     * waiting for a human nobody is watching is worse than one that fails closed immediately.
     */
    readonly confirmationChannel?: ConfirmationChannel | null;
    /** Every confirmation decision, for an operator channel (the CLI writes these to stderr). */
    readonly onConfirmation?: (record: ConfirmationRecord) => void;
    /**
     * The advisory `agent-threat-rules` detector. **Off unless this is supplied.**
     *
     * It is opt-in and takes a pre-built scanner rather than a boolean on purpose. `AtrScanner`
     * is measured at **0/8 catch and 0.0% FP on the `enforce` lane, 5/8 catch and 6.5% FP on
     * `alert`** (`test/unit/atr-fp.test.ts` prints the table). Shipping the enforcing lane on by
     * default would be security theatre: it blocks nothing that matters and is loud about the rest.
     * So nothing here constructs one, the default mode is `"advisory"`, and an operator who wants
     * the signal asks for it by name.
     */
    readonly atr?: AtrOptions;
    /**
     * Authorization scope for pin lookups (`PinScope`). Defaults to `DEFAULT_PIN_SCOPE`.
     *
     * Sets both halves of C-1 from one value: `MetadataPinGuard.resolveScope` (which scope pins are
     * written and verified under) and `PinnedToolDefinitionSource.defaultScope` (which scope the
     * runtime guards read). Setting only one of those would be worse than setting neither.
     */
    readonly pinScope?: PinScope;
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
    /** The one provider resolving `confirm` verdicts for this session (C-14). */
    readonly confirmationProvider: ConfirmationProvider;
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

    const pinScope = options.pinScope ?? DEFAULT_PIN_SCOPE;
    const tools = new PinnedToolDefinitionSource(options.pins, pinScope);
    const sink = audit.sink();

    /**
     * C-14 · ONE confirmation provider for the session.
     *
     * The budget is per instance, so constructing one per call would hand an attacker an unbounded
     * supply of prompts and hand the operator a rubber stamp. `ttyChannel()` returns `undefined`
     * with no controlling terminal and that value is passed straight through: an absent channel is
     * the fail-closed path (`no-channel`), not an error. `null` says so explicitly, for embedders
     * that know they are non-interactive even though `/dev/tty` happens to be openable.
     */
    const confirmationProvider: ConfirmationProvider =
        options.confirmationProvider ??
        new BudgetedConfirmationProvider({
            budget: policy.confirmation,
            channel: options.confirmationChannel === null ? undefined : (options.confirmationChannel ?? ttyChannel()),
            audit: sink,
            onDecision: (record: ConfirmationRecord) => {
                audit.record({
                    kind: 'lifecycle',
                    serverId: record.ctx.serverId,
                    method: record.ctx.method,
                    direction: record.ctx.direction,
                    detail: {
                        event: 'confirmation',
                        outcome: record.outcome,
                        rule: record.rule ?? 'none',
                        spent: record.spent,
                        remaining: record.remaining
                    }
                });
                options.onConfirmation?.(record);
            }
        });

    const pipeline = new DefaultGuardPipeline({
        confirmationProvider,
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
            // Both halves of C-1 read the same scope. See `PinnedToolDefinitionSource`.
            resolveScope: () => pinScope,
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

    /*
     * Invisible-character / ANSI rejection. Registered AFTER the pin guard on the methods they
     * share, for the C-10 reason: if the definition drifted, the text this guard is reading is
     * attacker-controlled as of that moment and the drift finding is the one to surface.
     *
     * It rejects rather than strips. A stripped description is one an attacker edited and we
     * laundered — and the pin hash would then be computed over our laundered copy, not over what
     * the server actually sent.
     */
    if (enable.unicode !== false) {
        const unicodeGuard = new UnicodeHygieneGuard({
            onFinding: (finding: Finding, ctx: GuardContext) => {
                sink([finding], ctx);
            }
        });
        for (const method of UNICODE_GUARD_RESPONSE_METHODS) {
            pipeline.register({ direction: 'response', method, guard: unicodeGuard });
        }
        registeredGuards.push(unicodeGuard.name);
    }

    /*
     * The advisory `agent-threat-rules` detector — constructed by the CALLER or not at all.
     * `enforce` lane: 0/8 caught. `alert` lane: 5/8 caught at 6.5% FP. Neither is a default.
     */
    if (options.atr !== undefined) {
        const atrGuard = new AtrAdvisoryGuard({
            scanner: options.atr.scanner,
            ...(options.atr.mode !== undefined ? { mode: options.atr.mode } : {}),
            onFinding: (finding: Finding, ctx: GuardContext) => {
                sink([finding], ctx);
            }
        });
        for (const method of ATR_GUARD_RESPONSE_METHODS) {
            pipeline.register({ direction: 'response', method, guard: atrGuard });
        }
        registeredGuards.push(atrGuard.name);
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

    /*
     * C-12 · SIX registrations, and the request-leg one is not optional.
     *
     * Five on the response leg — three result methods plus the two server->client REQUEST methods,
     * which travel toward the client and are therefore inspected on the "response" leg (C-4) — and
     * one on the request leg. That last one is where the guard records which tool is in flight
     * (without it there is nothing to correlate a result against, so `outputSchema` enforcement
     * silently stops) and where the ATPA sequence check runs. Both failures are silent: the guard
     * still runs, still reports, and enforces nothing. The count is asserted below.
     *
     * It goes LAST on `tools/call` request. Order is free per C-12 — it reads params and never
     * mutates them — but last means a call the three guards above blocked is never recorded as
     * in-flight, so the pending queue cannot accumulate calls whose results will never arrive.
     */
    if (enable.result !== false) {
        const resultGuard = new ResultGuard({ policy, tools, audit: sink });
        for (const method of RESULT_METHODS) {
            pipeline.register({ direction: 'response', method, guard: resultGuard });
        }
        for (const method of SERVER_REQUEST_METHODS) {
            pipeline.register({ direction: 'response', method, guard: resultGuard });
        }
        pipeline.register({ direction: 'request', method: 'tools/call', guard: resultGuard });
        registeredGuards.push(resultGuard.name);

        // A guard that is one registration short defends nothing and says nothing. Fail loudly at
        // assembly time rather than shipping a response leg that reports "clean" on everything.
        const registered = RESULT_METHODS.length + SERVER_REQUEST_METHODS.length + 1;
        if (registered !== 6) {
            throw new Error(
                `toolwall: ResultGuard must be registered on 6 (direction, method) pairs per contract C-12, ` +
                    `but this build registers ${registered}. Omitting one silently disables outputSchema and ATPA.`
            );
        }
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
        confirmationProvider,
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

export {
    DEFAULT_HAZARD_POLICY,
    UNICODE_GUARD_RESPONSE_METHODS,
    UnicodeHygieneGuard,
    hasHazard,
    scanSurface,
    scanText
} from './guards/metadata/unicode.js';
export type { Hazard, HazardClass, HazardDisposition, SurfaceHazard, UnicodeHygieneGuardOptions } from './guards/metadata/unicode.js';
export { ATR_GUARD_RESPONSE_METHODS, AtrAdvisoryGuard, AtrScanner, METADATA_RULE_CATEGORIES } from './guards/metadata/rules.js';
export type { AtrAdvisoryGuardOptions, AtrLane, AtrMode, AtrScannerOptions } from './guards/metadata/rules.js';

export { SchemaGuard, CapabilityGuard } from './guards/runtime/index.js';
export { ResultGuard, RESULT_METHODS, SERVER_REQUEST_METHODS } from './guards/runtime/result-guard.js';
export type { ResultGuardOptions } from './guards/runtime/result-guard.js';
export { BudgetedConfirmationProvider, ttyChannel, renderPrompt } from './guards/runtime/confirm.js';
export type {
    BudgetedConfirmationOptions,
    ConfirmationChannel,
    ConfirmationOutcome,
    ConfirmationRecord
} from './guards/runtime/confirm.js';
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
