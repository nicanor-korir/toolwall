#!/usr/bin/env node
/**
 * toolwall CLI.
 *
 * STDOUT IS THE PROTOCOL CHANNEL. Under the stdio transport every byte written
 * to stdout is JSON-RPC framing owned by `StdioServerTransport`. Nothing in this
 * file — banner, warning, error, stack trace — may go to stdout. Everything
 * diagnostic goes to stderr, which the spec explicitly says is free-form and
 * MUST NOT be assumed to be errors (`docs/RESEARCH-BRIEF.md` §1.6).
 *
 * This file is a thin driver. The product is assembled in `src/index.ts`
 * (`assembleToolwall`), so the CLI, the integration tests and the benchmark all
 * exercise the same wiring rather than three lookalikes.
 */

import { readFile } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

import { parseArgs, USAGE, type ParsedArgs } from './args.js';
import { assembleToolwall, type AtrOptions, type Toolwall } from '../index.js';
import { AtrScanner } from '../guards/metadata/rules.js';
import { ttyChannel } from '../guards/runtime/confirm.js';
import { AuditLog } from '../audit/log.js';
import { PinStore, PinStoreIntegrityError } from '../audit/manifest.js';
import { defaultPolicy, parsePolicy, type ResolvedPolicy } from '../policy/parse.js';
import { SpawnPolicyError, describeInheritedEnvironment, type SpawnSpec } from '../transport/spawn.js';
import { totalBackoffMs } from '../transport/reconnect.js';
import type { ProxyEvent } from '../transport/proxy.js';

const VERSION = '0.0.0';

function err(line: string): void {
    process.stderr.write(`${line}\n`);
}

/** Load `toolwall-policy.json`, or fall back to the tier preset with no policy file. */
async function loadPolicy(opts: ParsedArgs): Promise<{ policy: ResolvedPolicy } | { error: string }> {
    if (opts.policyFile === undefined) {
        return { policy: defaultPolicy(opts.tier) };
    }
    let raw: unknown;
    try {
        raw = JSON.parse(await readFile(opts.policyFile, 'utf8'));
    } catch (error) {
        return { error: `could not read ${opts.policyFile}: ${error instanceof Error ? error.message : String(error)}` };
    }
    const parsed = parsePolicy(raw);
    if (!parsed.ok) {
        const detail = parsed.errors.map(e => `  - ${e.at === '' ? '<root>' : e.at}: ${e.message}`).join('\n');
        return { error: `${opts.policyFile} is not a valid policy:\n${detail}` };
    }
    for (const warning of parsed.warnings) {
        err(`toolwall: policy warning: ${warning}`);
    }
    return { policy: parsed.policy };
}

export async function main(argv: readonly string[]): Promise<number> {
    const parsed = parseArgs(argv);

    switch (parsed.kind) {
        case 'help':
            err(USAGE);
            return 0;
        case 'version':
            err(VERSION);
            return 0;
        case 'error':
            err(`toolwall: ${parsed.message}`);
            return 2;
        case 'run':
            break;
        default: {
            const exhaustive: never = parsed;
            void exhaustive;
            return 2;
        }
    }

    const opts = parsed.value;
    const spec: SpawnSpec = {
        command: opts.command,
        args: opts.args,
        ...(opts.cwd !== undefined ? { cwd: opts.cwd } : {}),
        passthroughEnv: opts.passthroughEnv
    };

    const loaded = await loadPolicy(opts);
    if ('error' in loaded) {
        err(`toolwall: ${loaded.error}`);
        return 2;
    }

    // Security state. Fail closed: a pin file we cannot account for takes the proxy offline
    // rather than starting with unknown pins (CVE-2025-54136 is the auto-accept failure mode).
    const storeCwd = opts.cwd === undefined ? process.cwd() : path.resolve(opts.cwd);
    let pins: PinStore;
    try {
        pins = await PinStore.open({
            cwd: storeCwd,
            ...(opts.pinFile !== undefined ? { path: opts.pinFile } : {})
        });
    } catch (error) {
        if (error instanceof PinStoreIntegrityError) {
            err(`toolwall: ${error.message}`);
            return 4;
        }
        throw error;
    }
    for (const warning of pins.warnings) {
        err(`toolwall: pin store warning: ${warning}`);
    }

    const audit = new AuditLog({
        cwd: storeCwd,
        ...(opts.auditFile !== undefined ? { file: opts.auditFile } : {}),
        onWriteError: error => err(`toolwall: audit write failed: ${error instanceof Error ? error.message : String(error)}`)
    });

    // The advisory detector, only when the operator named a lane. Loading it is slow (~780 YAML
    // files) and the package is an optional dependency that may not be installed at all, so the
    // failure is explained rather than thrown as a module-resolution stack trace: "advisory
    // detector unavailable" must never look like "toolwall is broken".
    let atr: AtrOptions | undefined;
    if (opts.advisoryRules !== undefined) {
        try {
            const scanner = await AtrScanner.create({ lane: opts.advisoryRules });
            atr = { scanner, mode: 'advisory' };
            err(
                `toolwall: advisory rules ON, lane=${opts.advisoryRules}, ${scanner.ruleCount} rules loaded. ` +
                    'This detector NEVER blocks — matches go to stderr and the audit log only.'
            );
        } catch (error) {
            err(`toolwall: --advisory-rules could not start: ${error instanceof Error ? error.message : String(error)}`);
            return 2;
        }
    }

    // C-14: one confirmation channel, opened once, for the life of the session. Opened here rather
    // than inside `assembleToolwall` so the CLI can say on stderr whether a human can actually be
    // reached — an operator who thinks confirmation is available when it is not will misread every
    // fail-closed block that follows.
    const channel = ttyChannel();
    if (channel === undefined) {
        err(
            'toolwall: no controlling terminal, so nothing can ask you to confirm anything. ' +
                'Every verdict that needs a human fails closed. This is normal when a client spawned toolwall.'
        );
    }

    let toolwall: Toolwall;
    try {
        toolwall = assembleToolwall({
            clientTransport: new StdioServerTransport(),
            spec,
            spawnPolicy: {
                ...(opts.allowedCommands !== undefined ? { allowedCommands: opts.allowedCommands } : {}),
                allowInlineCode: opts.allowInlineCode,
                allowPrivilegePivots: opts.allowPrivilegePivots
            },
            era: opts.era,
            pins,
            policy: loaded.policy,
            audit,
            pinMode: opts.pinMode,
            onUnverifiable: opts.onUnverifiable,
            baseDir: storeCwd,
            reconnect: {
                enabled: opts.reconnect,
                maxAttempts: opts.reconnectAttempts,
                replayInFlight: opts.replayInFlight
            },
            // A reconnect spawns a NEW child with a NEW stderr pipe. Without
            // re-attaching here the server's diagnostics would go silent after
            // the first restart, which is exactly when an operator wants them.
            onUpstreamTransport: transport => {
                transport.stderr?.on('data', (chunk: Buffer | string) => {
                    process.stderr.write(chunk);
                });
            },
            ...(opts.serverId !== undefined ? { serverId: opts.serverId } : {}),
            ...(opts.noGuards
                ? { enable: { pinning: false, schema: false, capability: false, result: false, unicode: false } }
                : {}),
            ...(atr !== undefined ? { atr } : {}),
            confirmationChannel: channel ?? null,
            onConfirmation: record =>
                err(
                    `toolwall: confirmation ${record.outcome} for ${record.rule ?? 'an unnamed rule'} ` +
                        `on ${record.ctx.method} (${record.remaining} left this session)`
                ),
            onEvent: (event: ProxyEvent) => reportEvent(event, opts.verbose)
        });
    } catch (error) {
        if (error instanceof SpawnPolicyError) {
            err(error.message);
            return 3;
        }
        throw error;
    }

    // The spec asks stdio proxies to log all transport usage. This is that log.
    // Names only for the environment; values are never written anywhere.
    const env = describeInheritedEnvironment(spec);
    err(
        `toolwall: spawning upstream serverId=${toolwall.serverId} command=${JSON.stringify(toolwall.spawnAudit.command)} args=${JSON.stringify(toolwall.spawnAudit.args)} cwd=${JSON.stringify(toolwall.spawnAudit.cwd)} env=[${env.effective.join(',')}]`
    );
    for (const warning of toolwall.spawnAudit.warnings) {
        err(`toolwall: warning [${warning.ruleId}] ${warning.message}`);
    }

    if (opts.noGuards) {
        err('toolwall: --no-guards is set. Every control is OFF; this is a bare passthrough and defends nothing.');
    } else {
        err(
            `toolwall: guards=[${toolwall.registeredGuards.join(',')}] tier=${loaded.policy.tier} pin-mode=${opts.pinMode} on-unverifiable=${opts.onUnverifiable} pins=${pins.path} (${pins.size} pinned) confirm-budget=${loaded.policy.confirmation.maxPrompts}${channel === undefined ? ' (no tty: confirm fails closed)' : ''}`
        );
    }
    const reconnect = toolwall.proxy.reconnectPolicy;
    err(
        reconnect.enabled
            ? `toolwall: reconnect=on attempts=${reconnect.maxAttempts} over ~${totalBackoffMs(reconnect)}ms buffer<=${reconnect.maxBufferedRequests} replay-in-flight=${reconnect.replayInFlight} reverify=${reconnect.reverifyOnReconnect}`
            : 'toolwall: reconnect=off; an upstream blip ends the client session.'
    );
    if (opts.verbose) {
        err(`toolwall: env inherited from SDK defaults: [${env.sdkDefaults.join(',')}]`);
        err(`toolwall: env explicitly passed through: [${env.passthrough.join(',')}]`);
        err('toolwall: the full process environment is NOT forwarded to the child.');
        if (audit.path !== undefined) {
            err(`toolwall: audit log: ${audit.path}`);
        }
    }

    // The child's stderr is piped, not inherited, so it can never contaminate
    // our stdout; `onUpstreamTransport` above relays it verbatim to ours, for
    // the first process and for every replacement a reconnect spawns.

    const shutdown = (): void => {
        void persist(toolwall)
            .then(() => toolwall.close())
            .finally(() => process.exit(0));
    };
    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);

    try {
        await toolwall.start();
    } catch (error) {
        err(`toolwall: failed to start: ${error instanceof Error ? error.message : String(error)}`);
        await toolwall.close();
        return 1;
    }

    if (opts.verbose) {
        err(`toolwall: proxying (era=${toolwall.era}, pid=${toolwall.upstreamTransport.pid ?? 'unknown'})`);
    }

    // Stay alive until one of the two legs closes; `ToolwallProxy` tears the
    // other one down, which lets the event loop drain and the process exit.
    //
    // `StdioServerTransport` never reports EOF on stdin (it only listens for
    // 'data' and 'error'), so the client going away has to be detected here.
    // When it does, requests it already sent may still be in flight upstream:
    // drain them rather than dropping their responses on the floor.
    let clientGone = false;
    await new Promise<void>(resolve => {
        const poll = setInterval(() => {
            if (toolwall.proxy.closed) {
                clearInterval(poll);
                resolve();
            }
        }, 100);
        poll.unref();
        process.stdin.once('end', () => {
            clientGone = true;
            clearInterval(poll);
            resolve();
        });
    });

    if (clientGone) {
        await toolwall.closeWhenIdle();
    } else {
        await toolwall.close();
    }
    await persist(toolwall);
    return 0;
}

/**
 * Persist security state on the way out.
 *
 * Pins adopted under TOFU during this session live in memory until flushed; losing them means
 * the next session trusts the same definitions on first use all over again, which is the exact
 * window Deadbugz walks through. A flush failure is reported, never swallowed.
 */
async function persist(toolwall: Toolwall): Promise<void> {
    try {
        if (toolwall.pins.dirty) {
            await toolwall.pins.flush();
        }
    } catch (error) {
        err(`toolwall: could not write the pin store: ${error instanceof Error ? error.message : String(error)}`);
    }
    try {
        await toolwall.audit.flush();
    } catch (error) {
        err(`toolwall: could not write the audit log: ${error instanceof Error ? error.message : String(error)}`);
    }
}

function reportEvent(event: ProxyEvent, verbose: boolean): void {
    switch (event.kind) {
        case 'blocked':
            err(`toolwall: BLOCKED ${event.ctx.direction} ${event.ctx.method} code=${event.code}`);
            for (const f of event.findings) {
                err(`toolwall:   [${f.severity}] ${f.ruleId} at ${f.locus || '<payload>'}: ${f.message}`);
                err(`toolwall:   -> ${f.remediation}`);
            }
            break;
        case 'annotated':
        case 'findings':
            for (const f of event.findings) {
                err(`toolwall: [${f.severity}] ${f.ruleId} on ${event.ctx.direction} ${event.ctx.method} at ${f.locus || '<payload>'}: ${f.message}`);
            }
            break;
        case 'upstream-error':
            if (verbose) {
                err(`toolwall: upstream error: ${event.error.message}`);
            }
            break;
        case 'client-error':
            if (verbose) {
                err(`toolwall: client error: ${event.error.message}`);
            }
            break;
        case 'upstream-closed':
            if (verbose) {
                err('toolwall: upstream connection closed');
            }
            break;
        case 'client-closed':
            if (verbose) {
                err('toolwall: client connection closed');
            }
            break;
        case 'upstream-reconnecting':
            err(
                `toolwall: upstream connection lost; reconnect attempt ${event.attempt}/${event.maxAttempts}, ` +
                    `${event.buffered} request${event.buffered === 1 ? '' : 's'} buffered`
            );
            break;
        case 'upstream-reconnected':
            err(
                `toolwall: upstream reconnected after ${event.downtimeMs}ms on attempt ${event.attempt}; ` +
                    `re-verified against the pin store, releasing ${event.released} buffered request${event.released === 1 ? '' : 's'}`
            );
            break;
        case 'upstream-reconnect-refused':
            // Loud unconditionally. This is the rug pull arriving through a restart.
            err(
                'toolwall: REFUSED to resume. The upstream MCP server restarted and no longer matches what was approved, ' +
                    `so ${event.buffered} buffered request${event.buffered === 1 ? ' was' : 's were'} failed rather than released.`
            );
            for (const f of event.findings) {
                err(`toolwall:   [${f.severity}] ${f.ruleId} at ${f.locus || '<payload>'}: ${f.message}`);
                err(`toolwall:   -> ${f.remediation}`);
            }
            break;
        case 'upstream-reconnect-failed':
            err(
                `toolwall: upstream unreachable after ${event.attempts} attempts (${event.error.message}); ` +
                    `${event.buffered} buffered request${event.buffered === 1 ? '' : 's'} answered with -32603`
            );
            break;
        default: {
            const exhaustive: never = event;
            void exhaustive;
        }
    }
}

// Only run when executed as a binary, not when imported by a test.
const invokedDirectly = process.argv[1] !== undefined && /toolwall$|cli[/\\]index\.(js|ts)$/u.test(process.argv[1]);
if (invokedDirectly) {
    main(process.argv.slice(2))
        .then(code => {
            process.exitCode = code;
        })
        .catch((error: unknown) => {
            err(`toolwall: ${error instanceof Error ? (error.stack ?? error.message) : String(error)}`);
            process.exitCode = 1;
        });
}
