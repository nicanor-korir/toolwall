/**
 * CLI argument parsing. Kept separate from `index.ts` so it is unit-testable
 * without spawning anything.
 */

import type { AtrLane } from '../guards/metadata/rules.js';
import type { StrictnessTier } from '../policy/schema.js';
import { DEFAULT_LISTEN_HOST, splitAuthority } from '../transport/http.js';
import type { ReplayPolicy } from '../transport/reconnect.js';
import { isProtocolEra, rendered, type ProtocolEra } from '../types/protocol.js';

export type PinMode = 'tofu' | 'strict';
export type UnverifiableDisposition = 'block' | 'confirm' | 'allow';

const TIERS = ['permissive', 'balanced', 'strict'] as const;
const PIN_MODES = ['tofu', 'strict'] as const;
const UNVERIFIABLE = ['block', 'confirm', 'allow'] as const;
const REPLAY = ['none', 'read-only-methods', 'all'] as const;

export interface ParsedArgs {
    readonly command: string;
    readonly args: readonly string[];
    readonly cwd?: string;
    readonly allowedCommands?: readonly string[];
    readonly passthroughEnv: readonly string[];
    readonly era: ProtocolEra;
    readonly serverId?: string;
    readonly verbose: boolean;
    readonly allowInlineCode: boolean;
    readonly allowPrivilegePivots: boolean;
    /** Path to `toolwall-policy.json`. Absent means the tier preset with no policy file. */
    readonly policyFile?: string;
    /** Strictness tier when no policy file is given. Defaults to `balanced`. */
    readonly tier: StrictnessTier;
    /** Path to the pin store. Defaults to `.toolwall/pins.json` under `--cwd`. */
    readonly pinFile?: string;
    /** Path to the hash-chained audit log. Absent means in-memory only. */
    readonly auditFile?: string;
    readonly pinMode: PinMode;
    readonly onUnverifiable: UnverifiableDisposition;
    /**
     * Run as a bare passthrough with every guard disabled. Exists so the added latency of the
     * guard stack can be measured against the same binary, and so an operator can bisect a
     * suspected false positive. It turns the product off; the CLI says so on stderr.
     */
    readonly noGuards: boolean;
    /**
     * Lane for the advisory `agent-threat-rules` detector, or `undefined` to leave it OFF —
     * which is the default and the only honest one.
     *
     * Measured (`test/unit/atr-fp.test.ts`, printed on every run): the `enforce` lane catches
     * **0 of 8** published tool-poisoning payloads at 0.0% FP; `alert` catches 5 of 8 at 6.5% FP
     * on the benign metadata corpus. Neither justifies being on by default, and the verdict is
     * `allow` regardless of lane — the findings go to the audit log and stderr, nothing is blocked.
     * The rule pack is a 9.3 MB optional dependency; naming this flag is what installs the cost.
     */
    readonly advisoryRules?: AtrLane;
    /**
     * Inferred capability policy. **On by default**; `--no-inference` turns it off.
     *
     * Measured (`test/unit/infer.test.ts`, `test/unit/fp-harness.test.ts`): at zero configuration
     * it catches 16/17 capability-abuse calls (94.1%) against 0/17 without it, for 0.0% false
     * positives on the 63-case benign corpus — the same 0.0% the no-inference baseline scores. Off, the
     * capability layer enforces exactly what a policy file declares, which at day zero is nothing.
     */
    readonly inference: boolean;
    /**
     * True when the operator named at least one `--provenance*` / `--verify-provenance` flag.
     *
     * Absent, `assembleToolwall` is not given a `provenance` option at all and the entire T-09 path
     * — including the offline half — never runs. The *network* half additionally requires
     * `--verify-provenance`; that gate lives in `parseProvenanceArgs`, not here.
     */
    readonly provenance: boolean;
    /** `--server-json <path>`: a `server.json` whose `fileSha256` the artifact is checked against. */
    readonly serverJsonFile?: string;
    /**
     * Buffer and retry when the upstream server blips, instead of taking the
     * client session down with it. On by default.
     */
    readonly reconnect: boolean;
    readonly reconnectAttempts: number;
    /**
     * What to do with a request that was already on the wire when the
     * connection died. `read-only-methods` (default) resends only listing/read
     * methods; a `tools/call` whose execution status is unknown gets an explicit
     * `-32603` rather than being run a second time. See
     * `src/transport/reconnect.ts`.
     */
    readonly replayInFlight: ReplayPolicy;
    /**
     * Serve the client leg over Streamable HTTP instead of stdio.
     *
     * `undefined` means stdio, which is the default and stays the default. Present means a
     * loopback HTTP listener with a mandatory bearer token — see `src/transport/listener.ts` for
     * why every part of that sentence is load-bearing.
     */
    readonly listen?: ListenOptions;
}

/** `--listen` and its modifiers. Only constructed when `--listen` was actually named. */
export interface ListenOptions {
    readonly host: string;
    readonly port: number;
    readonly path: string;
    /** From `--listen-token`. Absent means one is generated and printed on stderr. */
    readonly token?: string;
    readonly allowedOrigins: readonly string[];
}

export type ParseResult =
    | { readonly kind: 'run'; readonly value: ParsedArgs }
    | { readonly kind: 'help' }
    | { readonly kind: 'version' }
    | { readonly kind: 'error'; readonly message: string };

/**
 * `--help`. Tagged `rendered` so it is typed `Rendered`, which is what the CLI's stderr writer
 * accepts — every fragment here is source code, there are no interpolations, and the tag passes
 * static fragments through verbatim, so the column alignment survives untouched.
 */
export const USAGE = rendered`toolwall — local-first MCP guardrail proxy

USAGE
  toolwall --server "<command> [args...]" [options]
  toolwall [options] -- <command> [args...]

REQUIRED
  --server <string>       Command line launching the upstream MCP server.
                          Quoted words are honoured; shell metacharacters are
                          NOT interpreted and are rejected (threat T-07).

OPTIONS
  --cwd <dir>             Working directory for the child process.
  --allow-command <name>  Restrict the spawnable binary to this basename.
                          Repeatable. Omit for no binary allowlist — validation
                          of the server command's own arguments still applies
                          either way. None of the three flags in this group
                          inspect TOOL arguments; that is the capability layer,
                          under GUARDS below.
  --pass-env <NAME>       Copy NAME from toolwall's environment into the child.
                          Repeatable. Nothing beyond the SDK's default set is
                          passed otherwise; run with --verbose to see exactly
                          what the child inherits.
  --era <revision>        Protocol era: 2025-11-25 (default) or 2026-07-28.
  --server-id <id>        Override the derived per-connection server identity.
  --allow-inline-code     Applies to the SERVER COMMAND you pass in --server,
                          not to tool arguments. Permits an interpreter to be
                          launched with an inline-code flag: sh -c, node -e,
                          python -c, powershell -EncodedCommand and the rest.
                          This is the documented bypass for --allow-command and
                          disables the primary T-07 control. Do not.
  --allow-privilege-pivot Also applies to the SERVER COMMAND, not to tool
                          arguments. Permits sudo / su / doas / env / ssh /
                          docker / kubectl / xargs and similar as the command
                          itself — binaries whose whole job is to run some
                          OTHER program, which makes a binary allowlist
                          meaningless.
  -v, --verbose           Diagnostics on stderr. Never on stdout: under stdio
                          transport stdout is the protocol channel.
  -h, --help              This text.
  --version               Print the version.

GUARDS
  --policy <file>         Capability policy (toolwall-policy.json). Omit to use
                          the tier preset with no per-tool declarations.
  --tier <name>           permissive | balanced (default) | strict. Ignored when
                          --policy is given; the file states its own tier.
  --pins <file>           Pin store. Default .toolwall/pins.json under --cwd.
  --pin-mode <mode>       tofu (default) pins the first definition it sees and
                          enforces from then on. strict never pins on its own:
                          an unapproved tool needs a human.
  --on-unverifiable <d>   block | confirm (default) | allow. What to do with a
                          tools/call that cannot be checked against a pin.
  --audit-log <file>      Append the hash-chained audit log here (JSONL). Local
                          file only; toolwall makes no network calls, ever.
  --no-guards             Bare passthrough, every guard off. This turns the
                          product off. For latency comparison and FP bisection.
  --no-inference          Turn OFF the inferred capability policy, which is ON
                          by default. Inference derives each tool's filesystem
                          and network capability from its own PINNED inputSchema,
                          so a calculator needs no hand-written rule saying it
                          may not read ~/.ssh/id_rsa. Measured on this repo's
                          corpora: 16/17 capability-abuse calls caught (94.1%)
                          with no policy file, against 0/17 without it, at 0.0%
                          false positives on the 63-case benign corpus — the same
                          0.0% the no-inference baseline scores. An explicit
                          declaration in --policy always wins per capability.
                          Turning this off means the capability layer enforces
                          only what a policy file declares.
  --advisory-rules <lane> enforce | alert | hunt. Turn ON the advisory
                          agent-threat-rules detector, which is OFF by default.
                          It never blocks: matches go to stderr and the audit
                          log and the verdict stays allow. Measured on this
                          repo's corpora: enforce catches 0/8 published
                          payloads, alert catches 5/8 at 6.5% false positives.
                          Needs the optional agent-threat-rules package
                          (9.3 MB); startup gets ~1s slower while it loads.

PROVENANCE (T-09) — OFF unless you name one of these
  --verify-provenance     Look up the package's npm build attestation. THIS IS
                          THE ONE FLAG THAT MAKES A NETWORK REQUEST. Without it
                          toolwall makes none, ever. It reports whether an
                          attestation exists and who published it; it does NOT
                          cryptographically verify the Sigstore bundle, and
                          provenance says who published a package, never that
                          its tools are honest.
  --provenance-registry <url>  Registry origin to query. https only. Default
                          https://registry.npmjs.org
  --provenance-bundle     Also fetch the attestation bundle to read the source
                          repo, commit and builder out of the SLSA predicate.
  --server-json <path>    A server.json describing this server. Its fileSha256
                          is the one check here that is fully offline and
                          deterministic.
  --provenance-artifact <path>  Local artifact (.mcpb / tarball) to hash against
                          that fileSha256. Offline; no network involved.

HTTP (Streamable HTTP, RFC-shaped per --era)
  --listen [host:port]    Serve the CLIENT leg over Streamable HTTP instead of
                          stdio. Default 127.0.0.1:0 (the OS picks a port,
                          printed on stderr). The upstream server is still
                          spawned over stdio.
                          SECURITY, none of which is optional:
                            * Binds LOOPBACK. Naming a non-loopback host is
                              accepted and warned about loudly; it makes the
                              proxy reachable from your network.
                            * Origin and Host are validated; a mismatch is 403.
                              CVE-2025-66414 shipped DNS-rebinding protection
                              OFF BY DEFAULT in the TypeScript SDK, and the same
                              default shipped simultaneously in the Python, Go,
                              Java, Rust and Ruby SDKs. toolwall enables it.
                            * A bearer token is REQUIRED on every request, and
                              generated if you do not supply one. There is no
                              flag to turn it off. CVE-2025-49596 (MCP
                              Inspector, CVSS 9.4) and CVE-2026-23744 (MCPJam,
                              CVSS 9.8, exploited in the wild from Feb 2026)
                              were both unauthenticated local endpoints a web
                              page could reach.
                            * Mirrored headers (Mcp-Method, Mcp-Name,
                              Mcp-Param-*) are checked against the JSON-RPC
                              body. Disagreement is 400 + -32020 HeaderMismatch.
                              A proxy that evaluates policy on the header while
                              execution follows the body enforces nothing.
                          Under --era 2026-07-28 the endpoint is POST-only with
                          no sessions and no resumability; GET and DELETE answer
                          405. Under 2025-11-25 sessions and the standalone GET
                          SSE stream work as that revision defines them.
  --listen-path <path>    Endpoint path. Default /mcp.
  --listen-token <tok>    Bearer token clients must present. Generated when
                          omitted; printed once on stderr, never written to disk.
  --listen-allow-origin <origin>  Additionally accept this web Origin (exact
                          scheme+host+port). Repeatable. Loopback origins are
                          accepted without being named; everything else is 403.

RESILIENCE
  --no-reconnect        Do not buffer and retry when the upstream server
                          blips; close the client session immediately instead.
  --reconnect-attempts <n>  Attempts before returning -32603 to the buffered
                          requests. Default 3, over roughly two seconds.
  --replay-in-flight <p>  none | read-only-methods (default) | all. What to do
                          with a request already on the wire when the
                          connection died. Its execution status is unknown, so
                          the default resends only listing/read methods and
                          answers -32603 for anything that may have side
                          effects. Setting all accepts at-least-once delivery.
                          Note the honest limit of the default: a hostile
                          server CAN make resources/read or prompts/get
                          side-effecting, so read-only-methods accepts
                          at-most-twice execution of server-side-only effects.
                          Use none if you do not accept that.
                          A reconnected server is ALWAYS re-verified against
                          the pin store before any buffered request is
                          released; that is not configurable.

EXAMPLE
  toolwall --server "node ./path/to/server.js"
  toolwall --allow-command node -- node ./path/to/server.js
  toolwall --policy ./toolwall-policy.json --audit-log ./toolwall-audit.jsonl \\
           --server "node ./path/to/server.js"
  toolwall --listen 127.0.0.1:8099 --server "node ./path/to/server.js"
`;

/**
 * Split a command line into argv.
 *
 * Honours single quotes, double quotes and backslash escaping so a real path
 * with a space works. Deliberately does NOT expand variables, globs, `~`,
 * subshells or any operator: this is a tokenizer, not a shell. Anything that
 * looks like shell syntax survives as a literal argument and is then rejected
 * by `validateSpawnSpec`, so a user who pipes a shell string in here gets an
 * error rather than an execution.
 */
export function tokenizeCommandLine(input: string): string[] {
    const tokens: string[] = [];
    let current = '';
    let has = false;
    let quote: '"' | "'" | null = null;

    for (let i = 0; i < input.length; i++) {
        const ch = input[i];
        if (ch === undefined) {
            break;
        }
        if (ch === '\\' && quote !== "'") {
            const next = input[i + 1];
            if (next !== undefined) {
                current += next;
                has = true;
                i += 1;
                continue;
            }
        }
        if (quote !== null) {
            if (ch === quote) {
                quote = null;
            } else {
                current += ch;
            }
            has = true;
            continue;
        }
        if (ch === '"' || ch === "'") {
            quote = ch;
            has = true;
            continue;
        }
        if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r') {
            if (has) {
                tokens.push(current);
                current = '';
                has = false;
            }
            continue;
        }
        current += ch;
        has = true;
    }

    if (quote !== null) {
        throw new Error(`Unterminated ${quote === '"' ? 'double' : 'single'} quote in --server value.`);
    }
    if (has) {
        tokens.push(current);
    }
    return tokens;
}

export function parseArgs(argv: readonly string[]): ParseResult {
    let serverLine: string | undefined;
    let cwd: string | undefined;
    let serverId: string | undefined;
    let era: ProtocolEra = '2025-11-25';
    let verbose = false;
    let allowInlineCode = false;
    let allowPrivilegePivots = false;
    let policyFile: string | undefined;
    let pinFile: string | undefined;
    let auditFile: string | undefined;
    let tier: StrictnessTier = 'balanced';
    let pinMode: PinMode = 'tofu';
    let onUnverifiable: UnverifiableDisposition = 'confirm';
    let noGuards = false;
    let advisoryRules: AtrLane | undefined;
    let inference = true;
    let provenance = false;
    let serverJsonFile: string | undefined;
    let reconnect = true;
    let reconnectAttempts = 3;
    let replayInFlight: ReplayPolicy = 'read-only-methods';
    let listen = false;
    let listenHost = DEFAULT_LISTEN_HOST;
    let listenPort = 0;
    let listenPath = '/mcp';
    let listenToken: string | undefined;
    const listenAllowedOrigins: string[] = [];
    const allowedCommands: string[] = [];
    const passthroughEnv: string[] = [];
    let trailing: string[] | undefined;

    const needsValue = (flag: string, value: string | undefined): string | null => {
        if (value === undefined || value.startsWith('--')) {
            return null;
        }
        void flag;
        return value;
    };

    for (let i = 0; i < argv.length; i++) {
        const arg = argv[i];
        if (arg === undefined) {
            continue;
        }
        if (arg === '--') {
            trailing = argv.slice(i + 1) as string[];
            break;
        }
        switch (arg) {
            case '-h':
            case '--help':
                return { kind: 'help' };
            case '--version':
                return { kind: 'version' };
            case '-v':
            case '--verbose':
                verbose = true;
                break;
            case '--allow-inline-code':
                allowInlineCode = true;
                break;
            case '--allow-privilege-pivot':
                allowPrivilegePivots = true;
                break;
            case '--advisory-rules': {
                const value = needsValue(arg, argv[++i]);
                if (value === null || (value !== 'enforce' && value !== 'alert' && value !== 'hunt')) {
                    return { kind: 'error', message: '--advisory-rules must be enforce, alert or hunt.' };
                }
                advisoryRules = value;
                break;
            }
            case '--no-guards':
                noGuards = true;
                break;
            case '--no-inference':
                inference = false;
                break;
            /*
             * The provenance flags are *consumed* here but *interpreted* by
             * `parseProvenanceArgs` in `src/audit/provenance.ts`, which the CLI calls on the same
             * argv. Deliberately not re-implemented: the opt-in, the default and the network gate
             * live in one file so "can this thing phone home without me asking" has one answer to
             * read. All this switch does is accept them as known options and record that at least
             * one was named, so an unnamed run never constructs the feature at all.
             */
            case '--verify-provenance':
            case '--provenance-bundle':
                provenance = true;
                break;
            case '--provenance-registry':
            case '--provenance-artifact': {
                const value = needsValue(arg, argv[++i]);
                if (value === null) {
                    return { kind: 'error', message: `${arg} requires a value.` };
                }
                provenance = true;
                break;
            }
            case '--server-json': {
                const value = needsValue(arg, argv[++i]);
                if (value === null) {
                    return { kind: 'error', message: '--server-json requires a path.' };
                }
                serverJsonFile = value;
                provenance = true;
                break;
            }
            case '--listen': {
                listen = true;
                // The value is OPTIONAL, so `needsValue` is not used: `--listen` on its own is the
                // common case and must not swallow the flag that follows it.
                const next = argv[i + 1];
                if (next !== undefined && !next.startsWith('-')) {
                    i += 1;
                    const parsedListen = parseListenAddress(next);
                    if ('error' in parsedListen) {
                        return { kind: 'error', message: parsedListen.error };
                    }
                    listenHost = parsedListen.host;
                    listenPort = parsedListen.port;
                }
                break;
            }
            case '--listen-path': {
                const value = needsValue(arg, argv[++i]);
                if (value === null || !value.startsWith('/')) {
                    return { kind: 'error', message: '--listen-path requires an absolute path, e.g. /mcp.' };
                }
                listen = true;
                listenPath = value;
                break;
            }
            case '--listen-token': {
                const value = needsValue(arg, argv[++i]);
                if (value === null || value.length < 16) {
                    return {
                        kind: 'error',
                        message: '--listen-token requires a value of at least 16 characters. Omit it and toolwall generates a 256-bit one.'
                    };
                }
                listen = true;
                listenToken = value;
                break;
            }
            case '--listen-allow-origin': {
                const value = needsValue(arg, argv[++i]);
                if (value === null) {
                    return { kind: 'error', message: '--listen-allow-origin requires an origin, e.g. https://app.example.' };
                }
                try {
                    // Parsed now rather than at bind time: an unparseable origin silently accepted
                    // here would become an allowlist entry that matches nothing, which reads as
                    // "configured" and behaves as "not configured".
                    void new URL(value);
                } catch {
                    return { kind: 'error', message: `--listen-allow-origin ${JSON.stringify(value)} is not a URL.` };
                }
                listen = true;
                listenAllowedOrigins.push(value);
                break;
            }
            case '--no-reconnect':
                reconnect = false;
                break;
            case '--reconnect-attempts': {
                const value = needsValue(arg, argv[++i]);
                const parsedValue = value === null ? Number.NaN : Number(value);
                if (!Number.isInteger(parsedValue) || parsedValue < 0 || parsedValue > 100) {
                    return { kind: 'error', message: '--reconnect-attempts must be an integer between 0 and 100.' };
                }
                reconnectAttempts = parsedValue;
                break;
            }
            case '--replay-in-flight': {
                const value = needsValue(arg, argv[++i]);
                if (value === null || !(REPLAY as readonly string[]).includes(value)) {
                    return { kind: 'error', message: '--replay-in-flight must be none, read-only-methods or all.' };
                }
                replayInFlight = value as ReplayPolicy;
                break;
            }
            case '--policy': {
                const value = needsValue(arg, argv[++i]);
                if (value === null) {
                    return { kind: 'error', message: '--policy requires a path to a toolwall-policy.json.' };
                }
                policyFile = value;
                break;
            }
            case '--pins': {
                const value = needsValue(arg, argv[++i]);
                if (value === null) {
                    return { kind: 'error', message: '--pins requires a path.' };
                }
                pinFile = value;
                break;
            }
            case '--audit-log': {
                const value = needsValue(arg, argv[++i]);
                if (value === null) {
                    return { kind: 'error', message: '--audit-log requires a path.' };
                }
                auditFile = value;
                break;
            }
            case '--tier': {
                const value = needsValue(arg, argv[++i]);
                if (value === null || !(TIERS as readonly string[]).includes(value)) {
                    return { kind: 'error', message: '--tier must be permissive, balanced or strict.' };
                }
                tier = value as StrictnessTier;
                break;
            }
            case '--pin-mode': {
                const value = needsValue(arg, argv[++i]);
                if (value === null || !(PIN_MODES as readonly string[]).includes(value)) {
                    return { kind: 'error', message: '--pin-mode must be tofu or strict.' };
                }
                pinMode = value as PinMode;
                break;
            }
            case '--on-unverifiable': {
                const value = needsValue(arg, argv[++i]);
                if (value === null || !(UNVERIFIABLE as readonly string[]).includes(value)) {
                    return { kind: 'error', message: '--on-unverifiable must be block, confirm or allow.' };
                }
                onUnverifiable = value as UnverifiableDisposition;
                break;
            }
            case '--server': {
                const value = needsValue(arg, argv[++i]);
                if (value === null) {
                    return { kind: 'error', message: '--server requires a command line, e.g. --server "node ./server.js"' };
                }
                serverLine = value;
                break;
            }
            case '--cwd': {
                const value = needsValue(arg, argv[++i]);
                if (value === null) {
                    return { kind: 'error', message: '--cwd requires a directory.' };
                }
                cwd = value;
                break;
            }
            case '--server-id': {
                const value = needsValue(arg, argv[++i]);
                if (value === null) {
                    return { kind: 'error', message: '--server-id requires a value.' };
                }
                serverId = value;
                break;
            }
            case '--era': {
                const value = needsValue(arg, argv[++i]);
                if (value === null || !isProtocolEra(value)) {
                    return { kind: 'error', message: '--era must be 2025-11-25 or 2026-07-28.' };
                }
                era = value;
                break;
            }
            case '--allow-command': {
                const value = needsValue(arg, argv[++i]);
                if (value === null) {
                    return { kind: 'error', message: '--allow-command requires a binary name.' };
                }
                allowedCommands.push(value);
                break;
            }
            case '--pass-env': {
                const value = needsValue(arg, argv[++i]);
                if (value === null) {
                    return { kind: 'error', message: '--pass-env requires an environment variable name.' };
                }
                passthroughEnv.push(value);
                break;
            }
            default:
                return { kind: 'error', message: `Unknown option ${JSON.stringify(arg)}. Run toolwall --help.` };
        }
    }

    let tokens: string[];
    if (trailing !== undefined && trailing.length > 0) {
        if (serverLine !== undefined) {
            return { kind: 'error', message: 'Use either --server "<cmd>" or -- <cmd>, not both.' };
        }
        tokens = trailing;
    } else if (serverLine !== undefined) {
        try {
            tokens = tokenizeCommandLine(serverLine);
        } catch (error) {
            return { kind: 'error', message: error instanceof Error ? error.message : String(error) };
        }
    } else {
        return { kind: 'error', message: 'Missing --server. Run toolwall --help.' };
    }

    const command = tokens[0];
    if (command === undefined || command.length === 0) {
        return { kind: 'error', message: '--server did not contain a command.' };
    }

    return {
        kind: 'run',
        value: {
            command,
            args: tokens.slice(1),
            ...(cwd !== undefined ? { cwd } : {}),
            ...(allowedCommands.length > 0 ? { allowedCommands } : {}),
            passthroughEnv,
            era,
            ...(serverId !== undefined ? { serverId } : {}),
            verbose,
            allowInlineCode,
            allowPrivilegePivots,
            ...(policyFile !== undefined ? { policyFile } : {}),
            tier,
            ...(pinFile !== undefined ? { pinFile } : {}),
            ...(auditFile !== undefined ? { auditFile } : {}),
            pinMode,
            onUnverifiable,
            noGuards,
            ...(advisoryRules !== undefined ? { advisoryRules } : {}),
            inference,
            provenance,
            ...(serverJsonFile !== undefined ? { serverJsonFile } : {}),
            reconnect,
            reconnectAttempts,
            replayInFlight,
            ...(listen
                ? {
                      listen: {
                          host: listenHost,
                          port: listenPort,
                          path: listenPath,
                          ...(listenToken !== undefined ? { token: listenToken } : {}),
                          allowedOrigins: listenAllowedOrigins
                      }
                  }
                : {})
        }
    };
}

/**
 * Parse the optional `--listen` value.
 *
 * Accepts `port`, `host:port`, `host`, and `[::1]:port`. A bare port is the common case and a bare
 * host is accepted so `--listen 0.0.0.0` works and gets the warning it deserves rather than an
 * error a user routes around by picking a worse flag.
 */
function parseListenAddress(value: string): { host: string; port: number } | { error: string } {
    if (/^\d+$/u.test(value)) {
        const port = Number(value);
        if (port < 0 || port > 65535) {
            return { error: `--listen port ${value} is out of range.` };
        }
        return { host: DEFAULT_LISTEN_HOST, port };
    }
    const { host, port } = splitAuthority(value);
    if (port === undefined) {
        return { host: value, port: 0 };
    }
    if (!/^\d+$/u.test(port)) {
        return { error: `--listen ${JSON.stringify(value)} does not end in a port number.` };
    }
    const parsedPort = Number(port);
    if (parsedPort < 0 || parsedPort > 65535) {
        return { error: `--listen port ${port} is out of range.` };
    }
    return { host: host.replace(/^\[|\]$/gu, ''), port: parsedPort };
}
