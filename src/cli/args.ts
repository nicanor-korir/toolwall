/**
 * CLI argument parsing. Kept separate from `index.ts` so it is unit-testable
 * without spawning anything.
 */

import type { StrictnessTier } from '../policy/schema.js';
import { isProtocolEra, type ProtocolEra } from '../types/protocol.js';

export type PinMode = 'tofu' | 'strict';
export type UnverifiableDisposition = 'block' | 'confirm' | 'allow';

const TIERS = ['permissive', 'balanced', 'strict'] as const;
const PIN_MODES = ['tofu', 'strict'] as const;
const UNVERIFIABLE = ['block', 'confirm', 'allow'] as const;

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
}

export type ParseResult =
    | { readonly kind: 'run'; readonly value: ParsedArgs }
    | { readonly kind: 'help' }
    | { readonly kind: 'version' }
    | { readonly kind: 'error'; readonly message: string };

export const USAGE = `toolwall — local-first MCP guardrail proxy

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
                          Repeatable. Omit for no binary allowlist — argument
                          level validation still applies either way.
  --pass-env <NAME>       Copy NAME from toolwall's environment into the child.
                          Repeatable. Nothing beyond the SDK's default set is
                          passed otherwise; run with --verbose to see exactly
                          what the child inherits.
  --era <revision>        Protocol era: 2025-11-25 (default) or 2026-07-28.
  --server-id <id>        Override the derived per-connection server identity.
  --allow-inline-code     Permit sh -c / node -e / npx -c style invocation.
                          This disables the primary T-07 control. Do not.
  --allow-privilege-pivot Permit sudo / docker / ssh / env as the command.
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

EXAMPLE
  toolwall --server "node ./path/to/server.js"
  toolwall --allow-command node -- node ./path/to/server.js
  toolwall --policy ./toolwall-policy.json --audit-log ./toolwall-audit.jsonl \\
           --server "node ./path/to/server.js"
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
            case '--no-guards':
                noGuards = true;
                break;
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
            noGuards
        }
    };
}
