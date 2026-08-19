import { describe, expect, it } from 'vitest';

import { parseArgs, tokenizeCommandLine } from '../../../src/cli/args.js';

describe('tokenizeCommandLine', () => {
    it('splits on whitespace', () => {
        expect(tokenizeCommandLine('node ./server.js --port 3000')).toStrictEqual(['node', './server.js', '--port', '3000']);
    });

    it('honours quotes so real paths with spaces work', () => {
        expect(tokenizeCommandLine('node "/Users/a b/server.js"')).toStrictEqual(['node', '/Users/a b/server.js']);
        expect(tokenizeCommandLine("node '/Users/a b/server.js'")).toStrictEqual(['node', '/Users/a b/server.js']);
        expect(tokenizeCommandLine('node /Users/a\\ b/server.js')).toStrictEqual(['node', '/Users/a b/server.js']);
    });

    it('preserves an empty quoted argument', () => {
        expect(tokenizeCommandLine('node server.js ""')).toStrictEqual(['node', 'server.js', '']);
    });

    it('does NOT interpret shell syntax — operators survive as literal text', () => {
        // This is the point: anything shell-looking becomes an argument and is
        // then rejected by validateSpawnSpec, rather than being executed.
        expect(tokenizeCommandLine('node server.js; id')).toStrictEqual(['node', 'server.js;', 'id']);
        expect(tokenizeCommandLine('node $(id)')).toStrictEqual(['node', '$(id)']);
        expect(tokenizeCommandLine('node $HOME')).toStrictEqual(['node', '$HOME']);
        expect(tokenizeCommandLine('node *.js')).toStrictEqual(['node', '*.js']);
    });

    it('rejects an unterminated quote instead of guessing', () => {
        expect(() => tokenizeCommandLine('node "unclosed')).toThrow(/Unterminated/u);
    });
});

describe('parseArgs', () => {
    it('parses the documented invocation', () => {
        const result = parseArgs(['--server', 'node path/to/server.js']);
        expect(result.kind).toBe('run');
        if (result.kind !== 'run') {
            return;
        }
        expect(result.value.command).toBe('node');
        expect(result.value.args).toStrictEqual(['path/to/server.js']);
        expect(result.value.era).toBe('2025-11-25');
        expect(result.value.allowInlineCode).toBe(false);
    });

    it('supports the -- form', () => {
        const result = parseArgs(['--allow-command', 'node', '--', 'node', 'server.js', '--flag']);
        expect(result.kind).toBe('run');
        if (result.kind !== 'run') {
            return;
        }
        expect(result.value.command).toBe('node');
        expect(result.value.args).toStrictEqual(['server.js', '--flag']);
        expect(result.value.allowedCommands).toStrictEqual(['node']);
    });

    it('rejects mixing --server and --', () => {
        const result = parseArgs(['--server', 'node a.js', '--', 'node', 'b.js']);
        expect(result).toStrictEqual({ kind: 'error', message: 'Use either --server "<cmd>" or -- <cmd>, not both.' });
    });

    it('collects repeatable flags', () => {
        const result = parseArgs(['--pass-env', 'A', '--pass-env', 'B', '--allow-command', 'node', '--allow-command', 'python3', '--server', 'node a.js']);
        expect(result.kind).toBe('run');
        if (result.kind !== 'run') {
            return;
        }
        expect(result.value.passthroughEnv).toStrictEqual(['A', 'B']);
        expect(result.value.allowedCommands).toStrictEqual(['node', 'python3']);
    });

    it('validates the era', () => {
        expect(parseArgs(['--era', '2026-07-28', '--server', 'node a.js'])).toMatchObject({ kind: 'run' });
        expect(parseArgs(['--era', '2024-11-05', '--server', 'node a.js']).kind).toBe('error');
    });

    it('requires a server', () => {
        expect(parseArgs([])).toStrictEqual({ kind: 'error', message: 'Missing --server. Run toolwall --help.' });
    });

    it('rejects a flag that swallowed the next flag as its value', () => {
        expect(parseArgs(['--server', '--verbose']).kind).toBe('error');
    });

    it('rejects unknown options rather than silently ignoring them', () => {
        expect(parseArgs(['--wat', '--server', 'node a.js']).kind).toBe('error');
    });

    it('handles help and version', () => {
        expect(parseArgs(['--help'])).toStrictEqual({ kind: 'help' });
        expect(parseArgs(['-h'])).toStrictEqual({ kind: 'help' });
        expect(parseArgs(['--version'])).toStrictEqual({ kind: 'version' });
    });

    it('buffers and retries by default, because a blip should not end the session', () => {
        const result = parseArgs(['--server', 'node a.js']);
        expect(result.kind).toBe('run');
        if (result.kind !== 'run') return;
        expect(result.value.reconnect).toBe(true);
        expect(result.value.reconnectAttempts).toBe(3);
        // Never resend a side-effecting call whose execution status is unknown.
        expect(result.value.replayInFlight).toBe('read-only-methods');
    });

    it('lets an operator turn reconnection off and tune it', () => {
        const result = parseArgs([
            '--no-reconnect',
            '--reconnect-attempts',
            '5',
            '--replay-in-flight',
            'all',
            '--server',
            'node a.js'
        ]);
        expect(result.kind).toBe('run');
        if (result.kind !== 'run') return;
        expect(result.value.reconnect).toBe(false);
        expect(result.value.reconnectAttempts).toBe(5);
        expect(result.value.replayInFlight).toBe('all');
    });

    it('rejects nonsense reconnection settings rather than coercing them', () => {
        expect(parseArgs(['--reconnect-attempts', 'many', '--server', 'node a.js']).kind).toBe('error');
        expect(parseArgs(['--reconnect-attempts', '-1', '--server', 'node a.js']).kind).toBe('error');
        expect(parseArgs(['--replay-in-flight', 'sometimes', '--server', 'node a.js']).kind).toBe('error');
    });
});
