import { describe, expect, it } from 'vitest';

import { USAGE, parseArgs, tokenizeCommandLine } from '../../../src/cli/args.js';

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

    it('turns the inferred capability policy ON by default, and --no-inference off', () => {
        // Default-ON is the whole Week-3 decision: with no policy file the capability layer
        // otherwise constrains nothing, and nobody writes policy files.
        const on = parseArgs(['--server', 'node a.js']);
        expect(on.kind).toBe('run');
        if (on.kind !== 'run') return;
        expect(on.value.inference).toBe(true);

        const off = parseArgs(['--no-inference', '--server', 'node a.js']);
        expect(off.kind).toBe('run');
        if (off.kind !== 'run') return;
        expect(off.value.inference).toBe(false);
    });

    it('leaves provenance off unless a provenance flag is named', () => {
        const none = parseArgs(['--server', 'node a.js']);
        expect(none.kind).toBe('run');
        if (none.kind !== 'run') return;
        expect(none.value.provenance, 'the T-09 path must not exist unless asked for').toBe(false);

        for (const argv of [
            ['--verify-provenance'],
            ['--provenance-bundle'],
            ['--provenance-registry', 'https://r.example'],
            ['--provenance-artifact', './bundle.mcpb'],
            ['--server-json', './server.json']
        ]) {
            const r = parseArgs([...argv, '--server', 'node a.js']);
            expect(r.kind, `${argv[0]} must be a known option`).toBe('run');
            if (r.kind !== 'run') return;
            expect(r.value.provenance, `${argv[0]} must turn the feature on`).toBe(true);
        }
    });

    it('rejects a provenance flag whose value is missing rather than swallowing the next flag', () => {
        expect(parseArgs(['--provenance-registry', '--verbose', '--server', 'node a.js']).kind).toBe('error');
        expect(parseArgs(['--provenance-artifact', '--verbose', '--server', 'node a.js']).kind).toBe('error');
        expect(parseArgs(['--server-json', '--verbose', '--server', 'node a.js']).kind).toBe('error');
    });

    it('the usage text says which single flag makes a network request', () => {
        expect(USAGE).toContain('--verify-provenance');
        expect(USAGE).toContain('THIS IS');
        expect(USAGE).toContain('--no-inference');
    });
});

describe('--listen (Streamable HTTP)', () => {
    const run = (argv: string[]): ReturnType<typeof parseArgs> => parseArgs([...argv, '--server', 'node a.js']);

    it('is absent unless asked for, so the default stays stdio', () => {
        const r = run([]);
        expect(r.kind).toBe('run');
        if (r.kind !== 'run') return;
        expect(r.value.listen, 'opening a port nobody asked for is the CVE-2025-49596 posture').toBeUndefined();
    });

    it('defaults to loopback and an OS-assigned port', () => {
        const r = run(['--listen']);
        expect(r.kind).toBe('run');
        if (r.kind !== 'run') return;
        expect(r.value.listen).toEqual({ host: '127.0.0.1', port: 0, path: '/mcp', allowedOrigins: [] });
    });

    it('accepts a bare port, a host:port, a bare host and an IPv6 authority', () => {
        const cases: Array<[string, { host: string; port: number }]> = [
            ['8099', { host: '127.0.0.1', port: 8099 }],
            ['127.0.0.1:8099', { host: '127.0.0.1', port: 8099 }],
            ['0.0.0.0:9000', { host: '0.0.0.0', port: 9000 }],
            ['0.0.0.0', { host: '0.0.0.0', port: 0 }],
            ['[::1]:9000', { host: '::1', port: 9000 }]
        ];
        for (const [value, expected] of cases) {
            const r = run(['--listen', value]);
            expect(r.kind, value).toBe('run');
            if (r.kind !== 'run') return;
            expect({ host: r.value.listen?.host, port: r.value.listen?.port }, value).toEqual(expected);
        }
    });

    it('does not swallow the next flag when --listen is given with no value', () => {
        // The value is optional, so a naive `needsValue` would eat `--verbose` and then complain
        // about a missing server.
        const r = run(['--listen', '--verbose']);
        expect(r.kind).toBe('run');
        if (r.kind !== 'run') return;
        expect(r.value.listen?.port).toBe(0);
        expect(r.value.verbose).toBe(true);
    });

    it('rejects a port that is not a number or is out of range', () => {
        expect(run(['--listen', '127.0.0.1:notaport']).kind).toBe('error');
        expect(run(['--listen', '99999']).kind).toBe('error');
    });

    it('turns the listener on when only a modifier is named, rather than silently ignoring it', () => {
        for (const argv of [['--listen-path', '/rpc'], ['--listen-token', 'x'.repeat(20)], ['--listen-allow-origin', 'https://app.example']]) {
            const r = run(argv);
            expect(r.kind, argv[0]).toBe('run');
            if (r.kind !== 'run') return;
            expect(r.value.listen, `${argv[0]} must not be accepted and then ignored`).toBeDefined();
        }
    });

    it('refuses a token short enough to guess, and a path that is not absolute', () => {
        expect(run(['--listen-token', 'short']).kind).toBe('error');
        expect(run(['--listen-path', 'mcp']).kind).toBe('error');
    });

    it('refuses an allowed origin that is not a URL, because it would match nothing', () => {
        expect(run(['--listen-allow-origin', 'app.example']).kind).toBe('error');
        const ok = run(['--listen-allow-origin', 'https://app.example', '--listen-allow-origin', 'http://localhost:5173']);
        expect(ok.kind).toBe('run');
        if (ok.kind !== 'run') return;
        expect(ok.value.listen?.allowedOrigins).toEqual(['https://app.example', 'http://localhost:5173']);
    });

    it('there is no flag that turns authentication off, and the usage text says so', () => {
        expect(run(['--listen-no-auth']).kind).toBe('error');
        expect(run(['--no-listen-auth']).kind).toBe('error');
        expect(USAGE).toContain('bearer token is REQUIRED');
        expect(USAGE).toContain('CVE-2025-66414');
        expect(USAGE).toContain('-32020 HeaderMismatch');
    });
});
