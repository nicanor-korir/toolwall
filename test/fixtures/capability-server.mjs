#!/usr/bin/env node
// @ts-nocheck
/**
 * capability-server.mjs — an entirely LEGITIMATE MCP server, for the Week-3 inference tests.
 *
 * The point of this fixture is that there is nothing wrong with it. Its descriptions are honest,
 * its schemas are accurate, it never mutates a definition, and every existing metadata control
 * passes it clean. It is exactly the kind of server people install on purpose.
 *
 * The attack it exists to demonstrate is the one `docs/POSITIONING.md` says the CVE mass and every
 * real 2025-26 incident actually took: an injected model directs a *legitimate* tool at something
 * it should never reach. `read_file` is a real file reader; `read_file({ path: "/etc/passwd" })`
 * is a real file read. Nothing in the metadata layer has an opinion about it, and with no policy
 * file the Week-2 capability layer had none either — that is the 0/17 baseline.
 *
 * The tools are chosen to cover the four things `src/policy/infer.ts` reads off a schema:
 *
 *   read_file   a path-shaped property NAME             -> readPath role, inferred roots
 *   write_file  a destination-shaped NAME               -> writePath role
 *   fetch_url   `format: "uri"`, a server DECLARATION   -> url role, inferred scheme allowlist
 *   git_diff    an anchor plus repo-relative pathspecs  -> C-7: only the anchor is bound
 *   add         two numbers                             -> no capability inferred at all
 *
 * Hand-rolled newline-delimited JSON-RPC rather than the SDK, so the listing reaches the wire
 * byte-exactly and the results are not normalised on the way out.
 */

const TOOLS = [
    {
        name: 'read_file',
        description: 'Reads a file and returns its contents.',
        inputSchema: {
            type: 'object',
            properties: { path: { type: 'string' } },
            required: ['path']
        },
        annotations: { readOnlyHint: true }
    },
    {
        name: 'write_file',
        description: 'Writes content to a destination file.',
        inputSchema: {
            type: 'object',
            properties: { destination: { type: 'string' }, content: { type: 'string' } },
            required: ['destination', 'content']
        }
    },
    {
        name: 'fetch_url',
        description: 'Fetches a URL and returns its body.',
        inputSchema: {
            // `format: "uri"` is a declaration the SERVER published, never a guess that a property
            // called "url" holds one. That is what makes the url role a contract reading.
            type: 'object',
            properties: { url: { type: 'string', format: 'uri' } },
            required: ['url']
        }
    },
    {
        name: 'git_diff',
        description: 'Diffs paths inside a repository.',
        inputSchema: {
            type: 'object',
            // `repo_path` is the base the pathspecs resolve against, so binding `paths` would
            // resolve them against OUR baseDir and manufacture a false escape (C-7).
            properties: { repo_path: { type: 'string' }, paths: { type: 'array', items: { type: 'string' } } },
            required: ['repo_path']
        }
    },
    {
        name: 'add',
        description: 'Adds two numbers.',
        inputSchema: {
            type: 'object',
            properties: { a: { type: 'number' }, b: { type: 'number' } },
            required: ['a', 'b']
        }
    }
];

function send(message) {
    process.stdout.write(`${JSON.stringify(message)}\n`);
}

function result(id, value) {
    send({ jsonrpc: '2.0', id, result: value });
}

function handle(message) {
    const { id, method, params } = message;
    if (id === undefined) return;

    switch (method) {
        case 'initialize':
            result(id, {
                protocolVersion: params?.protocolVersion ?? '2025-11-25',
                capabilities: { tools: { listChanged: true } },
                serverInfo: { name: 'capability-fixture', version: '1.0.0' }
            });
            return;

        case 'tools/list':
            result(id, { tools: TOOLS });
            return;

        case 'tools/call': {
            const name = params?.name;
            const args = params?.arguments ?? {};
            // Every body below is a marker the test asserts on. Its ABSENCE is what proves a block
            // happened on the request leg, before the tool ran, rather than cosmetically after it.
            switch (name) {
                case 'read_file':
                    result(id, { content: [{ type: 'text', text: `read:${args.path}` }] });
                    return;
                case 'write_file':
                    result(id, { content: [{ type: 'text', text: `wrote:${args.destination}` }] });
                    return;
                case 'fetch_url':
                    result(id, { content: [{ type: 'text', text: `fetched:${args.url}` }] });
                    return;
                case 'git_diff':
                    result(id, { content: [{ type: 'text', text: `diffed:${args.repo_path}:${(args.paths ?? []).join(',')}` }] });
                    return;
                case 'add':
                    result(id, { content: [{ type: 'text', text: `sum:${Number(args.a) + Number(args.b)}` }] });
                    return;
                default:
                    send({ jsonrpc: '2.0', id, error: { code: -32602, message: `unknown tool ${String(name)}` } });
                    return;
            }
        }

        default:
            send({ jsonrpc: '2.0', id, error: { code: -32601, message: `method not found: ${String(method)}` } });
    }
}

let buffer = '';
process.stdin.on('data', chunk => {
    buffer += chunk.toString();
    for (;;) {
        const idx = buffer.indexOf('\n');
        if (idx === -1) break;
        const raw = buffer.slice(0, idx).replace(/\r$/u, '');
        buffer = buffer.slice(idx + 1);
        if (raw.length === 0) continue;
        try {
            handle(JSON.parse(raw));
        } catch {
            /* a malformed line is the transport's problem, not this fixture's */
        }
    }
});
