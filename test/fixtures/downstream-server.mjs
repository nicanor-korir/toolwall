#!/usr/bin/env node
/**
 * A REAL downstream MCP server, spawned as a real child process and speaking
 * real newline-delimited JSON-RPC over real stdio.
 *
 * This is deliberately not a mock. The integration tests spawn this twice —
 * once directly, once behind ToolwallProxy — and compare the bytes a client
 * transport receives on each path.
 *
 * Everything it returns is deterministic (no timestamps, no randomness) so the
 * two paths are comparable.
 *
 * Exercises, on purpose:
 *   - tools/list, tools/call                       (ordinary traffic)
 *   - x-experimental/echo                          (a method the SDK does not
 *                                                   know: proves the proxy is
 *                                                   not enumerating methods)
 *   - sampling/createMessage                       (server -> client REQUEST,
 *                                                   live under 2025-11-25)
 *   - notifications/progress                       (progressToken correlation)
 *   - notifications/message                        (server -> client notification)
 *   - a JSON-RPC error with code + data            (error relay fidelity)
 *   - an unknown top-level key inside result       (loose passthrough)
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
    CallToolRequestSchema,
    ListToolsRequestSchema,
    ErrorCode,
    McpError
} from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';

const callLog = [];

const server = new Server(
    { name: 'toolwall-test-downstream', version: '1.2.3' },
    {
        capabilities: { tools: { listChanged: true }, logging: {}, resources: {}, prompts: {} },
        instructions: 'Fixture server. Instructions are a top-ranked injection surface, so they must survive the hop verbatim.'
    }
);

server.setRequestHandler(ListToolsRequestSchema, () => ({
    tools: [
        {
            name: 'echo',
            description: 'Echoes its argument back.',
            inputSchema: { type: 'object', properties: { text: { type: 'string' } }, required: ['text'] }
        },
        {
            name: 'ask',
            description: 'Asks the client to sample from its model.',
            inputSchema: { type: 'object', properties: {} }
        },
        {
            name: 'slow',
            description: 'Emits progress notifications.',
            inputSchema: { type: 'object', properties: {} }
        },
        { name: 'boom', description: 'Always fails.', inputSchema: { type: 'object', properties: {} } },
        { name: 'forbidden', description: 'Should never execute in the block test.', inputSchema: { type: 'object', properties: {} } },
        { name: 'calls', description: 'Returns the log of tool names invoked so far.', inputSchema: { type: 'object', properties: {} } },
        { name: 'hang', description: 'Blocks until cancelled.', inputSchema: { type: 'object', properties: {} } },
        {
            // Exists for `bench/latency.ts`. The `large` workload echoes 64 KiB back as ONE string,
            // which is ~6 nodes: it sizes the transport but barely exercises the response-leg walk
            // at all. A row set is the shape a SQL, search or listing tool actually returns, and it
            // is the shape where `measure()`/`hasProtoKey()` node cost is real.
            name: 'rows',
            description: 'Returns n structured rows. Sizes the response-leg walk in NODES, not bytes.',
            inputSchema: { type: 'object', properties: { n: { type: 'number' } }, required: ['n'] }
        }
    ],
    // An unknown key at result top level. `ResultSchema` is a loose object, so
    // this must survive both the direct and the proxied path untouched.
    'x-fixture-marker': { nested: [1, 2, { deep: true }] }
}));

server.setRequestHandler(CallToolRequestSchema, async (request, extra) => {
    const name = request.params.name;
    if (name !== 'calls') {
        callLog.push(name);
    }

    switch (name) {
        case 'echo':
            return { content: [{ type: 'text', text: String(request.params.arguments?.text ?? '') }] };

        case 'calls':
            return { content: [{ type: 'text', text: JSON.stringify(callLog) }] };

        case 'rows': {
            const n = Math.max(0, Math.min(20000, Number(request.params.arguments?.n ?? 0)));
            const rows = [];
            for (let i = 0; i < n; i++) {
                rows.push({ id: i, name: `row-${i}`, path: `/tmp/a/b/c/file-${i}.txt`, ok: i % 2 === 0, note: 'lorem ipsum dolor sit amet' });
            }
            return { content: [{ type: 'text', text: `${n} rows` }], structuredContent: { rows } };
        }

        case 'boom':
            throw new McpError(ErrorCode.InvalidParams, 'boom happened', { detail: 'structured error data', n: 42 });

        case 'forbidden':
            return { content: [{ type: 'text', text: 'this should never be reached' }] };

        // Blocks until the request is cancelled, then reports the reason it was
        // cancelled with. `extra.sendNotification` refuses to send once the
        // handler is aborted, so this goes out through the server directly.
        case 'hang': {
            await new Promise(resolve => {
                if (extra.signal.aborted) {
                    resolve();
                    return;
                }
                extra.signal.addEventListener('abort', () => resolve(), { once: true });
            });
            await server.notification({
                method: 'notifications/message',
                params: { level: 'info', logger: 'fixture', data: { cancelled: true, reason: String(extra.signal.reason) } }
            });
            return { content: [{ type: 'text', text: 'cancelled' }] };
        }

        case 'slow': {
            const token = extra._meta?.progressToken;
            if (token !== undefined) {
                await extra.sendNotification({
                    method: 'notifications/progress',
                    params: { progressToken: token, progress: 1, total: 2, message: 'halfway' }
                });
                await extra.sendNotification({
                    method: 'notifications/progress',
                    params: { progressToken: token, progress: 2, total: 2, message: 'done' }
                });
            }
            return { content: [{ type: 'text', text: 'slow finished' }] };
        }

        case 'ask': {
            const sampled = await extra.sendRequest(
                {
                    method: 'sampling/createMessage',
                    params: {
                        messages: [{ role: 'user', content: { type: 'text', text: 'what is 2+2?' } }],
                        maxTokens: 16,
                        systemPrompt: 'attacker-controlled natural language lives here'
                    }
                },
                z.unknown()
            );
            return { content: [{ type: 'text', text: `sampled:${JSON.stringify(sampled)}` }] };
        }

        default:
            throw new McpError(ErrorCode.InvalidParams, `unknown tool ${name}`);
    }
});

/**
 * Methods the SDK has never heard of land here. The proxy must forward them
 * without knowing they exist.
 */
server.fallbackRequestHandler = async request => {
    if (request.method === 'x-experimental/echo') {
        return { received: request.params ?? null, 'x-server-note': 'handled by fallback' };
    }
    // `_meta` deliberately NOT the first key. `ResultSchema` declares `_meta`,
    // and zod rebuilds objects with declared keys first, so this is the one
    // payload shape whose raw key order changes crossing the proxy. It is only
    // observable here: `Server.setRequestHandler` validates `tools/call`
    // results with `CallToolResultSchema`, which already normalises them on the
    // server's own way out.
    if (request.method === 'x-experimental/meta') {
        return { marker: 'value', _meta: { 'com.example/note': 1 } };
    }
    throw new McpError(ErrorCode.MethodNotFound, `Method not found: ${request.method}`);
};

server.fallbackNotificationHandler = async notification => {
    if (notification.method === 'x-experimental/ping') {
        await server.notification({
            method: 'notifications/message',
            params: { level: 'info', logger: 'fixture', data: { sawNotification: notification.params ?? null } }
        });
    }
};

await server.connect(new StdioServerTransport());
