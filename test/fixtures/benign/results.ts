import type { ToolDefinition } from "../../../src/policy/contract.js";

/**
 * BENIGN RESPONSE-LEG CORPUS.
 *
 * Week 1 measured the request leg. Week 2 added guards on the RESPONSE leg (T-03), and the project
 * rule is the same for both: no FP number, no merge. Every case here is a result a real server
 * returns on a normal working day, chosen to be adversarial to the specific rules we just shipped:
 *
 *  - results large enough to be interesting to the size caps,
 *  - results whose text contains `__proto__`, `constructor`, injection-shaped prose and URLs,
 *  - `structuredContent` from tools that publish an `outputSchema` — including one whose published
 *    schema is under-specified relative to what the server actually returns, which is the common
 *    real-world case and the reason `outputSchema` is `record` rather than `enforce` by default,
 *  - error results followed by a legitimate retry, which is the ATPA rule's whole false-positive
 *    surface,
 *  - elicitations that ask for ordinary things using words near the credential vocabulary.
 */

export interface BenignResultCase {
  readonly id: string;
  readonly serverId: string;
  /** Method whose RESULT this is. */
  readonly method: "tools/call" | "resources/read" | "prompts/get";
  /** The tool call that produced it, for the correlation the guard does. */
  readonly call?: { readonly name: string; readonly arguments: Record<string, unknown> };
  readonly result: unknown;
  readonly trap: string;
  readonly tags: readonly string[];
}

/** A benign multi-step sequence: call, result, retry. This is the ATPA rule's FP surface. */
export interface BenignSequenceCase {
  readonly id: string;
  readonly serverId: string;
  readonly steps: readonly (
    | { readonly kind: "call"; readonly name: string; readonly arguments: Record<string, unknown> }
    | { readonly kind: "result"; readonly result: unknown }
  )[];
  readonly trap: string;
}

export interface BenignElicitationCase {
  readonly id: string;
  readonly serverId: string;
  readonly params: Record<string, unknown>;
  readonly trap: string;
}

/* ------------------------------------------------------------------ */
/* Tool definitions referenced by the cases                            */
/* ------------------------------------------------------------------ */

export const resultToolDefinitions: readonly ToolDefinition[] = [
  {
    name: "read_file",
    inputSchema: { type: "object", properties: { path: { type: "string" } }, required: ["path"] },
  },
  {
    name: "query",
    inputSchema: { type: "object", properties: { sql: { type: "string" }, params: { type: "array" } }, required: ["sql"] },
    outputSchema: {
      type: "object",
      properties: { rows: { type: "array" }, rowCount: { type: "integer" } },
      required: ["rows"],
    },
  },
  {
    name: "get_forecast",
    inputSchema: { type: "object", properties: { city: { type: "string" } }, required: ["city"] },
    outputSchema: {
      type: "object",
      // Under-specified on purpose: the server also returns `humidity` and `updatedAt`. This is the
      // single most common real-world outputSchema defect and it is why the default is "record".
      properties: { tempC: { type: "number" }, summary: { type: "string" } },
      required: ["tempC", "summary"],
    },
  },
  {
    name: "search_issues",
    inputSchema: { type: "object", properties: { jql: { type: "string" } }, required: ["jql"] },
  },
  {
    name: "http_request",
    inputSchema: { type: "object", properties: { url: { type: "string", format: "uri" } }, required: ["url"] },
  },
  {
    name: "git_log",
    inputSchema: { type: "object", properties: { repo_path: { type: "string" }, max_count: { type: "integer" } }, required: ["repo_path"] },
  },
];

const text = (t: string): unknown => ({ content: [{ type: "text", text: t }] });

/* ------------------------------------------------------------------ */

export const benignResultCases: readonly BenignResultCase[] = [
  {
    id: "result.read-file-large-source",
    serverId: "editor",
    method: "tools/call",
    call: { name: "read_file", arguments: { path: "/w/src/bundle.ts" } },
    result: text("export const x = 1;\n".repeat(60_000)),
    trap: "A 1.1 MB source file. Large results are normal; a size cap tuned to intuition rather than to real files blocks a routine read.",
    tags: ["size"],
  },
  {
    id: "result.read-file-with-proto-in-text",
    serverId: "editor",
    method: "tools/call",
    call: { name: "read_file", arguments: { path: "/w/src/guard.ts" } },
    result: text('if (key === "__proto__" || key === "constructor") throw new Error("pollution");\n// see CVE-2026-25536'),
    trap: "The literal string `__proto__` inside returned source code. A rule that matched the text rather than the object key would flag every file that defends against prototype pollution — including ours.",
    tags: ["prototype", "content"],
  },
  {
    id: "result.jira-ticket-with-injection-prose",
    serverId: "jira",
    method: "tools/call",
    call: { name: "search_issues", arguments: { jql: "project = OPS ORDER BY created DESC" } },
    result: text(
      "PROJ-1841: Customer reports that our agent 'ignores previous instructions' when the prompt is long.\n" +
        "Repro: https://wiki.example.com/runbooks/agent#truncation\nWorkaround: set max_tokens. See also SYSTEM: note in the logs.",
    ),
    trap: "A ticket that quotes injection phrases because it is ABOUT prompt injection, and carries a URL to a host nobody allowlisted. This is the Atlassian JSM shape with none of the malice.",
    tags: ["content", "url"],
  },
  {
    id: "result.api-schema-document",
    serverId: "filesystem",
    method: "resources/read",
    result: {
      contents: [
        {
          uri: "file:///w/openapi.json",
          mimeType: "application/json",
          // `constructor` and `prototype` as genuine object KEYS in a real document.
          text: JSON.stringify({ definitions: { constructor: { type: "object" }, prototype: { type: "object" } } }),
        },
      ],
    },
    trap: "`constructor` and `prototype` are ordinary words that appear as keys in real API-schema documents. Blocking them would break reading any such file — which is why only `__proto__` is rejected.",
    tags: ["prototype"],
  },
  {
    id: "result.sql-rows-conforming",
    serverId: "postgres",
    method: "tools/call",
    call: { name: "query", arguments: { sql: "select id, email from users limit 500" } },
    result: {
      content: [],
      structuredContent: { rows: Array.from({ length: 500 }, (_, i) => ({ id: i, email: `u${i}@example.com` })), rowCount: 500 },
    },
    trap: "500 rows of structured output that conforms to the published outputSchema. Must be silent.",
    tags: ["outputSchema", "size"],
  },
  {
    id: "result.weather-extra-fields",
    serverId: "weather",
    method: "tools/call",
    call: { name: "get_forecast", arguments: { city: "Nairobi" } },
    result: { content: [], structuredContent: { tempC: 24.5, summary: "clear", humidity: 0.61, updatedAt: "2026-08-19T09:00:00Z" } },
    trap: "The server returns MORE than its published outputSchema declares. Extremely common; at `balanced` this must record, not block.",
    tags: ["outputSchema"],
  },
  {
    id: "result.git-log-deep-json",
    serverId: "git",
    method: "tools/call",
    call: { name: "git_log", arguments: { repo_path: "/w", max_count: 50 } },
    result: {
      content: [],
      structuredContent: { commits: Array.from({ length: 50 }, (_, i) => ({ sha: `${i}`.padStart(40, "0"), parents: [{ sha: "x", tree: { entries: [{ mode: "100644", blob: { size: i } }] } }] })) },
    },
    trap: "Nested structured output. Depth caps set by intuition rather than by real payloads reject ordinary git metadata.",
    tags: ["size"],
  },
  {
    id: "result.http-response-with-urls",
    serverId: "http",
    method: "tools/call",
    call: { name: "http_request", arguments: { url: "https://api.example.com/v2/links" } },
    result: text('{"next":"https://api.example.com/v2/links?page=2","cdn":"https://raw.cdn.assets.example.com/x.png","docs":"http://127.0.0.1:3000/docs"}'),
    trap: "URLs in a RESPONSE body. Egress control applies to where the model directs a call, not to every URL a server hands back; a rule that confused the two would flag every API response.",
    tags: ["url"],
  },
  {
    id: "result.prompt-get",
    serverId: "editor",
    method: "prompts/get",
    result: {
      description: "Code review prompt",
      messages: [{ role: "user", content: { type: "text", text: "Review this diff. Ignore formatting-only changes." } }],
    },
    trap: '"Ignore ..." in a legitimate prompt template.',
    tags: ["content"],
  },
  {
    id: "result.empty",
    serverId: "memory",
    method: "tools/call",
    call: { name: "read_file", arguments: { path: "/w/empty" } },
    result: { content: [] },
    trap: "The degenerate result. Must not trip a bounds rule or a correlation rule.",
    tags: ["size"],
  },
];

/* ------------------------------------------------------------------ */

export const benignSequenceCases: readonly BenignSequenceCase[] = [
  {
    id: "seq.retry-after-enoent",
    serverId: "editor",
    steps: [
      { kind: "call", name: "read_file", arguments: { path: "/w/src/typo.ts" } },
      { kind: "result", result: { isError: true, ...(text("ENOENT: no such file or directory, open '/w/src/typo.ts'") as object) } },
      { kind: "call", name: "read_file", arguments: { path: "/w/src/index.ts" } },
    ],
    trap: "The most common sequence in any agent session: a failed read, then a corrected one. Identical arguments shape, no new keys.",
  },
  {
    id: "seq.retry-supplying-declared-required-param",
    serverId: "postgres",
    steps: [
      { kind: "call", name: "query", arguments: {} },
      { kind: "result", result: { isError: true, ...(text("Missing required parameter: sql") as object) } },
      { kind: "call", name: "query", arguments: { sql: "select 1" } },
    ],
    trap: "The error names a parameter and the model then supplies it — the exact ATPA shape, except the parameter is DECLARED in the tool's own inputSchema. This is why the rule fires only on undeclared keys.",
  },
  {
    id: "seq.retry-adding-declared-optional-param",
    serverId: "git",
    steps: [
      { kind: "call", name: "git_log", arguments: { repo_path: "/w" } },
      { kind: "result", result: { isError: true, ...(text("history too large; pass max_count to limit the range") as object) } },
      { kind: "call", name: "git_log", arguments: { repo_path: "/w", max_count: 20 } },
    ],
    trap: "The error text names an argument, the retry adds it, and it is declared. A rule keyed on 'error mentions a key that then appears' without the declared check flags this.",
  },
  {
    id: "seq.retry-different-tool",
    serverId: "editor",
    steps: [
      { kind: "call", name: "read_file", arguments: { path: "/w/missing" } },
      { kind: "result", result: { isError: true, ...(text("ENOENT") as object) } },
      { kind: "call", name: "git_log", arguments: { repo_path: "/w", debug_context: "x" } },
    ],
    trap: "A different tool after an error, with an undeclared argument. The ATPA signature is same-tool; a looser rule would fire here.",
  },
  {
    id: "seq.success-then-new-argument",
    serverId: "weather",
    steps: [
      { kind: "call", name: "get_forecast", arguments: { city: "Nairobi" } },
      { kind: "result", result: { content: [], structuredContent: { tempC: 24.5, summary: "clear" } } },
      { kind: "call", name: "get_forecast", arguments: { city: "Nairobi", units: "metric" } },
    ],
    trap: "A new undeclared argument after a SUCCESSFUL call. No error, no signature.",
  },
];

/* ------------------------------------------------------------------ */

export const benignElicitationCases: readonly BenignElicitationCase[] = [
  {
    id: "elicit.branch-name",
    serverId: "git",
    params: { message: "Which branch should I push to?", requestedSchema: { type: "object", properties: { branch: { type: "string", title: "Branch name" } }, required: ["branch"] } },
    trap: "An ordinary string input.",
  },
  {
    id: "elicit.confirm-merge",
    serverId: "git",
    params: { message: "Merge #4821 into main?", requestedSchema: { type: "object", properties: { confirm: { type: "boolean", title: "Proceed with the merge?" } } } },
    trap: "A confirmation dialog.",
  },
  {
    id: "elicit.token-budget",
    serverId: "memory",
    params: { message: "Summarisation budget?", requestedSchema: { type: "object", properties: { maxTokens: { type: "integer", title: "Token limit" }, keyName: { type: "string", title: "Key name" } } } },
    trap: '"token" and "key" in isolation. Both are ordinary parameter words; a vocabulary containing either on its own would flag this.',
  },
  {
    id: "elicit.contact-details",
    serverId: "jira",
    params: {
      message: "Who should I assign this to?",
      requestedSchema: { type: "object", properties: { secretaryEmail: { type: "string", format: "email" }, accountName: { type: "string" }, pinnedIssue: { type: "string" } } },
    },
    trap: '"secretary" contains "secret", "account" and "pinned" are near-misses for the payment vocabulary. Substring matching on the vocabulary flags all three.',
  },
  {
    id: "elicit.deploy-target",
    serverId: "http",
    params: { message: "Deploy where?", requestedSchema: { type: "object", properties: { environment: { type: "string", enum: ["staging", "prod"] }, releaseNotes: { type: "string" } } } },
    trap: "An enum plus free text.",
  },
];

export function responseCorpusSummary(): { results: number; sequences: number; elicitations: number } {
  return { results: benignResultCases.length, sequences: benignSequenceCases.length, elicitations: benignElicitationCases.length };
}
