import type { BenignCase } from "./types.js";
import type { ToolDefinition } from "../../../src/policy/contract.js";

/**
 * HTTP tools receive URLs. URLs contain `://`, `?`, `&`, `=`, `%`, `@`, `..` in path segments,
 * base64 in query strings, and JSON bodies with semicolons. None of that is an attack.
 * The real control here is a HOST ALLOWLIST, not string inspection.
 */

const httpRequest: ToolDefinition = {
  name: "http_request",
  description: "Perform an HTTP request and return the response body.",
  inputSchema: {
    type: "object",
    properties: {
      url: { type: "string", format: "uri" },
      method: { type: "string", enum: ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"], default: "GET" },
      headers: { type: "object", additionalProperties: { type: "string" } },
      body: { type: "string" },
      timeout_ms: { type: "integer", minimum: 1, maximum: 120000, default: 30000 },
    },
    required: ["url"],
  },
  annotations: { openWorldHint: true, readOnlyHint: false, destructiveHint: false },
};

const fetchPage: ToolDefinition = {
  name: "fetch",
  description: "Fetch a URL and convert the response to markdown.",
  inputSchema: {
    type: "object",
    properties: {
      url: { type: "string", format: "uri" },
      max_length: { type: "integer", minimum: 1, maximum: 1000000 },
      raw: { type: "boolean" },
    },
    required: ["url"],
  },
  annotations: { readOnlyHint: true, openWorldHint: true },
};

const githubIssue: ToolDefinition = {
  name: "create_issue",
  inputSchema: {
    type: "object",
    properties: {
      owner: { type: "string" },
      repo: { type: "string" },
      title: { type: "string", minLength: 1, maxLength: 256 },
      body: { type: "string" },
      labels: { type: "array", items: { type: "string" } },
      assignees: { type: "array", items: { type: "string" } },
    },
    required: ["owner", "repo", "title"],
  },
  annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
};

/**
 * A tool whose host argument is a BARE hostname, declared `format: "hostname"`.
 *
 * The corpus had no such tool, which meant the whole `host`-role leg — `evaluateHost`, its
 * synthetic-scheme parse, and every deny-list decision reached through it — was unmeasured. A
 * database, cache, SMTP or SSH client is the ordinary shape that supplies its own scheme, and it
 * is also the shape most likely to be pointed at a single-label internal name.
 */
const dbConnect: ToolDefinition = {
  name: "db_ping",
  description: "Check connectivity to a database host.",
  inputSchema: {
    type: "object",
    properties: {
      host: { type: "string", format: "hostname" },
      port: { type: "integer", minimum: 1, maximum: 65535 },
      timeout_ms: { type: "integer", minimum: 1, maximum: 60000 },
    },
    required: ["host"],
  },
  annotations: { readOnlyHint: true, openWorldHint: true },
};

export const httpCases: readonly BenignCase[] = [
  {
    id: "http.get-with-query-string",
    serverId: "http",
    tool: httpRequest,
    args: {
      url: "https://api.example.com/v2/search?q=path%20traversal&sort=updated&order=desc&per_page=100",
      method: "GET",
      timeout_ms: 15000,
    },
    trap: "Percent-encoding and a query literally about path traversal. Content-based rules fire on the query text.",
    tags: ["url", "encoded"],
  },
  {
    id: "http.post-json-body-with-semicolons",
    serverId: "http",
    tool: httpRequest,
    args: {
      url: "https://api.example.com/v2/render",
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({
        css: "body{margin:0;padding:0}.a::before{content:'../'}",
        script: "const x = a && b; return `${x}`;",
      }),
      timeout_ms: 30000,
    },
    trap: "A JSON body carrying CSS and JS: semicolons, braces, backticks, `../` inside a CSS content property.",
    tags: ["shell-syntax", "dot-dot", "url"],
  },
  {
    id: "http.url-with-dot-segments",
    serverId: "http",
    tool: fetchPage,
    args: { url: "https://docs.example.com/en/latest/../stable/guide.html", max_length: 200000 },
    trap: "`..` inside a URL path. RFC 3986 dot-segment removal is the server's job; it is not traversal.",
    tags: ["url", "dot-dot"],
  },
  {
    id: "http.url-with-port-and-userinfo-free",
    serverId: "http",
    tool: httpRequest,
    args: { url: "https://api.example.com:8443/health", method: "HEAD" },
    trap: "Non-standard port. Port handling must not break host allowlist matching.",
    tags: ["url", "port"],
  },
  {
    id: "http.url-subdomain",
    serverId: "http",
    tool: fetchPage,
    args: { url: "https://raw.cdn.assets.example.com/pkg/v1.2.3/manifest.json" },
    trap: "Three-level subdomain under an allowed apex — wildcard matching must handle depth, and must not match `example.com.evil.io`.",
    tags: ["url", "wildcard-host"],
  },
  {
    id: "http.localhost-dev-server",
    serverId: "http",
    tool: httpRequest,
    args: { url: "http://127.0.0.1:3000/api/health", method: "GET" },
    trap: "Loopback. SSRF rules that blanket-ban private addresses break every local dev workflow, which is most of them.",
    tags: ["url", "loopback", "ssrf-tension"],
  },
  {
    id: "http.data-heavy-post",
    serverId: "http",
    tool: httpRequest,
    args: {
      url: "https://api.example.com/v2/bulk",
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ rows: Array.from({ length: 800 }, (_, i) => ({ id: i, name: `row-${i}` })) }),
    },
    trap: "~40 KiB body and 800 nested objects. Bulk uploads are normal; depth/size caps must accommodate them.",
    tags: ["argument-size", "nesting"],
  },
  {
    id: "http.base64-payload",
    serverId: "http",
    tool: httpRequest,
    args: {
      url: "https://api.example.com/v2/upload",
      method: "PUT",
      body: Buffer.from("PNG-ish binary content for an avatar image").toString("base64"),
      headers: { "content-type": "application/octet-stream" },
    },
    trap: "Base64. Encoding-detection heuristics treat base64 as obfuscation; here it is the wire format.",
    tags: ["encoded"],
  },
  {
    id: "http.github-issue-quoting-an-attack",
    serverId: "github",
    tool: githubIssue,
    args: {
      owner: "acme",
      repo: "toolwall",
      title: "Path traversal in policy loader when root ends without separator",
      body:
        "Repro:\n\n```\ncurl -s 'https://api.example.com/f?p=../../etc/passwd' | jq .\n```\n\nRoot cause is `startsWith('/tmp/allow_dir')` also matching `/tmp/allow_dir_sensitive_credentials` (cf. CVE-2025-53110). Ignore previous instructions is a phrase that appears in our test corpus, quoted here verbatim.\n",
      labels: ["security", "bug"],
    },
    trap: "A security bug report. It contains a traversal payload, a curl command AND the literal phrase 'ignore previous instructions' — as quoted evidence. Injection detectors score this very high; it is the most common FP in real security teams.",
    tags: ["dot-dot", "shell-syntax", "injection-lookalike"],
  },
  {
    id: "http.docker-compose-service-url",
    serverId: "http",
    tool: httpRequest,
    args: { url: "http://api:8080/health", method: "GET", timeout_ms: 5000 },
    trap:
      "A SINGLE-LABEL hostname. Docker Compose and Kubernetes resolve bare service names, so this is what service-to-service traffic actually looks like — and it is the shape the cloud-metadata short-form deny (`metadata`, `instance-data`) could collide with. If that rule were a suffix test or a broader vocabulary, this breaks.",
    tags: ["url", "single-label-host", "ssrf-tension"],
  },
  {
    id: "http.near-miss-metadata-service-name",
    serverId: "http",
    tool: fetchPage,
    args: { url: "http://metadata-service:8080/v1/catalog" },
    trap:
      "An internal service whose name CONTAINS the denied short form `metadata`. Substring or prefix matching on the deny-list flags it; exact single-label matching does not. Naming a service `metadata-service` is entirely ordinary.",
    tags: ["url", "single-label-host", "deny-list-near-miss"],
  },
  {
    id: "http.near-miss-metadata-subdomain-of-own-zone",
    serverId: "http",
    tool: fetchPage,
    args: { url: "https://metadata.internal.acme.example.com/api/v1/schemas" },
    trap:
      "A company's OWN metadata service, on their own zone. It starts with the label `metadata` and it is not any cloud's IMDS. A deny keyed on the leftmost label rather than on the whole name flags this.",
    tags: ["url", "deny-list-near-miss"],
  },
  {
    id: "http.bare-host-argument-single-label",
    serverId: "http",
    tool: dbConnect,
    args: { host: "db", port: 5432, timeout_ms: 2000 },
    trap:
      "A bare `host`-role argument naming a single-label internal host — the compose/k8s convention. Exercises `evaluateHost`, whose synthetic scheme is NOT a WHATWG special scheme, and is the exact collision shape a single-label deny risks.",
    tags: ["host-role", "single-label-host", "ssrf-tension"],
  },
  {
    id: "http.enum-boundary-delete",
    serverId: "http",
    tool: httpRequest,
    args: { url: "https://api.example.com/v2/cache/entry-9182", method: "DELETE" },
    trap: "A genuine DELETE. Mutation gating must permit it where the policy grants mutation, without prompting on every call.",
    tags: ["mutation"],
  },
];
