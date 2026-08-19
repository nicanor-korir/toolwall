import type { BenignCase } from "./types.js";
import type { ToolDefinition } from "../../../src/policy/contract.js";

/**
 * A SQL tool receives SQL. Semicolons, comments, quotes, `--`, and `DROP` in a string literal
 * are the medium, not the attack. Note the real threat we DO care about (Postgres MCP stacked
 * statements, THREAT-MODEL T-05) is not addressed by looking for `;` — it is addressed by the
 * capability policy declaring whether this tool may mutate at all.
 */

const query: ToolDefinition = {
  name: "query",
  description: "Run a read-only SQL query.",
  inputSchema: {
    type: "object",
    properties: {
      sql: { type: "string", maxLength: 100000 },
      params: { type: "array", items: {} },
      database: { type: "string" },
      row_limit: { type: "integer", minimum: 1, maximum: 10000, default: 1000 },
    },
    required: ["sql"],
  },
  annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true },
};

const execute: ToolDefinition = {
  name: "execute",
  description: "Run a statement that modifies data.",
  inputSchema: {
    type: "object",
    properties: {
      sql: { type: "string" },
      params: { type: "array", items: {} },
    },
    required: ["sql"],
  },
  annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false },
};

const listTables: ToolDefinition = {
  name: "list_tables",
  inputSchema: {
    type: "object",
    properties: { schema: { type: "string", default: "public" } },
  },
  annotations: { readOnlyHint: true },
};

export const sqlCases: readonly BenignCase[] = [
  {
    id: "sql.select-with-trailing-semicolon",
    serverId: "postgres",
    tool: query,
    args: { sql: "SELECT id, email, created_at FROM users WHERE tenant_id = $1 ORDER BY created_at DESC;", params: ["t-9012"], row_limit: 500 },
    trap: "A trailing semicolon. The single most common false positive in every SQL-aware scanner.",
    tags: ["sql-syntax", "semicolon"],
  },
  {
    id: "sql.cte-with-comments",
    serverId: "postgres",
    tool: query,
    args: {
      sql:
        "-- daily active users, excludes internal accounts\nWITH active AS (\n  SELECT user_id, date_trunc('day', ts) AS d\n  FROM events\n  WHERE ts > now() - interval '30 days'\n)\nSELECT d, count(DISTINCT user_id) FROM active\nJOIN users u ON u.id = active.user_id\nWHERE u.email NOT LIKE '%@acme-internal.com'\nGROUP BY 1 ORDER BY 1;",
      row_limit: 1000,
    },
    trap: "`--` comment marker at the start, `%` wildcards, quotes, and a semicolon. Textbook 'SQL injection' signature; textbook analytics query.",
    tags: ["sql-syntax", "semicolon", "comment"],
  },
  {
    id: "sql.string-literal-containing-drop",
    serverId: "postgres",
    tool: query,
    args: {
      sql: "SELECT * FROM audit_log WHERE statement ILIKE '%DROP SCHEMA public CASCADE%' AND ts > $1",
      params: ["2026-08-01T00:00:00Z"],
    },
    trap: "The literal text `DROP SCHEMA public CASCADE` — the exact Postgres-MCP stacked-statement payload — inside a WHERE clause. A DBA auditing for that attack gets blocked by a keyword rule.",
    tags: ["sql-syntax", "injection-lookalike"],
  },
  {
    id: "sql.union-report",
    serverId: "postgres",
    tool: query,
    args: {
      sql: "SELECT 'signup' AS kind, count(*) FROM users UNION ALL SELECT 'purchase', count(*) FROM orders",
    },
    trap: "`UNION ALL` — the canonical union-injection signature, here a perfectly ordinary report.",
    tags: ["sql-syntax", "injection-lookalike"],
  },
  {
    id: "sql.json-path-operators",
    serverId: "postgres",
    tool: query,
    args: {
      sql: "SELECT payload#>>'{user,profile,name}' AS name, payload->'flags'->>0 AS first_flag FROM events WHERE payload @> '{\"kind\":\"signup\"}'::jsonb",
    },
    trap: "Postgres JSON operators `#>>`, `->>`, `@>` and a `::jsonb` cast look like shell redirection and metacharacter soup.",
    tags: ["sql-syntax", "shell-syntax"],
  },
  {
    id: "sql.parameterized-update",
    serverId: "postgres",
    tool: execute,
    args: { sql: "UPDATE users SET last_seen_at = now() WHERE id = $1", params: ["u-4471"] },
    trap: "A genuine, correctly parameterized mutation on a tool annotated destructiveHint: true. Confirmation friction here is a policy choice we must measure, not hide.",
    tags: ["mutation", "destructive-hint"],
  },
  {
    id: "sql.migration-multi-statement",
    serverId: "postgres",
    tool: execute,
    args: {
      sql: "BEGIN;\nALTER TABLE users ADD COLUMN IF NOT EXISTS locale text NOT NULL DEFAULT 'en';\nCREATE INDEX CONCURRENTLY IF NOT EXISTS users_locale_idx ON users (locale);\nCOMMIT;",
    },
    trap: "Genuinely multi-statement, on purpose: it is a migration. The transaction-escape threat and a real migration are textually identical, which is precisely why the control must be capability policy, not string matching.",
    tags: ["mutation", "semicolon", "multi-statement"],
  },
  {
    id: "sql.list-tables-defaults",
    serverId: "postgres",
    tool: listTables,
    args: {},
    trap: "Empty arguments object. Required/optional and additionalProperties handling must not fail on `{}`.",
    tags: ["schema-optional"],
  },
];
