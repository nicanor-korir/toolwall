import type { BenignCase } from "./types.js";
import type { ToolDefinition } from "../../../src/policy/contract.js";

/**
 * Git tools receive `..` constantly and legitimately: it is git's own range syntax
 * (`main..HEAD`, `origin/main...HEAD`), and monorepo paths cross package boundaries.
 * A `../` blocklist makes a git MCP server unusable within an hour.
 */

const gitDiff: ToolDefinition = {
  name: "git_diff",
  description: "Show changes between commits, commit and working tree, etc.",
  inputSchema: {
    type: "object",
    properties: {
      repo_path: { type: "string" },
      revision_range: { type: "string" },
      paths: { type: "array", items: { type: "string" }, maxItems: 200 },
      context_lines: { type: "integer", minimum: 0, maximum: 100, default: 3 },
      stat_only: { type: "boolean" },
    },
    required: ["repo_path"],
  },
  annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true },
};

const gitLog: ToolDefinition = {
  name: "git_log",
  inputSchema: {
    type: "object",
    properties: {
      repo_path: { type: "string" },
      revision_range: { type: "string" },
      max_count: { type: "integer", minimum: 1, maximum: 1000 },
      author: { type: "string" },
      since: { type: "string", format: "date-time" },
    },
    required: ["repo_path"],
  },
  annotations: { readOnlyHint: true },
};

const gitCommit: ToolDefinition = {
  name: "git_commit",
  description: "Create a commit from the current index.",
  inputSchema: {
    type: "object",
    properties: {
      repo_path: { type: "string" },
      message: { type: "string", minLength: 1, maxLength: 20000 },
      files: { type: "array", items: { type: "string" } },
      amend: { type: "boolean", default: false },
    },
    required: ["repo_path", "message"],
  },
  // Deliberately NO annotations on this one: per spec defaults an unannotated tool is
  // destructiveHint: true, openWorldHint: true. This case measures how much friction our
  // "unannotated means destructive" posture costs on a perfectly ordinary commit.
};

const gitAdd: ToolDefinition = {
  name: "git_add",
  inputSchema: {
    type: "object",
    properties: {
      repo_path: { type: "string" },
      files: { type: "array", items: { type: "string" }, minItems: 1 },
    },
    required: ["repo_path", "files"],
  },
  annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true },
};

export const gitCases: readonly BenignCase[] = [
  {
    id: "git.diff-two-dot-range",
    serverId: "git",
    tool: gitDiff,
    args: { repo_path: "<WS>", revision_range: "main..HEAD", context_lines: 3 },
    trap: "`main..HEAD` — git's own range operator is literally two dots. Blocklists on `..` break it.",
    tags: ["dot-dot", "git-range"],
  },
  {
    id: "git.diff-three-dot-range",
    serverId: "git",
    tool: gitDiff,
    args: { repo_path: "<WS>", revision_range: "origin/main...feature/pathfix", stat_only: true },
    trap: "Three-dot symmetric-difference range plus a branch name that contains the word 'path'.",
    tags: ["dot-dot", "git-range"],
  },
  {
    id: "git.diff-parent-commit",
    serverId: "git",
    tool: gitDiff,
    args: { repo_path: "<WS>", revision_range: "HEAD~3..HEAD^2" },
    trap: "Caret and tilde commit selectors alongside a `..` range.",
    tags: ["dot-dot", "git-range", "shell-syntax"],
  },
  {
    id: "git.diff-monorepo-relative-paths",
    serverId: "git",
    tool: gitDiff,
    args: {
      repo_path: "<WS>/packages/api",
      paths: ["../shared/src/index.ts", "../../tools/build.mjs", "./src/routes/*.ts"],
      revision_range: "main..HEAD",
    },
    trap: "Relative paths with `../` and `../../` that all resolve back inside the repo. Standard monorepo diffing.",
    tags: ["dot-dot", "path-array"],
  },
  {
    id: "git.log-since",
    serverId: "git",
    tool: gitLog,
    args: { repo_path: "<WS>", revision_range: "v1.2.0..v1.3.0", max_count: 100, since: "2026-01-01T00:00:00Z" },
    trap: "Tag range with dots in the version numbers as well as the range operator.",
    tags: ["dot-dot", "git-range"],
  },
  {
    id: "git.log-author-with-quotes",
    serverId: "git",
    tool: gitLog,
    args: { repo_path: "<WS>", author: "O'Brien, Seán <sean.obrien@example.co.uk>", max_count: 20 },
    trap: "Apostrophe, comma, angle brackets and a non-ASCII name in a free-text field.",
    tags: ["shell-syntax", "unicode"],
  },
  {
    id: "git.commit-multiline-message",
    serverId: "git",
    tool: gitCommit,
    args: {
      repo_path: "<WS>",
      message:
        "fix(policy): reject `..` escapes via symlink\n\nUse canonical resolution instead of startsWith();\nsee CVE-2025-53110. Closes #142.\n\nCo-Authored-By: Dev 3 <dev3@example.com>\n",
      files: ["src/policy/containment.ts", "test/unit/containment.test.ts"],
    },
    trap: "Unannotated tool (spec default: destructive) with a commit message containing backticks, `..`, semicolons and angle brackets.",
    tags: ["unannotated", "shell-syntax", "dot-dot"],
  },
  {
    id: "git.commit-empty-file-list",
    serverId: "git",
    tool: gitCommit,
    args: { repo_path: "<WS>", message: "chore: bump deps", amend: false },
    trap: "Optional array omitted entirely — required/optional handling must not treat absent as invalid.",
    tags: ["unannotated", "schema-optional"],
  },
  {
    id: "git.add-many-files",
    serverId: "git",
    tool: gitAdd,
    args: {
      repo_path: "<WS>",
      files: Array.from({ length: 120 }, (_, i) => `src/generated/model_${i}.ts`),
    },
    trap: "120-element array. Any low maxItems/argument-count bound blocks a routine generated-code commit.",
    tags: ["argument-size", "path-array"],
  },
  {
    id: "git.add-dotfiles",
    serverId: "git",
    tool: gitAdd,
    args: { repo_path: "<WS>", files: [".github/workflows/ci.yml", ".env.example", ".gitignore"] },
    trap: "Leading-dot paths, including `.env.example`, which secret-scanners flag on the filename alone.",
    tags: ["dotfile"],
  },
];
