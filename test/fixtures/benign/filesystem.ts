import type { BenignCase } from "./types.js";
import type { ToolDefinition } from "../../../src/policy/contract.js";

/**
 * Filesystem cases that exercise canonical containment against a REAL temp workspace the harness
 * materializes (including a real in-workspace symlink). These are the calls that must survive the
 * CVE-2025-53110 / CVE-2025-53109 fix — a containment check that is too strict is just as broken
 * as one that is too loose, it simply fails in the direction nobody files a CVE about.
 */

const listDirectory: ToolDefinition = {
  name: "list_directory",
  inputSchema: {
    type: "object",
    properties: { path: { type: "string" }, recursive: { type: "boolean" }, max_depth: { type: "integer", minimum: 1, maximum: 32 } },
    required: ["path"],
  },
  annotations: { readOnlyHint: true },
};

const moveFile: ToolDefinition = {
  name: "move_file",
  inputSchema: {
    type: "object",
    properties: { source: { type: "string" }, destination: { type: "string" } },
    required: ["source", "destination"],
  },
  annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false },
};

const readMultiple: ToolDefinition = {
  name: "read_multiple_files",
  inputSchema: {
    type: "object",
    properties: { paths: { type: "array", items: { type: "string" }, minItems: 1, maxItems: 500 } },
    required: ["paths"],
  },
  annotations: { readOnlyHint: true },
};

const searchFiles: ToolDefinition = {
  name: "search_files",
  inputSchema: {
    type: "object",
    properties: {
      path: { type: "string" },
      pattern: { type: "string" },
      exclude_patterns: { type: "array", items: { type: "string" } },
    },
    required: ["path", "pattern"],
  },
  annotations: { readOnlyHint: true },
};

export const filesystemCases: readonly BenignCase[] = [
  {
    id: "fs.list-workspace-root",
    serverId: "filesystem",
    tool: listDirectory,
    args: { path: "<WS>", recursive: false },
    trap: "The allowed root itself. Containment checks that require a trailing separator reject the root and break the very first call a user makes.",
    tags: ["path-field", "containment-boundary"],
  },
  {
    id: "fs.list-with-trailing-separator",
    serverId: "filesystem",
    tool: listDirectory,
    args: { path: "<WS>/src/", recursive: true, max_depth: 4 },
    trap: "Trailing separator on a directory path. Naive string comparison treats `/a/b` and `/a/b/` as different.",
    tags: ["path-field", "containment-boundary"],
  },
  {
    id: "fs.read-through-in-workspace-symlink",
    serverId: "filesystem",
    tool: readMultiple,
    // `<WS>/link-to-src` is a real symlink -> `<WS>/src`, created by the harness.
    args: { paths: ["<WS>/link-to-src/index.ts", "<WS>/src/index.ts"] },
    trap: "A symlink that stays INSIDE the allowed root. Resolving symlinks is required for CVE-2025-53109, but resolving them must not reject legitimate in-tree links — node_modules, pnpm stores and monorepo links are all symlinks.",
    tags: ["symlink", "path-array"],
  },
  {
    id: "fs.read-normalizing-dotdot",
    serverId: "filesystem",
    tool: readMultiple,
    args: { paths: ["<WS>/src/../src/index.ts", "<WS>/./package.json"] },
    trap: "`..` and `.` segments that normalize back inside the root.",
    tags: ["dot-dot", "path-array"],
  },
  {
    id: "fs.write-to-nonexistent-nested-path",
    serverId: "filesystem",
    tool: moveFile,
    args: { source: "<WS>/src/index.ts", destination: "<WS>/dist/deeply/nested/not/created/yet/index.js" },
    trap: "Destination does not exist yet. realpath() throws ENOENT on it; a containment check that requires the path to exist blocks every file creation.",
    tags: ["path-field", "nonexistent", "mutation"],
  },
  {
    id: "fs.sibling-directory-with-shared-prefix",
    serverId: "filesystem",
    tool: listDirectory,
    // `<WS>-scratch` shares a string prefix with `<WS>` but is a SEPARATE allowed root.
    args: { path: "<WS>-scratch/notes.md" },
    trap: "The EscapeRoute shape in reverse: a directory whose name shares a prefix with an allowed root, which here is separately and legitimately allowed. Getting containment right must not mean rejecting explicitly granted roots.",
    tags: ["containment-boundary", "prefix-collision"],
  },
  {
    id: "fs.search-with-glob-excludes",
    serverId: "filesystem",
    tool: searchFiles,
    args: {
      path: "<WS>",
      pattern: "**/*.{ts,tsx}",
      exclude_patterns: ["**/node_modules/**", "**/dist/**", "../**"],
    },
    trap: "An exclude pattern that is literally `../**`. Glob patterns are not paths and must not be canonicalized as if they were.",
    tags: ["dot-dot", "glob"],
  },
  {
    id: "fs.read-many-paths",
    serverId: "filesystem",
    tool: readMultiple,
    args: { paths: Array.from({ length: 300 }, (_, i) => `<WS>/src/mod_${i}.ts`) },
    trap: "300 paths, all in-root. Per-path canonicalization must stay within the latency budget and must not be capped below the schema's own maxItems of 500.",
    tags: ["argument-size", "path-array", "perf"],
  },
];
