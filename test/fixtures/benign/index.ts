import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import type { BenignCase } from "./types.js";
import { codeEditingCases } from "./code-editing.js";
import { gitCases } from "./git.js";
import { httpCases } from "./http.js";
import { sqlCases } from "./sql.js";
import { filesystemCases } from "./filesystem.js";
import { miscCases } from "./misc.js";

export type { BenignCase } from "./types.js";

const RAW_CASES: readonly BenignCase[] = [
  ...codeEditingCases,
  ...gitCases,
  ...httpCases,
  ...sqlCases,
  ...filesystemCases,
  ...miscCases,
];

/**
 * Materialize a real temporary workspace so filesystem containment is measured against the real
 * filesystem — real directories, a real in-tree symlink, and a real sibling directory whose name
 * shares a prefix with the root (the EscapeRoute shape). Mocking this would let a containment bug
 * pass the corpus.
 */
export interface Workspace {
  readonly root: string;
  readonly scratch: string;
  cleanup(): void;
}

const DIRS = [
  "src",
  "src/db",
  "src/lib",
  "src/i18n",
  "src/guards/runtime",
  "packages/api",
  "packages/shared",
  "docs",
  "scripts",
  "dist",
  ".github/workflows",
];

const FILES: Readonly<Record<string, string>> = {
  "package.json": '{ "name": "workspace" }\n',
  "src/index.ts": "export const ok = true;\n",
  "src/log.ts": "console.log('start')\n",
  "packages/shared/types.ts": "export type Id = string;\n",
};

export function createWorkspace(): Workspace {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "toolwall-benign-"));
  // Sibling sharing a string prefix with `root` — `<root>-scratch`. This is the exact shape of
  // CVE-2025-53110, here as a legitimately-granted separate root.
  const scratch = `${root}-scratch`;
  fs.mkdirSync(scratch, { recursive: true });
  fs.writeFileSync(path.join(scratch, "notes.md"), "# notes\n");

  for (const d of DIRS) fs.mkdirSync(path.join(root, d), { recursive: true });
  for (const [f, content] of Object.entries(FILES)) fs.writeFileSync(path.join(root, f), content);
  for (let i = 0; i < 300; i++) fs.writeFileSync(path.join(root, "src", `mod_${i}.ts`), "export {};\n");

  // A symlink that stays inside the root. Resolution must follow it (CVE-2025-53109) without
  // rejecting it — node_modules, pnpm stores and monorepo links are all symlinks.
  const link = path.join(root, "link-to-src");
  if (!fs.existsSync(link)) fs.symlinkSync("src", link, "dir");

  return {
    root,
    scratch,
    cleanup(): void {
      fs.rmSync(root, { recursive: true, force: true });
      fs.rmSync(scratch, { recursive: true, force: true });
    },
  };
}

function substitute(value: unknown, root: string): unknown {
  if (typeof value === "string") return value.split("<WS>").join(root);
  if (Array.isArray(value)) return value.map((v) => substitute(v, root));
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) out[k] = substitute(v, root);
    return out;
  }
  return value;
}

/** The corpus with `<WS>` bound to a real directory. */
export function benignCorpus(ws: Workspace): readonly BenignCase[] {
  return RAW_CASES.map((c) => ({ ...c, args: substitute(c.args, ws.root) as Record<string, unknown> }));
}

/** Corpus size and composition, for the FP report header. */
export function corpusSummary(): { total: number; byTag: Record<string, number>; byServer: Record<string, number> } {
  const byTag: Record<string, number> = {};
  const byServer: Record<string, number> = {};
  for (const c of RAW_CASES) {
    byServer[c.serverId] = (byServer[c.serverId] ?? 0) + 1;
    for (const t of c.tags) byTag[t] = (byTag[t] ?? 0) + 1;
  }
  return { total: RAW_CASES.length, byTag, byServer };
}

/**
 * A tool-definition source backed by the corpus itself, standing in for Dev 2's pin store.
 */
export function corpusToolSource(cases: readonly BenignCase[]): { get(serverId: string, toolName: string): BenignCase["tool"] | undefined } {
  const map = new Map<string, BenignCase["tool"]>();
  for (const c of cases) map.set(`${c.serverId} ${c.tool.name}`, c.tool);
  return {
    get(serverId, toolName) {
      return map.get(`${serverId} ${toolName}`);
    },
  };
}

/**
 * The starter policy an operator would write for these servers — the "configured" scenario.
 *
 * Note what is NOT bound: `git_diff.paths`, `git_add.files` and `git_commit.files` are
 * repo-RELATIVE pathspecs, not filesystem paths, and binding them to a path role would resolve
 * them against the wrong base and produce false escapes. Role binding must reflect the argument's
 * actual semantics; a wrong binding is a self-inflicted false positive. (Per-argument resolution
 * bases are a known gap — see the report.)
 */
export function starterPolicyDocument(ws: Workspace): Record<string, unknown> {
  const roots = [ws.root, ws.scratch];
  const readOnly = { mutates: false } as const;

  return {
    version: 1,
    tier: "balanced",
    servers: {
      editor: {
        defaults: { filesystem: { read: roots, write: roots, allowNonexistent: true } },
        tools: {
          write_file: { roles: { writePath: ["/path"] }, mutates: true },
          edit_file: { roles: { writePath: ["/path"] }, mutates: true },
          read_file: { roles: { readPath: ["/path"] }, ...readOnly },
          grep: { roles: { readPath: ["/path"] }, ...readOnly },
        },
      },
      git: {
        defaults: { filesystem: { read: roots, write: roots, allowNonexistent: true } },
        tools: {
          git_diff: { roles: { readPath: ["/repo_path"] }, ...readOnly },
          git_log: { roles: { readPath: ["/repo_path"] }, ...readOnly },
          git_commit: { roles: { writePath: ["/repo_path"] }, mutates: true },
          git_add: { roles: { writePath: ["/repo_path"] }, mutates: true },
        },
      },
      filesystem: {
        defaults: { filesystem: { read: roots, write: roots, allowNonexistent: true } },
        tools: {
          list_directory: { roles: { readPath: ["/path"] }, ...readOnly },
          read_multiple_files: { roles: { readPath: ["/paths/*"] }, ...readOnly },
          search_files: { roles: { readPath: ["/path"] }, ...readOnly },
          move_file: { roles: { readPath: ["/source"], writePath: ["/destination"] }, mutates: true },
        },
      },
      http: {
        defaults: {
          network: {
            // The three public/loopback entries plus the internal service names this deployment's
            // own traffic uses. An operator who writes an allowlist writes it against the traffic
            // they see, and `http://api:8080/health` and a `db` host appear in that traffic every
            // day — omitting them would not be measuring a rule, it would be measuring a
            // mis-specified fixture. `metadata.internal.acme.example.com` is covered by the
            // `*.example.com` wildcard, and `memory`'s citation host is deliberately still absent
            // so `enforce: "scan"` keeps costing what it costs.
            hosts: ["api.example.com", "*.example.com", "127.0.0.1", "api", "metadata-service", "db"],
            schemes: ["https", "http"],
            allowIpLiterals: false,
            allowPrivateNetwork: false,
          },
        },
        tools: {
          // `url` roles come from the tools' own `"format": "uri"` declarations.
          http_request: { mutates: true },
          fetch: { ...readOnly },
          db_ping: { ...readOnly, roles: { host: ["/host"] } },
        },
      },
      github: { tools: { create_issue: { mutates: true } } },
      postgres: {
        tools: {
          query: { ...readOnly },
          list_tables: { ...readOnly },
          execute: { mutates: true },
        },
      },
      slack: { tools: { post_message: { mutates: true } } },
      jira: { tools: { search_issues: { ...readOnly } } },
      memory: { tools: { store_entity: { mutates: true } } },
      weather: { tools: { get_forecast: { ...readOnly } } },
      calc: { tools: { calculate: { ...readOnly } } },
    },
  };
}

/**
 * The starter policy PLUS a global egress allowlist — the Week 2 scenario.
 *
 * The host list is what an operator would plausibly write after looking at their own traffic:
 * their API, its subdomains, and localhost. It deliberately does NOT contain every host that
 * appears anywhere in the corpus, because a real operator's allowlist never does — and the gap is
 * exactly what `enforce: "scan"` costs. Measuring with a list tuned to score well would be
 * measuring nothing.
 */
export function egressPolicyDocument(ws: Workspace, enforce: "roles" | "scan"): Record<string, unknown> {
  return {
    ...starterPolicyDocument(ws),
    egress: {
      enforce,
      hosts: ["api.example.com", "*.example.com", "127.0.0.1", "api", "metadata-service", "db"],
      schemes: ["https", "http"],
    },
  };
}
