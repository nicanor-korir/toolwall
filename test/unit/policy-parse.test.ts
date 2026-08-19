import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { parsePolicy, defaultPolicy } from "../../src/policy/parse.js";
import { tierPreset } from "../../src/policy/schema.js";

let root: string;
beforeAll(() => {
  root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "toolwall-policy-")));
});
afterAll(() => fs.rmSync(root, { recursive: true, force: true }));

const errAt = (r: ReturnType<typeof parsePolicy>): string[] => (r.ok ? [] : r.errors.map((e) => e.at));

describe("policy validation rejects the mistakes that silently weaken a policy", () => {
  it("rejects a typo'd key rather than treating it as an empty allowlist", () => {
    const r = parsePolicy({ version: 1, tier: "balanced", servers: { s: { defaults: { network: { hots: ["a.com"] } } } } });
    expect(r.ok).toBe(false);
    expect(errAt(r)).toContain("/servers/s/defaults/network/hots");
  });

  it("rejects an unknown top-level key", () => {
    expect(parsePolicy({ version: 1, tier: "balanced", server: {} }).ok).toBe(false);
  });

  it("rejects a substring wildcard in a host entry", () => {
    const r = parsePolicy({ version: 1, servers: { s: { defaults: { network: { hosts: ["*example*"] } } } } });
    expect(r.ok).toBe(false);
    expect(errAt(r)).toContain("/servers/s/defaults/network/hosts/0");
  });

  it("rejects a role selector that is not a JSON Pointer", () => {
    const r = parsePolicy({ version: 1, servers: { s: { tools: { t: { roles: { readPath: ["path"] } } } } } });
    expect(r.ok).toBe(false);
    expect(errAt(r)).toContain("/servers/s/tools/t/roles/readPath/0");
  });

  it("rejects a relative filesystem root at load time", () => {
    const r = parsePolicy({ version: 1, servers: { s: { defaults: { filesystem: { read: ["./relative"] } } } } });
    expect(r.ok).toBe(false);
  });

  it("accepts a nonexistent filesystem root, which then contains nothing (fails safe, not silent)", () => {
    const r = parsePolicy({ version: 1, servers: { s: { defaults: { filesystem: { read: [path.join(root, "does-not-exist")] } } } } });
    // A root that does not exist cannot be canonicalized to what the operator meant.
    expect(r.ok).toBe(true); // it canonicalizes structurally
    // ...but it will never contain anything, which is the safe direction. Documented, not silent:
    if (r.ok) {
      const g = r.policy.grantFor("s", "t").grant;
      expect(g.filesystem?.read[0]).toBe(path.join(root, "does-not-exist"));
    }
  });

  it("rejects a bad tier and a bad version", () => {
    expect(parsePolicy({ version: 2, tier: "balanced" }).ok).toBe(false);
    expect(parsePolicy({ version: 1, tier: "paranoid" }).ok).toBe(false);
  });

  it("warns when strict is set with no servers declared, because everything will block", () => {
    const r = parsePolicy({ version: 1, tier: "strict" });
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.warnings.join(" ")).toContain("every tools/call will be blocked");
  });
});

describe("resolution and merge", () => {
  // Built lazily: `root` is assigned in beforeAll, which runs after the describe body.
  const doc = (): Record<string, unknown> => ({
    version: 1,
    tier: "balanced",
    defaults: { bounds: { maxDepth: 10 } },
    servers: {
      s: {
        defaults: { filesystem: { read: [root] }, mutation: "confirm" },
        tools: {
          t: { roles: { readPath: ["/p"] }, mutation: "allow" },
        },
      },
    },
  });

  it("layers tier -> global defaults -> server defaults -> tool", () => {
    const r = parsePolicy(doc());
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const { grant, known } = r.policy.grantFor("s", "t");
    expect(known).toBe(true);
    expect(grant.bounds.maxDepth).toBe(10); // from global defaults
    expect(grant.bounds.maxTotalBytes).toBe(tierPreset("balanced").bounds.maxTotalBytes); // from tier
    expect(grant.filesystem?.read).toEqual([root]); // from server defaults
    expect(grant.mutation).toBe("allow"); // tool overrides server
    expect(grant.roles.readPath).toEqual(["/p"]);
  });

  it("marks a tool with no entry as unknown but still inherits the server grant", () => {
    const r = parsePolicy(doc());
    if (!r.ok) throw new Error("parse failed");
    const { grant, known } = r.policy.grantFor("s", "other");
    expect(known).toBe(false);
    expect(grant.mutation).toBe("confirm");
  });

  it("arrays replace rather than concatenate, so a tool can NARROW a server grant", () => {
    const r = parsePolicy({
      version: 1,
      servers: { s: { defaults: { filesystem: { read: [root, os.tmpdir()] } }, tools: { t: { filesystem: { read: [root] } } } } },
    });
    if (!r.ok) throw new Error("parse failed");
    expect(r.policy.grantFor("s", "t").grant.filesystem?.read).toEqual([root]);
  });

  it("canonicalizes a symlinked root at load time", () => {
    const real = path.join(root, "real");
    const link = path.join(root, "link");
    fs.mkdirSync(real, { recursive: true });
    if (!fs.existsSync(link)) fs.symlinkSync(real, link, "dir");
    const r = parsePolicy({ version: 1, servers: { s: { defaults: { filesystem: { read: [link] } } } } });
    if (!r.ok) throw new Error("parse failed");
    expect(r.policy.grantFor("s", "t").grant.filesystem?.read).toEqual([real]);
  });
});

describe("tier presets", () => {
  it("balanced does not enforce undeclared capabilities, strict does", () => {
    expect(tierPreset("balanced").undeclaredCapability).toBe("allow");
    expect(tierPreset("strict").undeclaredCapability).toBe("deny");
  });

  it("strict ignores server annotations entirely", () => {
    expect(tierPreset("strict").trustAnnotations).toBe("never");
    expect(tierPreset("balanced").trustAnnotations).toBe("as-signal");
  });

  it("only strict rejects undeclared properties", () => {
    expect(tierPreset("permissive").schema.additionalProperties).toBe("schema");
    expect(tierPreset("balanced").schema.additionalProperties).toBe("schema");
    expect(tierPreset("strict").schema.additionalProperties).toBe("reject");
  });

  it("defaultPolicy returns the tier preset for every lookup and marks nothing known", () => {
    const p = defaultPolicy("balanced");
    expect(p.grantFor("anything", "at-all").known).toBe(false);
    expect(p.grantFor("anything", "at-all").grant.mutation).toBe("allow");
  });
});

describe("the shipped example policy parses", () => {
  it("toolwall-policy.example.json is valid", () => {
    const file = path.join(process.cwd(), "toolwall-policy.example.json");
    const doc = JSON.parse(fs.readFileSync(file, "utf8")) as Record<string, unknown>;
    // Roots in the example are placeholders; swap them for a real dir so canonicalization succeeds.
    const json = JSON.stringify(doc).split("/Users/you/projects/my-app").join(root);
    const r = parsePolicy(JSON.parse(json));
    if (!r.ok) throw new Error(JSON.stringify(r.errors, null, 2));
    expect(r.ok).toBe(true);
  });
});
