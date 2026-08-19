import { describe, expect, it } from "vitest";

import { SchemaGuard, looksCatastrophic } from "../../src/guards/runtime/schema-guard.js";
import { defaultPolicy } from "../../src/policy/parse.js";
import type { AuditSink, Finding, GuardContext, ToolDefinition, Verdict } from "../../src/policy/contract.js";
import type { StrictnessTier } from "../../src/policy/schema.js";

const ctx: GuardContext = { era: "2025-11-25", serverId: "srv", direction: "request", method: "tools/call" };

const calculator: ToolDefinition = {
  name: "calculate",
  inputSchema: {
    type: "object",
    properties: {
      a: { type: "number" },
      b: { type: "number" },
      op: { type: "string", enum: ["add", "sub", "mul", "div", "pow"] },
      precision: { type: "integer", minimum: 0, maximum: 15 },
    },
    required: ["a", "b", "op"],
    additionalProperties: false,
  },
  annotations: { readOnlyHint: true, openWorldHint: false },
};

// Informational findings ride the audit sink, not the verdict, because Dev 1's `allow` carries
// no findings. Collect them so the tests can assert on what the guard recorded but did not block.
let audited: Finding[] = [];
const audit: AuditSink = (f) => {
  audited.push(...f);
};

function guardFor(tool: ToolDefinition | undefined, tier: StrictnessTier = "balanced"): SchemaGuard {
  return new SchemaGuard({ policy: defaultPolicy(tier), tools: { get: () => tool }, audit });
}

function call(guard: SchemaGuard, name: string, args: unknown): Verdict {
  audited = [];
  // Dev 1 hands guards the raw JSON-RPC `params`.
  return guard.inspect({ name, arguments: args }, ctx);
}

/** Rule ids from the verdict AND the audit sink, with the `toolwall/` namespace stripped. */
const rules = (v: Verdict): string[] =>
  [...("findings" in v ? v.findings : []), ...audited].map((f) => f.ruleId.replace(/^toolwall\//, ""));

describe("schema enforcement — the tool's own published contract", () => {
  const g = guardFor(calculator);

  it("allows a conforming call", () => {
    expect(call(g, "calculate", { a: 1, b: 2, op: "add" }).action).toBe("allow");
  });

  it("blocks a filesystem path smuggled into a numeric argument", () => {
    // The design claim from the brief made concrete: a calculator cannot receive a path, and the
    // reason is not that we recognised the string as a path — it is that a string is not a number.
    const v = call(g, "calculate", { a: "../../../../etc/passwd", b: 2, op: "add" });
    expect(v.action).toBe("block");
    expect(rules(v)).toContain("schema.type");
    if (v.action === "block") expect(v.code).toBe(-32602);
  });

  it("blocks an enum violation", () => {
    const v = call(g, "calculate", { a: 1, b: 2, op: "exec" });
    expect(v.action).toBe("block");
    expect(rules(v)).toContain("schema.enum");
  });

  it("blocks an out-of-range integer", () => {
    expect(call(g, "calculate", { a: 1, b: 2, op: "add", precision: 99 }).action).toBe("block");
    expect(call(g, "calculate", { a: 1, b: 2, op: "add", precision: -1 }).action).toBe("block");
  });

  it("allows values exactly on inclusive bounds", () => {
    expect(call(g, "calculate", { a: 1, b: 2, op: "add", precision: 0 }).action).toBe("allow");
    expect(call(g, "calculate", { a: 1, b: 2, op: "add", precision: 15 }).action).toBe("allow");
  });

  it("blocks a missing required property", () => {
    const v = call(g, "calculate", { a: 1, b: 2 });
    expect(v.action).toBe("block");
    expect(rules(v)).toContain("schema.required");
  });

  it("blocks an undeclared property when the schema says additionalProperties: false", () => {
    const v = call(g, "calculate", { a: 1, b: 2, op: "add", shell: "rm -rf /" });
    expect(v.action).toBe("block");
    expect(rules(v)).toContain("schema.additionalProperties");
  });

  it("blocks prototype-pollution property names at every tier", () => {
    for (const tier of ["permissive", "balanced", "strict"] as const) {
      const v = call(guardFor(calculator, tier), "calculate", { a: 1, b: 2, op: "add", ["__proto__"]: { polluted: true } });
      expect(rules(v), tier).toContain("schema.prototype-key");
      expect(v.action, tier).toBe("block");
    }
  });

  it("rejects an integer keyword violated by a float", () => {
    expect(call(g, "calculate", { a: 1, b: 2, op: "add", precision: 1.5 }).action).toBe("block");
  });
});

describe("additionalProperties tiering", () => {
  const underSpecified: ToolDefinition = {
    name: "post_message",
    inputSchema: { type: "object", properties: { channel: { type: "string" }, text: { type: "string" } }, required: ["channel"] },
  };

  it("permits undeclared properties at balanced (JSON Schema's own default)", () => {
    const v = call(guardFor(underSpecified, "balanced"), "post_message", { channel: "C1", text: "hi", blocks: [] });
    expect(v.action).toBe("allow");
  });

  it("rejects them at strict, and says exactly how to opt out", () => {
    const v = call(guardFor(underSpecified, "strict"), "post_message", { channel: "C1", text: "hi", blocks: [] });
    expect(v.action).toBe("block");
    expect(rules(v)).toContain("schema.undeclared-property");
    if (v.action === "block") {
      const f = v.findings.find((x) => x.ruleId === "toolwall/schema.undeclared-property");
      expect(f?.remediation).toContain("additionalProperties");
      expect(f?.locus).toBe("/arguments/blocks");
    }
  });
});

describe("missing tool definition", () => {
  it("allows with a recorded gap at balanced", () => {
    const v = call(guardFor(undefined, "balanced"), "whatever", { x: 1 });
    expect(v.action).toBe("allow");
    expect(rules(v)).toContain("schema.definition-unavailable");
  });

  it("fails closed at strict", () => {
    const v = call(guardFor(undefined, "strict"), "whatever", { x: 1 });
    expect(v.action).toBe("block");
  });
});

describe("server-supplied regex is treated as hostile input", () => {
  it("refuses to evaluate a catastrophic-backtracking pattern rather than hanging on it", () => {
    const evil: ToolDefinition = {
      name: "t",
      inputSchema: { type: "object", properties: { s: { type: "string", pattern: "^(a+)+$" } } },
    };
    const started = Date.now();
    const v = call(guardFor(evil), "t", { s: "a".repeat(40) + "!" });
    expect(Date.now() - started).toBeLessThan(500);
    expect(rules(v)).toContain("schema.pattern-unsafe");
    // Our own limitation must not become the user's outage.
    expect(v.action).toBe("allow");
  });

  it("refuses an over-long pattern", () => {
    const long: ToolDefinition = {
      name: "t",
      inputSchema: { type: "object", properties: { s: { type: "string", pattern: "a".repeat(600) } } },
    };
    expect(rules(call(guardFor(long), "t", { s: "x" }))).toContain("schema.pattern-unsafe");
  });

  it("still enforces an ordinary pattern", () => {
    const ok: ToolDefinition = {
      name: "t",
      inputSchema: { type: "object", properties: { s: { type: "string", pattern: "^[CD][A-Z0-9]{8,}$" } } },
    };
    expect(call(guardFor(ok), "t", { s: "C01ABCDEF23" }).action).toBe("allow");
    expect(call(guardFor(ok), "t", { s: "not-a-channel" }).action).toBe("block");
  });

  it("looksCatastrophic flags nested quantifiers and not ordinary patterns", () => {
    expect(looksCatastrophic("^(a+)+$")).toBe(true);
    expect(looksCatastrophic("(x*)*")).toBe(true);
    expect(looksCatastrophic("^[CD][A-Z0-9]{8,}$")).toBe(false);
    expect(looksCatastrophic("^\\d{4}-\\d{2}-\\d{2}$")).toBe(false);
  });

  it("does not run a regex over an enormous input", () => {
    const ok: ToolDefinition = {
      name: "t",
      inputSchema: { type: "object", properties: { s: { type: "string", pattern: "^[a-z]+$" } } },
    };
    const v = call(guardFor(ok), "t", { s: "a".repeat(20_000) });
    expect(rules(v)).toContain("schema.pattern-skipped");
    expect(v.action).toBe("allow");
  });
});

describe("nested structures and $ref", () => {
  const nested: ToolDefinition = {
    name: "bulk",
    inputSchema: {
      type: "object",
      $defs: { id: { type: "string", minLength: 3 } },
      properties: {
        items: { type: "array", maxItems: 3, items: { type: "object", properties: { id: { $ref: "#/$defs/id" } }, required: ["id"] } },
      },
      required: ["items"],
    },
  };
  const g = guardFor(nested);

  it("resolves $ref and enforces through it", () => {
    expect(call(g, "bulk", { items: [{ id: "abc" }] }).action).toBe("allow");
    const v = call(g, "bulk", { items: [{ id: "ab" }] });
    expect(v.action).toBe("block");
    expect(rules(v)).toContain("schema.minLength");
  });

  it("points the finding at the exact offending element", () => {
    const v = call(g, "bulk", { items: [{ id: "abc" }, { id: "x" }] });
    expect(v.action).toBe("block");
    if (v.action === "block") expect(v.findings.some((f) => f.locus === "/arguments/items/1/id")).toBe(true);
  });

  it("enforces maxItems", () => {
    expect(call(g, "bulk", { items: [{ id: "aaa" }, { id: "bbb" }, { id: "ccc" }, { id: "ddd" }] }).action).toBe("block");
  });

  it("records but does not block on an unresolvable $ref", () => {
    const broken: ToolDefinition = {
      name: "b",
      inputSchema: { type: "object", properties: { x: { $ref: "#/$defs/missing" } } },
    };
    const v = call(guardFor(broken), "b", { x: 1 });
    expect(v.action).toBe("allow");
    expect(rules(v)).toContain("schema.unresolvable-ref");
  });
});

describe("non tools/call traffic is untouched", () => {
  it("passes tools/list through", () => {
    const g = guardFor(calculator);
    expect(g.inspect({}, { ...ctx, method: "tools/list" }).action).toBe("allow");
  });
  it("passes responses through (the response leg is Week 2)", () => {
    const g = guardFor(calculator);
    expect(g.inspect({ name: "calculate", arguments: { a: "x" } }, { ...ctx, direction: "response" }).action).toBe("allow");
  });
});
