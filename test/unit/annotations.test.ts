import { describe, expect, it } from "vitest";
import { resolveAnnotations } from "../../src/policy/annotations.js";

/**
 * The spec defaults are security-critical and counter-intuitive, so they get their own test:
 * an UNANNOTATED tool is `destructiveHint: true` and `openWorldHint: true` (RESEARCH-BRIEF §1.4).
 * Absence of annotations is the most dangerous configuration, not a claim of safety.
 */
describe("ToolAnnotations spec defaults", () => {
  it("treats a tool with no annotations as destructive and open-world", () => {
    const r = resolveAnnotations(undefined);
    expect(r.destructive).toBe(true);
    expect(r.openWorld).toBe(true);
    expect(r.readOnly).toBe(false);
    expect(r.idempotent).toBe(false);
    expect(r.annotated).toBe(false);
  });

  it("treats an empty annotations object identically to no annotations", () => {
    expect(resolveAnnotations({})).toEqual(resolveAnnotations(undefined));
  });

  it("distinguishes a claimed value from a defaulted one", () => {
    const r = resolveAnnotations({ destructiveHint: true });
    expect(r.claimed.destructive).toBe(true);
    expect(r.claimed.openWorld).toBe(false); // defaulted, not claimed
    expect(r.openWorld).toBe(true);
    expect(r.annotated).toBe(true);
  });

  it("ignores non-boolean hint values rather than coercing them", () => {
    const r = resolveAnnotations({ readOnlyHint: "true" as unknown as boolean });
    expect(r.readOnly).toBe(false);
    expect(r.claimed.readOnly).toBe(false);
  });
});
