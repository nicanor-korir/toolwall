/**
 * injection-sites.test.ts — proves the same payload is planted in EVERY attacker-controlled field,
 * and that a description-only guard (docs/PROMPT.md's Dev 2 scope) would miss all but one of them.
 *
 * Provable now, on data:
 *   1. the marker is actually present at each site (fixtures are well-formed), and
 *   2. it is NOT sitting in a plain top-level tools/list[].description — so a guard that only scrubs
 *      that one field leaves the site open.
 * The assertion that toolwall catches each site is it.todo, split by owning module.
 */
import { describe, it, expect } from "vitest";
import {
  INJECTION_SITES,
  MARKER,
  readPath,
} from "../fixtures/malicious/injection-sites.js";

describe("injection sites are well-formed and cover the full surface", () => {
  it("covers both metadata (T-01) and result-leg (T-03) injection", () => {
    const threats = new Set(INJECTION_SITES.map((s) => s.threat));
    expect(threats.has("T-01")).toBe(true);
    expect(threats.has("T-03")).toBe(true);
  });

  it("splits ownership between guards/metadata and guards/runtime", () => {
    const owners = new Set(INJECTION_SITES.map((s) => s.owner));
    expect(owners.has("guards/metadata")).toBe(true);
    expect(owners.has("guards/runtime")).toBe(true);
  });

  it("includes the fields PROMPT.md's description-only guard would skip", () => {
    const sites = new Set(INJECTION_SITES.map((s) => s.id));
    for (const required of [
      "site-tool-name",
      "site-tool-title",
      "site-schema-prop-description",
      "site-schema-enum",
      "site-meta",
      "site-server-instructions",
      "site-result-text",
      "site-result-structured",
      "site-result-embedded-resource",
    ]) {
      expect(sites.has(required)).toBe(true);
    }
  });

  it.each(INJECTION_SITES.map((s) => [s.id, s] as const))(
    "%s actually contains the marker payload",
    (_id, site) => {
      // Robust presence check (handles dotted _meta keys the simple path reader can't walk).
      expect(JSON.stringify(site.payload)).toContain(
        site.id === "site-tool-name"
          ? "ignore_all_prior_rules" // name-legal encoding for the charset-restricted name field
          : MARKER,
      );
    },
  );

  it("readPath locates the marker for non-dotted-key sites", () => {
    const textSite = INJECTION_SITES.find((s) => s.id === "site-result-text")!;
    expect(String(readPath(textSite.payload, textSite.markerPath))).toContain(MARKER);
  });

  it("none of the marker payloads live in a plain top-level tools/list[].description", () => {
    // A description-only guard scrubs exactly this path. Prove the payload is elsewhere.
    for (const site of INJECTION_SITES) {
      const descs =
        (site.payload as any)?.tools?.map((t: any) => t.description).filter(Boolean) ?? [];
      for (const d of descs) {
        expect(String(d)).not.toContain(MARKER);
      }
    }
  });
});

// ---------------------------------------------------------------------------
// PENDING — split by owner. Turn green by guarding the field, not by deleting the site.
// ---------------------------------------------------------------------------
describe("toolwall must guard every metadata site [pending Dev 2]", () => {
  it.todo("recurses into inputSchema/outputSchema property descriptions and enum values");
  it.todo("scans tool name, title, annotations.title, and _meta values");
  it.todo("scans server instructions, prompt metadata, and resource metadata");
});

describe("toolwall must guard the result leg [pending Dev 3]", () => {
  it.todo("scans tools/call result content[].text, structuredContent, and error text (T-03)");
  it.todo("scans embedded resource text and resource_link name/description");
});
