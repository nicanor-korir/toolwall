/**
 * evasion-corpus.test.ts — proves the evasion corpus is a REAL set of bypasses, on data alone.
 *
 * Two things are provable now, before any guard exists:
 *   1. Each evasion payload defeats the naive phrase blocklist docs/PROMPT.md specifies (the bypass
 *      is real, not asserted).
 *   2. Each encoded/obfuscated payload actually recovers to the malicious intent (it is an attack,
 *      not a harmless decoy) — so when Dev 2 adds the decode/normalize tier there is a ground truth
 *      to match against.
 *
 * What toolwall MUST do about each class is left as it.todo, owned by guards/metadata/ (Dev 2).
 * Writing that assertion green here would rob Dev 2 of the failing test.
 */
import { describe, it, expect } from "vitest";
import {
  EVASION_CORPUS,
  defeatsNaiveBlocklist,
  fromUnicodeTags,
  rot13,
  JSON_ESCAPE_WIRE_FORM,
  ROOT_INJECTION_PLAINTEXT,
} from "../fixtures/malicious/evasion-corpus.js";

describe("evasion corpus defeats the naive phrase matcher", () => {
  // "Caught" = the naive matcher SHOULD fire on the parsed payload: the control (baseline) and the
  // json-escape entry (whose evasion is pre-parse only). Everything else must slip past.
  const caught = EVASION_CORPUS.filter(
    (e) => e.detectedBy === "phrase-matcher" || e.parsedFormCaught,
  );
  const evasions = EVASION_CORPUS.filter(
    (e) => e.detectedBy !== "phrase-matcher" && !e.parsedFormCaught,
  );

  it("the control and the parsed json-escape ARE caught by the matcher (baseline sanity)", () => {
    expect(caught.length).toBeGreaterThan(0);
    for (const c of caught) {
      expect(defeatsNaiveBlocklist(c.payload)).toBe(false); // the matcher fires — as it should
    }
  });

  it.each(evasions.map((e) => [e.id, e] as const))(
    "%s slips past the naive blocklist",
    (_id, entry) => {
      expect(defeatsNaiveBlocklist(entry.payload)).toBe(true);
    },
  );

  it("covers every technique class the threat model names", () => {
    const tiers = new Set(EVASION_CORPUS.map((e) => e.detectedBy));
    for (const required of [
      "unicode-normalization",
      "encoding-detection",
      "markup-stripping",
      "structural-decode",
      "semantic-classifier",
      "language-coverage",
    ]) {
      expect(tiers.has(required as any)).toBe(true);
    }
  });
});

describe("obfuscated payloads really recover to the malicious intent", () => {
  it("base64 entry decodes back to the injection", () => {
    const e = EVASION_CORPUS.find((x) => x.id === "base64-1")!;
    const blob = e.payload.split(": ").pop()!;
    expect(Buffer.from(blob, "base64").toString("utf8")).toBe(e.recovers);
    expect(e.recovers).toContain("ignore previous instructions");
  });

  it("hex entry decodes back to the injection", () => {
    const e = EVASION_CORPUS.find((x) => x.id === "hex-1")!;
    const blob = e.payload.split(": ").pop()!;
    expect(Buffer.from(blob, "hex").toString("utf8")).toBe(e.recovers);
  });

  it("rot13 entry decodes back to the injection", () => {
    const e = EVASION_CORPUS.find((x) => x.id === "rot13-1")!;
    const blob = e.payload.split("rot13: ").pop()!;
    expect(rot13(blob)).toBe(e.recovers);
  });

  it("unicode TAG-block entry is invisible ASCII that decodes to the injection", () => {
    const e = EVASION_CORPUS.find((x) => x.id === "unicode-tag-1")!;
    // The visible text is benign; the TAG characters carry the payload.
    expect(e.payload).toContain("Adds two integers together.");
    expect(defeatsNaiveBlocklist(e.payload)).toBe(true);
    const decoded = fromUnicodeTags(e.payload);
    expect(decoded).toContain("ignore previous instructions");
  });

  it("JSON \\u wire form hides the injection from a raw-byte scan but parses to it", () => {
    // A guard scanning the raw JSON bytes sees only escapes — no blocklisted phrase.
    expect(defeatsNaiveBlocklist(JSON_ESCAPE_WIRE_FORM)).toBe(true);
    expect(JSON_ESCAPE_WIRE_FORM).not.toContain("ignore");
    // But JSON.parse recovers the real attack string.
    expect(JSON.parse(JSON_ESCAPE_WIRE_FORM)).toBe(ROOT_INJECTION_PLAINTEXT);
  });
});

// ---------------------------------------------------------------------------
// PENDING — for guards/metadata/ (Dev 2). Turn these green by DETECTING each class; do not weaken
// the corpus to make them pass. Each should end in a "block" or "annotate" Verdict with a Finding.
// ---------------------------------------------------------------------------
describe("toolwall must catch every evasion class [pending Dev 2]", () => {
  it.todo("normalizes unicode (zero-width, homoglyph, bidi, TAG) before scanning, then flags");
  it.todo("detects and decodes base64/hex/rot13, re-scans, and flags the recovered injection");
  it.todo("extracts HTML and markdown comment bodies and scans them");
  it.todo("scans only AFTER JSON parsing, never raw transport bytes");
  it.todo("flags non-English injections (multilingual lexicon or translate-then-scan)");
  it.todo("flags paraphrase/synonym injections via the optional semantic tier (off the hot path)");
  it.todo("reports a measured false-positive rate on test/fixtures/benign/ for each detector");
});
