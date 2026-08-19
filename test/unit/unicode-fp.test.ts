/**
 * The measured false-positive rate of the invisible-character / ANSI control.
 *
 * `docs/THREAT-MODEL.md` §3 rule 1: *"Every detector ships with a measured false-positive rate on
 * a benign corpus. No FP number, no merge."* This file is that number for
 * `src/guards/metadata/unicode.ts`, and it prints the report so the figure in the README can be
 * re-derived rather than trusted.
 *
 * The corpus is deliberately stacked against us: emoji ZWJ sequences, Persian ZWNJ, Devanagari
 * half-forms, Arabic RLM, French NBSP, real tabs and newlines, and CJK prose. A control that
 * claims "near-zero false positives" has to survive exactly those.
 */
import { describe, expect, it } from "vitest";

import {
  BENIGN_METADATA_CORPUS,
  benignStrings,
  benignToolListResults,
  corpusSummary,
} from "../fixtures/metadata/benign-metadata.js";
import { PUBLISHED_PAYLOADS } from "../fixtures/metadata/published-payloads.js";
import {
  DEFAULT_HAZARD_POLICY,
  UnicodeHygieneGuard,
  scanSurface,
} from "../../src/guards/metadata/unicode.js";
import type { GuardContext } from "../../src/types/protocol.js";

const ctx = (serverId: string, method = "tools/list"): GuardContext => ({
  era: "2025-11-25",
  serverId,
  direction: "response",
  method,
});

const pct = (n: number, d: number): string => (d === 0 ? "n/a" : `${((n / d) * 100).toFixed(1)}%`);

describe("false-positive rate on the benign metadata corpus", () => {
  it("blocks nothing in the benign corpus, and reports the measured rate", () => {
    const guard = new UnicodeHygieneGuard();
    const blocked: string[] = [];
    const recorded: string[] = [];

    for (const c of BENIGN_METADATA_CORPUS) {
      const method = c.kind === "server" ? "initialize" : "tools/list";
      const payload = c.kind === "server" ? c.payload : { tools: [c.payload] };
      const verdict = new UnicodeHygieneGuard({
        onFinding: (f) => {
          if (f.ruleId.endsWith("-recorded")) recorded.push(`${c.id} (${c.trap.slice(0, 40)}…)`);
        },
      }).inspect(payload, ctx(c.serverId, method));
      if (verdict.action !== "allow") blocked.push(`${c.id}: ${c.trap}`);
    }

    // Whole-listing pass as well, so per-tool and per-listing agree.
    for (const { serverId, result } of benignToolListResults()) {
      const verdict = guard.inspect(result, ctx(serverId));
      if (verdict.action !== "allow") blocked.push(`tools/list for ${serverId}`);
    }

    const summary = corpusSummary();
    const strings = benignStrings();
    /* eslint-disable no-console */
    console.log(
      [
        "",
        "  metadata invisible/ANSI detector — false-positive report",
        "  ---------------------------------------------------------",
        `  corpus            : ${summary.total} cases (${summary.byKind["tool"] ?? 0} tools, ${summary.byKind["server"] ?? 0} server instructions)`,
        `  strings scanned   : ${strings.length} (every string value and object key in the corpus)`,
        `  characters        : ${strings.reduce((n, s) => n + s.value.length, 0)}`,
        `  BLOCKED (false +) : ${blocked.length}  =>  ${pct(blocked.length, summary.total)}`,
        `  recorded, allowed : ${recorded.length}  (bidi marks in Arabic prose — reported, not blocked)`,
        `  hard cases        : ${BENIGN_METADATA_CORPUS.filter((c) => c.tags.includes("hard")).length} tagged "hard"`,
        ...blocked.map((b) => `    FALSE POSITIVE: ${b}`),
        "",
      ].join("\n"),
    );
    /* eslint-enable no-console */

    expect(blocked).toEqual([]);
  });

  it("the emoji, ZWNJ and RTL cases really do contain the characters they exempt", () => {
    // If these assertions ever fail the corpus stopped testing anything and the 0% is worthless.
    const byId = new Map(BENIGN_METADATA_CORPUS.map((c) => [c.id, c]));
    const raw = (id: string): string => JSON.stringify(byId.get(id)!.payload);

    expect(raw("emoji-status-tool")).toContain("‍"); // ZWJ in emoji sequences
    expect(raw("emoji-status-tool")).toContain("️"); // VS16
    expect(raw("i18n-translate-fa")).toContain("‌"); // ZWNJ, Persian
    expect(raw("i18n-translate-fa")).toContain("‍"); // ZWJ, Devanagari half-form
    expect(raw("rtl-arabic-with-marks")).toContain("‏"); // RLM
    expect(raw("accented-latin")).toContain(" "); // NBSP
    expect(raw("tabs-and-newlines")).toContain("\\t");
  });

  it("a policy that ignores context WOULD have false-positived — the exemptions are load-bearing", () => {
    // Same corpus, but joiners classified without the emoji/joining-script exemption. This is the
    // naive implementation, and it is what the numbers above are being compared against.
    const naiveHits = BENIGN_METADATA_CORPUS.filter((c) => /[‌‍]/u.test(JSON.stringify(c.payload)));
    expect(naiveHits.length).toBeGreaterThan(0);
    // ...while the shipped detector finds nothing in exactly those cases.
    for (const c of naiveHits) {
      expect(scanSurface(c.payload).filter((h) => h.class === "zero-width")).toEqual([]);
    }
    /* eslint-disable no-console */
    console.log(
      `  context-free joiner rule would have blocked ${naiveHits.length}/${BENIGN_METADATA_CORPUS.length} ` +
        `(${pct(naiveHits.length, BENIGN_METADATA_CORPUS.length)}); the shipped rule blocks 0.`,
    );
    /* eslint-enable no-console */
  });
});

describe("catch rate on published payloads — stated as a bounded claim, not a headline", () => {
  it("catches every payload that carries a hazard and NO payload that does not", () => {
    const guard = new UnicodeHygieneGuard();
    const caught: string[] = [];
    const missed: string[] = [];

    for (const p of PUBLISHED_PAYLOADS) {
      const verdict = guard.inspect({ tools: [{ name: "t", description: p.payload }] }, ctx("srv"));
      (verdict.action === "block" ? caught : missed).push(p.id);
      // The control is exact: it fires if and only if the payload carries a hazard.
      expect(verdict.action === "block").toBe(p.hasInvisibleHazard);
    }

    const withHazard = PUBLISHED_PAYLOADS.filter((p) => p.hasInvisibleHazard).length;
    /* eslint-disable no-console */
    console.log(
      [
        "",
        "  invisible/ANSI control vs published tool-poisoning payloads",
        `  caught : ${caught.length}/${PUBLISHED_PAYLOADS.length}  [${caught.join(", ")}]`,
        `  missed : ${missed.length}/${PUBLISHED_PAYLOADS.length}  [${missed.join(", ")}]`,
        `  This is the HONEST shape of the control: ${withHazard} of ${PUBLISHED_PAYLOADS.length} published`,
        "  payloads are plain visible English, and a character-level rule sees none of them. It owns",
        "  the class where the payload is invisible to the human approving it, and nothing else.",
        "",
      ].join("\n"),
    );
    /* eslint-enable no-console */

    expect(caught.length).toBe(withHazard);
  });

  it("the blocklist from docs/IDEA.md still scores 0 on the same corpus", async () => {
    const { IDEA_MD_MALICIOUS_PATTERNS, IDEA_MD_TRUNCATION_LIMIT } = await import(
      "../fixtures/metadata/published-payloads.js"
    );
    const hits = PUBLISHED_PAYLOADS.filter((p) =>
      IDEA_MD_MALICIOUS_PATTERNS.some((re) => re.test(p.payload)),
    );
    expect(hits).toEqual([]);
    // ...and truncation is a no-op on every one of them, because they are all short. Reproduces
    // `docs/RESEARCH-BRIEF.md` §4.1 on a corpus of 8 rather than 5.
    const overLimit = PUBLISHED_PAYLOADS.filter((p) => p.payload.length > IDEA_MD_TRUNCATION_LIMIT);
    expect(overLimit).toEqual([]);
  });
});

describe("second false-positive corpus: Dev 3's benign tool definitions", () => {
  it("finds nothing in the 59-case argument corpus's tool metadata either", async () => {
    // Reusing `test/fixtures/benign/` widens the denominator with definitions written by someone
    // who was not trying to make this detector pass.
    const { createWorkspace, benignCorpus } = await import("../fixtures/benign/index.js");
    const ws = createWorkspace();
    try {
      const cases = benignCorpus(ws);
      const guard = new UnicodeHygieneGuard();
      const blocked = cases.filter(
        (c) => guard.inspect({ tools: [c.tool] }, ctx(c.serverId)).action !== "allow",
      );
      /* eslint-disable no-console */
      console.log(
        `  second corpus (test/fixtures/benign): ${blocked.length}/${cases.length} blocked => ` +
          `${pct(blocked.length, cases.length)}`,
      );
      /* eslint-enable no-console */
      expect(blocked.map((c) => c.id)).toEqual([]);
    } finally {
      ws.cleanup();
    }
  });
});

describe("policy defaults are the ones the FP number was measured under", () => {
  it("bidi marks record, everything else rejects", () => {
    expect(DEFAULT_HAZARD_POLICY).toEqual({
      "tag-block": "reject",
      "bidi-control": "reject",
      "bidi-mark": "record",
      "zero-width": "reject",
      "ansi-escape": "reject",
      control: "reject",
      "private-use": "reject",
      "deceptive-format": "reject",
    });
  });
});

describe("cross-check against the red team's evasion corpus", () => {
  it("reports which evasion classes a character-level control actually covers", async () => {
    // `test/fixtures/malicious/evasion-corpus.ts` is red-team owned and left the "what toolwall
    // must do" assertions as `it.todo`. This measures the honest answer for THIS control rather
    // than editing their file to claim one.
    const { EVASION_CORPUS } = await import("../fixtures/malicious/evasion-corpus.js");
    const guard = new UnicodeHygieneGuard();

    const byTier = new Map<string, { caught: number; total: number; ids: string[] }>();
    for (const entry of EVASION_CORPUS) {
      const tier = entry.detectedBy;
      const row = byTier.get(tier) ?? { caught: 0, total: 0, ids: [] };
      row.total += 1;
      const blocked =
        guard.inspect({ tools: [{ name: "t", description: entry.payload }] }, ctx("srv")).action !==
        "allow";
      if (blocked) {
        row.caught += 1;
        row.ids.push(entry.id);
      }
      byTier.set(tier, row);
    }

    /* eslint-disable no-console */
    console.log(
      [
        "",
        "  invisible/ANSI control vs the red team's evasion corpus, by intended defense tier",
        ...[...byTier.entries()].map(
          ([tier, r]) =>
            `    ${tier.padEnd(24)} ${String(r.caught).padStart(2)}/${r.total}` +
            (r.ids.length > 0 ? `  [${r.ids.join(", ")}]` : ""),
        ),
        "",
        "  The control owns the unicode-normalization row and is structurally blind to the rest —",
        "  encoding, markup, paraphrase and non-English payloads are all plain visible characters.",
        "",
      ].join("\n"),
    );
    /* eslint-enable no-console */

    // The one row it must own outright: every payload whose whole trick is invisible characters.
    const unicodeRow = byTier.get("unicode-normalization");
    expect(unicodeRow).toBeDefined();
    expect(unicodeRow!.caught).toBe(3);
    expect(unicodeRow!.total).toBe(4);
    // The miss is `homoglyph-1`, and it is a deliberate scope boundary rather than a bug:
    // Cyrillic `а` is a visible, well-formed letter, and catching it needs a confusables skeleton
    // — a different control that fires on every description legitimately written in Cyrillic or
    // Greek. See the "Stated gap" section in `src/guards/metadata/unicode.ts`.
    expect(unicodeRow!.ids).not.toContain("homoglyph-1");
  });
});
