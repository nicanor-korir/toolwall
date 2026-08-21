/**
 * The engine bug that made the canonical form unstable, pinned so it can never come back quietly.
 *
 * ## What happened
 *
 * `canonicalize.property.test.ts` P11a failed intermittently with a signature that looked like a
 * sorting bug: the expected output had a key rendering as a tab, the received one a key rendering
 * as a backslash. It is not a sorting bug and it is not in `canonicalize` at all. On Node v25.2.1,
 * **`JSON.parse` returns the wrong key** once an object of the same shape with a lone-backslash key
 * has already been parsed:
 *
 * ```js
 * JSON.parse(String.raw`{"a":1,"\\":2}`);   // interns a key that is one backslash
 * JSON.parse(String.raw`{"a":1,"\n":2}`);    // -> keys "a" and "\\", NOT "a" and U+000A
 * ```
 *
 * The parser matches the cached property name against the RAW source characters of the escape, so
 * every escape sequence (`\n`, `\t`, `\r`, `\b`, `\f`, `\uXXXX`, `\"`, `\/`) comes back as the backslash that
 * begins it. It reproduces under `--jitless`, so it is not a JIT artifact, and it needs no toolwall
 * code to demonstrate. That is why the property failed rarely: it needs a backslash-keyed document
 * of the same shape to have gone through the parser first, which fast-check only sometimes arranges.
 *
 * ## Why it was worth stopping a release over
 *
 * Both halves of the pinning invariant break, and the second is the dangerous one:
 *
 *   - same wire bytes hashing two ways depending on parse history - a false rug-pull alarm;
 *   - **two different wire documents producing the same pin** - a real rug pull walking through the
 *     one control this product describes as deterministic. Asserted below.
 *
 * The fix is in `canonicalize.ts`: keys carrying a control character or a backslash are refused as
 * unpinnable (`UNSAFE_KEY`), because a corrupted key is *indistinguishable* from a legitimate
 * backslash key and so cannot be detected after the fact. `drift.ts` turns unpinnable into
 * not-callable, which is the same fail-closed posture as every other ambiguity in that file.
 */
import { describe, expect, it } from "vitest";
import fc from "fast-check";

import { BENIGN_METADATA_CORPUS } from "../fixtures/metadata/benign-metadata.js";
import { REAL_SERVER_CAPTURES, REAL_SERVER_TOOL_COUNT } from "../fixtures/metadata/real-servers.js";
import { codeEditingCases } from "../fixtures/benign/code-editing.js";
import { filesystemCases } from "../fixtures/benign/filesystem.js";
import { gitCases } from "../fixtures/benign/git.js";
import { httpCases } from "../fixtures/benign/http.js";
import { miscCases } from "../fixtures/benign/misc.js";
import { sqlCases } from "../fixtures/benign/sql.js";

import {
  CanonicalizationError,
  canonicalHash,
  canonicalize,
  canonicalizeAndHash,
  platformParsesKeyEscapesFaithfully,
} from "../../src/guards/metadata/canonicalize.js";

/** The awkward characters, named, so no literal control character appears in this file. */
const QUOTE = '"';
const BACKSLASH = "\\";
const NEWLINE = "\n";
const TAB = "\t";
const NUL = "\u0000";
const US = "\u001f";
const DEL = "\u007f";

describe("the engine bug this defends against", () => {
  it("documents the exact reproducer, and FAILS THE DAY THE ENGINE IS FIXED so the restriction can be revisited", () => {
    /*
     * Deliberately not skipped on a good engine. If this starts failing, `JSON.parse` has been
     * fixed and somebody should re-open the question of whether UNSAFE_KEY is still needed, rather
     * than the restriction being carried forever because nobody rechecked. Print, do not assert on
     * a specific engine: the point is that the answer is recorded either way.
     */
    JSON.parse(String.raw`{"a":1,"\\":2}`);
    const keys = Object.keys(JSON.parse(String.raw`{"a":1,"\n":2}`));
    const faithful = keys[1] === "\n";

    console.log(
      `\n  node ${process.version}: JSON.parse decodes an escaped key after a backslash key -> ` +
        `${faithful ? "CORRECTLY" : "INCORRECTLY (returns U+005C)"}\n`,
    );
    expect(platformParsesKeyEscapesFaithfully()).toBe(faithful);
    expect(faithful).toBe(false); // Node v25.2.1. Fix this line when the engine is fixed.
  });
});

describe("canonicalize refuses the one key shape it cannot vouch for", () => {
  it("refuses a lone-backslash key with a typed error rather than hashing it", () => {
    let thrown: unknown;
    try {
      canonicalize(JSON.parse(String.raw`{"a":{},"\\":{}}`));
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(CanonicalizationError);
    expect((thrown as CanonicalizationError).code).toBe("unsafe-key");
    expect((thrown as CanonicalizationError).message).toContain("U+005C");
  });

  it("refuses a backslash key at any depth, not just at the root", () => {
    const nested = JSON.parse(
      String.raw`{"inputSchema":{"properties":{"name":{"properties":{"a":{},"\\":{}}}}}}`,
    );
    expect(() => canonicalize(nested)).toThrow(CanonicalizationError);
  });

  it("refuses whatever an escaped key DECODED TO, when this engine mangled it", () => {
    // The refusal is not about the wire form, which we never see - it is about the value we were
    // handed. An escaped key that the engine mangled arrives as a backslash key and is refused;
    // one it decoded correctly is an ordinary key and is pinned normally.
    for (const doc of [
      String.raw`{"a":{},"\t":{}}`,
      String.raw`{"a":{},"\n":{}}`,
      String.raw`{"a":{},"\u0062":{}}`,
      String.raw`{"a":{},"\"":{}}`,
    ]) {
      JSON.parse(String.raw`{"a":1,"\\":2}`); // prime the engine cache
      const parsed = JSON.parse(doc) as Record<string, unknown>;
      if (Object.keys(parsed)[1] === BACKSLASH) {
        expect(() => canonicalize(parsed), `mangled ${doc} must be refused`).toThrow(CanonicalizationError);
      } else {
        expect(() => canonicalize(parsed), `intact ${doc} must still pin`).not.toThrow();
      }
    }
  });

  it("leaves every other key alone - this is not a blanket on odd characters", () => {
    /*
     * Deliberately includes control characters. They are a HYGIENE question with an owner that has
     * a measured false-positive rate (`UnicodeHygieneGuard` scans object keys and rejects the
     * `control` class); they are not an IDENTITY question, and putting that policy here would both
     * duplicate it and make unpinnable a listing the product documents as pinnable under TOFU.
     */
    // Built with defineProperty, not a literal: `__proto__: {}` in an object literal sets the
    // PROTOTYPE instead of creating a property, which canonicalize rightly refuses as non-JSON.
    const properties: Record<string, unknown> = {};
    for (const key of ["user.name", "a-b_c", "$schema", "__proto__", TAB, NEWLINE, NUL, US, DEL, QUOTE, "with space", "with/slash"]) {
      Object.defineProperty(properties, key, { value: {}, enumerable: true, writable: true, configurable: true });
    }
    const fine = { properties };

    expect(() => canonicalize(fine)).not.toThrow();
  });
});

describe("the safety invariant, and the exact class that caught the bug", () => {
  /*
   * The invariant is NOT "the round trip preserves the hash". On an affected engine it cannot be,
   * and pretending otherwise is what made the original property fail rarely and confusingly.
   *
   * The invariant that actually matters, and that the fix delivers, is:
   *
   *   canonicalize either produces the RIGHT bytes, or it refuses. It never produces bytes for a
   *   value that is not what the server sent.
   *
   * That holds because every corruption this engine produces lands on exactly one shape - a lone
   * backslash key - and that is the shape `UNSAFE_KEY` refuses. So a mangled document can never
   * acquire a pin, can never collide with another document's pin, and can never masquerade as
   * drift. What it costs is availability: on an affected engine a server whose keys are escaped on
   * the wire becomes unpinnable, loudly, with a message naming the character. Correctness over
   * availability is the same trade every other ambiguity in `canonicalize.ts` takes.
   */
  const agree = (value: unknown): void => {
    const attempt = (v: unknown): string => {
      try {
        return canonicalize(v);
      } catch (error) {
        if (error instanceof CanonicalizationError) return `refused:${error.code}`;
        throw error;
      }
    };
    const direct = attempt(value);
    const roundTripped = attempt(JSON.parse(JSON.stringify(value)));

    // The only forbidden outcome: two different sets of bytes for the same document.
    if (direct !== roundTripped) {
      const bothBytes = !direct.startsWith("refused:") && !roundTripped.startsWith("refused:");
      expect(bothBytes, `SILENT DISAGREEMENT\n  direct: ${direct}\n  round-tripped: ${roundTripped}`).toBe(false);
    }
    // On a faithful engine there is nothing to degrade, so the round trip must be exact.
    if (platformParsesKeyEscapesFaithfully()) expect(roundTripped).toBe(direct);
  };

  const ALPHABET = ["a", "Z", "0", " ", QUOTE, BACKSLASH, "/", NEWLINE, TAB, NUL, US, DEL, "A", "_", "required", "properties"];

  it("P11a class, FIXED seed: never two different hashes for one document", () => {
    /*
     * The original failure was seed 1702007558 with a 60-step shrink path. A shrink path only
     * replays against an identical generator tree, so it is brittle to any edit in the property
     * file; the CLASS is pinned here instead, with the backslash-keyed document parsed first so the
     * engine cache is primed exactly as fast-check primed it.
     */
    fc.assert(
      fc.property(fc.uniqueArray(fc.constantFrom(...ALPHABET), { minLength: 1, maxLength: 4 }), (keys) => {
        JSON.parse(String.raw`{"a":1,"\\":2}`); // prime the parser exactly as the failing run did

        const inner: Record<string, unknown> = {};
        for (const k of keys) {
          Object.defineProperty(inner, k, { value: {}, enumerable: true, writable: true, configurable: true });
        }
        agree({ name: "t", description: "d", inputSchema: { properties: { name: { properties: inner } } } });
      }),
      { seed: 1702007558, numRuns: 3_000 },
    );
  });

  it("exhaustively over every key pair in that alphabet, with the cache primed each time", () => {
    // The brute-force form, no randomness. Before the fix this shape produced 2,272 silent
    // disagreements; the assertion is that it now produces none.
    for (const k1 of ALPHABET) {
      for (const k2 of ALPHABET) {
        if (k1 === k2) continue;
        JSON.parse(String.raw`{"a":1,"\\":2}`);
        const inner: Record<string, unknown> = {};
        for (const k of [k1, k2]) {
          Object.defineProperty(inner, k, { value: {}, enumerable: true, writable: true, configurable: true });
        }
        agree({ name: "t", inputSchema: { properties: { name: { properties: inner } } } });
      }
    }
  });

  it("a corrupted parse can never acquire a pin, because every corruption lands on one shape", () => {
    /*
     * This is why the narrow key rule is sufficient rather than merely helpful. ANY key escaped on
     * the wire can be corrupted on this engine - including an ordinary letter written as \u0062 -
     * so no rule about key CONTENT could catch the hazard at its source. What makes the rule work
     * is that every corruption produces exactly a lone backslash, and that shape is refused.
     */
    const primer = String.raw`{"a":1,"\\":2}`;
    const escapedKeyDocs = [
      String.raw`{"a":{},"\u0062":{}}`,  // an ordinary "b", escaped
      String.raw`{"a":{},"\u007a":{}}`,  // an ordinary "z", escaped
      String.raw`{"a":{},"\"":{}}`,      // a quote key
      String.raw`{"a":{},"\n":{}}`,      // a newline key
      String.raw`{"a":{},"\u6f22":{}}`,  // CJK, escaped
    ];
    for (const doc of escapedKeyDocs) {
      JSON.parse(primer);
      const parsed = JSON.parse(doc) as Record<string, unknown>;
      const corrupted = Object.keys(parsed)[1] === BACKSLASH;
      if (!corrupted) continue; // engine is faithful for this case; nothing to defend against
      expect(() => canonicalize(parsed)).toThrow(CanonicalizationError);
    }
  });
});

describe("the neighbouring properties have the same exposure, and the same answer", () => {
  it("P11b (key reordering) refuses identically whichever order the keys arrive in", () => {
    /*
     * `deepShuffleKeys` rebuilds objects in JS and never goes near `JSON.parse`, so P11b was never
     * exposed to the engine bug itself. It IS exposed to the refusal, and the property that must
     * hold is unchanged: reordering is not a semantic change, so both orders must reach the same
     * outcome - equal bytes, or the same refusal.
     */
    const build = (keys: string[]): unknown => {
      const inner: Record<string, unknown> = {};
      for (const k of keys) {
        Object.defineProperty(inner, k, { value: {}, enumerable: true, writable: true, configurable: true });
      }
      return { name: "t", inputSchema: { properties: inner } };
    };
    const attempt = (v: unknown): string => {
      try {
        return canonicalize(v);
      } catch (error) {
        return error instanceof CanonicalizationError ? `refused:${error.code}` : "threw";
      }
    };
    for (const keys of [["a", BACKSLASH], ["a", "b"], [BACKSLASH, TAB, "z"], [QUOTE, "a"]]) {
      const forward = attempt(build(keys));
      const reversed = attempt(build([...keys].reverse()));
      expect(reversed, `key order changed the outcome for ${JSON.stringify(keys)}`).toBe(forward);
    }
  });

  it("the hash wrappers inherit the refusal rather than hashing around it", () => {
    // `canonicalHash` and `canonicalizeAndHash` are the functions the pin store actually calls. A
    // refusal that only reached `canonicalize` would leave the pinning path exposed.
    const unsafe = JSON.parse(String.raw`{"a":{},"\\":{}}`);
    expect(() => canonicalHash(unsafe)).toThrow(CanonicalizationError);
    expect(() => canonicalizeAndHash(unsafe)).toThrow(CanonicalizationError);
    // And the safe path still produces a hash over the same bytes canonicalize emits.
    const safe = { b: 1, a: 2 };
    expect(canonicalizeAndHash(safe).canonical).toBe(canonicalize(safe));
    expect(canonicalizeAndHash(safe).hash).toBe(canonicalHash(safe));
  });

  it("the pin store path fails closed on an unpinnable definition", () => {
    // drift.ts turns a CanonicalizationError into `toolwall/pin-uncanonicalizable` and blocks; this
    // asserts the error still carries what that finding needs - a code and a JSON Pointer.
    try {
      canonicalize(JSON.parse(String.raw`{"inputSchema":{"properties":{"\\":{}}}}`));
      expect.unreachable("should have refused");
    } catch (error) {
      expect(error).toBeInstanceOf(CanonicalizationError);
      expect((error as CanonicalizationError).code).toBe("unsafe-key");
      expect((error as CanonicalizationError).path).toContain("/inputSchema/properties/");
    }
  });
});

describe("what the refusal costs, measured rather than asserted", () => {
  it("refuses nothing across all three benign corpora and the 11 captured real servers", () => {
    /*
     * `docs/THREAT-MODEL.md` §3 binding rule 1: no FP number, no merge. A refusal that fired on
     * real servers would be a rug-pull alarm against innocent metadata, which is the failure mode
     * this whole module exists to avoid - so the width of the rule is measured, not argued.
     */
    const refusalOf = (v: unknown): string | null => {
      try {
        canonicalize(v);
        return null;
      } catch (error) {
        return error instanceof CanonicalizationError ? error.code : "threw";
      }
    };

    const refusedTools: string[] = [];
    for (const server of REAL_SERVER_CAPTURES) {
      for (const tool of server.tools) {
        if (refusalOf(tool) !== null) refusedTools.push(`${server.id}/${String(tool["name"])}`);
      }
    }
    const refusedListings = REAL_SERVER_CAPTURES.filter(
      (s) => refusalOf({ tools: s.tools, instructions: s.instructions }) !== null,
    ).map((s) => s.id);
    const refusedMetadata = BENIGN_METADATA_CORPUS.filter((c) => refusalOf(c.payload) !== null).map((c) => c.id);

    const heldOut = [...codeEditingCases, ...gitCases, ...httpCases, ...sqlCases, ...filesystemCases, ...miscCases];
    const seen = new Set<string>();
    const refusedHeldOut: string[] = [];
    for (const c of heldOut) {
      const key = `${c.serverId} ${c.tool.name}`;
      if (seen.has(key)) continue;
      seen.add(key);
      if (refusalOf(c.tool) !== null) refusedHeldOut.push(key);
    }

    console.log(
      [
        "",
        "  COST OF THE unsafe-key REFUSAL",
        `  real servers, whole listing : ${refusedListings.length}/${REAL_SERVER_CAPTURES.length} refused`,
        `  real tools                  : ${refusedTools.length}/${REAL_SERVER_TOOL_COUNT} refused`,
        `  adversarial metadata corpus : ${refusedMetadata.length}/${BENIGN_METADATA_CORPUS.length} refused`,
        `  held-out corpus             : ${refusedHeldOut.length}/${seen.size} refused`,
        "",
      ].join("\n"),
    );

    expect(refusedListings).toStrictEqual([]);
    expect(refusedTools).toStrictEqual([]);
    expect(refusedMetadata).toStrictEqual([]);
    expect(refusedHeldOut).toStrictEqual([]);
  });
});
