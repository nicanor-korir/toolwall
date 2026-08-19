/**
 * Deterministic conformance tests for the canonicalizer.
 *
 * The property tests prove the canonicalizer is *self-consistent*. These prove it produces the
 * *specific bytes RFC 8785 requires*, which is what makes a toolwall pin comparable with any
 * other JCS implementation — the whole reason ARCHITECTURE.md chose JCS over an ad-hoc scheme
 * (forward compatibility with SEP-3140's JWS-signed capability manifests, should it ever land).
 *
 * Several tests here pin behaviour of `JSON.stringify` that the implementation delegates to.
 * That is intentional: if a future V8 changed its string escaping, every pin in the field would
 * silently become unverifiable. These tests turn that into a build failure.
 *
 * Non-ASCII and non-printing characters are written as `\u` escapes throughout. A test about
 * invisible characters that contains invisible characters cannot be reviewed.
 */
import { describe, expect, it } from "vitest";

import {
  CANONICALIZATION_VERSION,
  CanonicalizationError,
  canonicalHash,
  canonicalize,
  canonicalizeAndHash,
  normalizeText,
  sha256Hex,
} from "../../src/guards/metadata/canonicalize.js";

/** RFC 8785 canonicalization without the NFC pre-pass — pure spec behaviour. */
const jcs = (v: unknown): string => canonicalize(v, { normalize: "none" });

const EURO = "\u20ac";
const O_DIAERESIS = "\u00f6";
const GRINNING = "\u{1f600}";
const DALET_DAGESH = "\ufb33"; // NFC-decomposes to U+05D3 U+05BC (composition exclusion)
const KELVIN = "\u212a"; // NFC-folds to "K"
const ANGSTROM = "\u212b"; // NFC-folds to U+00C5
const FFI_LIGATURE = "\ufb03"; // compatibility-only: NFC leaves it alone

describe("RFC 8785 conformance", () => {
  it("reproduces the Appendix B number/string/literal vector byte for byte", () => {
    const input: unknown = JSON.parse(
      '{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001],' +
        '"string":"\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"/",' +
        '"literals":[null,true,false]}',
    );
    expect(jcs(input)).toBe(
      '{"literals":[null,true,false],' +
        '"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],' +
        `"string":"${EURO}$\\u000f\\nA'B\\"\\\\\\\\\\"/"}`,
    );
  });

  it("sorts member names by UTF-16 code unit, not by code point", () => {
    // U+1F600 is the surrogate pair D83D DE00; its FIRST code unit (0xD83D) is below 0xFB33, so
    // the emoji sorts BEFORE U+FB33 even though its code point is far higher. A canonicalizer
    // that sorted by code point would order these two the other way round.
    const input: unknown = JSON.parse(
      '{"\\u20ac":"Euro Sign","\\r":"Carriage Return",' +
        '"\\ufb33":"Hebrew Letter Dalet With Dagesh","1":"One",' +
        '"\\ud83d\\ude00":"Emoji: Grinning Face","\\u0080":"Control",' +
        '"\\u00f6":"Latin Small Letter O With Diaeresis"}',
    );
    // Asserted on the canonical bytes, not on Object.keys: JavaScript reorders integer-like
    // keys ahead of everything else in property enumeration, so a parsed object cannot witness
    // the order the canonicalizer emitted.
    expect(jcs(input)).toBe(
      '{"\\r":"Carriage Return",' +
        '"1":"One",' +
        `"\u0080":"Control",` +
        `"${O_DIAERESIS}":"Latin Small Letter O With Diaeresis",` +
        `"${EURO}":"Euro Sign",` +
        `"${GRINNING}":"Emoji: Grinning Face",` +
        `"${DALET_DAGESH}":"Hebrew Letter Dalet With Dagesh"}`,
    );
  });

  it("uses minimal string escaping", () => {
    expect(jcs("\b\f\n\r\t")).toBe('"\\b\\f\\n\\r\\t"');
    expect(jcs('a"b\\c')).toBe('"a\\"b\\\\c"');
    // Other C0 controls take the lowercase \u00xx form.
    expect(jcs("\u0000\u001f")).toBe('"\\u0000\\u001f"');
    // Not escaped: forward slash, DEL, C1 controls, U+2028/U+2029, non-ASCII letters.
    expect(jcs("/")).toBe('"/"');
    expect(jcs("\u007f")).toBe(`"\u007f"`);
    expect(jcs("\u0080")).toBe(`"\u0080"`);
    expect(jcs("\u2028\u2029")).toBe(`"\u2028\u2029"`);
    // Unpaired surrogates get the lowercase escape mandated by well-formed JSON.stringify.
    expect(jcs("\ud800")).toBe('"\\ud800"');
    expect(jcs("\udfff")).toBe('"\\udfff"');
  });

  it("serializes numbers with the ECMAScript Number::toString algorithm", () => {
    expect(jcs(-0)).toBe("0");
    expect(jcs(0)).toBe("0");
    expect(jcs(1e21)).toBe("1e+21");
    expect(jcs(1e-7)).toBe("1e-7");
    expect(jcs(5e-324)).toBe("5e-324");
    expect(jcs(1.7976931348623157e308)).toBe("1.7976931348623157e+308");
    expect(jcs(1e20)).toBe("100000000000000000000");
    expect(jcs(0.1 + 0.2)).toBe("0.30000000000000004");
  });

  it("refuses values JSON cannot represent instead of coercing them to null", () => {
    // JSON.stringify silently turns these into `null`, which would make NaN and Infinity hash
    // identically to a legitimate null. A canonicalizer that loses that distinction is a
    // collision generator.
    for (const bad of [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY]) {
      expect(() => canonicalize(bad)).toThrow(CanonicalizationError);
    }
  });
});

describe("absent vs empty vs null are three different things", () => {
  it("distinguishes a missing field, an empty string, and an explicit null", () => {
    const forms = [
      canonicalize({ name: "t" }),
      canonicalize({ name: "t", description: "" }),
      canonicalize({ name: "t", description: null }),
    ];
    expect(new Set(forms).size).toBe(3);
    expect(forms[0]).toBe('{"name":"t"}');
    expect(forms[1]).toBe('{"description":"","name":"t"}');
    expect(forms[2]).toBe('{"description":null,"name":"t"}');
  });

  it("distinguishes empty containers from each other and from absent", () => {
    const forms = [
      canonicalize({}),
      canonicalize({ enum: [] }),
      canonicalize({ enum: {} }),
      canonicalize({ enum: null }),
      canonicalize({ enum: "" }),
    ];
    expect(new Set(forms).size).toBe(5);
  });

  it("treats an `undefined` property as absent, matching the JSON wire format", () => {
    expect(canonicalize({ a: 1, b: undefined })).toBe(canonicalize({ a: 1 }));
    // ...but `undefined` inside an array becomes null, exactly as JSON.stringify does, so a
    // reserialization round-trip cannot change the hash.
    expect(canonicalize([1, undefined, 2])).toBe("[1,null,2]");
  });

  it("preserves the empty-string key", () => {
    expect(canonicalize({ "": 1, a: 2 })).toBe('{"":1,"a":2}');
  });
});

describe("Unicode NFC — the documented deviation from RFC 8785", () => {
  it("makes NFD and NFC spellings of the same text hash identically", () => {
    const composed = "caf\u00e9";
    const decomposed = "cafe\u0301";
    expect(composed).not.toBe(decomposed);
    expect(canonicalHash({ description: composed })).toBe(
      canonicalHash({ description: decomposed }),
    );
    // Without the deviation these are different documents — which is the RFC's own position.
    expect(jcs({ description: composed })).not.toBe(jcs({ description: decomposed }));
  });

  it("normalizes object keys too, and re-sorts after normalizing", () => {
    // U+FB33 canonically decomposes under NFC (it is a composition exclusion), which moves it
    // from last to before U+20AC. This is exactly where we diverge from the RFC vector above,
    // so it is asserted rather than left as a surprise.
    const input: unknown = JSON.parse('{"\\u20ac":1,"\\ufb33":2}');
    expect(jcs(input)).toBe(`{"${EURO}":1,"${DALET_DAGESH}":2}`);
    expect(canonicalize(input)).toBe(`{"\u05d3\u05bc":2,"${EURO}":1}`);
  });

  it("folds the singleton homoglyphs that NFC folds, and no others", () => {
    // KELVIN SIGN and ANGSTROM SIGN have canonical singleton decompositions, so the hash cannot
    // see those substitutions. U+FB03 has only a *compatibility* decomposition, so NFC leaves it
    // alone and the hash does see it. Catching homoglyph swaps is the job of the Unicode-evasion
    // detectors, not of the hash — pinning answers "did it change", not "is it hostile".
    expect(normalizeText(KELVIN)).toBe("K");
    expect(normalizeText(ANGSTROM)).toBe("\u00c5");
    expect(normalizeText(FFI_LIGATURE)).toBe(FFI_LIGATURE);
    expect(canonicalHash({ n: KELVIN })).toBe(canonicalHash({ n: "K" }));
    expect(canonicalHash({ n: FFI_LIGATURE })).not.toBe(canonicalHash({ n: "ffi" }));
  });

  it("refuses a document whose keys collide after normalization", () => {
    const doc: unknown = JSON.parse('{"caf\\u00e9":1,"cafe\\u0301":2}');
    expect(Object.keys(doc as object)).toHaveLength(2);
    expect(() => canonicalize(doc)).toThrow(CanonicalizationError);
    try {
      canonicalize(doc);
      throw new Error("expected a throw");
    } catch (error) {
      expect((error as CanonicalizationError).code).toBe("key-collision");
    }
  });
});

describe("hostile-input handling", () => {
  it("hashes an own `__proto__` key like any other field", () => {
    // JSON.parse creates `__proto__` as a plain own property, so a server cannot use it to hide
    // a field from the pin.
    const parsed: unknown = JSON.parse('{"__proto__":{"description":"payload"},"name":"t"}');
    expect(canonicalize(parsed)).toBe('{"__proto__":{"description":"payload"},"name":"t"}');
    expect(canonicalize(parsed)).not.toBe(canonicalize({ name: "t" }));
  });

  it("accepts null-prototype objects", () => {
    const bare = Object.create(null) as Record<string, unknown>;
    bare["a"] = 1;
    expect(canonicalize(bare)).toBe('{"a":1}');
  });

  it("rejects host objects that are not JSON data", () => {
    // Date is the dangerous one: JSON.stringify would call its toJSON() and silently produce a
    // string, so a canonicalizer that leaned on JSON.stringify wholesale would hash a Date and
    // its ISO string identically.
    for (const bad of [new Date(0), new Map(), new Set(), /re/, new Uint8Array(2)]) {
      expect(() => canonicalize({ v: bad })).toThrow(CanonicalizationError);
    }
    expect(() => canonicalize(1n)).toThrow(CanonicalizationError);
  });

  it("omits function- and symbol-valued members, matching JSON.stringify", () => {
    expect(canonicalize({ a: 1, fn: () => 1, sym: Symbol("s") })).toBe(canonicalize({ a: 1 }));
    expect(canonicalize([1, () => 1, 2])).toBe("[1,null,2]");
  });

  it("rejects cycles rather than recursing forever", () => {
    const a: Record<string, unknown> = {};
    a["self"] = a;
    expect(() => canonicalize(a)).toThrow(/circular/);
  });

  it("bounds nesting depth", () => {
    let deep: unknown = 1;
    for (let i = 0; i < 200; i++) deep = [deep];
    expect(() => canonicalize(deep)).toThrow(CanonicalizationError);
    expect(() => canonicalize(deep, { maxDepth: 500 })).not.toThrow();
  });

  it("bounds total node count", () => {
    const wide = Array.from({ length: 100 }, (_, i) => i);
    expect(() => canonicalize(wide, { maxNodes: 10 })).toThrow(CanonicalizationError);
  });

  it("names the offending location with a JSON Pointer", () => {
    try {
      canonicalize({ inputSchema: { properties: { path: { default: Number.NaN } } } });
      throw new Error("expected a throw");
    } catch (error) {
      expect(error).toBeInstanceOf(CanonicalizationError);
      expect((error as CanonicalizationError).path).toBe("/inputSchema/properties/path/default");
    }
  });
});

describe("hashing", () => {
  it("produces a self-describing sha256 digest of the canonical bytes", () => {
    const value = { name: "read_file", description: "Read a file." };
    const canonical = canonicalize(value);
    expect(canonicalHash(value)).toBe(`sha256:${sha256Hex(canonical)}`);
    expect(canonicalHash(value)).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it("canonicalizeAndHash agrees with the separate functions", () => {
    const value = { a: [1, 2, { b: null }] };
    const both = canonicalizeAndHash(value);
    expect(both.canonical).toBe(canonicalize(value));
    expect(both.hash).toBe(canonicalHash(value));
  });

  it("exposes a version that pins can record", () => {
    expect(CANONICALIZATION_VERSION).toBe(1);
  });
});
