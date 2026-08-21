/**
 * RFC 8785 (JSON Canonicalization Scheme) serializer + SHA-256 hashing.
 *
 * This is the highest-risk module in toolwall. Everything the pinning engine claims rests on
 * one invariant: **the same JSON value must always produce the same bytes, and two different
 * JSON values must never produce the same bytes.** If the first half fails we raise a
 * rug-pull alarm against an innocent server; if the second half fails a real rug pull walks
 * straight through. The property tests in `test/unit/canonicalize.property.test.ts` were
 * written before this file and are the actual specification.
 *
 * ## Conformance
 *
 * Implements RFC 8785 §3.2:
 *   - object members sorted by the **UTF-16 code units** of their names (not code points, not
 *     locale collation) — JavaScript's `<` on strings is exactly that comparison;
 *   - array order preserved (significant);
 *   - numbers serialized with the ECMAScript `Number::toString` algorithm, which is what
 *     `String(n)` gives us verbatim (`1e+21`, `1e-7`, `5e-324` …);
 *   - strings escaped per RFC 8259 with minimal escaping: only `"`, `\` and C0 controls, using
 *     the two-character forms where they exist and lowercase `\u00xx` otherwise. `JSON.stringify`
 *     on a single string implements precisely this (including lowercase lone-surrogate escapes
 *     mandated by well-formed `JSON.stringify`, ES2019), so we delegate to it — verified by test.
 *
 * ## Documented deviation: Unicode NFC
 *
 * RFC 8785 deliberately does **not** normalize Unicode; it canonicalizes the JSON encoding, not
 * the text. toolwall applies NFC to every string and every object key **before** JCS
 * serialization. The output is still exactly the JCS form of the normalized document, so a
 * future SEP-3140 verifier that normalizes its input agrees with us byte for byte.
 *
 * The reason is threat-driven: a server that re-encodes "é" from precomposed U+00E9 to
 * U+0065 U+0301 has changed nothing an operator would call a change, and blocking every tool
 * call over it would be a false rug-pull alarm. Without NFC that reserialization is a hash
 * change. Note the asymmetry we accept: NFC folds a handful of singletons (KELVIN SIGN K to K,
 * ANGSTROM SIGN to Å) so those homoglyph swaps become invisible to the *hash*. They remain
 * fully visible to the Unicode-evasion detectors, which is the correct division of labour —
 * pinning answers "did it change", not "is it hostile".
 *
 * NFC on keys can make two distinct keys collide. That is a genuine ambiguity with a security
 * flavour (which value wins?), so we refuse it with a typed error rather than picking one.
 * Callers on the enforcement path must treat a `CanonicalizationError` as fail-closed.
 *
 * ## Absent vs empty — defined, not accidental
 *
 *   absent key            -> the key does not appear in the output
 *   `undefined` / fn / sym-> treated as absent in objects, as `null` in arrays (JSON.stringify
 *                            semantics; none can exist on the wire, so this only matters for
 *                            values constructed in-process)
 *   value `null`          -> `null`          — distinct from absent
 *   value `""`            -> `""`            — distinct from absent and from null
 *   value `[]` / `{}`     -> `[]` / `{}`     — distinct from absent
 *
 * We never coerce an empty string, empty array or empty object into "missing". A tool that
 * drops its `description` entirely and a tool that blanks it to `""` are different events and
 * must produce different hashes.
 */
import { createHash } from "node:crypto";

/**
 * Bump when the canonical byte output changes for any input. Every stored pin records the
 * version it was created under; a mismatch invalidates the pin and forces re-approval rather
 * than silently comparing hashes produced by two different algorithms.
 */
export const CANONICALIZATION_VERSION = 1;

export type CanonicalizationErrorCode =
  | "unsupported-type"
  | "non-finite-number"
  | "cycle"
  | "max-depth"
  | "max-nodes"
  | "key-collision"
  | "unsafe-key";

/** Thrown instead of producing a guess. On the enforcement path this must fail closed. */
export class CanonicalizationError extends Error {
  override readonly name = "CanonicalizationError";
  readonly code: CanonicalizationErrorCode;
  /** JSON Pointer (RFC 6901) to the offending node. */
  readonly path: string;

  constructor(code: CanonicalizationErrorCode, path: string, message: string) {
    super(`${message} (at ${path === "" ? "<root>" : path})`);
    this.code = code;
    this.path = path;
  }
}

export interface CanonicalizeOptions {
  /**
   * Maximum nesting depth. A hostile server can send a deeply nested `inputSchema` purely to
   * blow the stack of anything that walks it (T-08). Default 64 — real MCP schemas are <10.
   */
  readonly maxDepth?: number;
  /** Maximum total nodes visited, bounding work on the hot path. Default 50 000. */
  readonly maxNodes?: number;
  /** Unicode normalization form applied before serialization. Default `"NFC"`. */
  readonly normalize?: "NFC" | "none";
}

const DEFAULT_MAX_DEPTH = 64;
const DEFAULT_MAX_NODES = 50_000;

/**
 * Object keys this canonicalizer refuses: any key containing a backslash.
 *
 * ## Why, and it is not squeamishness about odd characters
 *
 * The canonical form is computed from a value that some **other** code parsed off the wire, and on
 * at least one shipping JavaScript engine that parse is not faithful. Reproduced on Node v25.2.1:
 *
 * ```js
 * JSON.parse(String.raw`{"a":1,"\\":2}`);   // interns a key that is one backslash
 * JSON.parse(String.raw`{"a":1,"\n":2}`);    // -> keys are "a" and "\", NOT "a" and U+000A
 * ```
 *
 * Once an object of a given shape whose key is a lone backslash has been parsed, a later object of
 * the same shape whose key is an **escape sequence** comes back as the raw first character of that
 * escape — a backslash — instead of the character the escape denotes. It affects every escape
 * (`\n`, `\t`, `\r`, `\b`, `\f`, `\uXXXX`, `\"`, `\/`), is not a JIT artifact (it reproduces
 * under `--jitless`), and needs no toolwall code to demonstrate.
 *
 * Both halves of the pinning invariant break under it:
 *
 *   - **Same bytes, different hash.** What a document parses to depends on what the process parsed
 *     before it, so one listing can hash two ways across two sessions. That is a false rug-pull
 *     alarm against a server that did nothing, which `docs/ARCHITECTURE.md` names as the failure
 *     that gets the product uninstalled.
 *   - **Different bytes, same hash — the serious one.** `{"a":{},"\\":{}}` and `{"a":{},"\t":{}}`
 *     are different documents that produce the **same pin**, verified in
 *     `test/unit/canonicalize.platform.test.ts`. A server pinned with the first can later ship the
 *     second and the pinning engine sees nothing. That is a rug pull walking through the one
 *     control this product claims is deterministic.
 *
 * ## Why refusing backslash keys is exactly the right width
 *
 * The corruption strikes only a key that is **entirely one escape sequence**, and its result is
 * always exactly one character: the backslash that began the escape. (`"a\\nb"` and `"\\n\\t"` decode
 * correctly — measured; it is the whole-key-is-one-escape case that breaks.) So:
 *
 *   - **Every corrupted key contains a backslash**, therefore refusing backslash keys means a
 *     corrupted document can never acquire a pin, never collide with another document's pin, and
 *     never masquerade as drift. That is the soundness argument, and it is the whole of it.
 *   - We cannot do better than refusal, because a mangled key is *indistinguishable* from a
 *     legitimate backslash key — the mangled form IS a backslash key.
 *   - We should not do more than this. Control characters in a key are a hygiene question, not an
 *     identity one, and they already have an owner with a measured false-positive rate:
 *     `UnicodeHygieneGuard` scans object keys and rejects the `control` class. Duplicating that
 *     policy here would put a hygiene decision in the module whose only job is identity, and would
 *     make unpinnable a listing the product deliberately documents as pinnable-under-TOFU
 *     (`test/integration/response-guards-e2e.test.ts`).
 *
 * A key we refuse makes the tool unpinnable, and `drift.ts` treats unpinnable as not callable —
 * fail-closed, the same posture as every other ambiguity in this file.
 *
 * The refusal is **unconditional**, not gated on a runtime probe, so that a pin means the same
 * thing on every machine and cannot become valid or invalid because of an engine upgrade.
 * {@link platformParsesKeyEscapesFaithfully} exists so the state of the running engine can still be
 * reported, and so the test suite notices the day the bug is fixed.
 *
 * **Cost, measured:** zero. No key in `test/fixtures/metadata/benign-metadata.ts`, no key in
 * `test/fixtures/benign/`, and no key across the 100 tools of the 11 captured real servers in
 * `test/fixtures/metadata/real-servers.ts` contains a backslash. JSON Schema property names in the
 * wild are identifiers.
 */
const UNSAFE_KEY = /\\/u;

/** Human-readable code points, for an error message a person can act on. */
function describeUnsafeKey(key: string): string {
  return [...key]
    .map((ch) => {
      const cp = ch.codePointAt(0) as number;
      return UNSAFE_KEY.test(ch)
        ? `U+${cp.toString(16).toUpperCase().padStart(4, "0")}`
        : ch;
    })
    .join("");
}

let platformProbe: boolean | undefined;

/**
 * Does this engine decode an escaped object key faithfully after it has seen a lone-backslash key?
 *
 * `true` on a correct engine. `false` on Node v25.2.1 and anything else carrying the same V8 bug.
 * Memoised; the probe is two `JSON.parse` calls.
 *
 * Nothing in the canonicalizer branches on this — the refusal above is unconditional on purpose.
 * It is exported so an operator report can say which engine they are on, and so
 * `test/unit/canonicalize.platform.test.ts` fails loudly on the day the engine is fixed and this
 * restriction can be revisited rather than carried forever out of habit.
 */
export function platformParsesKeyEscapesFaithfully(): boolean {
  if (platformProbe !== undefined) return platformProbe;
  try {
    // Same shape, so the second parse reuses the first's cached transition. Order matters, and
    // String.raw is used so the JSON text in this file reads exactly as it does on the wire.
    JSON.parse(String.raw`{"a":1,"\\":2}`);
    const keys = Object.keys(JSON.parse(String.raw`{"a":1,"\n":2}`));
    platformProbe = keys[1] === "\n";
  } catch {
    platformProbe = false;
  }
  return platformProbe;
}

/** Fast path: NFC is the identity on pure ASCII, and most metadata is pure ASCII. */
// eslint-disable-next-line no-control-regex
const NON_ASCII = /[^\x00-\x7f]/;

/** NFC-normalize, skipping the (relatively expensive) ICU call for ASCII-only input. */
export function normalizeText(value: string): string {
  return NON_ASCII.test(value) ? value.normalize("NFC") : value;
}

/**
 * ECMAScript `Number::toString`, which RFC 8785 §3.2.2.3 adopts by reference.
 * `-0` serializes as `0`: JSON has no negative zero, and `String(-0) === "0"` already, but the
 * branch is explicit because it is exactly the kind of subtlety that silently breaks a hash.
 */
function serializeNumber(value: number, path: string): string {
  if (!Number.isFinite(value)) {
    throw new CanonicalizationError(
      "non-finite-number",
      path,
      `NaN and Infinity are not representable in JSON; refusing to canonicalize ${String(value)}`,
    );
  }
  if (Object.is(value, -0)) return "0";
  return String(value);
}

/**
 * RFC 8259 minimal string escaping. `JSON.stringify` of a lone string implements the JCS rules
 * exactly (short forms for \b \f \n \r \t, lowercase `\u00xx` for other C0 controls, lowercase
 * surrogate escapes for unpaired surrogates, and — correctly — *no* escaping of DEL, U+2028 or
 * U+2029). `test/unit/canonicalize.test.ts` pins that behaviour so a future engine change
 * cannot silently invalidate every pin in the field.
 */
function serializeString(value: string, normalize: boolean): string {
  return JSON.stringify(normalize ? normalizeText(value) : value);
}

const OBJECT_PROTO = Object.prototype;

/** Accept plain objects and null-prototype objects (what `JSON.parse` can produce); nothing else. */
function isCanonicalizableObject(value: object): boolean {
  const proto: unknown = Object.getPrototypeOf(value);
  return proto === OBJECT_PROTO || proto === null;
}

/** RFC 6901 JSON Pointer escaping for error paths. */
function pointerSegment(key: string): string {
  return key.replace(/~/g, "~0").replace(/\//g, "~1");
}

/**
 * Serialize `value` to its RFC 8785 canonical form (with NFC applied, see module docs).
 *
 * @throws {CanonicalizationError} on cycles, non-finite numbers, non-JSON types,
 *   depth/size limits, or an NFC key collision.
 */
export function canonicalize(value: unknown, options: CanonicalizeOptions = {}): string {
  const maxDepth = options.maxDepth ?? DEFAULT_MAX_DEPTH;
  const maxNodes = options.maxNodes ?? DEFAULT_MAX_NODES;
  const normalize = (options.normalize ?? "NFC") === "NFC";

  let nodes = 0;
  const stack = new Set<object>();

  function emit(node: unknown, depth: number, path: string): string {
    if (++nodes > maxNodes) {
      throw new CanonicalizationError(
        "max-nodes",
        path,
        `document exceeds the ${maxNodes}-node canonicalization limit`,
      );
    }
    if (depth > maxDepth) {
      throw new CanonicalizationError(
        "max-depth",
        path,
        `document exceeds the ${maxDepth}-level nesting limit`,
      );
    }

    if (node === null) return "null";

    switch (typeof node) {
      case "boolean":
        return node ? "true" : "false";
      case "number":
        return serializeNumber(node, path);
      case "string":
        return serializeString(node, normalize);
      case "bigint":
        throw new CanonicalizationError(
          "unsupported-type",
          path,
          "bigint has no JSON representation and no defined JCS encoding",
        );
      case "undefined":
      case "function":
      case "symbol":
        // Only reachable inside arrays; object members are filtered before recursing.
        return "null";
      case "object":
        break;
      default:
        throw new CanonicalizationError(
          "unsupported-type",
          path,
          `unsupported value of type ${typeof node}`,
        );
    }

    const obj = node as object;
    if (stack.has(obj)) {
      throw new CanonicalizationError("cycle", path, "circular reference");
    }
    stack.add(obj);
    try {
      if (Array.isArray(obj)) {
        let out = "[";
        for (let i = 0; i < obj.length; i++) {
          if (i > 0) out += ",";
          out += emit(obj[i], depth + 1, `${path}/${i}`);
        }
        return out + "]";
      }

      if (!isCanonicalizableObject(obj)) {
        throw new CanonicalizationError(
          "unsupported-type",
          path,
          `${obj.constructor?.name ?? "exotic object"} is not JSON data; canonicalize only ` +
            "accepts values that could have come off the wire",
        );
      }

      const record = obj as Record<string, unknown>;
      // Own enumerable string keys only. `Object.keys` also returns an own "__proto__" data
      // property (which is what `JSON.parse('{"__proto__":1}')` creates), so a server cannot
      // hide a field from the hash behind a prototype-pollution-flavoured key.
      const rawKeys = Object.keys(record);

      const members: Array<{ key: string; raw: string }> = [];
      const seen = new Map<string, string>();
      for (const raw of rawKeys) {
        // `undefined`, functions and symbols are omitted from object members, exactly as
        // JSON.stringify omits them. None can exist on the wire; matching JSON.stringify is
        // what keeps `canonicalize(parse(stringify(x))) === canonicalize(x)` true for values
        // constructed in-process.
        const member = record[raw];
        if (member === undefined || typeof member === "function" || typeof member === "symbol") {
          continue;
        }
        const key = normalize ? normalizeText(raw) : raw;
        // See UNSAFE_KEY: a key carrying a control character or a backslash cannot be vouched for,
        // because the engine that parsed it may have handed us a different key from the one on the
        // wire — and the corrupted form is itself a backslash key, so it is undetectable after the
        // fact. Refuse rather than pin something we cannot stand behind.
        if (UNSAFE_KEY.test(key)) {
          throw new CanonicalizationError(
            "unsafe-key",
            `${path}/${pointerSegment(key)}`,
            `object key "${describeUnsafeKey(key)}" contains a backslash; a backslash key is ` +
              "indistinguishable from what this engine produces when it mis-decodes an escaped key " +
              "(see UNSAFE_KEY in canonicalize.ts for the reproducer), so it has no dependable " +
              "canonical form and toolwall will not pin one",
          );
        }
        const previous = seen.get(key);
        if (previous !== undefined) {
          throw new CanonicalizationError(
            "key-collision",
            `${path}/${pointerSegment(key)}`,
            `keys ${JSON.stringify(previous)} and ${JSON.stringify(raw)} are distinct on the ` +
              "wire but identical after NFC normalization; the document is ambiguous",
          );
        }
        seen.set(key, raw);
        members.push({ key, raw });
      }

      // RFC 8785 §3.2.3: sort by UTF-16 code units of the member name.
      members.sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));

      let out = "{";
      for (let i = 0; i < members.length; i++) {
        const member = members[i] as { key: string; raw: string };
        if (i > 0) out += ",";
        out += serializeString(member.key, false); // already normalized above
        out += ":";
        out += emit(record[member.raw], depth + 1, `${path}/${pointerSegment(member.key)}`);
      }
      return out + "}";
    } finally {
      stack.delete(obj);
    }
  }

  return emit(value, 0, "");
}

/** Lowercase hex SHA-256 of the UTF-8 encoding of `input`. */
export function sha256Hex(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("hex");
}

/**
 * The pinned identity of a value: `sha256:<hex>` over the UTF-8 bytes of the canonical form.
 * The algorithm prefix is stored with every pin so the digest can be migrated without
 * guessing what produced an old value.
 */
export function canonicalHash(value: unknown, options: CanonicalizeOptions = {}): string {
  return `sha256:${sha256Hex(canonicalize(value, options))}`;
}

/** Canonical form and hash in one pass, for callers that need both (drift reporting does). */
export function canonicalizeAndHash(
  value: unknown,
  options: CanonicalizeOptions = {},
): { canonical: string; hash: string } {
  const canonical = canonicalize(value, options);
  return { canonical, hash: `sha256:${sha256Hex(canonical)}` };
}
