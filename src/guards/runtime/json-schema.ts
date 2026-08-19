import { blockingFindings, type Finding, type JsonSchemaNode } from "../../policy/contract.js";
import type { SchemaEnforcement } from "../../policy/schema.js";

/**
 * The JSON Schema subset toolwall enforces, extracted so both legs can use it.
 *
 * Request leg: `SchemaGuard` validates `tools/call` arguments against the tool's PINNED
 * `inputSchema`. Response leg: `ResultGuard` validates `structuredContent` against the tool's
 * PINNED `outputSchema`. Same code, same limitations, same honesty about what it did not check —
 * so a gap fixed on one leg is fixed on both, and a schema construct we cannot evaluate produces
 * the same `low` "not checked" finding either way rather than a silent pass in one direction.
 *
 * Two limits carried over deliberately:
 *  1. **Server-supplied `pattern` regexes are compiled by US, so they are ours to be DoS'd by.**
 *     CVE-2026-0621 is a ReDoS in the SDK's own UriTemplate handling — same class, same input
 *     source. Patterns over `maxPatternLength`, or with a nested-quantifier construct, are not
 *     evaluated at all; a `low` finding records the skip.
 *  2. **`info`/`low` findings never block.** They record what the validator could NOT check. A
 *     block on our own inability to parse a schema is an outage wearing a security badge.
 */

export const MAX_SCHEMA_DEPTH = 32;
export const MAX_ERRORS = 25;
/** Inputs longer than this are not run through a server-supplied regex, regardless of pattern. */
export const MAX_PATTERN_INPUT = 8192;

export interface ValidationTarget {
  /** Tool name, for the finding's `evidence.tool`. */
  readonly toolName: string;
  /** Prepended to every locus, e.g. `"/arguments"` or `"/structuredContent"`. */
  readonly locusPrefix: string;
  /** Rule namespace, e.g. `"schema"` -> `toolwall/schema.type`. */
  readonly ruleGroup: string;
  readonly cfg: SchemaEnforcement;
}

export class SchemaValidator {
  readonly #regexCache = new Map<string, RegExp | null>();

  /** Validate `value` against `schema`. Returns findings; never throws on a hostile schema. */
  validate(value: unknown, schema: JsonSchemaNode, target: ValidationTarget): Finding[] {
    const errors: Finding[] = [];
    this.#validate(value, schema, schema, "", target, 0, errors);
    return errors;
  }

  #err(
    errors: Finding[],
    rule: string,
    target: ValidationTarget,
    pointer: string,
    message: string,
    remediation: string,
    detail?: Record<string, string | number | boolean>,
    severity: Finding["severity"] = "medium",
  ): void {
    if (errors.length >= MAX_ERRORS) return;
    errors.push({
      ruleId: `toolwall/${target.ruleGroup}.${rule}`,
      severity,
      // Loci resolve against the payload the guard was handed, which Dev 1 defines as the raw
      // JSON-RPC `params` (request) or `result` (response). Hence the caller-supplied prefix.
      locus: `${target.locusPrefix}${pointer}`,
      message,
      remediation,
      evidence: { tool: target.toolName, ...detail },
    });
  }

  #resolveRef(ref: string, root: JsonSchemaNode): JsonSchemaNode | undefined {
    if (!ref.startsWith("#/")) return undefined;
    let cur: unknown = root;
    for (const rawSeg of ref.slice(2).split("/")) {
      const seg = rawSeg.replace(/~1/g, "/").replace(/~0/g, "~");
      if (cur === null || typeof cur !== "object") return undefined;
      cur = (cur as Record<string, unknown>)[seg];
    }
    return cur !== null && typeof cur === "object" && !Array.isArray(cur) ? (cur as JsonSchemaNode) : undefined;
  }

  #compile(pattern: string, cfg: SchemaEnforcement): RegExp | null {
    const cached = this.#regexCache.get(pattern);
    if (cached !== undefined) return cached;
    let compiled: RegExp | null = null;
    if (pattern.length <= cfg.maxPatternLength && !looksCatastrophic(pattern)) {
      try {
        compiled = new RegExp(pattern, "u");
      } catch {
        try {
          compiled = new RegExp(pattern);
        } catch {
          compiled = null;
        }
      }
    }
    this.#regexCache.set(pattern, compiled);
    return compiled;
  }

  #validate(value: unknown, schema: JsonSchemaNode, root: JsonSchemaNode, pointer: string, target: ValidationTarget, depth: number, errors: Finding[]): void {
    if (depth > MAX_SCHEMA_DEPTH || errors.length >= MAX_ERRORS) return;
    const cfg = target.cfg;

    const ref = schema["$ref"];
    if (typeof ref === "string") {
      const resolved = this.#resolveRef(ref, root);
      if (resolved === undefined) {
        // Our limitation, not the caller's fault. `low` => recorded, never blocking.
        this.#err(errors, "unresolvable-ref", target, pointer, `Unresolvable $ref ${JSON.stringify(ref)}; that subschema was not enforced.`, "Report the schema upstream. The value at this location was NOT validated.", undefined, "low");
        return;
      }
      this.#validate(value, resolved, root, pointer, target, depth + 1, errors);
      return;
    }

    // --- combinators -------------------------------------------------
    const allOf = schema["allOf"];
    if (Array.isArray(allOf)) {
      for (const sub of allOf) {
        if (sub !== null && typeof sub === "object" && !Array.isArray(sub)) {
          this.#validate(value, sub as JsonSchemaNode, root, pointer, target, depth + 1, errors);
        }
      }
    }
    for (const key of ["anyOf", "oneOf"] as const) {
      const branches = schema[key];
      if (!Array.isArray(branches) || branches.length === 0) continue;
      let matched = 0;
      for (const sub of branches) {
        if (sub === null || typeof sub !== "object" || Array.isArray(sub)) continue;
        const probe: Finding[] = [];
        this.#validate(value, sub as JsonSchemaNode, root, pointer, target, depth + 1, probe);
        // Only blocking-severity findings count as a branch failure; a `low` note means "not
        // checked", which must not be mistaken for "did not match".
        if (blockingFindings(probe).length === 0) matched++;
      }
      const ok = key === "anyOf" ? matched >= 1 : matched === 1;
      if (!ok) {
        this.#err(errors, key, target, pointer, `Value does not satisfy the tool's ${key} constraint (${matched} of ${branches.length} branches matched).`, "Check the tool's published schema for the accepted shapes at this location.");
      }
    }

    // --- const / enum ------------------------------------------------
    if ("const" in schema && !deepEqual(value, schema["const"])) {
      this.#err(errors, "const", target, pointer, "Value does not equal the constant required by the schema.", "Send the exact value the schema declares.");
    }
    const enumVals = schema["enum"];
    if (Array.isArray(enumVals) && !enumVals.some((e) => deepEqual(e, value))) {
      this.#err(errors, "enum", target, pointer, "Value is not one of the enum values the tool declares.", `Use one of: ${enumVals.slice(0, 12).map((e) => JSON.stringify(e)).join(", ")}`, { enumSize: enumVals.length });
      return;
    }

    // --- type --------------------------------------------------------
    const declared = schema["type"];
    const types = typeof declared === "string" ? [declared] : Array.isArray(declared) ? declared.filter((t): t is string => typeof t === "string") : [];
    if (types.length > 0 && !types.some((t) => matchesJsonType(value, t))) {
      this.#err(errors, "type", target, pointer, `Expected ${types.join(" or ")}, received ${jsonTypeOf(value)}.`, "Correct the value type. This is the tool's own published contract; a type mismatch here means the call would not have worked anyway.", { expected: types.join("|"), actual: jsonTypeOf(value) });
      return;
    }

    // --- string ------------------------------------------------------
    if (typeof value === "string") {
      const minLength = schema["minLength"];
      if (typeof minLength === "number" && value.length < minLength) {
        this.#err(errors, "minLength", target, pointer, `String shorter than the declared minimum (${value.length} < ${minLength}).`, `Provide at least ${minLength} characters.`);
      }
      const maxLength = schema["maxLength"];
      if (typeof maxLength === "number" && value.length > maxLength) {
        this.#err(errors, "maxLength", target, pointer, `String longer than the declared maximum (${value.length} > ${maxLength}).`, `Truncate to ${maxLength} characters, or split the call.`);
      }
      const pattern = schema["pattern"];
      if (typeof pattern === "string") {
        if (value.length > MAX_PATTERN_INPUT) {
          // Skipping is the safe choice: a huge input plus a server regex is the ReDoS recipe.
          this.#err(errors, "pattern-skipped", target, pointer, "Input too long to test against the server-supplied pattern; the pattern was not evaluated.", "Recorded so the skip is visible in the audit trail; no operator action required.", { inputLength: value.length }, "low");
        } else {
          const re = this.#compile(pattern, cfg);
          if (re === null) {
            this.#err(errors, "pattern-unsafe", target, pointer, "The server-supplied regex was rejected as unsafe or uncompilable and was not evaluated.", "This is a defect in the server's schema. The value was NOT validated against it.", { patternLength: pattern.length }, "low");
          } else if (!re.test(value)) {
            this.#err(errors, "pattern", target, pointer, "String does not match the pattern the tool declares.", "Check the tool's schema pattern for this location.");
          }
        }
      }
      const format = schema["format"];
      if (typeof format === "string" && cfg.enforceFormats.includes(format) && !checkFormat(format, value)) {
        this.#err(errors, "format", target, pointer, `String is not a valid ${format}.`, `Provide a well-formed ${format} value.`, { format });
      }
    }

    // --- number ------------------------------------------------------
    if (typeof value === "number") {
      const min = schema["minimum"];
      if (typeof min === "number" && value < min) {
        this.#err(errors, "minimum", target, pointer, `Value ${value} is below the declared minimum ${min}.`, `Use a value >= ${min}.`);
      }
      const max = schema["maximum"];
      if (typeof max === "number" && value > max) {
        this.#err(errors, "maximum", target, pointer, `Value ${value} exceeds the declared maximum ${max}.`, `Use a value <= ${max}.`);
      }
      const exMin = schema["exclusiveMinimum"];
      if (typeof exMin === "number" && value <= exMin) {
        this.#err(errors, "exclusiveMinimum", target, pointer, `Value ${value} must be strictly greater than ${exMin}.`, `Use a value > ${exMin}.`);
      }
      const exMax = schema["exclusiveMaximum"];
      if (typeof exMax === "number" && value >= exMax) {
        this.#err(errors, "exclusiveMaximum", target, pointer, `Value ${value} must be strictly less than ${exMax}.`, `Use a value < ${exMax}.`);
      }
      const mult = schema["multipleOf"];
      if (typeof mult === "number" && mult > 0 && !isMultipleOf(value, mult)) {
        this.#err(errors, "multipleOf", target, pointer, `Value ${value} is not a multiple of ${mult}.`, `Use a multiple of ${mult}.`);
      }
    }

    // --- array -------------------------------------------------------
    if (Array.isArray(value)) {
      const minItems = schema["minItems"];
      if (typeof minItems === "number" && value.length < minItems) {
        this.#err(errors, "minItems", target, pointer, `Array has ${value.length} items, minimum is ${minItems}.`, `Provide at least ${minItems} items.`);
      }
      const maxItems = schema["maxItems"];
      if (typeof maxItems === "number" && value.length > maxItems) {
        this.#err(errors, "maxItems", target, pointer, `Array has ${value.length} items, maximum is ${maxItems}.`, `Split the call into batches of at most ${maxItems}.`);
      }
      if (schema["uniqueItems"] === true && hasDuplicates(value)) {
        this.#err(errors, "uniqueItems", target, pointer, "Array contains duplicate items but the schema requires uniqueness.", "Remove duplicates.");
      }
      const items = schema["items"];
      if (items !== null && typeof items === "object" && !Array.isArray(items)) {
        for (let i = 0; i < value.length; i++) {
          if (errors.length >= MAX_ERRORS) break;
          this.#validate(value[i], items as JsonSchemaNode, root, `${pointer}/${i}`, target, depth + 1, errors);
        }
      }
    }

    // --- object ------------------------------------------------------
    if (value !== null && typeof value === "object" && !Array.isArray(value)) {
      const obj = value as Record<string, unknown>;
      const props = schema["properties"];
      const propMap = props !== null && typeof props === "object" && !Array.isArray(props) ? (props as Record<string, unknown>) : {};

      const required = schema["required"];
      if (Array.isArray(required)) {
        for (const r of required) {
          if (typeof r === "string" && !Object.prototype.hasOwnProperty.call(obj, r)) {
            this.#err(errors, "required", target, `${pointer}/${escapeToken(r)}`, `Required property "${r}" is missing.`, `Supply "${r}"; the tool declares it as required.`);
          }
        }
      }

      const minProps = schema["minProperties"];
      if (typeof minProps === "number" && Object.keys(obj).length < minProps) {
        this.#err(errors, "minProperties", target, pointer, `Object has fewer than ${minProps} properties.`, `Provide at least ${minProps} properties.`);
      }
      const maxProps = schema["maxProperties"];
      if (typeof maxProps === "number" && Object.keys(obj).length > maxProps) {
        this.#err(errors, "maxProperties", target, pointer, `Object has more than ${maxProps} properties.`, `Reduce to at most ${maxProps} properties.`);
      }

      const addl = schema["additionalProperties"];
      const addlDeclared = "additionalProperties" in schema;
      // Prototype-pollution keys are never legitimate and are rejected at every tier, on both legs:
      // a `__proto__` key in a RESULT reaches the client's own parser, not just ours.
      for (const key of Object.keys(obj)) {
        if (key === "__proto__" || key === "constructor" || key === "prototype") {
          this.#err(errors, "prototype-key", target, `${pointer}/${escapeToken(key)}`, `Property name "${key}" is never a legitimate value here.`, "Remove it. This name is a prototype-pollution vector (T-08) and is rejected at every tier.", undefined, "high");
        }
      }

      for (const [key, sub] of Object.entries(obj)) {
        if (errors.length >= MAX_ERRORS) break;
        const declaredSub = Object.prototype.hasOwnProperty.call(propMap, key) ? propMap[key] : undefined;
        if (declaredSub !== null && typeof declaredSub === "object" && !Array.isArray(declaredSub)) {
          this.#validate(sub, declaredSub as JsonSchemaNode, root, `${pointer}/${escapeToken(key)}`, target, depth + 1, errors);
          continue;
        }
        if (addl === false) {
          this.#err(errors, "additionalProperties", target, `${pointer}/${escapeToken(key)}`, `Property "${key}" is not declared and the schema sets additionalProperties: false.`, `Remove "${key}", or fix the server's schema if the property is genuinely supported.`);
        } else if (addl !== null && typeof addl === "object" && !Array.isArray(addl)) {
          this.#validate(sub, addl as JsonSchemaNode, root, `${pointer}/${escapeToken(key)}`, target, depth + 1, errors);
        } else if (!addlDeclared && cfg.additionalProperties === "reject") {
          this.#err(errors, "undeclared-property", target, `${pointer}/${escapeToken(key)}`, `Property "${key}" is not declared in the tool's schema, and this tier rejects undeclared properties.`, `Either remove "${key}", or if the tool genuinely uses it, set schema.additionalProperties = "schema" for this tool in toolwall-policy.json. Under-specified published schemas are common and this rule has a measured cost — see the FP report.`);
        }
      }
    }
  }
}

/* ---------------------------------------------------------------- */
/* Helpers                                                            */
/* ---------------------------------------------------------------- */

export function escapeToken(t: string): string {
  return t.replace(/~/g, "~0").replace(/\//g, "~1");
}

export function jsonTypeOf(v: unknown): string {
  if (v === null) return "null";
  if (Array.isArray(v)) return "array";
  const t = typeof v;
  if (t === "number") return Number.isInteger(v) ? "integer" : "number";
  return t;
}

export function matchesJsonType(v: unknown, t: string): boolean {
  switch (t) {
    case "null":
      return v === null;
    case "boolean":
      return typeof v === "boolean";
    case "string":
      return typeof v === "string";
    case "number":
      return typeof v === "number" && Number.isFinite(v);
    case "integer":
      return typeof v === "number" && Number.isInteger(v);
    case "array":
      return Array.isArray(v);
    case "object":
      return v !== null && typeof v === "object" && !Array.isArray(v);
    default:
      // Unknown type keyword: do not invent a failure out of our own ignorance.
      return true;
  }
}

function isMultipleOf(value: number, mult: number): boolean {
  const q = value / mult;
  return Math.abs(q - Math.round(q)) < 1e-9;
}

export function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (typeof a !== typeof b || a === null || b === null || typeof a !== "object") return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  if (Array.isArray(a) && Array.isArray(b)) {
    if (a.length !== b.length) return false;
    return a.every((x, i) => deepEqual(x, b[i]));
  }
  const ka = Object.keys(a as object);
  const kb = Object.keys(b as object);
  if (ka.length !== kb.length) return false;
  return ka.every((k) => deepEqual((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k]));
}

function hasDuplicates(arr: readonly unknown[]): boolean {
  if (arr.length > 500) return false; // O(n^2) guard; large arrays are bounded by ArgumentBounds instead
  for (let i = 0; i < arr.length; i++) {
    for (let j = i + 1; j < arr.length; j++) if (deepEqual(arr[i], arr[j])) return true;
  }
  return false;
}

/**
 * Conservative nested-quantifier detector. Not a decision procedure — it is a cheap refusal to
 * compile the shapes that actually cause catastrophic backtracking, e.g. `(a+)+`, `(a|a)*`.
 */
export function looksCatastrophic(pattern: string): boolean {
  if (/\((?:[^()]|\\.)*[+*]\)[+*]/.test(pattern)) return true;
  if (/\((?:[^()]|\\.)*\{\d+,\d*\}\)\{\d+,\d*\}/.test(pattern)) return true;
  if (/\((?:[^()|]+)\|(?:[^()|]+)\)[+*]/.test(pattern) && /\|/.test(pattern)) {
    // (a|a)* style alternation with overlapping branches; only flag when branches can overlap.
    const m = /\(([^()|]+)\|([^()|]+)\)[+*]/.exec(pattern);
    if (m && m[1] !== undefined && m[2] !== undefined && (m[1] === m[2] || m[1].includes(m[2]) || m[2].includes(m[1]))) return true;
  }
  return false;
}

const RE_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const RE_IPV4 = /^((25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(25[0-5]|2[0-4]\d|1?\d?\d)$/;
const RE_EMAIL = /^[^\s@]+@[^\s@.]+(\.[^\s@.]+)+$/;
const RE_DATETIME = /^\d{4}-\d{2}-\d{2}[Tt ]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$/;

export function checkFormat(format: string, value: string): boolean {
  switch (format) {
    case "uri":
    case "iri":
      try {
        new URL(value);
        return true;
      } catch {
        return false;
      }
    case "uuid":
      return RE_UUID.test(value);
    case "ipv4":
      return RE_IPV4.test(value);
    case "ipv6":
      return value.includes(":") && /^[0-9a-f:.]+$/i.test(value);
    case "email":
      return RE_EMAIL.test(value);
    case "date-time":
      return RE_DATETIME.test(value) && !Number.isNaN(Date.parse(value));
    default:
      return true;
  }
}
