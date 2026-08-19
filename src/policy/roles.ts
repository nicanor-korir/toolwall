import type { JsonSchemaNode, ToolDefinition } from "./contract.js";
import type { ArgumentRoles } from "./schema.js";

/**
 * Argument role binding — the mechanism that keeps the false-positive rate at zero.
 *
 * The guard **never** inspects a string to decide whether it "looks like a path" or "looks like a
 * URL". That heuristic is exactly what produces the 78%-FP results in the literature: a
 * code-editing tool's `content` argument is full of paths and URLs and shell syntax, and none of
 * it is a capability request.
 *
 * Instead a role is bound to an argument *location*, from two sources only:
 *
 *  1. The operator's policy (`roles.readPath`, `roles.writePath`, `roles.url`), as JSON Pointer
 *     selectors with `*` as a single-segment wildcard: `/path`, `/paths/*`, `/edits/<*>/file_path` (wildcard shown as <*> here to avoid closing this comment).
 *  2. The tool's own published `inputSchema`, where a string property declares `"format": "uri"`.
 *     The schema is a contract the server published; reading a role out of it is not guesswork.
 *     Note that path roles are deliberately NOT derived — JSON Schema has no standard path format,
 *     and inferring from property names (`path`, `file`, `dir`, ...) is the same name-guessing
 *     heuristic in a different coat.
 *
 * An argument with no bound role is not examined for capability purposes at all.
 */

export type Role = "readPath" | "writePath" | "url";

export interface RoleTarget {
  readonly role: Role;
  /** JSON Pointer into the arguments object, e.g. `/paths/2`. */
  readonly pointer: string;
  readonly value: unknown;
}

interface CompiledSelector {
  readonly role: Role;
  readonly segments: readonly string[];
}

function compile(role: Role, selector: string): CompiledSelector | undefined {
  if (!selector.startsWith("/")) return undefined;
  const segments = selector.slice(1).split("/");
  if (segments.some((s) => s === "")) return undefined;
  return { role, segments };
}

function selectorMatches(sel: CompiledSelector, pointerSegments: readonly string[]): boolean {
  if (sel.segments.length !== pointerSegments.length) return false;
  for (let i = 0; i < sel.segments.length; i++) {
    const s = sel.segments[i];
    if (s === "*") continue;
    if (s !== pointerSegments[i]) return false;
  }
  return true;
}

/** JSON Pointer escaping (RFC 6901). */
function escapeToken(t: string): string {
  return t.replace(/~/g, "~0").replace(/\//g, "~1");
}

const MAX_SCHEMA_DEPTH = 8;

/**
 * Derive `url` selectors from the tool's own inputSchema by walking `properties` / `items`, so
 * `{ properties: { links: { type: "array", items: { format: "uri" } } } }` yields `/links/*`.
 */
export function deriveUrlSelectors(tool: ToolDefinition): string[] {
  const out: string[] = [];
  walk(tool.inputSchema, [], 0);
  return out;

  function walk(node: unknown, at: string[], depth: number): void {
    if (depth > MAX_SCHEMA_DEPTH || node === null || typeof node !== "object" || Array.isArray(node)) return;
    const n = node as JsonSchemaNode;

    const format = n["format"];
    if (typeof format === "string" && (format === "uri" || format === "iri") && at.length > 0) {
      out.push("/" + at.join("/"));
    }

    const props = n["properties"];
    if (props !== null && typeof props === "object" && !Array.isArray(props)) {
      for (const [key, sub] of Object.entries(props as Record<string, unknown>)) {
        walk(sub, [...at, escapeToken(key)], depth + 1);
      }
    }

    const items = n["items"];
    if (items !== null && typeof items === "object" && !Array.isArray(items)) {
      walk(items, [...at, "*"], depth + 1);
    }
  }
}

export interface RoleBindingOptions {
  /** Hard cap on nodes visited, so role collection cannot be turned into a DoS. */
  readonly maxNodes?: number;
}

/**
 * Walk the arguments object once, emitting every value whose location matches a bound selector.
 * Values are emitted as-is (including non-strings) so the caller can report a type mismatch on an
 * argument the policy says is a path.
 */
export function collectRoleTargets(
  args: unknown,
  roles: ArgumentRoles,
  tool: ToolDefinition | undefined,
  opts: RoleBindingOptions = {},
): RoleTarget[] {
  const selectors: CompiledSelector[] = [];
  for (const s of roles.readPath) {
    const c = compile("readPath", s);
    if (c) selectors.push(c);
  }
  for (const s of roles.writePath) {
    const c = compile("writePath", s);
    if (c) selectors.push(c);
  }
  for (const s of roles.url) {
    const c = compile("url", s);
    if (c) selectors.push(c);
  }
  if (roles.deriveUrlFromSchema && tool) {
    for (const s of deriveUrlSelectors(tool)) {
      const c = compile("url", s);
      if (c) selectors.push(c);
    }
  }

  if (selectors.length === 0) return [];
  if (args === null || typeof args !== "object") return [];

  const out: RoleTarget[] = [];
  const maxNodes = opts.maxNodes ?? 50_000;
  let nodes = 0;

  const stack: Array<{ value: unknown; segs: string[] }> = [{ value: args, segs: [] }];
  while (stack.length > 0) {
    const frame = stack.pop();
    if (frame === undefined) break;
    if (++nodes > maxNodes) break;

    // Test this location against every selector, whatever its type.
    if (frame.segs.length > 0) {
      for (const sel of selectors) {
        if (selectorMatches(sel, frame.segs)) {
          out.push({ role: sel.role, pointer: "/" + frame.segs.join("/"), value: frame.value });
        }
      }
    }

    const v = frame.value;
    if (Array.isArray(v)) {
      for (let i = 0; i < v.length; i++) stack.push({ value: v[i], segs: [...frame.segs, String(i)] });
    } else if (v !== null && typeof v === "object") {
      for (const [k, sub] of Object.entries(v as Record<string, unknown>)) {
        stack.push({ value: sub, segs: [...frame.segs, escapeToken(k)] });
      }
    }
  }

  return out;
}

/**
 * True when a selector list references a location, without needing the arguments. Used to decide
 * whether a capability is "exercised" for the undeclared-capability check.
 */
export function hasAnyRole(roles: ArgumentRoles, tool: ToolDefinition | undefined): boolean {
  if (roles.readPath.length > 0 || roles.writePath.length > 0 || roles.url.length > 0) return true;
  if (roles.deriveUrlFromSchema && tool) return deriveUrlSelectors(tool).length > 0;
  return false;
}
