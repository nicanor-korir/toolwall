/**
 * Extraction of the *pinned surface*: the subset of a server's self-description whose mutation
 * constitutes a rug pull (T-02).
 *
 * ## Deny-list, not allow-list — deliberate
 *
 * The obvious design is to pick out `name`, `title`, `description`, `inputSchema`,
 * `outputSchema` and `annotations` and hash those. It is also wrong. An allow-list means any
 * field a future spec revision adds — or any non-standard field a client happens to render —
 * is outside the pin by construction, and an attacker who finds one has an unpinned channel
 * into the model's context. So we pin **every** own field of the tool object and subtract an
 * explicit, short, justified exclusion list.
 *
 * The one exclusion is `_meta`. RESEARCH-BRIEF §1.5 correctly lists it as attacker-controlled
 * text, but it is also the designated carrier for transport bookkeeping (progress tokens,
 * tracing, log level, vendor extensions) and is the field most likely to carry a value that
 * changes legitimately between two identical `tools/list` responses. Pinning it would trade a
 * narrow coverage gap for a broad false-alarm surface, and false rug-pull alarms are the
 * failure mode that gets the product uninstalled.
 *
 * **This is a stated coverage gap, not a solved problem.** `_meta` is unpinned; set
 * `unpinnedFields: []` to pin it and accept the churn. Week 2's detectors run over `_meta`
 * regardless of whether it is pinned.
 */

/** Fields excluded from the tool pin. Keep this list short and keep each entry justified. */
export const UNPINNED_TOOL_FIELDS: readonly string[] = ["_meta"];

/** Reserved subject name for the server-level `instructions` pin. */
export const SERVER_INSTRUCTIONS_SUBJECT = "instructions";

export type PinKind = "tool" | "server";

export class ToolSurfaceError extends Error {
  override readonly name = "ToolSurfaceError";
  constructor(message: string) {
    super(message);
  }
}

export interface ToolSurface {
  /** The tool's wire name, which is half of the pin key. */
  readonly toolName: string;
  /** The value that gets canonicalized and hashed. */
  readonly surface: Record<string, unknown>;
}

export interface ExtractOptions {
  readonly unpinnedFields?: readonly string[];
}

const isRecord = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

/**
 * Reduce one `Tool` object from a `tools/list` result to its pinned surface.
 *
 * @throws {ToolSurfaceError} when the object is not a tool-shaped record with a usable name.
 *   Callers on the enforcement path must treat this as fail-closed: a tool we cannot identify
 *   is a tool we cannot pin, and an unpinnable tool must not be callable.
 */
export function extractToolSurface(tool: unknown, options: ExtractOptions = {}): ToolSurface {
  if (!isRecord(tool)) {
    throw new ToolSurfaceError(
      `tool entry is ${tool === null ? "null" : typeof tool}, expected an object`,
    );
  }
  const name = tool["name"];
  if (typeof name !== "string" || name.length === 0) {
    throw new ToolSurfaceError("tool entry has no usable string `name`");
  }

  const excluded = new Set(options.unpinnedFields ?? UNPINNED_TOOL_FIELDS);
  const surface: Record<string, unknown> = {};
  for (const key of Object.keys(tool)) {
    if (excluded.has(key)) continue;
    Object.defineProperty(surface, key, {
      value: tool[key],
      enumerable: true,
      writable: true,
      configurable: true,
    });
  }
  return { toolName: name, surface };
}

/**
 * The server-level pinned surface: `instructions`, the free-form text the spec explicitly
 * designs to be placed in the client's system prompt (RESEARCH-BRIEF §1.5). It ranks alongside
 * tool descriptions in severity and is precisely what Pillar's Deadbugz campaign mutates after
 * three tool calls.
 *
 * Under `2025-11-25` this arrives on the `initialize` result; under `2026-07-28` on
 * `server/discover`. Same field, same pin, different carrier.
 *
 * `serverInfo` is deliberately **not** pinned. It is self-reported (the threat model says we do
 * not trust it) and its `version` legitimately changes on every server upgrade, which would
 * make a version bump indistinguishable from an attack. Connection identity is established by
 * `deriveServerId` instead, from how the server was launched.
 */
export function extractServerSurface(result: unknown): Record<string, unknown> {
  if (!isRecord(result)) {
    throw new ToolSurfaceError(
      `server descriptor is ${result === null ? "null" : typeof result}, expected an object`,
    );
  }
  const instructions = result["instructions"];
  if (instructions !== undefined && typeof instructions !== "string") {
    throw new ToolSurfaceError("server `instructions` is present but is not a string");
  }
  // Absent vs empty is preserved: no `instructions` key at all hashes differently from `""`.
  return instructions === undefined ? {} : { instructions };
}

/** Pull the `tools` array out of a `tools/list` result, or `null` if this is not one. */
export function readToolList(result: unknown): unknown[] | null {
  if (!isRecord(result)) return null;
  const tools = result["tools"];
  return Array.isArray(tools) ? tools : null;
}

/** Pull `params.name` out of a `tools/call` request payload. */
export function readCallToolName(params: unknown): string | null {
  if (!isRecord(params)) return null;
  const name = params["name"];
  return typeof name === "string" && name.length > 0 ? name : null;
}
