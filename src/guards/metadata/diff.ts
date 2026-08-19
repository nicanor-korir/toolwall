/**
 * Field-level structural diff and human-readable rendering.
 *
 * "Hash mismatch" is a useless alert. The operator's actual question is *what changed*, and the
 * answer decides whether they re-approve or pull the server. So a drift block carries a diff
 * naming every changed JSON Pointer with the pinned value and the live value side by side.
 *
 * ## Why the renderer escapes invisible characters
 *
 * A rug pull can be carried entirely by characters that render as nothing: zero-width spaces,
 * bidi overrides that reorder displayed text, Unicode tag characters (U+E0000–U+E007F) which
 * most terminals and every notification toast drop silently. Printing such a diff raw produces
 * two lines that look *identical* to the human being asked to make a security decision — the
 * alert argues against itself. Every non-printing character is therefore rendered as its code
 * point, and a change consisting only of invisible characters is called out by name.
 *
 * This is rendering, not detection. It makes no claim about whether a change is hostile.
 */

/** Characters that are invisible, direction-altering, or otherwise not faithfully rendered. */
const INVISIBLE = new RegExp(
  "[" +
    "\\u0000-\\u001f\\u007f-\\u009f" + // C0 controls, DEL, C1 controls
    "\\u00ad" + // soft hyphen
    "\\u034f" + // combining grapheme joiner
    "\\u061c" + // arabic letter mark
    "\\u115f\\u1160\\u17b4\\u17b5\\u180b-\\u180f" + // filler / vowel separators / variation selectors
    "\\u200b-\\u200f" + // ZWSP, ZWNJ, ZWJ, LRM, RLM
    "\\u202a-\\u202e" + // bidi embedding / override
    "\\u2060-\\u2064\\u2066-\\u206f" + // word joiner, invisible operators, isolates, deprecated formats
    "\\u3164" + // hangul filler
    "\\ufe00-\\ufe0f" + // variation selectors
    "\\ufeff" + // BOM / ZWNBSP
    "\\ufff9-\\ufffb" + // interlinear annotation
    "\\uffa0" + // halfwidth hangul filler
    "]",
  "gu",
);

/** Same set, plus astral-plane members that need a surrogate-aware pattern. */
const INVISIBLE_ASTRAL = /[\u{1d173}-\u{1d17a}\u{e0000}-\u{e0fff}]/gu;

/** Replace every non-rendering character with a visible `‹U+XXXX›` marker. */
export function escapeInvisible(text: string): string {
  return text
    .replace(INVISIBLE_ASTRAL, (c) => codePointLabel(c))
    .replace(INVISIBLE, (c) => codePointLabel(c));
}

function codePointLabel(char: string): string {
  const cp = char.codePointAt(0) ?? 0;
  const named: Record<number, string> = {
    0x09: "TAB",
    0x0a: "LF",
    0x0d: "CR",
    0x200b: "ZWSP",
    0x200c: "ZWNJ",
    0x200d: "ZWJ",
    0x200e: "LRM",
    0x200f: "RLM",
    0x202e: "RLO",
    0x2066: "LRI",
    0x2067: "RLI",
    0x2068: "FSI",
    0x2069: "PDI",
    0xfeff: "BOM",
  };
  const name = named[cp];
  const hex = cp.toString(16).toUpperCase().padStart(4, "0");
  return name === undefined ? `‹U+${hex}›` : `‹U+${hex} ${name}›`;
}

/** True when the string contains at least one non-rendering character. */
export function containsInvisible(text: string): boolean {
  INVISIBLE.lastIndex = 0;
  INVISIBLE_ASTRAL.lastIndex = 0;
  return INVISIBLE.test(text) || INVISIBLE_ASTRAL.test(text);
}

function stripInvisible(text: string): string {
  return text.replace(INVISIBLE_ASTRAL, "").replace(INVISIBLE, "");
}

export type DiffKind = "added" | "removed" | "changed";

export interface FieldDiff {
  /** RFC 6901 JSON Pointer into the pinned surface, e.g. `/inputSchema/properties/path/description`. */
  readonly path: string;
  readonly kind: DiffKind;
  /** Value in the pin. Absent for `added`. */
  readonly before?: unknown;
  /** Value observed live. Absent for `removed`. */
  readonly after?: unknown;
  /**
   * The two strings differ only in characters that do not render. Set on `changed` string
   * fields only. High signal: a human comparing the raw values would see no difference at all.
   */
  readonly invisibleOnly?: boolean;
}

export interface DiffOptions {
  /** Stop after this many differences to bound work on hostile input. Default 200. */
  readonly maxDiffs?: number;
}

const isRecord = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

function pointer(base: string, segment: string | number): string {
  const escaped =
    typeof segment === "number"
      ? String(segment)
      : segment.replace(/~/g, "~0").replace(/\//g, "~1");
  return `${base}/${escaped}`;
}

/**
 * Structural diff of two JSON values. Objects are compared key-wise, arrays index-wise; a type
 * change or a scalar change is reported at the deepest path where the two still agree on shape.
 */
export function diffValues(before: unknown, after: unknown, options: DiffOptions = {}): FieldDiff[] {
  const maxDiffs = options.maxDiffs ?? 200;
  const diffs: FieldDiff[] = [];

  const walk = (a: unknown, b: unknown, path: string): void => {
    if (diffs.length >= maxDiffs) return;
    if (Object.is(a, b)) return;

    if (isRecord(a) && isRecord(b)) {
      const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
      for (const key of [...keys].sort()) {
        const inA = Object.hasOwn(a, key);
        const inB = Object.hasOwn(b, key);
        if (inA && !inB) diffs.push({ path: pointer(path, key), kind: "removed", before: a[key] });
        else if (!inA && inB) diffs.push({ path: pointer(path, key), kind: "added", after: b[key] });
        else walk(a[key], b[key], pointer(path, key));
        if (diffs.length >= maxDiffs) return;
      }
      return;
    }

    if (Array.isArray(a) && Array.isArray(b)) {
      const len = Math.max(a.length, b.length);
      for (let i = 0; i < len; i++) {
        if (i >= b.length) diffs.push({ path: pointer(path, i), kind: "removed", before: a[i] });
        else if (i >= a.length) diffs.push({ path: pointer(path, i), kind: "added", after: b[i] });
        else walk(a[i], b[i], pointer(path, i));
        if (diffs.length >= maxDiffs) return;
      }
      return;
    }

    if (typeof a === "string" && typeof b === "string") {
      const invisibleOnly = a !== b && stripInvisible(a) === stripInvisible(b);
      diffs.push(
        invisibleOnly
          ? { path, kind: "changed", before: a, after: b, invisibleOnly: true }
          : { path, kind: "changed", before: a, after: b },
      );
      return;
    }

    if (!deepEqual(a, b)) diffs.push({ path, kind: "changed", before: a, after: b });
  };

  walk(before, after, "");
  return diffs;
}

function deepEqual(a: unknown, b: unknown): boolean {
  if (Object.is(a, b)) return true;
  if (Array.isArray(a) && Array.isArray(b)) {
    return a.length === b.length && a.every((x, i) => deepEqual(x, b[i]));
  }
  if (isRecord(a) && isRecord(b)) {
    const ka = Object.keys(a).sort();
    const kb = Object.keys(b).sort();
    return (
      ka.length === kb.length &&
      ka.every((k, i) => k === kb[i]) &&
      ka.every((k) => deepEqual(a[k], b[k]))
    );
  }
  return false;
}

export interface RenderOptions {
  /** Truncate rendered values to this many characters. Default 400. */
  readonly maxValueLength?: number;
  /** Label for the pinned side. Default `"pinned"`. */
  readonly beforeLabel?: string;
  /** Label for the observed side. Default `"live"`. */
  readonly afterLabel?: string;
  /** Prefix every line with this. Default `"  "`. */
  readonly indent?: string;
}

/**
 * Strings are rendered inside quotes with their interior text left as prose (only non-printing
 * characters are escaped, by `escapeInvisible`). The quotes are not decoration: without a
 * delimiter, a description that gained a trailing space renders as two identical-looking lines,
 * which is the same failure mode as the zero-width-space case one rung down.
 */
function renderValue(value: unknown, maxLength: number): string {
  const isString = typeof value === "string";
  const escaped = escapeInvisible(isString ? value : safeStringify(value));
  const clipped =
    escaped.length <= maxLength
      ? escaped
      : `${escaped.slice(0, maxLength)}… (${escaped.length - maxLength} more characters)`;
  return isString ? `"${clipped}"` : clipped;
}

function safeStringify(value: unknown): string {
  try {
    return JSON.stringify(value) ?? String(value);
  } catch {
    return String(value);
  }
}

/**
 * Render a diff for a human making an approve/deny decision. Plain text: this has to survive a
 * terminal, a log line, and a desktop notification without losing the part that matters.
 */
export function renderFieldDiffs(diffs: FieldDiff[], options: RenderOptions = {}): string {
  const maxValueLength = options.maxValueLength ?? 400;
  const beforeLabel = options.beforeLabel ?? "pinned";
  const afterLabel = options.afterLabel ?? "live";
  const indent = options.indent ?? "  ";
  const pad = " ".repeat(Math.max(beforeLabel.length, afterLabel.length));
  const label = (text: string): string => (text + pad).slice(0, pad.length);

  if (diffs.length === 0) return `${indent}(no field-level differences)`;

  const lines: string[] = [];
  for (const diff of diffs) {
    const at = diff.path === "" ? "<whole definition>" : diff.path;
    switch (diff.kind) {
      case "added":
        lines.push(`${indent}+ ${at}`);
        lines.push(`${indent}    ${label(afterLabel)} : ${renderValue(diff.after, maxValueLength)}`);
        break;
      case "removed":
        lines.push(`${indent}- ${at}`);
        lines.push(
          `${indent}    ${label(beforeLabel)} : ${renderValue(diff.before, maxValueLength)}`,
        );
        break;
      case "changed":
        lines.push(`${indent}~ ${at}`);
        lines.push(
          `${indent}    ${label(beforeLabel)} : ${renderValue(diff.before, maxValueLength)}`,
        );
        lines.push(`${indent}    ${label(afterLabel)} : ${renderValue(diff.after, maxValueLength)}`);
        if (diff.invisibleOnly === true) {
          lines.push(
            `${indent}    !! these two differ ONLY in characters that do not render — ` +
              "the change is invisible in any UI that does not escape them",
          );
        }
        break;
      default:
        break;
    }
  }
  return lines.join("\n");
}
