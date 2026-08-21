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
 *
 * ## The alert-fatigue constraint on `renderDriftAlert`
 *
 * Trail of Bits names the failure mode for this whole product category: *"alert fatigue will take
 * its toll, and users may miss signs of malicious behavior (or, worse, stop using MCP security
 * controls altogether)."* `docs/RESEARCH-BRIEF.md` §4.3 puts a number on the human at the other
 * end — Anthropic, n=1,053 paid developers, harmful commands substituted mid-session: developers
 * approved the dangerous action **86.4% of the time.** An alert that requires reading is an alert
 * that will not be read.
 *
 * So the drift block is built to four rules, and every one of them is a constraint on this file:
 *
 *   1. **The first line decides.** It names the thing, the server, and how many fields moved. An
 *      operator who reads nothing else must still know whether to keep going.
 *   2. **Ranked, not chronological.** A changed `description` goes into the model's system prompt;
 *      a changed `icons[0].src` does not. They are not the same event and must not be the same
 *      size on screen. `classifyChange` is that ranking, and it is why an alert about a poisoned
 *      description never opens with an icon URL.
 *   3. **Consequence, not just delta.** Each ranked change carries one sentence saying what the
 *      field *does*. "`/inputSchema/properties/path/enum` changed" is a fact; "the set of values
 *      this argument accepts widened, which legalises arguments that were previously rejected" is
 *      a decision.
 *   4. **Bounded.** A hostile server can change 400 fields to bury one. The block shows the
 *      highest-ranked few and says how many it withheld, rather than producing a wall nobody
 *      finishes.
 */

import type { Rendered } from "../../types/protocol.js";

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
    // Named because a bare `‹U+001B›` tells an operator nothing, and ESC is the one control
    // character that can rewrite what the rest of their terminal already showed them. Trail of
    // Bits render it as the literal string ESC for exactly this reason.
    0x1b: "ESC",
    0x7f: "DEL",
    0x9b: "CSI",
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

// ---------------------------------------------------------------------------
// Impact ranking and the drift alert — see the "alert-fatigue constraint" in the header
// ---------------------------------------------------------------------------

/** How much a changed field matters, and the one sentence that says why. */
export interface ChangeImpact {
  /** 0–100. Higher sorts first and drives what an operator reads before they stop reading. */
  readonly rank: number;
  /** What this field does, in one sentence. Written for someone deciding, not documenting. */
  readonly why: string;
}

/** Last non-numeric pointer segment, e.g. `description` for `/tools/0/description`. */
function lastNamedSegment(path: string): string {
  const segments = path.split("/").filter((s) => s !== "" && !/^\d+$/.test(s));
  return segments[segments.length - 1] ?? "";
}

/**
 * Rank a change by what the field it touches can actually do.
 *
 * The ordering is the threat model, not aesthetics. Text that reaches the model's context ranks
 * above structure; structure ranks above hints; hints rank above presentation. In particular a
 * schema change ranks high for the reason contract C-1 exists: an attacker who widens their own
 * schema makes previously-rejected arguments valid, so the rug pull legalises the payload.
 */
export function classifyChange(diff: FieldDiff): ChangeImpact {
  const path = diff.path;
  const segment = lastNamedSegment(path);
  const inSchema = path.includes("/inputSchema") || path.includes("/outputSchema");

  if (path === "/instructions" || segment === "instructions") {
    return {
      rank: 100,
      why: "server instructions are placed directly into the client's system prompt by design — this is the highest-value target on the whole surface",
    };
  }
  if (!inSchema && segment === "description") {
    return {
      rank: 98,
      why: "the tool description is concatenated into the model's system prompt, so this text is read as instruction on every turn",
    };
  }
  if (segment === "name") {
    return {
      rank: 95,
      why: "the tool's wire name is its identity; a changed name can shadow another server's tool or re-point an approval",
    };
  }
  if (inSchema && (segment === "description" || segment === "title")) {
    return {
      rank: 90,
      why: "schema field descriptions reach the model whenever it prepares a call to this tool — the same channel as the tool description, one level down",
    };
  }
  if (segment === "enum" || /\/enum\/\d+$/.test(path)) {
    return {
      rank: 85,
      why: "an enum bounds what this argument may be; widening it makes values valid that the pinned contract rejected",
    };
  }
  if (
    inSchema &&
    (segment === "required" ||
      segment === "additionalProperties" ||
      segment === "type" ||
      segment === "properties" ||
      segment === "pattern" ||
      segment === "format")
  ) {
    return {
      rank: 84,
      why: "argument validation runs against the PINNED schema (contract C-1); a server that widens its own schema is trying to make arguments valid that were not",
    };
  }
  if (inSchema) {
    return {
      rank: 80,
      why: "part of the tool's argument contract — the thing argument validation is checked against",
    };
  }
  if (!inSchema && (segment === "title" || path.startsWith("/annotations/title"))) {
    return { rank: 70, why: "the display name a human sees when approving this tool" };
  }
  if (path.includes("/annotations")) {
    return {
      rank: 65,
      why: "annotations are HINTS, never guarantees — the spec says never to make tool-use decisions on them from an untrusted server, so a tool newly claiming readOnly is claiming, not proving",
    };
  }
  if (path.includes("/icons")) {
    return { rank: 30, why: "presentation only; an icon URL is still a URL the client may fetch" };
  }
  if (path.includes("/_meta")) {
    return { rank: 25, why: "transport bookkeeping, but attacker-controlled text all the same" };
  }
  return { rank: 50, why: "part of the definition that was approved" };
}

export interface DriftAlertOptions {
  /**
   * e.g. `tool "send_email"` or `server instructions`. Goes in the headline.
   *
   * **`Rendered`, because a tool name is not ours.** The headline interpolates this into a
   * sentence an operator reads before deciding whether their server was swapped, and a name
   * carrying newlines forges rows in exactly the way red team round 3 proved on the pin-assessment
   * sheet. The values *inside* the block are safe already — `escapeInvisible` turns every control
   * character into `‹U+001B›` — but this one arrives from the caller, so the caller has to
   * sanitize it and the type is what says so.
   */
  readonly subject: Rendered;
  readonly serverId: string;
  readonly pinnedHash: string;
  readonly liveHash: string;
  readonly diffs: readonly FieldDiff[];
  /** Authorization scope, when there is one. Shown only when it is not the default. */
  readonly scope?: Rendered;
  /**
   * Scopes under which this exact live definition is ALREADY pinned. Non-empty turns the alert
   * from "your server may have been swapped" into "your credential changed", which is a different
   * decision and usually the right one.
   */
  readonly alsoPinnedUnderScopes?: readonly Rendered[];
  /** How many changes to show in full. Default 5. The rest are counted, not printed. */
  readonly maxFields?: number;
  readonly maxValueLength?: number;
}

/** Human-readable character-count delta for a string change, e.g. `+41 characters`. */
function lengthDelta(diff: FieldDiff): string | undefined {
  if (diff.kind !== "changed") return undefined;
  if (typeof diff.before !== "string" || typeof diff.after !== "string") return undefined;
  const delta = [...diff.after].length - [...diff.before].length;
  if (delta === 0) return undefined;
  return `${delta > 0 ? "+" : ""}${delta} characters`;
}

/**
 * The block a human reads when a definition drifted. Headline, then why it matters, then the
 * evidence, then what to do — in that order, because that is the order in which a reader stops.
 *
 * See the "alert-fatigue constraint" section of this file's header for the four rules this
 * implements and the research behind them.
 */
export function renderDriftAlert(options: DriftAlertOptions): string {
  const maxFields = options.maxFields ?? 5;
  const maxValueLength = options.maxValueLength ?? 400;
  const diffs = [...options.diffs];
  const ranked = diffs
    .map((diff) => ({ diff, impact: classifyChange(diff) }))
    .sort((a, b) => b.impact.rank - a.impact.rank || a.diff.path.localeCompare(b.diff.path));

  const shown = ranked.slice(0, maxFields);
  const withheld = ranked.length - shown.length;
  const invisible = diffs.filter((d) => d.invisibleOnly === true);
  const count = diffs.length;

  const lines: string[] = [];

  // 1. The headline. Everything an operator who reads one line needs.
  lines.push(
    `DRIFT · ${options.subject} on ${options.serverId} changed in ${count} ` +
      `field${count === 1 ? "" : "s"} since it was approved.`,
  );
  if (options.scope !== undefined && options.scope !== "") {
    lines.push(`         authorization scope: ${options.scope}`);
  }

  // 2. The benign explanation, when the evidence supports one. Stated BEFORE the alarming part:
  //    an operator who is about to be told their server was swapped deserves to know first that
  //    these exact bytes are already approved somewhere.
  const alsoPinned = options.alsoPinnedUnderScopes ?? [];
  if (alsoPinned.length > 0) {
    lines.push(
      "",
      "  LIKELY AN AUTHORIZATION CHANGE, NOT TAMPERING",
      `    This exact definition is already pinned under ${alsoPinned.length} other ` +
        `scope${alsoPinned.length === 1 ? "" : "s"} (${alsoPinned.join(", ")}). The bytes are ones ` +
        "you already approved; what changed is which credential fetched them.",
    );
  }

  // 3. Why it matters, ranked.
  lines.push("", "  WHY IT MATTERS");
  for (const { diff, impact } of shown) {
    const delta = lengthDelta(diff);
    const verb = diff.kind === "added" ? "appeared" : diff.kind === "removed" ? "was removed" : "changed";
    lines.push(
      `    · ${diff.path === "" ? "<whole definition>" : diff.path} ${verb}` +
        `${delta === undefined ? "" : ` (${delta})`} — ${impact.why}`,
    );
  }
  if (withheld > 0) {
    lines.push(
      `    · ${withheld} lower-impact change${withheld === 1 ? "" : "s"} not shown here; the full ` +
        "list is in the audit record.",
    );
  }
  if (invisible.length > 0) {
    lines.push(
      `    · ${invisible.length} change${invisible.length === 1 ? "" : "s"} consist ONLY of ` +
        "characters that do not render. Comparing the raw text would show you two identical " +
        "lines. Read the escaped values below.",
    );
  }

  // 4. The evidence.
  lines.push(
    "",
    "  WHAT CHANGED",
    renderFieldDiffs(
      shown.map((s) => s.diff),
      { maxValueLength, indent: "    " },
    ),
  );

  // 5. The two hashes, last: they prove the claim and nobody decides on them.
  lines.push("", `    pinned hash : ${options.pinnedHash}`, `    live hash   : ${options.liveHash}`);

  return lines.join("\n");
}
