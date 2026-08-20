/**
 * `Rendered` — the type that makes "I forgot to sanitize this" a compile error.
 *
 * ## Why a type and not another call-site fix
 *
 * This is the **third** instance of one class of bug, and the first two were both fixed by
 * sanitizing at the call sites that were known about at the time:
 *
 *  1. **Round 2** — `Finding.locus` reached the `/dev/tty` confirmation dialog raw, so a server
 *     could write its own `│ rule : … [info]` rows into the box a human reads before approving a
 *     tool call. Fixed by calling `sanitizeLocus` / `sanitizeRenderedText` in `confirm.ts` and
 *     `proxy.ts`.
 *  2. **Round 3 follow-up** — tool *names* reached the pin-time assessment sheet raw, through
 *     three headline template literals and through `SignalExample.subject`. A name keeps its
 *     newlines, so the same forged-row attack landed on the same kind of surface. `subjects` was
 *     clipped and safe; the headline beside it was not.
 *
 * Both times the reasoning was *"these fields are ours"*, and both times a server-controlled
 * substring was sitting inside them. `ruleId` and `severity` are ours; `locus` and `name` are not,
 * and they are interpolated into the same sentence. A convention that has failed twice will fail a
 * third time, so the guarantee has to move from the author's attention into the type system:
 *
 * > **A string that has touched server input cannot reach a human-rendered surface without passing
 * > a sanitizer.**
 *
 * ## How the guarantee is obtained
 *
 * `Rendered` is a branded string. `Rendered` is assignable to `string` (so every consumer that
 * reads a headline as text is unaffected), but `string` is **not** assignable to `Rendered`, and
 * the brand is a `unique symbol` that nothing outside this module can name. So the only way to
 * produce one is {@link renderText} or the {@link rendered} tagged template, and both sanitize.
 *
 * The tagged template is the part that makes this stick. Interpolation is where the bug lives —
 * `` `"${name}" declares readOnlyHint: true` `` looks like it is composing our own sentence, and it
 * is, right up until `name` contains a newline. With the tag:
 *
 * ```ts
 * rendered`"${name}" declares readOnlyHint: true but its own name states a mutating operation`
 * ```
 *
 * the static fragments come from `TemplateStringsArray`, which is source code and cannot be
 * influenced by a server, and **every interpolated value goes through the sanitizer automatically.**
 * There is no version of this the author can get wrong, because there is no unsanitized path to
 * write. A field typed `Rendered` that someone tries to fill with a plain template literal is a
 * type error at the point of the mistake, which is what the previous two fixes could not give.
 *
 * ## Why it delegates rather than reimplements
 *
 * The flattening itself is `sanitizeRenderedText` from `src/types/protocol.ts`, unchanged and
 * untouched — a second implementation of "what is dangerous in a terminal" would drift from the
 * first, and the two would disagree in exactly the situation where it matters. This module adds the
 * type discipline around that function; it does not add a competing opinion about ANSI escapes.
 *
 * **Where this should eventually live:** next to `sanitizeRenderedText` in `src/types/protocol.ts`,
 * so `guards/runtime/confirm.ts` and `transport/proxy.ts` — the Round 2 sinks, which still call the
 * raw sanitizer by hand — get the same compiler guarantee. That file is Dev 1's, so this sits in
 * `src/audit/` for now, which every module can already import and which is where the other
 * human-and-audit-surface concerns live.
 */
import { sanitizeRenderedText } from "../types/protocol.js";

declare const RENDERED: unique symbol;

/**
 * Text that has been through the sanitizer and is safe to write to a terminal, a log line or a
 * report a human reads.
 *
 * Assignable to `string`; `string` is not assignable to it. Obtainable only from {@link renderText}
 * and {@link rendered}.
 */
export type Rendered = string & { readonly [RENDERED]: true };

/** Default clip for an interpolated value, matching `sanitizeRenderedText`'s own default. */
export const DEFAULT_RENDER_LENGTH = 300;

/**
 * Sanitize one value and brand it.
 *
 * Guarantees on the result, all inherited from `sanitizeRenderedText`:
 *   - no C0/C1 control characters, so no ANSI escape can repaint the reader's terminal, and no
 *     newline can forge a row;
 *   - no `U+2028`/`U+2029`, which are line terminators to some renderers and not to others;
 *   - no box-drawing characters, so untrusted text cannot draw the frame around itself;
 *   - all whitespace collapsed to single spaces;
 *   - **at most `maxLength` characters, inclusive of any ellipsis.** `sanitizeRenderedText` slices
 *     to its bound and then appends `"..."`, so its result can exceed the number it was given by
 *     three. That is fine for a dialog and wrong for a caller who asked for a hard bound, so the
 *     length contract is enforced here. This adds no second opinion about which characters are
 *     dangerous — that stays entirely in `sanitizeRenderedText`.
 *
 * Numbers, bigints and booleans pass through as their own decimal form: they cannot carry a
 * control character, and routing them through a string sanitizer that returns `""` for non-strings
 * would silently delete them from the sentence they were counted for. Everything else is
 * stringified first, and `null`/`undefined` become `""`.
 *
 * **Idempotent.** Sanitizing already-`Rendered` text is a no-op, which is what lets a value be
 * pre-clipped to a tighter bound and then interpolated into a template without being re-expanded
 * or double-escaped.
 */
export function renderText(value: unknown, maxLength: number = DEFAULT_RENDER_LENGTH): Rendered {
  if (typeof value === "number" || typeof value === "bigint" || typeof value === "boolean") {
    return String(value) as Rendered;
  }
  if (value === null || value === undefined) return "" as Rendered;
  const text = typeof value === "string" ? value : String(value);
  const flat = sanitizeRenderedText(text, maxLength);
  if (flat.length <= maxLength) return flat as Rendered;
  return `${flat.slice(0, Math.max(0, maxLength - 3))}...` as Rendered;
}

/**
 * Compose a sentence from our own words and untrusted values, sanitizing every value.
 *
 * ```ts
 * rendered`"${toolName}" is advertised ${count} times in one listing`
 * ```
 *
 * The literal fragments are source code. The interpolations are not, and every one of them is
 * passed through {@link renderText}. This is the only interpolation form that produces a
 * `Rendered`, so a field typed `Rendered` cannot be filled with an unsanitized template literal.
 */
export function rendered(strings: TemplateStringsArray, ...values: readonly unknown[]): Rendered {
  let out = strings[0] ?? "";
  for (let i = 0; i < values.length; i++) {
    out += renderText(values[i]);
    out += strings[i + 1] ?? "";
  }
  return out as Rendered;
}

/**
 * Characters that must never appear in anything a human is shown.
 *
 * Exported so the property can be asserted end-to-end on a whole rendered report rather than field
 * by field — the type system prevents the mistake at construction, and this catches anything that
 * reached the page by a route the types did not cover. Belt and braces, because the braces have
 * now failed twice.
 *
 * `\n` and `\t` are absent on purpose: a *report* is multi-line, its own renderer writes those, and
 * the guarantee is that no untrusted **fragment** can contribute one.
 */
export const FORBIDDEN_RENDER_CHARS =
  /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\u2028\u2029\u2500-\u257F]/u;
