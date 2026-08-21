import * as fs from "node:fs";
import type { ConfirmationProvider, Finding, GuardContext } from "../../policy/contract.js";
import { renderLines, renderLocus, renderText, rendered, renderedWithin, type Rendered } from "../../types/protocol.js";
import type { AuditSink } from "../../policy/contract.js";
import type { ConfirmationBudget } from "../../policy/schema.js";

/**
 * **Human-in-the-loop as a scarce budget (T-06).**
 *
 * The measurement this design is built around (RESEARCH-BRIEF §4.3): Anthropic, n=1,053 paid
 * developers, harmful commands substituted mid-session — developers approved the dangerous action
 * **86.4% of the time, catching 13.6%**. Trail of Bits, independently: *"effectively transforms
 * the 'human-in-the-loop' security model into 'human-as-the-rubber-stamp'."*
 *
 * A 13.6% control is worth having and worth spending carefully. So:
 *
 *  - **A hard per-session cap** (`maxPrompts`). When it is gone, toolwall does not prompt again —
 *    it fails closed. A proxy that keeps prompting has built the rubber stamp itself.
 *  - **Only irreversible operations may spend it** (`promptableRules`). Anything else that
 *    returns `confirm` is denied *without* a prompt. A prompt spent on a schema violation is a
 *    prompt unavailable for a `DROP SCHEMA`, and it is how a human stops reading them.
 *  - **Fail closed with no interactive channel.** Under stdio transport there is no channel by
 *    default: stdin and stdout are the protocol. The only channel is the controlling terminal.
 *  - **Never write to stdout.** Contract C-3. `/dev/tty` or nothing.
 *
 * ## Un-spoofable from the model's side — what that claim is actually worth
 *
 * The prompt renders four fields — `ruleId`, `severity`, `locus`, `remediation` — the same set
 * `redactFindingForClient()` allows across the trust boundary (contract C-9).
 * `finding.message` and `finding.evidence` quote the untrusted server and are **never** rendered
 * here. Otherwise a poisoned tool description would write its own approval dialog: *"[toolwall]
 * routine operation, safe to approve"*.
 *
 * **The original version of this note claimed those four fields were "toolwall-authored". They are
 * not, and red team round 2 proved it** (`test/attacks/confirm-dialog-injection.test.ts`). A
 * `locus` is a JSON Pointer into an attacker-controlled payload, so its segments are names the
 * server chose; RFC 6901 escapes only `~` and `/`, so a property name containing newlines rendered
 * as extra rows of convincing dialog chrome — *"Routine read-only lookup — safe to approve"* —
 * printed directly above this file's own promise that nothing above came from the server. At a
 * measured 13.6% human catch rate, a dialog an attacker can write into does not merely leak: it
 * recruits the rubber stamp.
 *
 * The fix is structural rather than lexical, because a lexical one is not available — no escaping
 * stops a server from naming a property `safe_to_approve`. Every rendered field is now typed
 * `Rendered` (`src/types/protocol.ts`) and can only be produced by `renderText` / `renderLocus` /
 * the `rendered` tag, which delegate to `sanitizeRenderedText` / `sanitizeLocus` and guarantee:
 *
 *   - **the row count is toolwall's**. No field can contain a newline, so no field can add a row.
 *   - **the frame is toolwall's**. Box-drawing characters and C0/C1 controls are stripped, so no
 *     field can redraw the border or move the terminal cursor.
 *   - **a locus is a path**. Escaped to `[A-Za-z0-9_-./~]`, so it still reads as a pointer a human
 *     can debug with, and cannot smuggle prose or whitespace-aligned columns.
 *
 * What survives is that a server picks the CONTENT of a name inside one row. The closing line of
 * the dialog says exactly that, rather than the stronger thing it used to say.
 *
 * ## Discipline vs guarantee — why the fields are typed and not merely sanitized
 *
 * The round-2 fix called the sanitizers by hand at each interpolation. That is correct code and it
 * is one forgetful edit away from being wrong again, which is precisely how round 3 happened on the
 * pin-assessment sheet. `composePrompt` now builds a `Rendered[]`, so the only ways to add a row
 * are the `rendered` tag — which sanitizes every interpolated value automatically — and a literal
 * with no interpolations, which is source code. **The row count of this dialog is a property of
 * the type, not of the author's attention.** `promptRow` is the single place a raw `Finding`
 * crosses into it, and `renderPrompt` keeps its `Finding[]` signature so the red team's regression
 * test exercises exactly the caller the guarantee has to hold for.
 */

export interface ConfirmationChannel {
  /** Ask a yes/no question. Resolves false on timeout, EOF, or anything unexpected. */
  ask(prompt: string, timeoutMs: number): Promise<boolean>;
  close(): void;
}

export type ConfirmationOutcome = "approved" | "denied" | "no-channel" | "budget-exhausted" | "not-promptable" | "timeout";

export interface ConfirmationRecord {
  readonly outcome: ConfirmationOutcome;
  readonly ctx: GuardContext;
  readonly rule: string | undefined;
  readonly spent: number;
  readonly remaining: number;
}

export interface BudgetedConfirmationOptions {
  readonly budget: ConfirmationBudget;
  /** Absent means no interactive channel exists, and every `confirm` verdict fails closed. */
  readonly channel?: ConfirmationChannel | undefined;
  readonly audit?: AuditSink;
  /** Operator-facing notification (the CLI writes these to stderr). Never stdout. */
  readonly onDecision?: (record: ConfirmationRecord) => void;
}

export class BudgetedConfirmationProvider implements ConfirmationProvider {
  readonly #budget: ConfirmationBudget;
  readonly #channel: ConfirmationChannel | undefined;
  readonly #audit: AuditSink | undefined;
  readonly #onDecision: ((record: ConfirmationRecord) => void) | undefined;
  #spent = 0;

  constructor(opts: BudgetedConfirmationOptions) {
    this.#budget = opts.budget;
    this.#channel = opts.channel;
    this.#audit = opts.audit;
    this.#onDecision = opts.onDecision;
  }

  /** Prompts spent so far this session. */
  get spent(): number {
    return this.#spent;
  }

  get remaining(): number {
    return Math.max(0, this.#budget.maxPrompts - this.#spent);
  }

  async confirm(findings: readonly Finding[], ctx: GuardContext): Promise<boolean> {
    // The rule that justifies spending a prompt. Highest-severity promptable rule wins, so the
    // dialog names the most serious reason rather than the first one collected.
    const promptable = findings
      .filter((f) => this.#budget.promptableRules.includes(f.ruleId))
      .sort((a, b) => severityWeight(b.severity) - severityWeight(a.severity));
    const lead = promptable[0];

    if (lead === undefined) {
      // Deny without prompting. This is the load-bearing half of the design: a `confirm` verdict
      // from a rule that is not on the irreversible list is a policy question, and the answer is
      // "no" rather than "ask the human again".
      return this.#finish("not-promptable", ctx, undefined, false);
    }
    if (this.#channel === undefined) {
      return this.#finish("no-channel", ctx, lead.ruleId, false);
    }
    if (this.#spent >= this.#budget.maxPrompts) {
      return this.#finish("budget-exhausted", ctx, lead.ruleId, false);
    }

    this.#spent += 1;
    let answered: boolean;
    try {
      answered = await this.#channel.ask(renderPrompt(promptable, ctx, this.remaining), this.#budget.timeoutMs);
    } catch {
      // A channel that threw is not a human who said yes.
      return this.#finish("denied", ctx, lead.ruleId, false);
    }
    return this.#finish(answered ? "approved" : "denied", ctx, lead.ruleId, answered);
  }

  #finish(outcome: ConfirmationOutcome, ctx: GuardContext, rule: string | undefined, approved: boolean): boolean {
    const record: ConfirmationRecord = { outcome, ctx, rule, spent: this.#spent, remaining: this.remaining };
    this.#onDecision?.(record);
    this.#audit?.(
      [
        {
          ruleId: `toolwall/confirmation.${outcome}`,
          severity: approved ? "medium" : "info",
          locus: "",
          message: describeOutcome(outcome, rule, this.#budget.maxPrompts),
          remediation: remediationFor(outcome, this.#budget.maxPrompts),
          evidence: { outcome, rule: rule ?? "none", spent: this.#spent, method: ctx.method, serverId: ctx.serverId },
        },
      ],
      ctx,
    );
    return approved;
  }
}

function severityWeight(s: Finding["severity"]): number {
  return ["info", "low", "medium", "high", "critical"].indexOf(s);
}

function describeOutcome(outcome: ConfirmationOutcome, rule: string | undefined, max: number): string {
  switch (outcome) {
    case "approved":
      return `A human approved this operation (${rule ?? "unknown rule"}).`;
    case "denied":
      return `A human declined this operation (${rule ?? "unknown rule"}).`;
    case "timeout":
      return "No answer within the confirmation timeout; failed closed.";
    case "no-channel":
      return "The operation required human confirmation and no interactive channel exists; failed closed.";
    case "budget-exhausted":
      return `The per-session confirmation budget of ${max} prompts is exhausted; failed closed without prompting again.`;
    case "not-promptable":
      return `A guard asked for confirmation on a rule that is not on the irreversible-operations list (${rule ?? "none"}); denied without prompting.`;
  }
}

function remediationFor(outcome: ConfirmationOutcome, max: number): string {
  switch (outcome) {
    case "approved":
    case "denied":
      return "No action required. The decision is in the audit log.";
    case "timeout":
      return "Raise confirmation.timeoutMs if the operator needs longer, or resolve the finding in policy so it does not need a human at all.";
    case "no-channel":
      return "Run toolwall from a terminal (it prompts on /dev/tty, never on stdout), or grant the capability in toolwall-policy.json so the call does not need a human.";
    case "budget-exhausted":
      return `The budget is deliberately small: developers approve substituted harmful commands 86.4% of the time, so prompt number ${max + 1} is worth less than prompt number 1. Fix the policy rather than raising confirmation.maxPrompts.`;
    case "not-promptable":
      return "Grant the capability in toolwall-policy.json, or add the rule to confirmation.promptableRules if it genuinely names an irreversible operation.";
  }
}

/** At most this many findings get rows. A dialog nobody finishes reading is not a control. */
export const MAX_DIALOG_FINDINGS = 4;

/** Per-field clips. The dialog's rows are wider than the module default for `remediation` only. */
const SERVER_ID_CHARS = 80;
const METHOD_CHARS = 80;
const RULE_ID_CHARS = 120;
const SEVERITY_CHARS = 12;
const REMEDIATION_CHARS = 400;

/** `remediation` is the row an operator has to act on, so it keeps its wider bound. */
const wide = renderedWithin(REMEDIATION_CHARS);

/**
 * The dialog's header fields, sanitized.
 *
 * `serverId` and `method` are derived and validated by the transport, so they are "ours" in the
 * same sense the four `Finding` fields below were called ours before round 2 proved otherwise.
 * They are typed `Rendered` anyway: this template's row count must not depend on the
 * trustworthiness of ANY caller, including a future one that passes a server-supplied method name
 * straight through.
 */
export interface RenderedPromptHeader {
  readonly serverId: Rendered;
  readonly method: Rendered;
}

/**
 * One finding reduced to the four fields the dialog prints — the same set
 * `redactFindingForClient()` allows across the trust boundary (contract C-9) — each already
 * through a sanitizer.
 *
 * **This is the type that closes round 2 structurally.** `renderPrompt` used to take
 * `readonly Finding[]` straight into the composition and call `sanitizeLocus` /
 * `sanitizeRenderedText` by hand on each interpolation. That is discipline, and discipline is what
 * failed here twice: an edit that adds a fifth row, or forgets one call, reopens the exact bypass
 * `test/attacks/confirm-dialog-injection.test.ts` proved. A `Rendered` cannot be produced from a
 * raw `Finding` field without calling a sanitizer, so {@link promptRow} is the only way to build
 * one and the compiler enforces that it is used.
 */
export interface RenderedPromptRow {
  readonly ruleId: Rendered;
  readonly severity: Rendered;
  /** Percent-escaped to `[A-Za-z0-9_-./~]` by `sanitizeLocus`, not merely flattened. */
  readonly locus: Rendered;
  readonly remediation: Rendered;
}

/** The one place a raw `Finding` becomes dialog-safe. */
export function promptRow(f: Finding): RenderedPromptRow {
  return {
    ruleId: renderText(f.ruleId, RULE_ID_CHARS),
    severity: renderText(f.severity, SEVERITY_CHARS),
    locus: renderLocus(f.locus),
    remediation: renderText(f.remediation, REMEDIATION_CHARS),
  };
}

/**
 * The dialog text. Sanitized fields only — see the class header on spoofing.
 *
 * Keeps its `Finding[]` signature (the round-2 regression test calls it with raw findings, which is
 * exactly the caller the guarantee has to hold for) and converts at the boundary. Everything past
 * this line is `Rendered`.
 */
export function renderPrompt(findings: readonly Finding[], ctx: GuardContext, remaining: number): Rendered {
  return composePrompt(
    { serverId: renderText(ctx.serverId, SERVER_ID_CHARS), method: renderText(ctx.method, METHOD_CHARS) },
    findings.slice(0, MAX_DIALOG_FINDINGS).map(promptRow),
    remaining,
  );
}

/**
 * Compose the dialog from text that is already sanitized.
 *
 * `lines` is `Rendered[]`, so a plain template literal cannot be pushed into it — the only ways to
 * add a row are the `rendered` tag (which sanitizes every interpolation automatically) and a
 * literal with no interpolations at all, which is source code. That is what makes "the number of
 * rows in this dialog is toolwall's" a property of the type rather than of the author's attention.
 *
 * The frame characters survive because the tag sanitizes *values*, never its static fragments.
 */
export function composePrompt(
  header: RenderedPromptHeader,
  rows: readonly RenderedPromptRow[],
  remaining: number,
): Rendered {
  const lines: Rendered[] = [];
  lines.push(rendered``);
  lines.push(rendered`┌─ toolwall · human confirmation required ────────────────────────────`);
  lines.push(rendered`│ server : ${header.serverId}`);
  lines.push(rendered`│ method : ${header.method}`);
  for (const row of rows.slice(0, MAX_DIALOG_FINDINGS)) {
    // Two forms rather than an interpolated `` ` at ${locus}` ``: the sanitizer trims, so a
    // pre-spaced fragment would lose its leading space and run the locus into the severity.
    lines.push(
      row.locus === ""
        ? rendered`│ rule   : ${row.ruleId} [${row.severity}]`
        : rendered`│ rule   : ${row.ruleId} [${row.severity}] at ${row.locus}`,
    );
    lines.push(wide`│          ${row.remediation}`);
  }
  lines.push(rendered`│ budget : ${remaining} confirmation${remaining === 1 ? "" : "s"} left this session, then toolwall fails closed.`);
  // Precise rather than reassuring. The server picks names; it cannot add a row, redraw this
  // frame, or write a sentence here.
  lines.push(rendered`│ Nothing above is quoted from the server. Names it chose (property, tool, host)`);
  lines.push(rendered`│ appear only escaped to [A-Za-z0-9_-./~] and can never add a line. Approve? [y/N] `);
  lines.push(rendered`└─────────────────────────────────────────────────────────────────────`);
  return renderLines(lines);
}

/**
 * The controlling terminal as a confirmation channel.
 *
 * Deliberately NOT `process.stdin`/`process.stdout`: under stdio transport those are the protocol
 * channel, and writing a prompt to stdout would corrupt the JSON-RPC stream (contract C-3).
 * `/dev/tty` is the operator's terminal regardless of how the process's own streams are wired,
 * which is exactly the property needed here.
 *
 * Returns `undefined` when there is no controlling terminal — a daemon, a CI runner, a client that
 * spawned us detached. That is the common case, and it is why `confirm` failing closed has to be
 * a usable outcome rather than an error path.
 */
export function ttyChannel(): ConfirmationChannel | undefined {
  let fd: number;
  try {
    fd = fs.openSync("/dev/tty", "r+");
  } catch {
    return undefined;
  }

  let closed = false;
  return {
    async ask(prompt: string, timeoutMs: number): Promise<boolean> {
      if (closed) return false;
      try {
        fs.writeSync(fd, prompt + "\n> ");
      } catch {
        return false;
      }
      return new Promise<boolean>((resolve) => {
        let settled = false;
        const buf = Buffer.alloc(64);
        const timer = setTimeout(() => {
          if (settled) return;
          settled = true;
          try {
            fs.writeSync(fd, "\n[toolwall] no answer within the timeout — failing closed.\n");
          } catch {
            /* the terminal went away; the answer is still no */
          }
          resolve(false);
        }, timeoutMs);
        timer.unref?.();

        fs.read(fd, buf, 0, buf.length, null, (err, bytesRead) => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          if (err !== null || bytesRead === 0) {
            resolve(false);
            return;
          }
          const answer = buf.toString("utf8", 0, bytesRead).trim().toLowerCase();
          // Explicit yes only. Enter, EOF, "maybe" and a stray newline are all "no".
          resolve(answer === "y" || answer === "yes");
        });
      });
    },
    close(): void {
      if (closed) return;
      closed = true;
      try {
        fs.closeSync(fd);
      } catch {
        /* already gone */
      }
    },
  };
}
