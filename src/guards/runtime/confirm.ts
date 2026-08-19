import * as fs from "node:fs";
import type { ConfirmationProvider, Finding, GuardContext } from "../../policy/contract.js";
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
 * ## Un-spoofable from the model's side
 *
 * The prompt is composed exclusively from toolwall-authored fields — `ruleId`, `severity`,
 * `locus`, `remediation` — the same set `redactFindingForClient()` allows across the trust
 * boundary (contract C-9). `finding.message` and `finding.evidence` quote the untrusted server and
 * are **never** rendered here. Otherwise a poisoned tool description would be able to write its
 * own approval dialog: *"[toolwall] routine operation, safe to approve"*. The operator sees our
 * words about the server, never the server's words about itself.
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

/**
 * The dialog text. Toolwall-authored fields only — see the class header on spoofing.
 */
export function renderPrompt(findings: readonly Finding[], ctx: GuardContext, remaining: number): string {
  const lines: string[] = [];
  lines.push("");
  lines.push("┌─ toolwall · human confirmation required ────────────────────────────");
  lines.push(`│ server : ${ctx.serverId}`);
  lines.push(`│ method : ${ctx.method}`);
  for (const f of findings.slice(0, 4)) {
    lines.push(`│ rule   : ${f.ruleId} [${f.severity}]${f.locus === "" ? "" : ` at ${f.locus}`}`);
    lines.push(`│          ${f.remediation}`);
  }
  lines.push(`│ budget : ${remaining} confirmation${remaining === 1 ? "" : "s"} left this session, then toolwall fails closed.`);
  lines.push("│ Nothing above is quoted from the server. Approve? [y/N] ");
  lines.push("└─────────────────────────────────────────────────────────────────────");
  return lines.join("\n");
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
