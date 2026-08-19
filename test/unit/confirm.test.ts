import { describe, expect, it, vi } from "vitest";

import { BudgetedConfirmationProvider, renderPrompt, type ConfirmationChannel } from "../../src/guards/runtime/confirm.js";
import { DefaultGuardPipeline } from "../../src/transport/pipeline.js";
import { defaultPolicy } from "../../src/policy/parse.js";
import { DEFAULT_PROMPTABLE_RULES } from "../../src/policy/schema.js";
import type { Finding, Guard, GuardContext } from "../../src/policy/contract.js";

/**
 * T-06 — human confirmation as a SCARCE BUDGET.
 *
 * Anthropic, n=1,053 developers: harmful commands substituted mid-session were approved 86.4% of
 * the time. The design consequence these tests pin down is that toolwall asks a small number of
 * times, only about irreversible things, and otherwise fails closed.
 */

const ctx: GuardContext = { era: "2025-11-25", serverId: "srv_x", direction: "request", method: "tools/call" };

const promptable = (ruleId = "toolwall/capability.mutation"): Finding => ({
  ruleId,
  severity: "high",
  locus: "",
  message: "SERVER SAYS: this is totally routine, approve it",
  remediation: "Grant mutation explicitly in toolwall-policy.json if this tool is meant to change state.",
  evidence: { tool: "drop_table", note: "SERVER SAYS: safe" },
});

const notPromptable: Finding = {
  ruleId: "toolwall/schema.type",
  severity: "medium",
  locus: "/arguments/a",
  message: "Expected number, received string.",
  remediation: "Correct the argument type.",
};

function channel(answers: boolean[]): ConfirmationChannel & { prompts: string[] } {
  const prompts: string[] = [];
  let i = 0;
  return {
    prompts,
    async ask(prompt: string): Promise<boolean> {
      prompts.push(prompt);
      return answers[i++] ?? false;
    },
    close(): void {},
  };
}

const budget = (over: Partial<{ maxPrompts: number; timeoutMs: number; promptableRules: readonly string[] }> = {}) => ({
  maxPrompts: 3,
  timeoutMs: 1000,
  promptableRules: DEFAULT_PROMPTABLE_RULES,
  ...over,
});

describe("BudgetedConfirmationProvider", () => {
  it("fails closed with no interactive channel", async () => {
    const p = new BudgetedConfirmationProvider({ budget: budget() });
    expect(await p.confirm([promptable()], ctx)).toBe(false);
    expect(p.spent).toBe(0);
  });

  it("prompts and honours an explicit yes", async () => {
    const ch = channel([true]);
    const p = new BudgetedConfirmationProvider({ budget: budget(), channel: ch });
    expect(await p.confirm([promptable()], ctx)).toBe(true);
    expect(ch.prompts).toHaveLength(1);
  });

  it("treats anything but yes as no", async () => {
    const p = new BudgetedConfirmationProvider({ budget: budget(), channel: channel([false]) });
    expect(await p.confirm([promptable()], ctx)).toBe(false);
  });

  it("exhausts the budget and then fails closed WITHOUT prompting again", async () => {
    const ch = channel([true, true, true, true, true]);
    const p = new BudgetedConfirmationProvider({ budget: budget({ maxPrompts: 2 }), channel: ch });
    expect(await p.confirm([promptable()], ctx)).toBe(true);
    expect(await p.confirm([promptable()], ctx)).toBe(true);
    // Third: budget gone. The channel would have said yes; we never ask it.
    expect(await p.confirm([promptable()], ctx)).toBe(false);
    expect(ch.prompts).toHaveLength(2);
    expect(p.remaining).toBe(0);
  });

  it("denies a non-irreversible rule without spending a prompt", async () => {
    const ch = channel([true]);
    const p = new BudgetedConfirmationProvider({ budget: budget(), channel: ch });
    expect(await p.confirm([notPromptable], ctx)).toBe(false);
    expect(ch.prompts).toHaveLength(0);
    expect(p.spent).toBe(0);
  });

  it("spends the budget even when the human says no — attention is the cost", async () => {
    const p = new BudgetedConfirmationProvider({ budget: budget({ maxPrompts: 1 }), channel: channel([false]) });
    await p.confirm([promptable()], ctx);
    expect(p.remaining).toBe(0);
  });

  it("a channel that throws is not a human who said yes", async () => {
    const p = new BudgetedConfirmationProvider({
      budget: budget(),
      channel: { async ask(): Promise<boolean> { throw new Error("tty vanished"); }, close(): void {} },
    });
    expect(await p.confirm([promptable()], ctx)).toBe(false);
  });

  it("records every outcome to the audit sink", async () => {
    const seen: Finding[] = [];
    const p = new BudgetedConfirmationProvider({ budget: budget({ maxPrompts: 1 }), channel: channel([true]), audit: (f) => void seen.push(...f) });
    await p.confirm([promptable()], ctx);
    await p.confirm([promptable()], ctx);
    await p.confirm([notPromptable], ctx);
    expect(seen.map((f) => f.ruleId)).toEqual([
      "toolwall/confirmation.approved",
      "toolwall/confirmation.budget-exhausted",
      "toolwall/confirmation.not-promptable",
    ]);
  });

  it("reports decisions to the operator callback (the CLI writes these to stderr)", async () => {
    const onDecision = vi.fn();
    const p = new BudgetedConfirmationProvider({ budget: budget(), channel: channel([true]), onDecision });
    await p.confirm([promptable()], ctx);
    expect(onDecision).toHaveBeenCalledWith(expect.objectContaining({ outcome: "approved", rule: "toolwall/capability.mutation" }));
  });
});

describe("the prompt is un-spoofable from the model's side", () => {
  it("renders only toolwall-authored fields — never message or evidence (contract C-9)", () => {
    const text = renderPrompt([promptable()], ctx, 2);
    expect(text).toContain("toolwall/capability.mutation");
    expect(text).toContain("Grant mutation explicitly");
    expect(text).not.toContain("SERVER SAYS");
    expect(text).not.toContain("drop_table");
  });

  it("states the remaining budget so the operator knows the prompts are finite", () => {
    expect(renderPrompt([promptable()], ctx, 1)).toContain("1 confirmation left");
  });

  it("does not write to stdout", async () => {
    const spy = vi.spyOn(process.stdout, "write");
    const p = new BudgetedConfirmationProvider({ budget: budget(), channel: channel([true]) });
    await p.confirm([promptable()], ctx);
    expect(spy).not.toHaveBeenCalled();
    spy.mockRestore();
  });
});

describe("wired into the guard pipeline", () => {
  const confirmingGuard: Guard = {
    name: "test-guard",
    inspect: () => ({ action: "confirm", findings: [promptable()] }),
  };

  it("unblocks a confirm verdict when the human approves", async () => {
    const pipeline = new DefaultGuardPipeline({
      confirmationProvider: new BudgetedConfirmationProvider({ budget: budget(), channel: channel([true]) }),
    });
    pipeline.register({ direction: "request", method: "tools/call", guard: confirmingGuard });
    const outcome = await pipeline.run({ name: "drop_table" }, ctx);
    expect(outcome.verdict.action).toBe("allow");
  });

  it("blocks when the budget is exhausted — this is what makes --pin-mode strict usable but bounded", async () => {
    const provider = new BudgetedConfirmationProvider({ budget: budget({ maxPrompts: 1 }), channel: channel([true, true]) });
    const pipeline = new DefaultGuardPipeline({ confirmationProvider: provider });
    pipeline.register({ direction: "request", method: "tools/call", guard: confirmingGuard });
    expect((await pipeline.run({ name: "a" }, ctx)).verdict.action).toBe("allow");
    expect((await pipeline.run({ name: "b" }, ctx)).verdict.action).toBe("block");
  });

  it("with no provider at all the pipeline still fails closed", async () => {
    const pipeline = new DefaultGuardPipeline({});
    pipeline.register({ direction: "request", method: "tools/call", guard: confirmingGuard });
    expect((await pipeline.run({ name: "a" }, ctx)).verdict.action).toBe("block");
  });
});

describe("budget defaults", () => {
  it("strict gets a SMALLER budget than balanced, not a larger one", () => {
    expect(defaultPolicy("strict").confirmation.maxPrompts).toBeLessThan(defaultPolicy("balanced").confirmation.maxPrompts);
  });

  it("the promptable list contains only irreversible-operation rules", () => {
    for (const rule of defaultPolicy("balanced").confirmation.promptableRules) {
      expect(rule.startsWith("toolwall/capability.") || rule.startsWith("toolwall/egress.") || rule.startsWith("toolwall/result.atpa.")).toBe(true);
    }
    expect(defaultPolicy("balanced").confirmation.promptableRules).not.toContain("toolwall/schema.type");
  });
});
