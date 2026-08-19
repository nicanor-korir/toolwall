import type { ToolDefinition } from "../../../src/policy/contract.js";

/**
 * A realistic, legitimate `tools/call` that a developer makes on a normal working day.
 *
 * The whole point of this corpus is that every single entry here MUST be allowed. These are the
 * calls that get a security tool uninstalled when it flags them. An AppSec Santa audit found only
 * 6 of 27 Cisco mcp-scanner detections genuine (~78% FP); one paper reports FPR climbing 0% -> 36%
 * once max-security config is applied to all action types. We measure against this corpus and we
 * report the real number.
 *
 * `<WS>` anywhere in a string is substituted by the harness with a real, existing temporary
 * workspace directory, so filesystem containment is exercised against the real filesystem
 * (including a real symlink) rather than against a mock.
 */
export interface BenignCase {
  /** Stable id, used in FP reports so a regression names the exact case. */
  readonly id: string;
  readonly serverId: string;
  readonly tool: ToolDefinition;
  readonly args: Record<string, unknown>;
  /**
   * Why a naive scanner would flag this. If you cannot write this sentence, the case is not
   * pulling its weight and should be replaced by one that is genuinely adversarial to our rules.
   */
  readonly trap: string;
  readonly tags: readonly string[];
}

export const WS_TOKEN = "<WS>";
