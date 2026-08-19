import type { Finding, ToolAnnotations, ToolDefinition } from "./contract.js";
import type { CapabilityGrant } from "./schema.js";

/**
 * `ToolAnnotations` handling.
 *
 * The spec's own schema doc comment: *"Clients should never make tool use decisions based on
 * ToolAnnotations received from untrusted servers."* Annotations are server-supplied, therefore
 * attacker-supplied, therefore an **input signal and never an authorization**.
 *
 * Concretely, in this codebase:
 *  - No annotation can grant a capability, widen a root, raise a bound, or admit a host.
 *  - No annotation can move a verdict from `block` to `allow`.
 *  - `readOnlyHint: true` can only ever reduce friction (confirm -> allow), and only at tiers where
 *    `trustAnnotations` is `"as-signal"`. At `strict` it is ignored outright.
 *  - Whenever a hint did influence anything, an `info` finding says so by name, so the audit record
 *    shows that the decision rested on untrusted server input.
 *
 * ## The defaults are the security-critical part
 *
 * RESEARCH-BRIEF §1.4: an **unannotated tool is `destructiveHint: true` and `openWorldHint: true`.**
 * Absence of annotations is not a claim of safety; it is the most dangerous configuration. A great
 * many real servers ship no annotations at all, which is why we measure what that posture costs on
 * the benign corpus rather than assuming it is free.
 */
export interface ResolvedAnnotations {
  readonly readOnly: boolean;
  readonly destructive: boolean;
  readonly idempotent: boolean;
  readonly openWorld: boolean;
  /** Whether the server supplied an annotations object at all. */
  readonly annotated: boolean;
  /** Per-field provenance, so the audit record can distinguish a claim from a default. */
  readonly claimed: {
    readonly readOnly: boolean;
    readonly destructive: boolean;
    readonly idempotent: boolean;
    readonly openWorld: boolean;
  };
}

const SPEC_DEFAULTS = {
  readOnlyHint: false,
  destructiveHint: true,
  idempotentHint: false,
  openWorldHint: true,
} as const;

export function resolveAnnotations(a: ToolAnnotations | undefined): ResolvedAnnotations {
  const has = (v: unknown): v is boolean => typeof v === "boolean";
  return {
    readOnly: has(a?.readOnlyHint) ? a.readOnlyHint : SPEC_DEFAULTS.readOnlyHint,
    destructive: has(a?.destructiveHint) ? a.destructiveHint : SPEC_DEFAULTS.destructiveHint,
    idempotent: has(a?.idempotentHint) ? a.idempotentHint : SPEC_DEFAULTS.idempotentHint,
    openWorld: has(a?.openWorldHint) ? a.openWorldHint : SPEC_DEFAULTS.openWorldHint,
    annotated: a !== undefined && Object.keys(a).length > 0,
    claimed: {
      readOnly: has(a?.readOnlyHint),
      destructive: has(a?.destructiveHint),
      idempotent: has(a?.idempotentHint),
      openWorld: has(a?.openWorldHint),
    },
  };
}

export interface MutationAssessment {
  readonly mutating: boolean;
  /** How the decision was reached. Goes verbatim into the audit record. */
  readonly basis: "policy" | "server-hint" | "spec-default";
  readonly findings: readonly Finding[];
}

/**
 * Decide whether a call should be treated as mutating.
 *
 * Precedence, highest first:
 *  1. `grant.mutates` — the operator's own statement. Authoritative; annotations are not consulted.
 *  2. `readOnlyHint === true`, but only when `grant.trustAnnotations === "as-signal"`. Emits an
 *     `info` finding naming the untrusted source.
 *  3. Spec default: mutating. Absence of information is treated as the dangerous case.
 */
export function assessMutation(tool: ToolDefinition, grant: CapabilityGrant): MutationAssessment {
  if (grant.mutates !== undefined) {
    return { mutating: grant.mutates, basis: "policy", findings: [] };
  }

  const resolved = resolveAnnotations(tool.annotations);

  if (grant.trustAnnotations === "as-signal" && resolved.claimed.readOnly && resolved.readOnly) {
    return {
      mutating: false,
      basis: "server-hint",
      findings: [
        {
          ruleId: "toolwall/annotation.readonly-hint-honoured",
          severity: "info",
          locus: "",
          message:
            "Treated as non-mutating because the server claimed readOnlyHint: true. That claim is server-supplied and unverified.",
          remediation: `Pin this decision locally: set tools["${tool.name}"].mutates = false in toolwall-policy.json, or raise the tier to "strict" where server hints are ignored.`,
          evidence: { tool: tool.name, basis: "server-hint", annotated: resolved.annotated },
        },
      ],
    };
  }

  const findings: Finding[] = [];
  if (!resolved.annotated) {
    findings.push({
      ruleId: "toolwall/annotation.absent",
      severity: "info",
      locus: "",
      message:
        "Tool declares no annotations. Per spec defaults that means destructiveHint: true and openWorldHint: true; it is treated as mutating and open-world.",
      remediation: `If this tool is read-only, record that locally: tools["${tool.name}"].mutates = false.`,
      evidence: { tool: tool.name, basis: "spec-default" },
    });
  } else if (resolved.claimed.readOnly && resolved.readOnly && grant.trustAnnotations === "never") {
    findings.push({
      ruleId: "toolwall/annotation.readonly-hint-ignored",
      severity: "info",
      locus: "",
      message: "Server claimed readOnlyHint: true; ignored because trustAnnotations is \"never\" at this tier.",
      remediation: `If the claim is true, assert it locally: tools["${tool.name}"].mutates = false.`,
      evidence: { tool: tool.name, basis: "spec-default" },
    });
  }

  return { mutating: true, basis: resolved.annotated ? "spec-default" : "spec-default", findings };
}
