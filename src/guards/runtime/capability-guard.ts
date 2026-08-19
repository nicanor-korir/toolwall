import * as path from "node:path";
import {
  TOOLWALL_BLOCKED,
  type AuditSink,
  type Finding,
  type Guard,
  type GuardContext,
  type ToolDefinition,
  type ToolDefinitionSource,
  type Verdict,
} from "../../policy/contract.js";
import type { ResolvedPolicy } from "../../policy/parse.js";
import type { ArgumentBounds, CapabilityGrant, FilesystemGrant } from "../../policy/schema.js";
import { canonicalizePath, contains, defaultCaseInsensitive, nodeFsProbe, type FsProbe } from "../../policy/containment.js";
import { evaluateUrl } from "../../policy/hosts.js";
import { collectRoleTargets, hasAnyRole, type Role, type RoleTarget } from "../../policy/roles.js";
import { assessMutation } from "../../policy/annotations.js";
import { extractToolCall } from "./schema-guard.js";

/**
 * Capability enforcement for `tools/call` — "what is this tool allowed to touch".
 *
 * Checks, in order:
 *  1. **Unknown tool** — no policy entry at all. Tier decides allow / confirm / block.
 *  2. **Argument bounds** — structural size, depth and cardinality. Cheap, deterministic, and the
 *     mitigation for the T-08 oversized/deeply-nested payload class against the proxy itself.
 *  3. **Filesystem containment** — canonical, symlink-resolved, segment-wise. CVE-2025-53110 and
 *     CVE-2025-53109 live here; see `src/policy/containment.ts` for the mechanism.
 *  4. **Egress** — host and scheme allowlist on URL-role arguments.
 *  5. **Mutation** — whether this tool may change state at all, using `ToolAnnotations` strictly as
 *     an input signal and never as authorization.
 *
 * What it deliberately does NOT do: look at any argument that has no bound capability role. A
 * `content` field carrying shell script, a `sql` field carrying semicolons and a commit message
 * carrying `../` are all invisible to this guard, by design. That is the whole reason its measured
 * false-positive rate on the benign corpus is what it is.
 */

export interface CapabilityGuardOptions {
  readonly policy: ResolvedPolicy;
  /** Optional; used only to derive `url` roles from the tool's own `format: "uri"` declarations. */
  readonly tools?: ToolDefinitionSource;
  /** Base directory for resolving relative path arguments. */
  readonly baseDir?: string;
  readonly probe?: FsProbe;
  readonly caseInsensitive?: boolean;
  /**
   * Where non-blocking findings go. Dev 1's `{ action: "allow" }` carries no findings, so the
   * record that (say) a symlink was traversed but stayed in-root would otherwise be lost.
   */
  readonly audit?: AuditSink;
}

type Disposition = "allow" | "confirm" | "block";

const RANK: Record<Disposition, number> = { allow: 0, confirm: 1, block: 2 };

export class CapabilityGuard implements Guard {
  readonly name = "capability-guard";
  readonly #policy: ResolvedPolicy;
  readonly #tools: ToolDefinitionSource | undefined;
  readonly #baseDir: string;
  readonly #probe: FsProbe;
  readonly #caseInsensitive: boolean;
  readonly #audit: AuditSink | undefined;

  constructor(opts: CapabilityGuardOptions) {
    this.#policy = opts.policy;
    this.#tools = opts.tools;
    this.#baseDir = opts.baseDir ?? process.cwd();
    this.#probe = opts.probe ?? nodeFsProbe;
    this.#caseInsensitive = opts.caseInsensitive ?? defaultCaseInsensitive();
    this.#audit = opts.audit;
  }

  inspect(payload: unknown, ctx: GuardContext): Verdict {
    if (ctx.direction !== "request" || ctx.method !== "tools/call") return { action: "allow" };

    const params = extractToolCall(payload);
    if (params === undefined) return { action: "allow" };

    const { grant, known } = this.#policy.grantFor(ctx.serverId, params.name);
    const tool = this.#tools?.get(ctx.serverId, params.name);
    const findings: Finding[] = [];
    // Collected rather than folded into a mutable `let`, because TypeScript's control-flow
    // analysis cannot see writes made through the closure and would narrow the result to "allow".
    const dispositions: Disposition[] = [];
    const raise = (d: Disposition): void => {
      dispositions.push(d);
    };

    // 1. Unknown tool ------------------------------------------------
    if (!known && grant.unknownTool !== "allow") {
      findings.push({
        ruleId: "toolwall/capability.unknown-tool",
        severity: grant.unknownTool === "block" ? "high" : "medium",
        locus: "/name",
        message: `No policy entry exists for this tool on server "${ctx.serverId}".`,
        remediation: `Add servers["${ctx.serverId}"].tools["${params.name}"] to toolwall-policy.json declaring what it may touch, or lower the tier.`,
        evidence: { tool: params.name, serverId: ctx.serverId },
      });
      raise(grant.unknownTool);
    }

    // 2. Argument bounds ---------------------------------------------
    const shape = measure(params.arguments ?? {});
    for (const f of boundsFindings(shape, grant.bounds, params.name)) {
      findings.push(f);
      raise("block");
    }

    // 3/4. Capability roles ------------------------------------------
    const targets = collectRoleTargets(params.arguments ?? {}, grant.roles, tool);
    const usesFs = targets.some((t) => t.role === "readPath" || t.role === "writePath");
    const usesNet = targets.some((t) => t.role === "url");

    if (usesFs) {
      if (grant.filesystem === undefined) {
        raise(this.#undeclared(findings, params.name, "filesystem", grant, ctx));
      } else {
        for (const t of targets) {
          if (t.role !== "readPath" && t.role !== "writePath") continue;
          const d = this.#checkPath(t, grant.filesystem, params.name, findings);
          raise(d);
        }
      }
    }

    if (usesNet) {
      if (grant.network === undefined) {
        raise(this.#undeclared(findings, params.name, "network", grant, ctx));
      } else {
        for (const t of targets) {
          if (t.role !== "url") continue;
          const decision = evaluateUrl(t.value, grant.network);
          if (decision.ok) {
            for (const note of decision.notes) {
              findings.push({
                ruleId: `toolwall/egress.${note}`,
                severity: "info",
                locus: `/arguments${t.pointer}`,
                message: `URL carries embedded credentials; host was matched as "${decision.hostname}", not as the userinfo portion.`,
                remediation: "No action required. Recorded because this is the shape of the https://trusted@attacker.tld confusion.",
                evidence: { tool: params.name, hostname: decision.hostname },
              });
            }
            continue;
          }
          findings.push({
            ruleId: `toolwall/egress.${decision.reason}`,
            severity: "high",
            locus: `/arguments${t.pointer}`,
            message: describeEgress(decision.reason, decision.detail),
            remediation: egressRemediation(decision.reason, decision.detail, ctx.serverId, params.name),
            evidence: { tool: params.name, reason: decision.reason, detail: decision.detail },
          });
          raise("block");
        }
      }
    }

    // A declared capability that no argument role points at cannot be enforced. Say so.
    if (grant.filesystem !== undefined && !hasAnyRole(grant.roles, tool)) {
      const unenforceable: Disposition = this.#policy.tier === "strict" ? "block" : "allow";
      findings.push({
        ruleId: "toolwall/capability.no-roles-bound",
        severity: unenforceable === "block" ? "high" : "low",
        locus: "/arguments",
        message:
          "A filesystem capability is declared for this tool but no argument is bound to a path role, so containment could not be enforced on anything.",
        remediation: `Set servers["${ctx.serverId}"].tools["${params.name}"].roles.readPath / .writePath to JSON Pointer selectors, e.g. ["/path"] or ["/paths/*"].`,
        evidence: { tool: params.name },
      });
      raise(unenforceable);
    }

    // 5. Mutation ----------------------------------------------------
    const mutation = assessMutation(tool ?? { name: params.name, inputSchema: { type: "object" } }, grant);
    findings.push(...mutation.findings);
    if (mutation.mutating && grant.mutation !== "allow") {
      findings.push({
        ruleId: "toolwall/capability.mutation",
        severity: grant.mutation === "deny" ? "high" : "medium",
        locus: "",
        message: `This call is treated as state-changing (basis: ${mutation.basis}) and the policy sets mutation = "${grant.mutation}".`,
        remediation:
          grant.mutation === "deny"
            ? `Grant mutation for this tool explicitly: servers["${ctx.serverId}"].tools["${params.name}"].mutation = "allow".`
            : "A human must approve this call. Interactive confirmation lands in Week 2; until then this verdict is advisory to the caller.",
        evidence: { tool: params.name, basis: mutation.basis },
      });
      raise(grant.mutation === "deny" ? "block" : "confirm");
    }

    const worst = dispositions.reduce<Disposition>((a, b) => (RANK[b] > RANK[a] ? b : a), "allow");
    // TOOLWALL_BLOCKED (-32600) rather than "invalid params": the params here are well-formed, they
    // are simply not permitted. Neither code falls in the spec-reserved -32099..-32020 range.
    if (worst === "block") return { action: "block", code: TOOLWALL_BLOCKED, findings };
    if (worst === "confirm") return { action: "confirm", findings };
    if (findings.length > 0) this.#audit?.(findings, ctx);
    return { action: "allow" };
  }

  #undeclared(findings: Finding[], toolName: string, capability: "filesystem" | "network", grant: CapabilityGrant, ctx: GuardContext): Disposition {
    const d: Disposition = grant.undeclaredCapability === "deny" ? "block" : grant.undeclaredCapability === "confirm" ? "confirm" : "allow";
    findings.push({
      ruleId: `toolwall/capability.undeclared.${capability}`,
      severity: d === "block" ? "high" : d === "confirm" ? "medium" : "info",
      locus: "/arguments",
      message: `The call exercises the ${capability} capability, which the policy has not declared for this tool.`,
      remediation: `Declare it: servers["${ctx.serverId}"].tools["${toolName}"].${capability} = { ... }. At tiers "permissive"/"balanced" an undeclared capability is not enforced, which is why a fresh install does not block your first call — see the tier table in src/policy/schema.ts.`,
      evidence: { tool: toolName, tier: this.#policy.tier, disposition: d },
    });
    return d;
  }

  #checkPath(t: RoleTarget, fsGrant: FilesystemGrant, toolName: string, findings: Finding[]): Disposition {
    const roots = t.role === "writePath" ? fsGrant.write : [...fsGrant.read, ...fsGrant.write];

    if (typeof t.value !== "string") {
      findings.push({
        ruleId: "toolwall/capability.fs.not-a-path",
        severity: "medium",
        locus: `/arguments${t.pointer}`,
        message: `Policy binds this argument to a ${t.role} role but the value is ${t.value === null ? "null" : typeof t.value}, not a string.`,
        remediation: "Fix the role selector in toolwall-policy.json, or the caller's arguments.",
        evidence: { tool: toolName, role: t.role },
      });
      return "block";
    }

    const c = canonicalizePath(t.value, { base: this.#baseDir, probe: this.#probe });
    if (!c.ok) {
      findings.push({
        ruleId: `toolwall/capability.fs.${c.reason}`,
        severity: "high",
        locus: `/arguments${t.pointer}`,
        message: `Path argument could not be canonicalized (${c.reason}).`,
        remediation: "Reject and investigate. A path that cannot be canonicalized cannot be shown to be contained.",
        evidence: { tool: toolName, reason: c.reason },
      });
      return "block";
    }

    if (!c.existed && !fsGrant.allowNonexistent) {
      findings.push({
        ruleId: "toolwall/capability.fs.nonexistent",
        severity: "medium",
        locus: `/arguments${t.pointer}`,
        message: "Path does not exist and the grant sets allowNonexistent: false.",
        remediation: "Set filesystem.allowNonexistent = true if this tool legitimately creates files.",
        evidence: { tool: toolName },
      });
      return "block";
    }

    for (const denied of fsGrant.deny) {
      if (contains(denied, c.path, this.#caseInsensitive)) {
        findings.push({
          ruleId: "toolwall/capability.fs.denied-root",
          severity: "high",
          locus: `/arguments${t.pointer}`,
          message: "Path canonicalizes into a root the policy explicitly denies.",
          remediation: "The deny list wins over the allow list by design. Remove the entry from filesystem.deny if this access is intended.",
          evidence: { tool: toolName, deniedRoot: denied, canonical: c.path },
        });
        return "block";
      }
    }

    const inRoot = roots.some((r) => contains(r, c.path, this.#caseInsensitive));
    if (!inRoot) {
      findings.push({
        ruleId: "toolwall/capability.fs.escape",
        severity: "critical",
        locus: `/arguments${t.pointer}`,
        message:
          `Path canonicalizes to ${c.path}, which is not inside any granted ${t.role === "writePath" ? "write" : "read"} root.` +
          (c.traversedSymlink ? " A symlink was traversed during resolution (CVE-2025-53109 shape)." : ""),
        remediation: `If this access is intended, add the containing directory to servers[...].tools["${toolName}"].filesystem.${t.role === "writePath" ? "write" : "read"}. Note that roots are compared segment-wise, so "/tmp/allow_dir" does not admit "/tmp/allow_dir_sensitive_credentials" (CVE-2025-53110).`,
        evidence: { tool: toolName, canonical: c.path, traversedSymlink: c.traversedSymlink, roots: roots.length },
      });
      return "block";
    }

    if (c.traversedSymlink) {
      findings.push({
        ruleId: "toolwall/capability.fs.symlink-in-root",
        severity: "info",
        locus: `/arguments${t.pointer}`,
        message: "A symlink was traversed; its target resolves inside a granted root, so the access is permitted.",
        remediation: "No action required. Recorded because symlink resolution is the CVE-2025-53109 control point.",
        evidence: { tool: toolName, canonical: c.path },
      });
    }

    return "allow";
  }
}

/* ---------------------------------------------------------------- */
/* Argument shape measurement                                         */
/* ---------------------------------------------------------------- */

export interface ArgumentShape {
  readonly totalBytes: number;
  readonly maxStringLength: number;
  readonly maxArrayItems: number;
  readonly maxObjectProperties: number;
  readonly maxDepth: number;
  readonly nodes: number;
}

/** Single traversal; no serialization. Bounded so measurement itself cannot be weaponized. */
export function measure(value: unknown, nodeCap = 200_000): ArgumentShape {
  let totalBytes = 0;
  let maxStringLength = 0;
  let maxArrayItems = 0;
  let maxObjectProperties = 0;
  let maxDepth = 0;
  let nodes = 0;

  const stack: Array<{ v: unknown; d: number }> = [{ v: value, d: 0 }];
  while (stack.length > 0) {
    const frame = stack.pop();
    if (frame === undefined) break;
    if (++nodes > nodeCap) break;
    if (frame.d > maxDepth) maxDepth = frame.d;

    const v = frame.v;
    if (typeof v === "string") {
      if (v.length > maxStringLength) maxStringLength = v.length;
      totalBytes += Buffer.byteLength(v, "utf8");
    } else if (typeof v === "number" || typeof v === "boolean" || v === null) {
      totalBytes += 8;
    } else if (Array.isArray(v)) {
      if (v.length > maxArrayItems) maxArrayItems = v.length;
      totalBytes += 2 + v.length;
      for (const item of v) stack.push({ v: item, d: frame.d + 1 });
    } else if (typeof v === "object") {
      const keys = Object.keys(v as object);
      if (keys.length > maxObjectProperties) maxObjectProperties = keys.length;
      totalBytes += 2 + keys.length * 4;
      for (const k of keys) {
        totalBytes += Buffer.byteLength(k, "utf8");
        stack.push({ v: (v as Record<string, unknown>)[k], d: frame.d + 1 });
      }
    }
  }

  return { totalBytes, maxStringLength, maxArrayItems, maxObjectProperties, maxDepth, nodes };
}

function boundsFindings(shape: ArgumentShape, bounds: ArgumentBounds, toolName: string): Finding[] {
  const out: Finding[] = [];
  const check = (actual: number, limit: number, rule: string, what: string, fix: string): void => {
    if (actual <= limit) return;
    out.push({
      ruleId: `toolwall/bounds.${rule}`,
      severity: "medium",
      locus: "/arguments",
      message: `${what}: ${actual} exceeds the configured limit of ${limit}.`,
      remediation: fix,
      evidence: { tool: toolName, actual, limit },
    });
  };
  check(shape.totalBytes, bounds.maxTotalBytes, "totalBytes", "Total argument size", "Split the call, or raise bounds.maxTotalBytes for this tool.");
  check(shape.maxStringLength, bounds.maxStringLength, "stringLength", "Longest string argument", "Split the call, or raise bounds.maxStringLength for this tool.");
  check(shape.maxArrayItems, bounds.maxArrayItems, "arrayItems", "Largest array argument", "Batch the call, or raise bounds.maxArrayItems for this tool.");
  check(shape.maxObjectProperties, bounds.maxObjectProperties, "objectProperties", "Widest object argument", "Raise bounds.maxObjectProperties for this tool if this shape is legitimate.");
  check(shape.maxDepth, bounds.maxDepth, "depth", "Argument nesting depth", "Raise bounds.maxDepth for this tool if this shape is legitimate. Deep nesting is also a proxy-DoS vector (T-08).");
  return out;
}

/* ---------------------------------------------------------------- */

function describeEgress(reason: string, detail: string): string {
  switch (reason) {
    case "unparseable":
      return `URL argument is not a parseable absolute URL (${detail}).`;
    case "scheme-not-granted":
      return `Scheme "${detail}" is not in the granted scheme list.`;
    case "host-not-granted":
      return `Host "${detail}" is not in the granted host allowlist.`;
    case "ip-literal":
      return `Host "${detail}" is a bare IP literal and the grant sets allowIpLiterals: false.`;
    case "private-network":
      return `Host "${detail}" is a private/loopback/link-local address reached via a wildcard grant.`;
    default:
      return `Egress denied (${reason}: ${detail}).`;
  }
}

function egressRemediation(reason: string, detail: string, serverId: string, toolName: string): string {
  const at = `servers["${serverId}"].tools["${toolName}"].network`;
  switch (reason) {
    case "scheme-not-granted":
      return `Add "${detail}" to ${at}.schemes if this scheme is intended.`;
    case "host-not-granted":
      return `Add "${detail}" (or "*.${detail.split(".").slice(-2).join(".")}") to ${at}.hosts if this destination is intended. Only exact hosts and "*.suffix" wildcards are supported — substring matching is not, because it is how host allowlists get bypassed.`;
    case "ip-literal":
      return `Set ${at}.allowIpLiterals = true, or add "${detail}" to ${at}.hosts as an exact entry — an exact entry is an explicit grant and always wins.`;
    case "private-network":
      return `Add "${detail}" to ${at}.hosts as an exact entry (explicit grants always win), or set ${at}.allowPrivateNetwork = true. Note: no DNS resolution is performed, so a public hostname that resolves to a private address is NOT caught by this rule.`;
    default:
      return `Review ${at}.`;
  }
}

/** Convenience for callers assembling a `baseDir` without importing node:path themselves. */
export const resolveBaseDir = (p: string): string => path.resolve(p);
export type { Role };
