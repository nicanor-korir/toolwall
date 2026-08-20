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
import { dedupeTargets, evaluateEgressTarget, scanForUrls, type EgressTarget } from "../../policy/egress.js";
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
 *  4. **Egress** — two intersected allowlists on URL- and host-role arguments: the per-server
 *     `egress` block (deny-by-default once declared, an upper bound on every tool) and the per-tool
 *     `network` grant (narrows further, never widens). In `enforce: "scan"` mode the server-level
 *     layer additionally reads absolute URLs out of every string argument. Note the honest scope:
 *     this constrains where the MODEL can direct a call, not what a compromised server opens on
 *     its own sockets — see `src/policy/egress.ts`.
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

    const egress = this.#policy.egressFor(ctx.serverId);
    const serverEgressActive = egress.declared && egress.enforce !== "off";
    const egressTargets = dedupeTargets([
      ...targets
        .filter((t) => t.role === "url" || t.role === "host")
        .map((t): EgressTarget => ({ pointer: t.pointer, value: t.value, kind: t.role === "host" ? "host" : "url", discovery: "role" })),
      // `scan` reaches into arguments no role covers. Only reachable when the operator declared an
      // egress block AND asked for it; see EgressPolicy for the measured cost of that choice.
      ...(serverEgressActive && egress.enforce === "scan" ? scanForUrls(params.arguments ?? {}) : []),
    ]);
    const usesNet = egressTargets.length > 0;

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
      // Two allowlists, intersected: the per-server `egress` block (deny-by-default once declared,
      // an upper bound on every tool) and the per-tool `network` grant (narrows further). Scanned
      // targets exist only in `enforce: "scan"`, which requires a declared block, so they can never
      // route into the "undeclared capability" branch below.
      if (!serverEgressActive && grant.network === undefined) {
        raise(this.#undeclared(findings, params.name, "network", grant, ctx));
      } else {
        for (const t of egressTargets) {
          const outcome = evaluateEgressTarget(t, serverEgressActive ? egress : undefined, grant.network);
          const decision = outcome.decision;
          if (decision.ok) {
            for (const note of decision.notes) {
              findings.push({
                ruleId: `toolwall/egress.${note}`,
                severity: "info",
                locus: `/arguments${t.pointer}`,
                message:
                  note === "exact-grant-admits-denied-destination"
                    ? `Host "${decision.hostname}" is a cloud metadata / link-local destination that the default deny list covers, and it was permitted because the operator listed it as an exact host entry.`
                    : `URL carries embedded credentials; host was matched as "${decision.hostname}", not as the userinfo portion.`,
                remediation:
                  note === "exact-grant-admits-denied-destination"
                    ? "No action required if that grant is deliberate. Recorded every time, because an explicit grant is the only way past this deny list and the audit trail must show who opened it."
                    : "No action required. Recorded because this is the shape of the https://trusted@attacker.tld confusion.",
                evidence: { tool: params.name, hostname: decision.hostname },
              });
            }
            continue;
          }
          const d: Disposition =
            outcome.layer === "server" ? (egress.onViolation === "allow" ? "allow" : egress.onViolation) : "block";
          findings.push({
            ruleId: outcome.layer === "server" ? "toolwall/egress.server-allowlist" : `toolwall/egress.${decision.reason}`,
            severity: d === "allow" ? "low" : "high",
            locus: `/arguments${t.pointer}`,
            message:
              describeEgress(decision.reason, decision.detail) +
              (outcome.layer === "server" ? ` Denied by the server-level egress allowlist for "${ctx.serverId}".` : "") +
              (t.discovery === "scan" ? " The destination was found by scanning argument text, not in an argument bound to a URL role." : ""),
            remediation: egressRemediation(decision.reason, decision.detail, ctx.serverId, params.name, outcome.layer),
            evidence: {
              tool: params.name,
              reason: decision.reason,
              detail: decision.detail,
              layer: outcome.layer ?? "none",
              discovery: t.discovery,
              kind: t.kind,
            },
          });
          raise(d);
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

/** {@link ArgumentShape} plus the `__proto__` verdict, from the same single traversal. */
export interface ScannedShape extends ArgumentShape {
  /**
   * `__proto__` appeared as an object key somewhere in the payload.
   *
   * `false` when `scanProto` was not requested, and `false` rather than "unknown" when the node cap
   * cut the walk short — the same fail-open bound the standalone `hasProtoKey` has always had, at
   * four times the budget because it now shares `measure`'s 200k cap instead of its own 50k one.
   */
  readonly protoKey: boolean;
}

const hasOwn = Object.prototype.hasOwnProperty;

/**
 * The one traversal.
 *
 * Two parallel stacks rather than a stack of `{v, d}` frames: on a 64 KiB result that is one fewer
 * heap allocation per node, and the node count is exactly the number of values a payload contains.
 * Bounded, so measurement itself cannot be weaponized (T-08).
 *
 * `scanProto` costs one `hasOwnProperty` call per object — O(1), not a second pass, and not a
 * second `Object.getOwnPropertyNames` allocation. It is deliberately the same test the standalone
 * `hasProtoKey` performs: a `__proto__` that a JSON parser stored as a real own property. An
 * inherited accessor is not an own property and does not match, which is the point.
 */
function walk(value: unknown, nodeCap: number, scanProto: boolean): ScannedShape {
  let totalBytes = 0;
  let maxStringLength = 0;
  let maxArrayItems = 0;
  let maxObjectProperties = 0;
  let maxDepth = 0;
  let nodes = 0;
  let protoKey = false;

  const values: unknown[] = [value];
  const depths: number[] = [0];
  while (values.length > 0) {
    const v = values.pop();
    const d = depths.pop() as number;
    if (++nodes > nodeCap) break;
    if (d > maxDepth) maxDepth = d;

    if (typeof v === "string") {
      if (v.length > maxStringLength) maxStringLength = v.length;
      totalBytes += Buffer.byteLength(v, "utf8");
    } else if (typeof v === "number" || typeof v === "boolean" || v === null) {
      totalBytes += 8;
    } else if (Array.isArray(v)) {
      if (v.length > maxArrayItems) maxArrayItems = v.length;
      totalBytes += 2 + v.length;
      for (const item of v) {
        values.push(item);
        depths.push(d + 1);
      }
    } else if (typeof v === "object" && v !== null) {
      if (scanProto && !protoKey && hasOwn.call(v, "__proto__")) protoKey = true;
      const keys = Object.keys(v);
      if (keys.length > maxObjectProperties) maxObjectProperties = keys.length;
      totalBytes += 2 + keys.length * 4;
      for (const k of keys) {
        totalBytes += Buffer.byteLength(k, "utf8");
        values.push((v as Record<string, unknown>)[k]);
        depths.push(d + 1);
      }
    }
  }

  return { totalBytes, maxStringLength, maxArrayItems, maxObjectProperties, maxDepth, nodes, protoKey };
}

/** Single traversal; no serialization. Bounded so measurement itself cannot be weaponized. */
export function measure(value: unknown, nodeCap = 200_000): ArgumentShape {
  return walk(value, nodeCap, false);
}

/**
 * Measure the payload AND decide the `__proto__` question in one walk.
 *
 * `ResultGuard` needs both on every `tools/call`, `resources/read` and `prompts/get` result, and
 * running `measure()` then `hasProtoKey()` walked the same bytes twice. On a 64 KiB result that
 * second walk is where the added-p99 headroom went — `docs/ARCHITECTURE.md` C-11 measured 4.348 ms
 * against a 5 ms budget and named this as the follow-up.
 */
export function measureAndScan(value: unknown, nodeCap = 200_000): ScannedShape {
  return walk(value, nodeCap, true);
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
    case "denied-destination":
      return `Destination ${detail} is on the default deny list: no legitimate tool argument names a cloud instance-metadata endpoint or link-local address, and reading one yields the instance's own IAM credentials.`;
    default:
      return `Egress denied (${reason}: ${detail}).`;
  }
}

function egressRemediation(reason: string, detail: string, serverId: string, toolName: string, layer: "server" | "tool" | undefined): string {
  if (layer === "server") {
    const hosts = `servers["${serverId}"].egress.hosts`;
    if (reason === "denied-destination") {
      return (
        `Denied by the default deny list, which applies on top of the server-level allowlist for "${serverId}" and is not affected by allowPrivateNetwork or allowIpLiterals. ` +
        `Add the exact host to ${hosts} (an explicit grant always wins) or set servers["${serverId}"].egress.allowMetadataEndpoints = true if this server legitimately reads instance metadata. ` +
        "Reading it returns the instance's own IAM credentials, so do neither on a tool whose arguments an LLM chooses."
      );
    }
    return (
      `Add "${detail}" to ${hosts} if this destination is intended, or remove the servers["${serverId}"].egress block to stop enforcing a server-level allowlist. ` +
      "The server-level allowlist is deny-by-default and is an upper bound: a per-tool network grant can narrow it but never widen it. " +
      "Note the limit of this control — it constrains where the MODEL can direct a tool, not what a compromised server does on its own sockets."
    );
  }
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
    case "denied-destination":
      return (
        `This is a default deny, not an allowlist miss: it applies even under a wildcard grant and even when allowPrivateNetwork/allowIpLiterals are true. ` +
        `If this tool genuinely needs the instance metadata service, add the exact host to ${at}.hosts (an explicit grant always wins) or set ${at}.allowMetadataEndpoints = true. ` +
        "Do neither on a tool whose arguments an LLM chooses: the MCP specification mandates blocking this destination class for its own OAuth discovery, and reading it returns the instance's IAM credentials."
      );
    default:
      return `Review ${at}.`;
  }
}

/** Convenience for callers assembling a `baseDir` without importing node:path themselves. */
export const resolveBaseDir = (p: string): string => path.resolve(p);
export type { Role };
