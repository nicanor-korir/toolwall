import type { ToolDefinition } from "./contract.js";
import {
  confirmationPreset,
  DECLARED_EGRESS_DEFAULT_ENFORCE,
  egressPreset,
  responsePreset,
  tierPreset,
  type ArgumentBounds,
  type ArgumentRoles,
  type CapabilityGrant,
  type FilesystemGrant,
  type GrantOverride,
  type NetworkGrant,
  type ConfirmationBudget,
  type EgressPolicy,
  type ResponsePolicy,
  type SchemaEnforcement,
  type StrictnessTier,
  type ToolwallPolicy,
} from "./schema.js";
import { canonicalizeRoot, nodeFsProbe, type FsProbe } from "./containment.js";
import { ANY_HOST } from "./hosts.js";

/**
 * Parsing and resolution of `toolwall-policy.json`.
 *
 * Hand-rolled rather than delegated to a schema library on purpose: the only runtime dependency
 * this project has is `@modelcontextprotocol/sdk`, and a security proxy adding a transitive
 * dependency tree to read its own config is a poor trade. The validator is strict about unknown
 * keys, because a typo in a security policy that silently does nothing is the worst failure mode
 * available — `"hots"` instead of `"hosts"` must be an error, not an empty allowlist.
 */

export interface PolicyError {
  /** Location in the document, JSON-Pointer style. */
  readonly at: string;
  readonly message: string;
}

export interface ResolvedPolicy {
  readonly tier: StrictnessTier;
  /**
   * The effective grant for one tool, plus whether the operator has actually written an entry for
   * it (which drives the `unknownTool` disposition).
   */
  grantFor(serverId: string, toolName: string): { grant: CapabilityGrant; known: boolean };
  /**
   * The per-server egress allowlist. Always returns a value; `declared: false` means the operator
   * has written no `egress` block, in which case nothing is enforced at this layer and the
   * per-tool `network` capability rules apply unchanged. Declaring one switches that server to
   * deny-by-default.
   */
  egressFor(serverId: string): EgressPolicy;
  /** Response-leg controls for this server (T-03). */
  responseFor(serverId: string): ResponsePolicy;
  /** The session-wide human-confirmation budget (T-06). */
  readonly confirmation: ConfirmationBudget;
}

export type ParseResult = { ok: true; policy: ResolvedPolicy; warnings: readonly string[] } | { ok: false; errors: readonly PolicyError[] };

/* ---------------------------------------------------------------- */
/* Skeletons for partially-specified capability objects               */
/* ---------------------------------------------------------------- */

const FS_SKELETON: FilesystemGrant = {
  read: [],
  write: [],
  deny: [],
  followSymlinksOutOfRoot: false,
  allowNonexistent: true,
};

const NET_SKELETON: NetworkGrant = {
  hosts: [],
  schemes: ["https"],
  allowPrivateNetwork: false,
  allowIpLiterals: false,
};

/* ---------------------------------------------------------------- */
/* Validation helpers                                                 */
/* ---------------------------------------------------------------- */

const GRANT_KEYS = new Set([
  "filesystem",
  "network",
  "mutation",
  "mutates",
  "bounds",
  "roles",
  "schema",
  "undeclaredCapability",
  "trustAnnotations",
  "unknownTool",
]);
const FS_KEYS = new Set(["read", "write", "deny", "followSymlinksOutOfRoot", "allowNonexistent"]);
const NET_KEYS = new Set(["hosts", "schemes", "allowPrivateNetwork", "allowIpLiterals"]);
const BOUNDS_KEYS = new Set(["maxTotalBytes", "maxStringLength", "maxArrayItems", "maxObjectProperties", "maxDepth"]);
const ROLES_KEYS = new Set(["readPath", "writePath", "url", "host", "deriveUrlFromSchema"]);
const EGRESS_KEYS = new Set(["enforce", "hosts", "schemes", "allowPrivateNetwork", "allowIpLiterals", "onViolation"]);
const RESPONSE_KEYS = new Set(["enabled", "bounds", "outputSchema", "atpa", "inputRequests", "elicitation"]);
const CONFIRMATION_KEYS = new Set(["maxPrompts", "timeoutMs", "promptableRules"]);
const SCHEMA_KEYS = new Set(["enabled", "additionalProperties", "requireKnownSchema", "maxPatternLength", "enforceFormats"]);

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function checkKeys(v: Record<string, unknown>, allowed: Set<string>, at: string, errors: PolicyError[]): void {
  for (const k of Object.keys(v)) {
    if (!allowed.has(k)) {
      errors.push({ at: `${at}/${k}`, message: `unknown key "${k}". A typo here would silently weaken the policy, so it is rejected.` });
    }
  }
}

function checkStringArray(v: unknown, at: string, errors: PolicyError[]): void {
  if (v === undefined) return;
  if (!Array.isArray(v) || v.some((x) => typeof x !== "string")) {
    errors.push({ at, message: "expected an array of strings" });
  }
}

function checkEnum(v: unknown, allowed: readonly string[], at: string, errors: PolicyError[]): void {
  if (v === undefined) return;
  if (typeof v !== "string" || !allowed.includes(v)) {
    errors.push({ at, message: `expected one of ${allowed.map((a) => JSON.stringify(a)).join(", ")}` });
  }
}

function checkBool(v: unknown, at: string, errors: PolicyError[]): void {
  if (v !== undefined && typeof v !== "boolean") errors.push({ at, message: "expected a boolean" });
}

function checkPositiveInt(v: unknown, at: string, errors: PolicyError[]): void {
  if (v === undefined) return;
  if (typeof v !== "number" || !Number.isInteger(v) || v < 0) errors.push({ at, message: "expected a non-negative integer" });
}

function validateGrant(v: unknown, at: string, errors: PolicyError[]): void {
  if (!isPlainObject(v)) {
    errors.push({ at, message: "expected an object" });
    return;
  }
  checkKeys(v, GRANT_KEYS, at, errors);

  const fsv = v["filesystem"];
  if (fsv !== undefined) {
    if (!isPlainObject(fsv)) errors.push({ at: `${at}/filesystem`, message: "expected an object" });
    else {
      checkKeys(fsv, FS_KEYS, `${at}/filesystem`, errors);
      checkStringArray(fsv["read"], `${at}/filesystem/read`, errors);
      checkStringArray(fsv["write"], `${at}/filesystem/write`, errors);
      checkStringArray(fsv["deny"], `${at}/filesystem/deny`, errors);
      checkBool(fsv["followSymlinksOutOfRoot"], `${at}/filesystem/followSymlinksOutOfRoot`, errors);
      checkBool(fsv["allowNonexistent"], `${at}/filesystem/allowNonexistent`, errors);
    }
  }

  const net = v["network"];
  if (net !== undefined) {
    if (!isPlainObject(net)) errors.push({ at: `${at}/network`, message: "expected an object" });
    else {
      checkKeys(net, NET_KEYS, `${at}/network`, errors);
      checkStringArray(net["hosts"], `${at}/network/hosts`, errors);
      checkStringArray(net["schemes"], `${at}/network/schemes`, errors);
      checkBool(net["allowPrivateNetwork"], `${at}/network/allowPrivateNetwork`, errors);
      checkBool(net["allowIpLiterals"], `${at}/network/allowIpLiterals`, errors);
      checkHostList(net["hosts"], `${at}/network/hosts`, errors);
    }
  }

  checkEnum(v["mutation"], ["deny", "confirm", "allow"], `${at}/mutation`, errors);
  checkBool(v["mutates"], `${at}/mutates`, errors);
  checkEnum(v["undeclaredCapability"], ["allow", "confirm", "deny"], `${at}/undeclaredCapability`, errors);
  checkEnum(v["trustAnnotations"], ["never", "as-signal"], `${at}/trustAnnotations`, errors);
  checkEnum(v["unknownTool"], ["allow", "confirm", "block"], `${at}/unknownTool`, errors);

  const bounds = v["bounds"];
  if (bounds !== undefined) {
    if (!isPlainObject(bounds)) errors.push({ at: `${at}/bounds`, message: "expected an object" });
    else {
      checkKeys(bounds, BOUNDS_KEYS, `${at}/bounds`, errors);
      for (const k of BOUNDS_KEYS) checkPositiveInt(bounds[k], `${at}/bounds/${k}`, errors);
    }
  }

  const roles = v["roles"];
  if (roles !== undefined) {
    if (!isPlainObject(roles)) errors.push({ at: `${at}/roles`, message: "expected an object" });
    else {
      checkKeys(roles, ROLES_KEYS, `${at}/roles`, errors);
      for (const k of ["readPath", "writePath", "url", "host"] as const) {
        checkStringArray(roles[k], `${at}/roles/${k}`, errors);
        const arr = roles[k];
        if (Array.isArray(arr)) {
          for (const [i, s] of arr.entries()) {
            if (typeof s === "string" && !s.startsWith("/")) {
              errors.push({ at: `${at}/roles/${k}/${i}`, message: `"${s}": selectors are JSON Pointers and must start with "/", e.g. "/paths/*"` });
            }
          }
        }
      }
      checkBool(roles["deriveUrlFromSchema"], `${at}/roles/deriveUrlFromSchema`, errors);
    }
  }

  const sch = v["schema"];
  if (sch !== undefined) {
    if (!isPlainObject(sch)) errors.push({ at: `${at}/schema`, message: "expected an object" });
    else {
      checkKeys(sch, SCHEMA_KEYS, `${at}/schema`, errors);
      checkBool(sch["enabled"], `${at}/schema/enabled`, errors);
      checkEnum(sch["additionalProperties"], ["schema", "reject"], `${at}/schema/additionalProperties`, errors);
      checkBool(sch["requireKnownSchema"], `${at}/schema/requireKnownSchema`, errors);
      checkPositiveInt(sch["maxPatternLength"], `${at}/schema/maxPatternLength`, errors);
      checkStringArray(sch["enforceFormats"], `${at}/schema/enforceFormats`, errors);
    }
  }
}

/** Shared host-list validation: the only supported wildcard is a leading `*.`. */
function checkHostList(hosts: unknown, at: string, errors: PolicyError[]): void {
  if (!Array.isArray(hosts)) return;
  for (const [i, h] of hosts.entries()) {
    if (typeof h !== "string") continue;
    // The single any-host token. Legal, and `parsePolicy` warns about it below, because an operator
    // who writes it has disabled host matching for that list and should be told so out loud.
    if (h === ANY_HOST) continue;
    if (h.includes("*") && !h.startsWith("*.")) {
      errors.push({
        at: `${at}/${i}`,
        message: `"${h}": the only supported wildcard form is "*.example.com". Substring wildcards are not supported because they are how host allowlists get bypassed.`,
      });
    }
  }
}

function validateEgress(v: unknown, at: string, errors: PolicyError[]): void {
  if (!isPlainObject(v)) {
    errors.push({ at, message: "expected an object" });
    return;
  }
  checkKeys(v, EGRESS_KEYS, at, errors);
  checkEnum(v["enforce"], ["off", "roles", "scan"], `${at}/enforce`, errors);
  checkStringArray(v["hosts"], `${at}/hosts`, errors);
  checkStringArray(v["schemes"], `${at}/schemes`, errors);
  checkBool(v["allowPrivateNetwork"], `${at}/allowPrivateNetwork`, errors);
  checkBool(v["allowIpLiterals"], `${at}/allowIpLiterals`, errors);
  checkEnum(v["onViolation"], ["block", "confirm", "allow"], `${at}/onViolation`, errors);
  checkHostList(v["hosts"], `${at}/hosts`, errors);
}

function validateResponse(v: unknown, at: string, errors: PolicyError[]): void {
  if (!isPlainObject(v)) {
    errors.push({ at, message: "expected an object" });
    return;
  }
  checkKeys(v, RESPONSE_KEYS, at, errors);
  checkBool(v["enabled"], `${at}/enabled`, errors);
  for (const k of ["outputSchema", "atpa", "inputRequests", "elicitation"] as const) {
    checkEnum(v[k], ["enforce", "record", "off"], `${at}/${k}`, errors);
  }
  const bounds = v["bounds"];
  if (bounds !== undefined) {
    if (!isPlainObject(bounds)) errors.push({ at: `${at}/bounds`, message: "expected an object" });
    else {
      checkKeys(bounds, BOUNDS_KEYS, `${at}/bounds`, errors);
      for (const k of BOUNDS_KEYS) checkPositiveInt(bounds[k], `${at}/bounds/${k}`, errors);
    }
  }
}

function validateConfirmation(v: unknown, at: string, errors: PolicyError[]): void {
  if (!isPlainObject(v)) {
    errors.push({ at, message: "expected an object" });
    return;
  }
  checkKeys(v, CONFIRMATION_KEYS, at, errors);
  checkPositiveInt(v["maxPrompts"], `${at}/maxPrompts`, errors);
  checkPositiveInt(v["timeoutMs"], `${at}/timeoutMs`, errors);
  checkStringArray(v["promptableRules"], `${at}/promptableRules`, errors);
}

/* ---------------------------------------------------------------- */
/* Merge                                                              */
/* ---------------------------------------------------------------- */

function mergeBounds(base: ArgumentBounds, o: Partial<ArgumentBounds> | undefined): ArgumentBounds {
  return o === undefined ? base : { ...base, ...o };
}
function mergeRoles(base: ArgumentRoles, o: Partial<ArgumentRoles> | undefined): ArgumentRoles {
  return o === undefined ? base : { ...base, ...o };
}
function mergeSchema(base: SchemaEnforcement, o: Partial<SchemaEnforcement> | undefined): SchemaEnforcement {
  return o === undefined ? base : { ...base, ...o };
}
function mergeFs(base: FilesystemGrant | undefined, o: Partial<FilesystemGrant> | undefined): FilesystemGrant | undefined {
  if (o === undefined) return base;
  return { ...(base ?? FS_SKELETON), ...o };
}
function mergeNet(base: NetworkGrant | undefined, o: Partial<NetworkGrant> | undefined): NetworkGrant | undefined {
  if (o === undefined) return base;
  return { ...(base ?? NET_SKELETON), ...o };
}

/**
 * Arrays replace rather than concatenate. Concatenation would mean a tool-level entry could only
 * ever *widen* what the server-level entry granted, which is the wrong direction for a capability
 * model — an operator narrowing one tool must be able to do so.
 */
function mergeGrant(base: CapabilityGrant, o: GrantOverride | undefined): CapabilityGrant {
  if (o === undefined) return base;
  return {
    filesystem: mergeFs(base.filesystem, o.filesystem as Partial<FilesystemGrant> | undefined),
    network: mergeNet(base.network, o.network as Partial<NetworkGrant> | undefined),
    mutation: o.mutation ?? base.mutation,
    mutates: o.mutates ?? base.mutates,
    bounds: mergeBounds(base.bounds, o.bounds as Partial<ArgumentBounds> | undefined),
    roles: mergeRoles(base.roles, o.roles as Partial<ArgumentRoles> | undefined),
    schema: mergeSchema(base.schema, o.schema as Partial<SchemaEnforcement> | undefined),
    undeclaredCapability: o.undeclaredCapability ?? base.undeclaredCapability,
    trustAnnotations: o.trustAnnotations ?? base.trustAnnotations,
    unknownTool: o.unknownTool ?? base.unknownTool,
  };
}

/**
 * Merging a declared `egress` block sets `declared: true` and, unless the operator said otherwise,
 * turns enforcement on at `"roles"`. Writing the block IS the act of opting in to deny-by-default;
 * a block that parsed but enforced nothing would be the silent-no-op failure mode this parser
 * exists to prevent.
 */
function mergeEgress(base: EgressPolicy, o: Partial<EgressPolicy> | undefined): EgressPolicy {
  if (o === undefined) return base;
  const declared = true;
  return {
    ...base,
    ...o,
    declared,
    enforce: o.enforce ?? (base.declared ? base.enforce : DECLARED_EGRESS_DEFAULT_ENFORCE),
  };
}

function mergeResponse(base: ResponsePolicy, o: Partial<ResponsePolicy> | undefined): ResponsePolicy {
  if (o === undefined) return base;
  return { ...base, ...o, bounds: mergeBounds(base.bounds, o.bounds as Partial<ArgumentBounds> | undefined) };
}

/** Canonicalize declared roots once, at load time. Symlinked roots must not surprise us later. */
function canonicalizeGrantRoots(g: CapabilityGrant, at: string, probe: FsProbe, errors: PolicyError[]): CapabilityGrant {
  if (g.filesystem === undefined) return g;
  const conv = (list: readonly string[], field: string): string[] => {
    const out: string[] = [];
    for (const [i, r] of list.entries()) {
      const c = canonicalizeRoot(r, probe);
      if (c.ok) out.push(c.path);
      else errors.push({ at: `${at}/filesystem/${field}/${i}`, message: c.detail });
    }
    return out;
  };
  return {
    ...g,
    filesystem: {
      ...g.filesystem,
      read: conv(g.filesystem.read, "read"),
      write: conv(g.filesystem.write, "write"),
      deny: conv(g.filesystem.deny, "deny"),
    },
  };
}

/* ---------------------------------------------------------------- */
/* Entry points                                                       */
/* ---------------------------------------------------------------- */

export interface ParseOptions {
  readonly probe?: FsProbe;
}

export function parsePolicy(raw: unknown, opts: ParseOptions = {}): ParseResult {
  const errors: PolicyError[] = [];
  const warnings: string[] = [];
  const probe = opts.probe ?? nodeFsProbe;

  if (!isPlainObject(raw)) return { ok: false, errors: [{ at: "", message: "policy must be a JSON object" }] };
  checkKeys(raw, new Set(["$schema", "version", "tier", "defaults", "egress", "response", "confirmation", "servers"]), "", errors);

  if (raw["version"] !== 1) errors.push({ at: "/version", message: 'expected "version": 1' });
  const tierRaw = raw["tier"] ?? "balanced";
  checkEnum(tierRaw, ["permissive", "balanced", "strict"], "/tier", errors);
  const tier = (typeof tierRaw === "string" ? tierRaw : "balanced") as StrictnessTier;

  if (raw["defaults"] !== undefined) validateGrant(raw["defaults"], "/defaults", errors);
  if (raw["egress"] !== undefined) validateEgress(raw["egress"], "/egress", errors);
  if (raw["response"] !== undefined) validateResponse(raw["response"], "/response", errors);
  if (raw["confirmation"] !== undefined) validateConfirmation(raw["confirmation"], "/confirmation", errors);

  const serversRaw = raw["servers"];
  if (serversRaw !== undefined && !isPlainObject(serversRaw)) {
    errors.push({ at: "/servers", message: "expected an object keyed by serverId" });
  }
  if (isPlainObject(serversRaw)) {
    for (const [sid, sp] of Object.entries(serversRaw)) {
      if (!isPlainObject(sp)) {
        errors.push({ at: `/servers/${sid}`, message: "expected an object" });
        continue;
      }
      checkKeys(sp, new Set(["defaults", "tools", "egress", "response"]), `/servers/${sid}`, errors);
      if (sp["defaults"] !== undefined) validateGrant(sp["defaults"], `/servers/${sid}/defaults`, errors);
      if (sp["egress"] !== undefined) validateEgress(sp["egress"], `/servers/${sid}/egress`, errors);
      if (sp["response"] !== undefined) validateResponse(sp["response"], `/servers/${sid}/response`, errors);
      const tools = sp["tools"];
      if (tools !== undefined && !isPlainObject(tools)) errors.push({ at: `/servers/${sid}/tools`, message: "expected an object keyed by tool name" });
      if (isPlainObject(tools)) {
        for (const [tn, tg] of Object.entries(tools)) validateGrant(tg, `/servers/${sid}/tools/${tn}`, errors);
      }
    }
  }

  if (errors.length > 0) return { ok: false, errors };

  const doc = raw as unknown as ToolwallPolicy;
  const base = mergeGrant(tierPreset(tier), doc.defaults);
  const globalGrant = canonicalizeGrantRoots(base, "/defaults", probe, errors);

  const globalEgress = mergeEgress(egressPreset(tier), doc.egress as Partial<EgressPolicy> | undefined);
  const globalResponse = mergeResponse(responsePreset(tier), doc.response as Partial<ResponsePolicy> | undefined);
  const confirmation: ConfirmationBudget = { ...confirmationPreset(tier), ...(doc.confirmation as Partial<ConfirmationBudget> | undefined) };

  const perServer = new Map<string, CapabilityGrant>();
  const perTool = new Map<string, CapabilityGrant>();
  const knownTools = new Set<string>();
  const perServerEgress = new Map<string, EgressPolicy>();
  const perServerResponse = new Map<string, ResponsePolicy>();

  for (const [sid, sp] of Object.entries(doc.servers ?? {})) {
    const sGrant = canonicalizeGrantRoots(mergeGrant(globalGrant, sp.defaults), `/servers/${sid}/defaults`, probe, errors);
    perServer.set(sid, sGrant);
    perServerEgress.set(sid, mergeEgress(globalEgress, sp.egress as Partial<EgressPolicy> | undefined));
    perServerResponse.set(sid, mergeResponse(globalResponse, sp.response as Partial<ResponsePolicy> | undefined));
    for (const [tn, tg] of Object.entries(sp.tools ?? {})) {
      const key = `${sid} ${tn}`;
      perTool.set(key, canonicalizeGrantRoots(mergeGrant(sGrant, tg), `/servers/${sid}/tools/${tn}`, probe, errors));
      knownTools.add(key);
    }
  }

  if (errors.length > 0) return { ok: false, errors };

  if (tier === "strict" && (doc.servers === undefined || Object.keys(doc.servers).length === 0)) {
    warnings.push(
      'tier is "strict" but no servers are declared: every tools/call will be blocked by the unknownTool rule. Declare your servers or start at "balanced".',
    );
  }

  // A declared-but-empty allowlist denies every destination. That is a legitimate posture ("this
  // server talks to nothing") and it is also what a truncated edit looks like, so say so out loud
  // rather than letting the operator discover it as an outage.
  for (const [sid, e] of perServerEgress) {
    if (e.declared && e.enforce !== "off" && e.hosts.length === 0) {
      warnings.push(`servers["${sid}"].egress declares an empty host allowlist: every URL or host argument on this server will be denied.`);
    }
  }
  for (const [sid, e] of perServerEgress) {
    if (e.declared && e.hosts.includes(ANY_HOST)) {
      warnings.push(
        `servers["${sid}"].egress.hosts contains "${ANY_HOST}", which matches every host. Only the scheme, IP-literal and private-network checks still apply on that list.`,
      );
    }
  }
  if (globalEgress.declared && globalEgress.hosts.includes(ANY_HOST)) {
    warnings.push(`egress.hosts contains "${ANY_HOST}", which matches every host. Only the scheme, IP-literal and private-network checks still apply on that list.`);
  }
  for (const e of [globalEgress, ...perServerEgress.values()]) {
    if (e.enforce === "scan") {
      warnings.push(
        'egress.enforce = "scan" inspects every string argument for URLs, not only the ones bound to a role. It catches destinations hidden in free-text fields and it has a measured false-positive cost on content-carrying tools - see the FP report before leaving it on.',
      );
      break;
    }
  }

  const policy: ResolvedPolicy = {
    tier,
    confirmation,
    grantFor(serverId, toolName) {
      const key = `${serverId} ${toolName}`;
      const t = perTool.get(key);
      if (t) return { grant: t, known: true };
      const s = perServer.get(serverId);
      if (s) return { grant: s, known: false };
      return { grant: globalGrant, known: false };
    },
    egressFor(serverId) {
      return perServerEgress.get(serverId) ?? globalEgress;
    },
    responseFor(serverId) {
      return perServerResponse.get(serverId) ?? globalResponse;
    },
  };

  return { ok: true, policy, warnings };
}

/** The policy in force when the operator has written no `toolwall-policy.json` at all. */
export function defaultPolicy(tier: StrictnessTier = "balanced"): ResolvedPolicy {
  const grant = tierPreset(tier);
  const egress = egressPreset(tier);
  const response = responsePreset(tier);
  return {
    tier,
    confirmation: confirmationPreset(tier),
    grantFor() {
      return { grant, known: false };
    },
    egressFor() {
      return egress;
    },
    responseFor() {
      return response;
    },
  };
}

/** Convenience for `ToolDefinition`-keyed lookups in callers that already have the definition. */
export function grantForTool(policy: ResolvedPolicy, serverId: string, tool: ToolDefinition): { grant: CapabilityGrant; known: boolean } {
  return policy.grantFor(serverId, tool.name);
}
