/**
 * toolwall capability policy — the `toolwall-policy.json` format.
 *
 * This is a CAPABILITY model, not a blocklist. A policy declares what each tool is *allowed* to
 * touch: which filesystem roots, which hosts, whether it may mutate, and what argument shapes are
 * in bounds. Allowlists beat blocklists structurally: an attacker cannot enumerate their way past
 * "only these two directories" the way they can past "not these twelve characters".
 *
 * Deliberately absent: any character or regex blocklist on argument strings. `docs/THREAT-MODEL.md`
 * §3 is explicit that these are high-false-positive and low-value, and the benign corpus in
 * `test/fixtures/benign/` demonstrates why — a code-editing tool receives shell syntax as normal
 * business, a git tool receives `..` as git's own range operator, a SQL tool receives semicolons.
 *
 * ## Strictness tiers
 *
 * A guard everyone disables protects nobody, so the tier is a first-class, explicit choice:
 *
 * | | permissive | balanced (default) | strict |
 * |---|---|---|---|
 * | Undeclared capability | allow | allow | deny |
 * | Unknown tool (no policy entry) | allow | allow | block |
 * | Mutation | allow | allow | confirm |
 * | `additionalProperties` omitted | per schema (allowed) | per schema (allowed) | rejected |
 * | Server `readOnlyHint` | used as a signal | used as a signal | ignored entirely |
 * | Private-network hosts (wildcard-matched) | allow | allow | deny |
 *
 * The load-bearing tier decision is **undeclared capability**. At `permissive`/`balanced`, a
 * capability the operator has not declared is not enforced — otherwise a fresh install with no
 * policy file would block every filesystem tool on first use and be uninstalled the same day.
 * At those tiers the real day-zero controls are schema enforcement and argument bounds, which are
 * deterministic and near-zero-FP. Capability enforcement switches on the moment the operator
 * declares roots or hosts. `strict` inverts the default to deny. We measure and publish the
 * false-positive rate at every tier, both with and without a policy file, rather than shipping a
 * tier whose cost we have not counted.
 */

export type StrictnessTier = "permissive" | "balanced" | "strict";

/** Filesystem capability. Roots are canonicalized (symlinks resolved) at policy-load time. */
export interface FilesystemGrant {
  /** Absolute directory roots this tool may read from. */
  readonly read: readonly string[];
  /** Absolute directory roots this tool may write to. Implies read on the same root. */
  readonly write: readonly string[];
  /** Roots carved out of the above, checked after canonicalization. e.g. `<root>/.git`, `<root>/.env`. */
  readonly deny: readonly string[];
  /**
   * Whether a symlink whose target resolves OUTSIDE the granted roots may be followed.
   * Always false in any sane configuration — CVE-2025-53109 is exactly this. Present only so the
   * check is a visible policy decision rather than an invisible assumption.
   */
  readonly followSymlinksOutOfRoot: boolean;
  /** Allow paths that do not exist yet (required for any tool that creates files). */
  readonly allowNonexistent: boolean;
}

/** Network capability. The exfiltration leg — the most valuable edge of the lethal trifecta to cut. */
export interface NetworkGrant {
  /**
   * Allowed hosts. Two forms only:
   *  - `example.com`      exact host, case-insensitive, after URL/IDNA normalization
   *  - `*.example.com`    any strict subdomain of example.com (NOT example.com itself)
   * Never substring-matched. `evil-example.com` and `example.com.evil.io` match neither form.
   */
  readonly hosts: readonly string[];
  /** Allowed URL schemes, lowercase, without the colon. */
  readonly schemes: readonly string[];
  /**
   * Whether a host that resolved to a private/loopback/link-local literal may be contacted when it
   * was matched by a WILDCARD entry. An exact-host entry is an explicit operator grant and always
   * wins — otherwise `127.0.0.1` in the allowlist would be silently ignored, which is the kind of
   * surprise that gets a tool uninstalled.
   */
  readonly allowPrivateNetwork: boolean;
  /** Whether bare IP literals (v4/v6) are acceptable hosts at all. */
  readonly allowIpLiterals: boolean;
}

export type MutationDisposition = "deny" | "confirm" | "allow";

/**
 * Structural bounds on the arguments object. These are cheap, deterministic, and also the
 * mitigation for the T-08 payload-shape attacks (deeply nested / oversized JSON) against the
 * proxy itself. They are NOT content inspection.
 */
export interface ArgumentBounds {
  readonly maxTotalBytes: number;
  readonly maxStringLength: number;
  readonly maxArrayItems: number;
  readonly maxObjectProperties: number;
  readonly maxDepth: number;
}

/**
 * Which arguments carry which capability-relevant meaning.
 *
 * This is the mechanism that keeps the false-positive rate at zero: the guard NEVER inspects a
 * string to decide whether it "looks like a path". It checks the arguments the operator (or the
 * tool's own published schema) declared to BE paths, and ignores everything else. A `content`
 * field full of shell script is not a path and is never treated as one.
 *
 * Selector syntax is a JSON Pointer with `*` as a single-segment wildcard:
 *   `/path`  `/paths/*`  `/files/*`  `/edits/<*>/file_path`
 */
export interface ArgumentRoles {
  /** Arguments that name a filesystem location the tool will READ. */
  readonly readPath: readonly string[];
  /** Arguments that name a filesystem location the tool will WRITE/DELETE/MOVE. */
  readonly writePath: readonly string[];
  /** Arguments that carry a URL. */
  readonly url: readonly string[];
  /**
   * Additionally derive the `url` role from the tool's own `inputSchema` where a string property
   * declares `"format": "uri"`. The schema is a contract the server published; reading a role out
   * of it is not guesswork. Path roles are NOT derived — JSON Schema has no standard path format,
   * and guessing from property names is how false positives start.
   */
  readonly deriveUrlFromSchema: boolean;
}

export interface SchemaEnforcement {
  readonly enabled: boolean;
  /**
   * `"schema"` — honour JSON Schema's own default: absent `additionalProperties` permits them.
   * `"reject"` — treat an absent `additionalProperties` as `false`.
   *
   * `"reject"` is real security (it closes undocumented parameters that a poisoned schema could
   * later legitimise) and it has a real, measured cost: published tool schemas are frequently
   * under-specified relative to the API behind them. Tier-gated for that reason.
   */
  readonly additionalProperties: "schema" | "reject";
  /** Block a `tools/call` for which no tool definition is available to enforce against. */
  readonly requireKnownSchema: boolean;
  /**
   * Server-supplied `pattern` regexes are compiled by US. CVE-2026-0621 (ReDoS in the SDK's
   * UriTemplate) is the same class of bug against the same kind of input. Patterns longer than
   * this, or containing a nested-quantifier construct, are not evaluated; a finding is recorded
   * instead. We never turn the server's regex into our own denial of service.
   */
  readonly maxPatternLength: number;
  /** Which JSON Schema `format` values are enforced rather than treated as annotation. */
  readonly enforceFormats: readonly string[];
}

/** A fully-resolved capability grant for one tool. Every field populated; nothing implicit. */
export interface CapabilityGrant {
  /** `undefined` = the operator has not declared this capability. See `undeclaredCapability`. */
  readonly filesystem: FilesystemGrant | undefined;
  readonly network: NetworkGrant | undefined;
  readonly mutation: MutationDisposition;
  /**
   * Operator's authoritative statement of whether this tool mutates state. When set, server
   * annotations are irrelevant. When unset, see `trustAnnotations`.
   */
  readonly mutates: boolean | undefined;
  readonly bounds: ArgumentBounds;
  readonly roles: ArgumentRoles;
  readonly schema: SchemaEnforcement;
  /** What to do when an argument exercises a capability the operator never declared. */
  readonly undeclaredCapability: "allow" | "confirm" | "deny";
  /**
   * `"never"` — server `ToolAnnotations` have zero effect on the decision. An unannotated tool and
   *             a tool claiming `readOnlyHint: true` are treated identically.
   * `"as-signal"` — `readOnlyHint: true` may downgrade a tool to non-mutating, and an `info`
   *             finding is emitted recording that the decision rested on untrusted server input.
   *
   * Annotations are NEVER able to grant a capability, raise a bound, or widen a root under either
   * setting. The spec is unambiguous: "Clients should never make tool use decisions based on
   * ToolAnnotations received from untrusted servers."
   */
  readonly trustAnnotations: "never" | "as-signal";
  /** Disposition for a tool with no policy entry of its own. */
  readonly unknownTool: "allow" | "confirm" | "block";
}

/* ---------------------------------------------------------------- */
/* On-disk format                                                     */
/* ---------------------------------------------------------------- */

type DeepPartial<T> = {
  [K in keyof T]?: T[K] extends readonly (infer U)[]
    ? readonly U[]
    : T[K] extends object | undefined
      ? DeepPartial<NonNullable<T[K]>>
      : T[K];
};

/** A partial grant as written in `toolwall-policy.json`. Merged over the tier preset. */
export type GrantOverride = DeepPartial<CapabilityGrant>;

export interface ServerPolicy {
  /** Applies to every tool on this server. */
  readonly defaults?: GrantOverride;
  /** Per-tool overrides, keyed by tool name. Presence here also marks the tool as "known". */
  readonly tools?: Readonly<Record<string, GrantOverride>>;
}

export interface ToolwallPolicy {
  /** Format version. Bumped on any breaking change to this file's semantics. */
  readonly version: 1;
  readonly tier: StrictnessTier;
  /** Applies to every server. */
  readonly defaults?: GrantOverride;
  /** Keyed by `GuardContext.serverId` — the stable per-connection identity, NOT serverInfo.name (T-04). */
  readonly servers?: Readonly<Record<string, ServerPolicy>>;
}

/* ---------------------------------------------------------------- */
/* Tier presets                                                       */
/* ---------------------------------------------------------------- */

const BOUNDS: Readonly<Record<StrictnessTier, ArgumentBounds>> = {
  // Sized from the benign corpus, not from intuition: the largest legitimate case is a 180 KiB
  // generated bundle written by a code-editing tool, and a 300-element path array.
  permissive: { maxTotalBytes: 8 << 20, maxStringLength: 4 << 20, maxArrayItems: 10_000, maxObjectProperties: 4096, maxDepth: 64 },
  balanced: { maxTotalBytes: 4 << 20, maxStringLength: 1 << 20, maxArrayItems: 5_000, maxObjectProperties: 1024, maxDepth: 32 },
  strict: { maxTotalBytes: 1 << 20, maxStringLength: 512 << 10, maxArrayItems: 1_000, maxObjectProperties: 256, maxDepth: 20 },
};

const ROLES: ArgumentRoles = {
  readPath: [],
  writePath: [],
  url: [],
  deriveUrlFromSchema: true,
};

const ENFORCED_FORMATS: readonly string[] = ["uri", "date-time", "uuid", "email", "ipv4", "ipv6"];

export function tierPreset(tier: StrictnessTier): CapabilityGrant {
  const bounds = BOUNDS[tier];
  switch (tier) {
    case "permissive":
      return {
        filesystem: undefined,
        network: undefined,
        mutation: "allow",
        mutates: undefined,
        bounds,
        roles: ROLES,
        schema: {
          enabled: true,
          additionalProperties: "schema",
          requireKnownSchema: false,
          maxPatternLength: 512,
          enforceFormats: [],
        },
        undeclaredCapability: "allow",
        trustAnnotations: "as-signal",
        unknownTool: "allow",
      };
    case "balanced":
      return {
        filesystem: undefined,
        network: undefined,
        mutation: "allow",
        mutates: undefined,
        bounds,
        roles: ROLES,
        schema: {
          enabled: true,
          additionalProperties: "schema",
          requireKnownSchema: false,
          maxPatternLength: 512,
          enforceFormats: ENFORCED_FORMATS,
        },
        undeclaredCapability: "allow",
        trustAnnotations: "as-signal",
        unknownTool: "allow",
      };
    case "strict":
      return {
        filesystem: undefined,
        network: undefined,
        mutation: "confirm",
        mutates: undefined,
        bounds,
        roles: ROLES,
        schema: {
          enabled: true,
          additionalProperties: "reject",
          requireKnownSchema: true,
          maxPatternLength: 512,
          enforceFormats: ENFORCED_FORMATS,
        },
        undeclaredCapability: "deny",
        trustAnnotations: "never",
        unknownTool: "block",
      };
  }
}

/** Ordered list of tiers, weakest first. Exported for reporting loops in the FP harness. */
export const TIERS: readonly StrictnessTier[] = ["permissive", "balanced", "strict"];
