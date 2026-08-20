import * as os from "node:os";

import { DEFAULT_PROTOCOL_ERA, type AuditSink, type Finding, type JsonSchemaNode, type ProtocolEra, type ToolDefinition, type ToolDefinitionSource } from "./contract.js";
import { canonicalizeRoot, nodeFsProbe, type FsProbe } from "./containment.js";
import { deriveUrlSelectors } from "./roles.js";
import { ANY_HOST } from "./hosts.js";
import type { ResolvedPolicy } from "./parse.js";
import type { ArgumentRoles, CapabilityGrant, FilesystemGrant, NetworkGrant } from "./schema.js";

/**
 * **Inferred capability policy — the capability floor that needs no configuration.**
 *
 * ## Why this file exists
 *
 * `docs/POSITIONING.md`: the capability and egress layer is the product, and it is the layer that
 * would have stopped every documented 2025–26 incident. But Week 2 shipped it `enforce: "off"`
 * until an operator writes a policy file, and **nobody writes policy files** — `mcp-proxy` does 5M
 * downloads/month with zero security while every configuration-requiring tool in the prior-art
 * survey sits at hundreds. A control that requires configuration to do anything protects nobody.
 *
 * So: derive a capability profile per tool from evidence that is already on the wire, and make the
 * hand-written policy an **override** rather than the entry price. *Learn-then-enforce beats
 * declare-then-enforce for adoption.*
 *
 * ## The three signals, in descending order of trustworthiness
 *
 * 1. **The tool's own `inputSchema`.** The strongest signal, because it is the server's published
 *    contract and — under contract **C-1** — we read it from the **PINNED** definition, so it
 *    cannot be widened after approval. A `format: "uri"` property means the tool reaches the
 *    network. A path-shaped property means it reaches the filesystem. **Neither present means
 *    neither needed**, and that is the whole point: a calculator whose schema is two numbers does
 *    not need a hand-written rule saying it may not read `~/.ssh/id_rsa`.
 *
 * 2. **`annotations`, as a signal and never as authorization.** Spec defaults are load-bearing
 *    here: an unannotated tool is `destructiveHint: true` and `openWorldHint: true`, so absence of
 *    annotations is the *dangerous* configuration, not a claim of safety. The invariant enforced
 *    below is absolute: **an annotation may only ever narrow an inferred profile, never widen it.**
 *    In particular `openWorldHint: true` grants no network capability — only a `format: "uri"` or
 *    `format: "hostname"` property does. A hostile server therefore gains nothing by lying.
 *
 * 3. **Observed behaviour across a session** (`observation`, default `"off"` — see below).
 *
 * ## What inference deliberately does NOT do
 *
 * It never inspects an argument *value* to decide what an argument *is*. Roles are bound to schema
 * locations, exactly as in the hand-written path — that is the property that keeps the measured
 * false-positive rate where it is, and giving it up here would import the 78%-FP failure mode the
 * threat model forbids.
 *
 * It also never infers a **host allowlist**. It cannot: nothing on the wire says which hosts are
 * legitimate for your deployment, and a guessed allowlist is either useless or an outage. What the
 * inferred network grant enforces is the URL **scheme** (§`INFERRED_SCHEMES`) — which catches
 * `file:///etc/passwd` and `gopher://` handed to a fetch tool, a real LFI/SSRF shape — plus the
 * default deny list of cloud instance-metadata and link-local destinations, whose enumeration is
 * closed and therefore needs no evidence from the wire. Positive host allowlisting stays an
 * operator declaration. Say this plainly rather than implying egress coverage we do not have.
 *
 * ## Precedence: an explicit operator declaration always wins
 *
 * Inference is a **floor**, never a replacement. Per capability:
 *
 * | operator wrote… | effect |
 * |---|---|
 * | `filesystem` grant, or any `roles.readPath` / `roles.writePath` | inference stands down on filesystem entirely |
 * | `network` grant, or any `roles.url` / `roles.host` | inference stands down on network entirely |
 * | `roles.deriveUrlFromSchema: false` | no `url` role is inferred |
 * | nothing | the inferred profile applies |
 *
 * "The operator wrote it" is decided structurally, not by a flag: every tier preset ships
 * `filesystem: undefined`, `network: undefined` and four empty role arrays, so a non-`undefined`
 * grant or a non-empty selector list can only have come from `toolwall-policy.json`.
 *
 * Standing down on the *whole* capability rather than merging is deliberate. `docs/ARCHITECTURE.md`
 * C-7 records that `git_diff.paths` must NOT be bound to a path role — the pathspecs are
 * repo-relative and binding them resolves against the wrong base, which is a self-inflicted false
 * positive. An operator who deliberately left an argument unbound must not have inference bind it
 * behind their back.
 *
 * ## Measured, 2026-08-19 — the gate this had to pass to default ON
 *
 * False positives, 63-case benign request corpus, `balanced` (`test/unit/fp-harness.test.ts`):
 *
 * | scenario | blocked | confirm | BLOCK RATE | FRICTION RATE |
 * |---|---|---|---|---|
 * | day-zero, no inference (the baseline to beat) | 0 | 0 | 0.0% | 0.0% |
 * | **day-zero + inference** | **0** | **0** | **0.0%** | **0.0%** |
 * | day-zero + inference, `includeTempDir: false` | 1 | 0 | 1.7% | 1.7% |
 * | starter policy + inference | 0 | 0 | 0.0% | 0.0% |
 *
 * Response leg: all 20 benign response cases reach an identical verdict with and without
 * inference — this module decorates `grantFor` and nothing else (`test/unit/infer.test.ts`).
 *
 * True positives, 17 capability-abuse calls on legitimate tools (`test/unit/infer.test.ts`):
 *
 * | configuration | caught | CATCH RATE |
 * |---|---|---|
 * | day-zero, no inference | 0 / 17 | **0.0%** |
 * | **day-zero + inference** | **16 / 17** | **94.1%** |
 * | hand-written starter policy | 17 / 17 | 100.0% |
 * | hand-written + inference | 17 / 17 | 100.0% |
 *
 * **Read the two numbers together, and read them honestly.** Inference does **not** beat a
 * hand-written policy — 94.1% against 100% — and it is not meant to. What it beats is *what is
 * actually installed*, which is no policy file at all and therefore a 0.0% catch rate. It buys 16
 * of the 17 attacks for zero measured false positives and zero configuration.
 *
 * The single case it misses is documented and asserted as a miss, so the gap can neither silently
 * close nor silently widen: an exfiltration POST to an unlisted host. That one is **not
 * inferable** — nothing on the wire says which hosts your deployment trusts, and a guessed
 * allowlist is either useless or an outage. **A declared `egress` block is what catches it, and
 * the README must keep saying so.** Inference is the floor, not the ceiling.
 *
 * It was two until the default deny list landed (`deniedDestination` in `./hosts.ts`). The
 * `169.254.169.254` cloud-metadata SSRF *was* closable without configuration because its
 * enumeration is closed: a fixed, published set of magic addresses no legitimate tool argument
 * names, unlike an attacker-chosen hostname. What did NOT change is `allowPrivateNetwork: true` in
 * the inferred grant. Denying loopback at zero configuration would be a false positive on one of
 * the commonest benign destinations a developer's session has, and the benign corpus carries
 * `http://127.0.0.1:3000` for exactly that reason. Metadata and link-local space are denied;
 * loopback and RFC1918 are not. Measured cost of that split on the 63-case benign corpus: 0
 * blocked, 0 friction — `toolwall/egress.denied-destination` appears nowhere in its report — and
 * the loopback/RFC1918 side of the split is asserted directly in `test/unit/hosts.test.ts`.
 */

/* ------------------------------------------------------------------ */
/* Options                                                             */
/* ------------------------------------------------------------------ */

/**
 * How a session-observation window is used once it closes.
 *
 * `"off"` is the default and the shipped posture. The mechanism below is safe by construction
 * (see `SessionObserver`), but its false-positive cost is a function of *session shape* — a tool
 * that legitimately first touches the filesystem on call 21 — and a single-shot benign corpus
 * cannot measure that. `docs/ARCHITECTURE.md` "Non-negotiables" #2 says every detector reports a
 * measured FP rate on a benign corpus; we do not default on a control whose cost we have not
 * counted. It is implemented, tested, and available to operators who want it.
 */
export type ObservationMode = "off" | "record" | "revoke";

export interface InferenceOptions {
  /**
   * Filesystem roots an inferred grant permits. Defaults to `[process.cwd()]` — the directory the
   * client was working in when it spawned the proxy, i.e. the project the user is actually on.
   */
  readonly roots?: readonly string[];
  /**
   * Union the system temp directory into the inferred roots. Default `true`.
   *
   * Honest trade, stated because it is a real weakening: build tools, editors and formatters write
   * to `os.tmpdir()` constantly, so excluding it produces false positives on ordinary work. It also
   * means an inferred grant does not stop a tool being directed to write into `/tmp`. `/tmp` is not
   * where credentials live — `~/.ssh`, `~/.aws`, `~/.config` and `/etc` are, and those stay out of
   * the inferred roots. The FP harness reports the number both ways.
   */
  readonly includeTempDir?: boolean;
  /** URL schemes an inferred network grant permits. See `INFERRED_SCHEMES`. */
  readonly schemes?: readonly string[];
  /** See `ObservationMode`. Default `"off"`. */
  readonly observation?: ObservationMode;
  /** Calls per tool before the learning window closes. Default 20. */
  readonly learnCalls?: number;
  /** Wall-clock milliseconds before the learning window closes. Default 10 minutes. */
  readonly learnMs?: number;
  /** Injectable clock, so the window is testable without waiting. */
  readonly now?: () => number;
  readonly probe?: FsProbe;
  /** Informational records (what was inferred, what a window revoked) go here. */
  readonly audit?: AuditSink;
  readonly era?: ProtocolEra;
}

/**
 * Schemes an inferred network grant permits.
 *
 * The exclusions are the point: `file:`, `data:`, `jar:`, `netdoc:` and `gopher:` handed to a tool
 * whose contract declares a *network* argument are a filesystem read or an SSRF primitive wearing a
 * URL. A tool that legitimately needs one of them is one `network.schemes` line away.
 */
export const INFERRED_SCHEMES: readonly string[] = ["http", "https", "ws", "wss"];

const DEFAULT_LEARN_CALLS = 20;
const DEFAULT_LEARN_MS = 10 * 60_000;

/* ------------------------------------------------------------------ */
/* Name lexicons                                                       */
/* ------------------------------------------------------------------ */

/**
 * Property names that denote a filesystem location.
 *
 * An **allowlist of whole names**, not a substring or suffix heuristic. `substring("path")` would
 * bind `revision_range`-adjacent things like `pathspec`, and — worse — would bind free-text fields
 * whose names merely contain the token. Whole-name matching is the difference between a contract
 * reading and a guess.
 */
const PATH_NAMES: ReadonlySet<string> = new Set([
  "path",
  "paths",
  "filepath",
  "file_path",
  "filepaths",
  "file_paths",
  "file",
  "files",
  "dir",
  "dirs",
  "directory",
  "directories",
  "folder",
  "folders",
  "source",
  "src",
  "source_path",
  "src_path",
  "destination",
  "dest",
  "dest_path",
  "destination_path",
  "target_path",
  "output_path",
  "out_path",
  "input_path",
  "in_path",
  "repo_path",
  "repository_path",
  "project_path",
  "base_path",
  "root_path",
  "local_path",
  "absolute_path",
  "full_path",
  "cwd",
  "workdir",
  "working_dir",
  "working_directory",
  "workspace",
  "workspace_path",
  "workspace_root",
  "project_root",
  "root",
  "repo",
  "repository",
]);

/**
 * Names that denote a **base directory** the tool resolves its other path arguments against.
 *
 * This encodes `docs/ARCHITECTURE.md` C-7 as an inference rule rather than as a footnote: when a
 * tool declares one of these, its *other* path-shaped arguments are pathspecs relative to it, not
 * filesystem paths relative to our `baseDir`, and binding them produces false escapes. `git_diff`
 * is the canonical case — `repo_path` plus `paths: ["../shared/src/index.ts"]`, where every entry
 * resolves correctly inside the repo and incorrectly outside our base.
 *
 * So: when an anchor is present, **only the anchor is bound.** We enforce containment on the one
 * argument whose resolution base we know, and record the rest as unenforceable.
 */
const ANCHOR_NAMES: ReadonlySet<string> = new Set([
  "repo_path",
  "repository_path",
  "repo",
  "repository",
  "cwd",
  "workdir",
  "working_dir",
  "working_directory",
  "project_path",
  "project_root",
  "root",
  "root_path",
  "base_path",
  "directory",
  "dir",
  "folder",
  "workspace",
  "workspace_path",
  "workspace_root",
]);

/** Path names that denote a destination the tool writes to. Narrowed away by `readOnlyHint`. */
const WRITE_NAMES: ReadonlySet<string> = new Set([
  "destination",
  "dest",
  "dest_path",
  "destination_path",
  "target_path",
  "output_path",
  "out_path",
]);

/** `format` values that mean "network destination". */
const URL_FORMATS: ReadonlySet<string> = new Set(["uri", "iri", "url"]);
const HOST_FORMATS: ReadonlySet<string> = new Set(["hostname", "idn-hostname", "host-name"]);
/** `format` values that mean "filesystem location" regardless of the property's name. */
const PATH_FORMATS: ReadonlySet<string> = new Set(["path", "file-path", "filepath", "directory-path", "dir-path"]);
/**
 * `format` values that positively rule a property OUT of being a path, even when its name is in
 * `PATH_NAMES`. A `source` declared `format: "email"` is not a directory.
 */
const NON_PATH_FORMATS: ReadonlySet<string> = new Set([
  "uri",
  "iri",
  "url",
  "uri-reference",
  "uri-template",
  "hostname",
  "idn-hostname",
  "host-name",
  "email",
  "idn-email",
  "date",
  "time",
  "date-time",
  "duration",
  "uuid",
  "regex",
  "ipv4",
  "ipv6",
  "json-pointer",
  "relative-json-pointer",
  "binary",
  "byte",
  "password",
]);

/* ------------------------------------------------------------------ */
/* Profile                                                             */
/* ------------------------------------------------------------------ */

export type InferenceSignal = "schema-format" | "schema-name" | "annotation" | "spec-default" | "observation";

/** One inference, with the evidence that produced it. Surfaced so a user can audit the profile. */
export interface InferenceReason {
  readonly capability: "filesystem" | "network" | "none";
  readonly signal: InferenceSignal;
  /** JSON Pointer selector this reason produced, or `""` when it produced none. */
  readonly selector: string;
  readonly detail: string;
}

/** The capability profile derived for one tool from its pinned definition. */
export interface CapabilityProfile {
  readonly toolName: string;
  readonly readPath: readonly string[];
  readonly writePath: readonly string[];
  readonly host: readonly string[];
  /** `url`-role selectors the tool's own `format: "uri"` declarations produce. */
  readonly url: readonly string[];
  /** `undefined` when the contract declares no filesystem-shaped argument. */
  readonly filesystem: FilesystemGrant | undefined;
  /** `undefined` when the contract declares no network-shaped argument. */
  readonly network: NetworkGrant | undefined;
  /** Base-directory arguments found; their presence unbinds the tool's other path arguments (C-7). */
  readonly anchors: readonly string[];
  readonly reasons: readonly InferenceReason[];
}

function escapeToken(t: string): string {
  return t.replace(/~/g, "~0").replace(/\//g, "~1");
}

function typesOf(node: JsonSchemaNode): readonly string[] {
  const t = node["type"];
  if (typeof t === "string") return [t];
  if (Array.isArray(t)) return t.filter((x): x is string => typeof x === "string");
  return [];
}

function formatOf(node: JsonSchemaNode): string | undefined {
  const f = node["format"];
  return typeof f === "string" ? f.toLowerCase() : undefined;
}

function isPlainObject(v: unknown): v is JsonSchemaNode {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

interface Candidate {
  /** Top-level property name, unescaped. */
  readonly name: string;
  /** JSON Pointer selector into the arguments object. */
  readonly selector: string;
  /** The schema node carrying `format` / `enum` — the array item node for arrays. */
  readonly leaf: JsonSchemaNode;
  readonly isArray: boolean;
}

/**
 * Top-level string properties (and arrays of strings) of the tool's `inputSchema`.
 *
 * **Top level only**, deliberately. Real path and host arguments live at the top of the arguments
 * object; nested ones are almost always payload. The benign corpus contains the exact counter-case
 * that justifies the restriction: `store_entity.metadata.source` is a *citation URL* nested one
 * level down, and a name-based rule that recursed would bind it as a filesystem path. `url` roles
 * are exempt because they come from `format: "uri"` — a declaration, not a name — and
 * `deriveUrlSelectors` already walks nested schemas with a measured 0.0% FP rate.
 */
function candidates(tool: ToolDefinition): Candidate[] {
  const out: Candidate[] = [];
  const props = tool.inputSchema["properties"];
  if (!isPlainObject(props)) return out;

  for (const [name, raw] of Object.entries(props)) {
    if (!isPlainObject(raw)) continue;
    const types = typesOf(raw);
    if (types.includes("string")) {
      out.push({ name, selector: `/${escapeToken(name)}`, leaf: raw, isArray: false });
      continue;
    }
    if (types.includes("array")) {
      const items = raw["items"];
      if (!isPlainObject(items)) continue;
      const itemTypes = typesOf(items);
      // An untyped `items: {}` is not a string declaration; `query.params` is exactly that shape.
      if (!itemTypes.includes("string")) continue;
      out.push({ name, selector: `/${escapeToken(name)}/*`, leaf: items, isArray: true });
    }
  }
  return out;
}

function canonicalRoots(opts: InferenceOptions): string[] {
  const probe = opts.probe ?? nodeFsProbe;
  const declared = opts.roots ?? [process.cwd()];
  const all = (opts.includeTempDir ?? true) ? [...declared, os.tmpdir()] : [...declared];
  const out: string[] = [];
  for (const r of all) {
    const c = canonicalizeRoot(r, probe);
    // A root that cannot be canonicalized is dropped rather than guessed at. Dropping narrows the
    // grant, which is the safe direction; guessing would widen it.
    if (c.ok && !out.includes(c.path)) out.push(c.path);
  }
  return out;
}

/**
 * Derive the capability profile for one tool from its **pinned** definition.
 *
 * Pure and synchronous apart from one canonicalization of the roots, which the caller caches.
 */
export function inferProfile(tool: ToolDefinition, opts: InferenceOptions = {}, roots?: readonly string[]): CapabilityProfile {
  const resolvedRoots = roots ?? canonicalRoots(opts);
  const reasons: InferenceReason[] = [];

  // --- annotations, as a NARROWING signal only ---------------------------
  // Spec defaults (RESEARCH-BRIEF §1.4): unannotated => destructiveHint: true, openWorldHint: true.
  // Neither default, and neither claim, can grant a capability here. `openWorldHint: true` — the
  // default, and what a hostile server would assert — produces no network grant whatsoever; only a
  // `format: "uri"`/`"hostname"` property does. The single thing an annotation does below is push
  // a write-named path argument down to a read role when the server claims `readOnlyHint: true`,
  // which can only ever reduce what the tool may do.
  const readOnlyClaimed = tool.annotations?.readOnlyHint === true;
  if (readOnlyClaimed) {
    reasons.push({
      capability: "filesystem",
      signal: "annotation",
      selector: "",
      detail: 'server claims readOnlyHint: true; write-named path arguments are classified as read. Narrowing only — an annotation can never grant, widen or admit anything here.',
    });
  }
  if (tool.annotations === undefined || Object.keys(tool.annotations).length === 0) {
    reasons.push({
      capability: "none",
      signal: "spec-default",
      selector: "",
      detail: "tool declares no annotations; per spec that is destructiveHint: true and openWorldHint: true. Absence is the dangerous configuration, and it grants nothing.",
    });
  }

  const cands = candidates(tool);

  // --- anchors (C-7) -----------------------------------------------------
  const anchors = cands
    .filter((c) => !c.isArray && ANCHOR_NAMES.has(c.name.toLowerCase()) && pathShape(c) !== "none")
    .map((c) => c.name);

  const readPath: string[] = [];
  const writePath: string[] = [];
  const host: string[] = [];

  for (const c of cands) {
    const fmt = formatOf(c.leaf);
    const lower = c.name.toLowerCase();

    if (fmt !== undefined && HOST_FORMATS.has(fmt)) {
      host.push(c.selector);
      reasons.push({ capability: "network", signal: "schema-format", selector: c.selector, detail: `format: "${fmt}"` });
      continue;
    }
    if (fmt !== undefined && URL_FORMATS.has(fmt)) {
      // Recorded for completeness; the selector itself comes from `deriveUrlSelectors`, which is
      // already wired through `ArgumentRoles.deriveUrlFromSchema`.
      reasons.push({ capability: "network", signal: "schema-format", selector: c.selector, detail: `format: "${fmt}"` });
      continue;
    }

    const shape = pathShape(c);
    if (shape === "none") continue;

    if (anchors.length > 0 && !ANCHOR_NAMES.has(lower)) {
      reasons.push({
        capability: "filesystem",
        signal: "schema-name",
        selector: "",
        detail: `"${c.name}" is path-shaped but the tool also declares the base directory "${anchors[0] ?? ""}", so it is a pathspec relative to that argument and NOT to our baseDir. Left unbound (C-7): binding it would resolve against the wrong base and manufacture a false escape.`,
      });
      continue;
    }

    const write = WRITE_NAMES.has(lower) && !readOnlyClaimed;
    (write ? writePath : readPath).push(c.selector);
    reasons.push({
      capability: "filesystem",
      signal: shape === "format" ? "schema-format" : "schema-name",
      selector: c.selector,
      detail: shape === "format" ? `format: "${fmt ?? ""}"` : `property name "${c.name}" denotes a filesystem location`,
    });
  }

  const urlSelectors = deriveUrlSelectors(tool);

  const filesystem: FilesystemGrant | undefined =
    readPath.length > 0 || writePath.length > 0
      ? {
          read: resolvedRoots,
          write: resolvedRoots,
          deny: [],
          followSymlinksOutOfRoot: false,
          // Required, not optional: every tool that creates a file passes a path that does not
          // exist yet, and rejecting those blocks the first useful call anyone makes.
          allowNonexistent: true,
        }
      : undefined;

  const network: NetworkGrant | undefined =
    urlSelectors.length > 0 || host.length > 0
      ? {
          // `ANY_HOST` — inference cannot know your hosts and will not pretend to. What this grant
          // enforces is the scheme; host allowlisting stays an operator declaration.
          hosts: [ANY_HOST],
          schemes: opts.schemes ?? INFERRED_SCHEMES,
          // Both true, and both are honest admissions rather than oversights. Localhost dev
          // servers are a large share of the HTTP traffic in a real MCP session — the benign corpus
          // carries `http://127.0.0.1:3000` for that reason — and denying private addresses at zero
          // configuration would break local workflows wholesale. Inference therefore provides no
          // *general* SSRF protection;
          // `network.allowPrivateNetwork: false` in a policy file does.
          allowPrivateNetwork: true,
          allowIpLiterals: true,
          // The one exception, and the reason it is an exception rather than an inconsistency: the
          // deny list (`deniedDestination` in ./hosts.ts) covers cloud instance-metadata endpoints
          // and link-local space only. Nobody's dev server is on `169.254.169.254`, so denying it
          // costs zero benign calls — measured 0/63, on a corpus carrying four single-label
          // internal service names precisely so this rule could fail against them — while closing
          // IMDS credential theft, which
          // was the single highest-value network-leg attack inference used to miss.
          allowMetadataEndpoints: false,
        }
      : undefined;

  if (filesystem === undefined && network === undefined) {
    reasons.push({
      capability: "none",
      signal: "schema-name",
      selector: "",
      detail: "the pinned inputSchema declares no path-shaped and no network-shaped argument, so this tool is profiled as needing neither capability.",
    });
  }

  return { toolName: tool.name, readPath, writePath, host, url: urlSelectors, filesystem, network, anchors, reasons };

  function pathShape(c: Candidate): "format" | "name" | "none" {
    const fmt = formatOf(c.leaf);
    if (fmt !== undefined && PATH_FORMATS.has(fmt)) return "format";
    if (fmt !== undefined && NON_PATH_FORMATS.has(fmt)) return "none";
    // A closed value set is a mode selector, not a free-form location.
    if (Array.isArray(c.leaf["enum"])) return "none";
    return PATH_NAMES.has(c.name.toLowerCase()) ? "name" : "none";
  }
}

/* ------------------------------------------------------------------ */
/* Session observation — learn, then enforce                           */
/* ------------------------------------------------------------------ */

export interface ObservationWindow {
  readonly firstCallAt: number;
  readonly calls: number;
  readonly closed: boolean;
  readonly usedFilesystem: boolean;
  readonly usedNetwork: boolean;
}

/**
 * **Learn-then-enforce, and the reason it cannot be gamed.**
 *
 * Per `(serverId, toolName)` a window opens on the first call and closes **permanently** at the
 * first call where `calls >= learnCalls` **or** `now - firstCallAt >= learnMs` — whichever comes
 * first. While it is open, we record only *which capabilities were exercised*. When it closes, a
 * capability that was never exercised is revoked for the rest of the session.
 *
 * The security property, stated precisely because "learn-then-enforce" is exactly the shape that
 * usually hides a bypass:
 *
 *  1. **Observation is monotonically restrictive.** The schema-derived profile is the ceiling and
 *     nothing observed ever raises it. Hosts seen on the wire do NOT become an allowlist; paths
 *     seen do NOT become roots. Observation can only subtract.
 *  2. **Therefore an extended window is worth nothing to an attacker.** Both bounds are monotone
 *     in attacker effort — more calls or more elapsed time only close the window *sooner*, and
 *     there is no message that reopens it. The best an attacker can do is keep it open by staying
 *     idle, and an infinitely open window is exactly equivalent to `observation: "off"`, i.e. to
 *     the pinned contract's ceiling. There is no state in which observation grants more than the
 *     pinned contract already did.
 *  3. **A rug pull does not reopen it.** The window is keyed on the tool *name*, not on the
 *     definition, so mutating the definition cannot restart learning. (The mutation is blocked by
 *     `MetadataPinGuard` first regardless — C-10 puts identity before content.)
 *  4. **Blocked calls do not teach.** `observe()` takes an `allowed` flag; a call the guard
 *     refused never marks a capability as exercised, so an attacker cannot preserve a capability
 *     for later by making one denied attempt at it during the window.
 */
export class SessionObserver {
  readonly #mode: ObservationMode;
  readonly #learnCalls: number;
  readonly #learnMs: number;
  readonly #now: () => number;
  readonly #audit: AuditSink | undefined;
  readonly #era: ProtocolEra;
  readonly #windows = new Map<string, { firstCallAt: number; calls: number; closed: boolean; usedFilesystem: boolean; usedNetwork: boolean }>();

  constructor(opts: InferenceOptions = {}) {
    this.#mode = opts.observation ?? "off";
    this.#learnCalls = opts.learnCalls ?? DEFAULT_LEARN_CALLS;
    this.#learnMs = opts.learnMs ?? DEFAULT_LEARN_MS;
    this.#now = opts.now ?? Date.now;
    this.#audit = opts.audit;
    this.#era = opts.era ?? DEFAULT_PROTOCOL_ERA;
  }

  get mode(): ObservationMode {
    return this.#mode;
  }

  window(serverId: string, toolName: string): ObservationWindow | undefined {
    return this.#windows.get(`${serverId} ${toolName}`);
  }

  /**
   * Record one call against the learning window.
   *
   * `exercised` is what the CALLER measured against the inferred roles — the observer never looks
   * at arguments itself, so it cannot become a second, value-inspecting code path.
   */
  observe(
    serverId: string,
    toolName: string,
    exercised: { readonly filesystem: boolean; readonly network: boolean },
    allowed = true,
  ): void {
    if (this.#mode === "off") return;
    const key = `${serverId} ${toolName}`;
    const now = this.#now();
    const w = this.#windows.get(key) ?? { firstCallAt: now, calls: 0, closed: false, usedFilesystem: false, usedNetwork: false };
    this.#windows.set(key, w);
    if (w.closed) return;

    w.calls += 1;
    if (allowed) {
      if (exercised.filesystem) w.usedFilesystem = true;
      if (exercised.network) w.usedNetwork = true;
    }

    if (w.calls >= this.#learnCalls || now - w.firstCallAt >= this.#learnMs) {
      w.closed = true;
      this.#audit?.(
        [
          {
            ruleId: "toolwall/infer.window-closed",
            severity: "info",
            locus: "",
            message: `Learning window for "${toolName}" closed after ${w.calls} call(s). Observed capabilities: filesystem=${w.usedFilesystem}, network=${w.usedNetwork}.`,
            remediation:
              this.#mode === "revoke"
                ? "Capabilities not observed during the window are now revoked for this session. Restart the session, or declare the capability in toolwall-policy.json, if the tool legitimately needs it later."
                : 'Recording only (observation: "record"). Set observation: "revoke" to enforce.',
            evidence: { tool: toolName, serverId, calls: w.calls, usedFilesystem: w.usedFilesystem, usedNetwork: w.usedNetwork, mode: this.#mode },
          },
        ],
        { era: this.#era, serverId, direction: "request", method: "tools/call" },
      );
    }
  }

  /** Apply a closed window's narrowing. Never widens; returns the input unchanged when `"off"`. */
  narrow(grant: CapabilityGrant, profile: CapabilityProfile, serverId: string): CapabilityGrant {
    if (this.#mode !== "revoke") return grant;
    const w = this.#windows.get(`${serverId} ${profile.toolName}`);
    if (w === undefined || !w.closed) return grant;

    let out = grant;
    if (profile.filesystem !== undefined && !w.usedFilesystem && out.filesystem === profile.filesystem) {
      out = { ...out, filesystem: { ...profile.filesystem, read: [], write: [] } };
    }
    if (profile.network !== undefined && !w.usedNetwork && out.network === profile.network) {
      out = { ...out, network: { ...profile.network, hosts: [], schemes: [] } };
    }
    return out;
  }
}

/* ------------------------------------------------------------------ */
/* The policy decorator                                                */
/* ------------------------------------------------------------------ */

export interface InferredPolicy extends ResolvedPolicy {
  /** The learning window, for callers that wire observation. Inert when `observation: "off"`. */
  readonly observer: SessionObserver;
  /** The profile in force for a tool, for reporting and for tests. */
  profileFor(serverId: string, toolName: string): CapabilityProfile | undefined;
  /** Every profile computed so far this session — what a `--explain` command would print. */
  profiles(): ReadonlyMap<string, CapabilityProfile>;
}

/** True when the operator, not a tier preset, is the source of this capability. */
function operatorDeclaredFilesystem(grant: CapabilityGrant): boolean {
  return grant.filesystem !== undefined || grant.roles.readPath.length > 0 || grant.roles.writePath.length > 0;
}
function operatorDeclaredNetwork(grant: CapabilityGrant): boolean {
  return grant.network !== undefined || grant.roles.url.length > 0 || grant.roles.host.length > 0;
}

/**
 * Wrap a `ResolvedPolicy` so that tools with no operator declaration get their inferred capability
 * profile instead of nothing.
 *
 * Everything other than `grantFor` — `egressFor`, `responseFor`, `confirmation`, `tier` — is
 * delegated verbatim. Inference changes what a tool may *touch*; it does not touch the response
 * leg, the egress declaration or the confirmation budget.
 *
 * `tools` MUST be the pin-backed source (C-1). A tool with no pinned definition gets no profile at
 * all: inferring from a live, attacker-mutable listing would let a server widen its own schema and
 * mint itself a capability, which is precisely the rug pull the pin store exists to stop.
 */
export function inferredPolicy(base: ResolvedPolicy, tools: ToolDefinitionSource, opts: InferenceOptions = {}): InferredPolicy {
  const roots = canonicalRoots(opts);
  const observer = new SessionObserver(opts);
  const cache = new Map<string, { tool: ToolDefinition; profile: CapabilityProfile }>();
  const audit = opts.audit;
  const era = opts.era ?? DEFAULT_PROTOCOL_ERA;
  const announced = new Set<string>();

  function profileFor(serverId: string, toolName: string): CapabilityProfile | undefined {
    const tool = tools.get(serverId, toolName);
    if (tool === undefined) return undefined;
    const key = `${serverId} ${toolName}`;
    const hit = cache.get(key);
    // Identity comparison, not a deep hash: the pin store hands back the same stored object for the
    // same pin, and a changed object means a changed pin, which must not reuse a stale profile.
    if (hit !== undefined && hit.tool === tool) return hit.profile;
    const profile = inferProfile(tool, opts, roots);
    cache.set(key, { tool, profile });
    if (audit !== undefined && !announced.has(key)) {
      announced.add(key);
      audit([describeProfile(serverId, profile)], { era, serverId, direction: "request", method: "tools/call" });
    }
    return profile;
  }

  return {
    tier: base.tier,
    confirmation: base.confirmation,
    egressFor: (serverId) => base.egressFor(serverId),
    responseFor: (serverId) => base.responseFor(serverId),
    observer,
    profileFor,
    profiles: () => new Map([...cache].map(([k, v]) => [k, v.profile])),
    grantFor(serverId, toolName) {
      const { grant, known } = base.grantFor(serverId, toolName);
      const profile = profileFor(serverId, toolName);
      if (profile === undefined) return { grant, known };

      const fsDeclared = operatorDeclaredFilesystem(grant);
      const netDeclared = operatorDeclaredNetwork(grant);
      if (fsDeclared && netDeclared) return { grant, known };

      const roles: ArgumentRoles = {
        readPath: fsDeclared ? grant.roles.readPath : profile.readPath,
        writePath: fsDeclared ? grant.roles.writePath : profile.writePath,
        url: grant.roles.url,
        host: netDeclared ? grant.roles.host : profile.host,
        deriveUrlFromSchema: grant.roles.deriveUrlFromSchema,
      };

      let merged: CapabilityGrant = {
        ...grant,
        roles,
        filesystem: fsDeclared ? grant.filesystem : profile.filesystem,
        // `deriveUrlFromSchema: false` is an operator turning URL derivation off; honour it by
        // withholding the grant that would enforce against selectors we are no longer deriving.
        network: netDeclared || !grant.roles.deriveUrlFromSchema ? grant.network : profile.network,
      };

      merged = observer.narrow(merged, profile, serverId);
      return { grant: merged, known };
    },
  };
}

function describeProfile(serverId: string, p: CapabilityProfile): Finding {
  const fs = p.filesystem === undefined ? "none" : `${p.readPath.length + p.writePath.length} path argument(s), ${p.filesystem.read.length} root(s)`;
  const net = p.network === undefined ? "none" : `${p.url.length + p.host.length} network argument(s), schemes ${p.network.schemes.join("/")}`;
  return {
    ruleId: "toolwall/infer.profile",
    severity: "info",
    locus: "",
    message: `Inferred capability profile for "${p.toolName}" from its pinned inputSchema — filesystem: ${fs}; network: ${net}.`,
    remediation:
      `Inference is a floor, not a ceiling: declare servers["${serverId}"].tools["${p.toolName}"] in toolwall-policy.json to override it. ` +
      "An explicit declaration always wins.",
    evidence: {
      tool: p.toolName,
      serverId,
      readPath: [...p.readPath],
      writePath: [...p.writePath],
      host: [...p.host],
      url: [...p.url],
      anchors: [...p.anchors],
      roots: p.filesystem?.read.length ?? 0,
      reasons: p.reasons.map((r) => `${r.capability}:${r.signal}${r.selector === "" ? "" : ` ${r.selector}`} — ${r.detail}`),
    },
  };
}

/**
 * Which capabilities a set of arguments actually exercised, measured against an inferred profile.
 *
 * Exported so the caller that wires observation does not have to reimplement role collection (and
 * so the observer itself never grows an argument-inspection path).
 */
export function exercisedCapabilities(
  targets: readonly { readonly role: string }[],
): { readonly filesystem: boolean; readonly network: boolean } {
  return {
    filesystem: targets.some((t) => t.role === "readPath" || t.role === "writePath"),
    network: targets.some((t) => t.role === "url" || t.role === "host"),
  };
}
