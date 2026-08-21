/**
 * Drift detection — the enforcement half of the pinning engine (T-02, threat rank #1).
 *
 * ## Where verification happens, and why it matters
 *
 * Existing tooling verifies tool definitions at first connect and stops. Trail of Bits'
 * `mcp-context-protector` pins at connect; Pillar's *Deadbugz* campaign mutates after **three
 * tool calls**, walking straight through that gap. So this guard re-verifies **before every
 * `tools/call`**, not at a handshake and not at first connect. Under the 2026-07-28 revision
 * there is no handshake left to pin at anyway (`initialize` was removed), so continuous
 * verification is not merely stronger, it is the only remaining option.
 *
 * ## How it stays inside the 5ms hot-path budget
 *
 * Canonicalization and hashing happen once, when a `tools/list` response is observed. The
 * per-call path is two `Map` lookups and a comparison of two 71-byte hash strings — no
 * re-serialization, no cloning, no I/O, no work proportional to payload size.
 *
 * ## Never auto-accept
 *
 * A hash mismatch produces `block`, a field-level diff, and a quarantine entry. It never
 * updates the pin. Re-approval goes through `approveQuarantined()`, which requires a named
 * human decider and is refused for anything automated. Auto-accepting drift is precisely
 * CVE-2025-54136 (Cursor, CVSS 7.2), where approval was keyed on file identity rather than on
 * content, so a swapped config inherited the old approval.
 *
 * ## What this catches, stated precisely
 *
 * The pin is compared against **the definition the model is actually working from** — the last
 * one that crossed this proxy. Three consequences worth being explicit about, because the
 * difference between them is the difference between a real control and a marketing claim:
 *
 *   1. A mutated `tools/list` is caught the moment it crosses the proxy, whether or not the
 *      server sent `notifications/tools/list_changed` first. We never trust the notification to
 *      tell us something changed.
 *   2. A `list_changed` notification with no re-list afterwards marks the cached catalogue
 *      **stale**, and calls against a stale catalogue are unverifiable rather than allowed. The
 *      server has told us its definitions moved and we no longer know what the client holds.
 *   3. A server that mutates *silently* and is never re-listed is not caught before the next
 *      listing — and until that listing happens the mutated text has not reached the model
 *      either, because the client is still holding the definition we pinned. The exposure
 *      begins at the next listing, which is exactly where case 1 catches it. Forcing a re-list
 *      of our own would close the window earlier; that needs the transport to originate a
 *      request and is not Week 1.
 *
 * ## What this does not do
 *
 * Pinning answers "did this definition change since you approved it" with certainty. It says
 * nothing about whether the original definition was safe: a tool that is malicious on first
 * sight is pinned as-is under trust-on-first-use. That is the known weakness of TOFU and the
 * reason `mode: "strict"` exists. Judging whether a definition is *hostile* is the job of the
 * Week 2 detectors, and those are heuristics with a false-positive rate, not proofs.
 *
 * ## The pin-time assessment
 *
 * Because that weakness is real and every supply-chain case in T-09 is a *first-sighting* attack,
 * this guard runs `assessPinCandidate()` (see `./assess.ts`) exactly once, at the moment a pin
 * decision is actually pending — never on a listing whose every subject is already pinned, and
 * never on `tools/call`. The result rides on the `pinned` event as {@link PinEvent.assessment}
 * under TOFU, and is rendered into the `toolwall/pin-unpinned` finding under `strict`, which is
 * the confirmation prompt a human answers.
 *
 * It changes no verdict. Nothing in this guard blocks on an aggregate, and the assessment does not
 * produce one to block on.
 */
import type { PinCandidate, PinRiskAssessment } from "./assess.js";
import { assessPinCandidate, assessmentFinding } from "./assess.js";
import type { CanonicalizeOptions } from "./canonicalize.js";
import { CANONICALIZATION_VERSION, CanonicalizationError, canonicalizeAndHash } from "./canonicalize.js";
import type { FieldDiff } from "./diff.js";
import { classifyChange, diffValues, renderDriftAlert, renderFieldDiffs } from "./diff.js";
import type { PinKind } from "./surface.js";
import {
  SERVER_INSTRUCTIONS_SUBJECT,
  extractServerSurface,
  extractToolSurface,
  readCallToolName,
  readToolList,
} from "./surface.js";
import type { PinDecision, PinRecord, PinScope, PinStore } from "../../audit/manifest.js";
import { DEFAULT_PIN_SCOPE } from "../../audit/manifest.js";
import type { ProvenanceReport } from "../../audit/provenance.js";
import type { Finding, Guard, GuardContext, ProtocolEra, Verdict } from "../../types/protocol.js";
import { ALLOW, TOOLWALL_BLOCKED, renderText, rendered, type Rendered } from "../../types/protocol.js";

/** Methods whose *response* carries a server's pinned surface, by era. */
const SERVER_DESCRIPTOR_METHODS: Readonly<Record<ProtocolEra, string>> = {
  // `initialize` still exists in the deployed 2025-11-25 SDK and carries `instructions`.
  "2025-11-25": "initialize",
  // 2026-07-28 removed the handshake; `server/discover` is mandatory and carries `instructions`.
  "2026-07-28": "server/discover",
};

const LIST_CHANGED_NOTIFICATION = "notifications/tools/list_changed";

export type PinEventKind =
  | "pinned"
  | "verified"
  | "drift"
  | "unverifiable"
  | "withdrawn"
  | "stale"
  | "algorithm-changed"
  | "malformed"
  /**
   * The listing declared `cacheScope: "public"`, meaning intermediaries MAY serve it **across
   * authorization contexts** (RESEARCH-BRIEF §1.4). That is a cache-poisoning surface a proxy has
   * to reason about explicitly rather than inherit: a listing fetched under one credential can be
   * replayed to another, and scope-keyed pins do not help if the listing never reaches us again.
   */
  | "cache-public"
  /**
   * A listing declared a `ttlMs`, so the client is entitled to cache it and **the proxy will not
   * see every fetch**. Recorded because it bounds what "we observe every listing" can mean.
   */
  | "cache-ttl";

export interface PinEvent {
  readonly kind: PinEventKind;
  readonly serverId: string;
  /** Authorization context, or {@link DEFAULT_PIN_SCOPE} when there is none. */
  readonly scope: PinScope;
  readonly pinKind: PinKind;
  readonly subject: string;
  readonly message: string;
  /**
   * The pin-time risk assessment, on the FIRST `pinned` event of a listing that adopted anything.
   *
   * Present only on `"pinned"`, only once per listing, and only when the assessment ran — which it
   * does whenever a pin decision was actually pending. `message` already carries its one-line
   * headline, so a consumer that ignores this field still gets the summary in the audit log; a
   * consumer that reads it gets `assessment.rendered`, the full report.
   *
   * Additive and optional on purpose: nothing that already consumes `PinEvent` has to change, and
   * no new event kind was introduced, so the pin event stream is byte-identical for any consumer
   * that does not ask for this.
   */
  readonly assessment?: PinRiskAssessment;
}

export interface DriftReport {
  readonly serverId: string;
  /** Authorization context the drifted listing arrived under. */
  readonly scope: PinScope;
  readonly pinKind: PinKind;
  readonly subject: string;
  readonly pinnedHash: string;
  readonly liveHash: string;
  readonly pinnedDefinition: unknown;
  readonly liveDefinition: unknown;
  readonly diffs: readonly FieldDiff[];
  readonly detectedAt: string;
  /** Rendered, invisible-character-safe diff. This is what a human is shown. */
  readonly rendered: string;
  /**
   * Scopes under which this exact `liveHash` is **already pinned**. Non-empty means the operator
   * is almost certainly looking at an authorization change rather than tampering: the bytes are
   * ones they already approved, just under a different credential. Stated in the alert, because
   * the difference between "your server was swapped" and "your token changed" is the whole
   * decision and getting it wrong in the loud direction is how drift alerts stop being read.
   */
  readonly alsoPinnedUnderScopes: readonly PinScope[];
}

export interface MetadataPinGuardOptions {
  readonly store: PinStore;
  readonly era: ProtocolEra;
  /**
   * `"tofu"` (default) pins the first definition seen and enforces from then on.
   * `"strict"` never pins automatically: an unpinned tool yields `confirm` until a human
   * approves it. Strict is the honest setting — TOFU cannot tell a benign first sighting from
   * a tool that was hostile before you ever saw it.
   */
  readonly mode?: "tofu" | "strict";
  /**
   * What to do when a `tools/call` arrives that cannot be checked against a pin — no pin, no
   * observed definition, or a catalogue the server has told us is stale. Default `"confirm"`.
   * `"allow"` disables the control for that case and should be justified in writing.
   */
  readonly onUnverifiable?: "block" | "confirm" | "allow";
  /**
   * JSON-RPC error code for a block. Defaults to `TOOLWALL_BLOCKED` (-32600). Anything in
   * -32020..-32099 is reserved for the MCP spec and gets rewritten by the pipeline, so do not
   * pick a code in that range.
   */
  readonly blockCode?: number;
  readonly now?: () => Date;
  readonly onEvent?: (event: PinEvent) => void;
  readonly canonicalizeOptions?: CanonicalizeOptions;
  /** Passed through to `extractToolSurface`; see `UNPINNED_TOOL_FIELDS`. */
  readonly unpinnedFields?: readonly string[];
  /**
   * Which authorization context this payload was fetched under. Defaults to
   * {@link DEFAULT_PIN_SCOPE}, which is correct for stdio (one process, one credential) and for
   * any HTTP connection that presents a single credential for its lifetime.
   *
   * ## Why this is an injected resolver rather than a field on `GuardContext`
   *
   * `2026-07-28` says `tools/list` MUST NOT vary per-connection but MAY vary by the authorization
   * presented (RESEARCH-BRIEF §4.5 item 6). Keying pins on the credential is therefore required
   * for correctness, not hardening: without it, a user narrowing their token from `repo:write` to
   * `repo:read` gets a critical rug-pull alarm on every tool, for doing the right thing.
   *
   * The credential itself is Dev 1's (`src/transport/`), and `GuardContext` carries no
   * authorization field today. Rather than reach across that boundary, this guard takes a
   * resolver. **Requested additive change to `GuardContext`, for Dev 1:** an optional
   * `authorizationScope?: string`, written by the transport from whatever credential it presented,
   * derived through {@link deriveScopeId} so no secret ever reaches a guard. When that lands, the
   * default here becomes `(ctx) => ctx.authorizationScope ?? DEFAULT_PIN_SCOPE` and this option
   * stays for callers with a bespoke notion of scope.
   *
   * The resolver MUST return a non-secret identifier. See `PinScope` in
   * `src/audit/manifest.ts`; `deriveScopeId` refuses credential-shaped input for this reason.
   */
  readonly resolveScope?: (ctx: GuardContext) => PinScope;
  /**
   * Pin-time risk assessment. **On by default** — it is pure, offline, bounded string work that
   * runs only when a pin decision is pending, and turning it off means a human is asked to grant
   * trust with nothing in front of them, which is the state this option exists to end.
   *
   * Pass `false` to disable it, or an object to feed it the two opt-in inputs it cannot obtain
   * for itself. Absent inputs are reported as "not checked" in the report rather than silently
   * omitted.
   */
  readonly assess?: false | PinAssessmentOptions;
}

/**
 * The inputs to {@link assessPinCandidate} that this guard cannot produce on its own.
 *
 * Both are opt-in elsewhere in the product and both stay opt-in here. Supplying neither is the
 * default and produces a report that says, in as many words, which two checks did not run.
 */
export interface PinAssessmentOptions {
  /**
   * Advisory `agent-threat-rules` findings for this payload. The scanner is the caller's
   * (`AtrScanner.create()`); this guard never constructs one, for the reasons in `./rules.ts`.
   */
  readonly atrFindings?: (payload: unknown, ctx: GuardContext) => readonly Finding[];
  /**
   * The completed T-09 provenance report for this server, when one exists.
   *
   * A function rather than a value because provenance is asynchronous and may not have finished
   * when the first listing arrives; returning `undefined` is the normal case and is reported as
   * "not checked", which is deliberately not the same thing as "clean".
   */
  readonly provenance?: (serverId: string) => ProvenanceReport | undefined;
}

interface LiveEntry {
  readonly hash: string;
  /** Detached, NFC-normalized copy of the definition. Never aliases the live payload. */
  readonly definition: unknown;
  readonly observedAt: string;
}

/**
 * A one-shot holder for the listing's assessment.
 *
 * Mutable and passed down on purpose: the report is about the listing, so exactly one of the
 * per-subject outcomes should carry it. Whichever gets there first takes it and empties the box.
 */
interface AssessmentBox {
  assessment: PinRiskAssessment | undefined;
}

interface ServerState {
  readonly entries: Map<string, LiveEntry>;
  /**
   * The server announced `tools/list_changed` and we have not seen a listing since, so the
   * cached entries no longer describe what the server is advertising.
   */
  stale: boolean;
}

/** Type-checks a finding literal at its construction site. */
function finding(f: Finding): Finding {
  return f;
}

function quarantineKey(
  serverId: string,
  scope: PinScope,
  kind: PinKind,
  subject: string,
): string {
  return `${serverId}\u0000${scope}\u0000${kind}\u0000${subject}`;
}

/**
 * Key into the per-connection cache of observed definitions. Scoped, for the same reason the
 * pin key is: the tool a narrow credential sees is not the tool a broad one sees, and letting
 * the two share a cache entry would make the last listing win regardless of which credential
 * fetched it.
 */
function subjectKey(scope: PinScope, kind: PinKind, subject: string): string {
  return `${scope}\u0000${kind}\u0000${subject}`;
}

export class MetadataPinGuard implements Guard {
  readonly name = "metadata.pin";

  readonly #store: PinStore;
  readonly #era: ProtocolEra;
  readonly #mode: "tofu" | "strict";
  readonly #onUnverifiable: "block" | "confirm" | "allow";
  readonly #blockCode: number;
  readonly #now: () => Date;
  readonly #onEvent: (event: PinEvent) => void;
  readonly #canonicalizeOptions: CanonicalizeOptions;
  readonly #unpinnedFields: readonly string[] | undefined;
  readonly #resolveScope: (ctx: GuardContext) => PinScope;

  readonly #assess: false | PinAssessmentOptions;

  /** serverId -> last observed definitions and their hashes. */
  readonly #live = new Map<string, ServerState>();
  /** Drift reports awaiting a human decision. Nothing listed here is callable. */
  readonly #quarantine = new Map<string, DriftReport>();
  /**
   * serverId -> the `instructions` this server sent, so a `tools/list` assessment can include the
   * highest-severity injection surface the spec has instead of reporting it as unavailable.
   */
  readonly #instructions = new Map<string, string>();
  /** serverId -> the most recent pin-time assessment, for an operator UI that wants to re-read it. */
  readonly #assessments = new Map<string, PinRiskAssessment>();

  constructor(options: MetadataPinGuardOptions) {
    this.#store = options.store;
    this.#era = options.era;
    this.#mode = options.mode ?? "tofu";
    this.#onUnverifiable = options.onUnverifiable ?? "confirm";
    this.#blockCode = options.blockCode ?? TOOLWALL_BLOCKED;
    this.#now = options.now ?? (() => new Date());
    this.#onEvent = options.onEvent ?? (() => undefined);
    this.#canonicalizeOptions = options.canonicalizeOptions ?? {};
    this.#unpinnedFields = options.unpinnedFields;
    this.#resolveScope = options.resolveScope ?? (() => DEFAULT_PIN_SCOPE);
    this.#assess = options.assess ?? {};
  }

  // -------------------------------------------------------------------------
  // Guard entry point
  // -------------------------------------------------------------------------

  /**
   * `payload` is the live object the transport will forward. This guard only ever reads it;
   * everything it retains is a detached copy produced by canonicalization.
   */
  inspect(payload: unknown, ctx: GuardContext): Verdict {
    if (ctx.direction === "response") {
      if (ctx.method === "tools/list") return this.observeToolList(payload, ctx);
      if (ctx.method === SERVER_DESCRIPTOR_METHODS[ctx.era]) {
        return this.observeServerDescriptor(payload, ctx);
      }
      if (ctx.method === LIST_CHANGED_NOTIFICATION) {
        this.#markStale(ctx.serverId, this.#resolveScope(ctx));
        return ALLOW;
      }
    }
    if (ctx.direction === "request" && ctx.method === "tools/call") {
      return this.verifyToolCall(payload, ctx);
    }
    // Transparency rule: anything we have no opinion about is forwarded untouched.
    return ALLOW;
  }

  // -------------------------------------------------------------------------
  // Observation (cold path — canonicalize + hash happen here, once)
  // -------------------------------------------------------------------------

  /** Ingest a `tools/list` result: hash every tool, pin or compare, quarantine anything drifted. */
  observeToolList(result: unknown, ctx: GuardContext): Verdict {
    const scope = this.#resolveScope(ctx);
    const tools = readToolList(result);
    if (tools === null) {
      return this.#block([
        finding({
          ruleId: "toolwall/pin-malformed",
          severity: "high",
          message: "tools/list response has no `tools` array, so no definition could be verified",
          locus: "",
          remediation:
            "Inspect what this server returned for tools/list; toolwall refuses a listing it " +
            "cannot parse rather than forwarding it unverified.",
        }),
      ]);
    }

    const state = this.#stateFor(ctx.serverId);
    // A listing has crossed the proxy, so whatever the server told us about staleness is settled.
    state.stale = false;

    this.#noteCacheDirectives(result, ctx, scope);

    /*
     * The pin-time assessment, run once and only when a decision is actually pending.
     *
     * "Pending" is checked against the store first, with the same cheap map lookup `#reconcile`
     * will do anyway, so a listing whose every tool is already pinned costs nothing. That is the
     * difference between "runs at pin time" and "runs on every listing": a server that re-lists on
     * a timer would otherwise re-render the same report forever and the report would stop being
     * read, which is the alert-fatigue failure this codebase keeps designing against.
     */
    const pinPending = tools.some((tool) => {
      if (tool === null || typeof tool !== "object" || Array.isArray(tool)) return true;
      const name = (tool as Record<string, unknown>)["name"];
      if (typeof name !== "string" || name.length === 0) return true;
      return this.#store.get(ctx.serverId, "tool", name, scope) === undefined;
    });
    const box: AssessmentBox = {
      assessment:
        pinPending && this.#assess !== false
          ? this.#assess1(ctx, { serverId: ctx.serverId, tools, ...this.#atr(result, ctx), ...this.#prov(ctx) })
          : undefined,
    };

    const findings: Finding[] = [];
    let blocked = false;
    const seen = new Set<string>();

    for (let index = 0; index < tools.length; index++) {
      const locus = `/tools/${index}`;
      let toolName: string;
      let definition: Record<string, unknown>;
      try {
        const extracted =
          this.#unpinnedFields === undefined
            ? extractToolSurface(tools[index])
            : extractToolSurface(tools[index], { unpinnedFields: this.#unpinnedFields });
        toolName = extracted.toolName;
        definition = extracted.surface;
      } catch (error) {
        blocked = true;
        findings.push(
          finding({
            ruleId: "toolwall/pin-malformed",
            severity: "high",
            message: `tool entry could not be reduced to a pinnable definition: ${(error as Error).message}`,
            locus,
            remediation:
              "A tool that cannot be pinned cannot be verified before it is called; fix the " +
              "server's listing or remove the server.",
          }),
        );
        this.#emit("malformed", ctx.serverId, scope, "tool", "<unknown>", (error as Error).message);
        continue;
      }

      seen.add(toolName);
      const outcome = this.#reconcile(ctx, scope, "tool", toolName, definition, locus, box);
      if (outcome.finding !== undefined) findings.push(outcome.finding);
      if (outcome.blocked) blocked = true;
    }

    // A pinned tool that vanished from the listing is not itself dangerous — it cannot be
    // called — but it is a state change worth surfacing. Reported as an event, not a verdict.
    //
    // Filtered to THIS scope. A tool pinned under a broader credential is legitimately absent from
    // a listing fetched with a narrower one — that is scope narrowing working as designed, and
    // reporting it as a withdrawal would put a security event in front of an operator for every
    // token they downgrade.
    for (const record of this.#store.list({ serverId: ctx.serverId, kind: "tool", scope })) {
      if (!seen.has(record.subject)) {
        this.#emit(
          "withdrawn",
          ctx.serverId,
          scope,
          "tool",
          record.subject,
          "a pinned tool is no longer advertised by this server under this authorization scope",
        );
      }
    }

    if (blocked) return this.#block(findings);
    if (findings.length > 0) return { action: "confirm", findings };
    return ALLOW;
  }

  /**
   * Ingest a server descriptor (`initialize` under 2025-11-25, `server/discover` under
   * 2026-07-28) and pin its `instructions` — the free-form text the spec designs to be placed
   * straight into the client's system prompt, and the exact field Deadbugz mutates.
   */
  observeServerDescriptor(result: unknown, ctx: GuardContext): Verdict {
    let definition: Record<string, unknown>;
    try {
      definition = extractServerSurface(result);
      const instructions = definition["instructions"];
      // Remembered so the next `tools/list` assessment can include the field the spec designs to
      // be placed straight into the client's system prompt, rather than reporting it as unseen.
      if (typeof instructions === "string") this.#instructions.set(ctx.serverId, instructions);
    } catch (error) {
      return this.#block([
        finding({
          ruleId: "toolwall/pin-malformed",
          severity: "high",
          message: `server descriptor could not be reduced to a pinnable definition: ${(error as Error).message}`,
          locus: "",
          remediation: "Inspect what this server returned; toolwall will not pin what it cannot read.",
        }),
      ]);
    }
    const scope = this.#resolveScope(ctx);
    const pinPending =
      this.#store.get(ctx.serverId, "server", SERVER_INSTRUCTIONS_SUBJECT, scope) === undefined;
    const instructions = definition["instructions"];
    const box: AssessmentBox = {
      assessment:
        pinPending && this.#assess !== false && typeof instructions === "string"
          ? this.#assess1(ctx, {
              serverId: ctx.serverId,
              instructions,
              ...this.#atr(result, ctx),
              ...this.#prov(ctx),
            })
          : undefined,
    };
    const outcome = this.#reconcile(
      ctx,
      scope,
      "server",
      SERVER_INSTRUCTIONS_SUBJECT,
      definition,
      "/instructions",
      box,
    );
    if (outcome.blocked) {
      return this.#block(outcome.finding === undefined ? [] : [outcome.finding]);
    }
    if (outcome.finding !== undefined) return { action: "confirm", findings: [outcome.finding] };
    return ALLOW;
  }

  // -------------------------------------------------------------------------
  // Enforcement (hot path — two map lookups and a string compare)
  // -------------------------------------------------------------------------

  /** Verify the tool named in a `tools/call` request against its pin. Runs before every call. */
  verifyToolCall(params: unknown, ctx: GuardContext): Verdict {
    const toolName = readCallToolName(params);
    if (toolName === null) {
      return this.#block([
        finding({
          ruleId: "toolwall/pin-malformed",
          severity: "high",
          message: "tools/call request has no usable `name`, so there is nothing to verify",
          locus: "/name",
          remediation: "Reject the call; a request that names no tool cannot be checked against a pin.",
        }),
      ]);
    }

    const scope = this.#resolveScope(ctx);
    const quarantined = this.#quarantine.get(quarantineKey(ctx.serverId, scope, "tool", toolName));
    if (quarantined !== undefined) {
      return this.#block([this.#driftFinding(quarantined, "/name")]);
    }

    const pin = this.#store.get(ctx.serverId, "tool", toolName, scope);
    const state = this.#live.get(ctx.serverId);
    const live = state?.entries.get(subjectKey(scope, "tool", toolName));
    const stale = state?.stale === true;

    if (pin !== undefined && live !== undefined && !stale) {
      if (pin.hash === live.hash) {
        this.#store.markVerified(ctx.serverId, "tool", toolName, this.#now(), scope);
        return ALLOW;
      }
      // Should already have been caught at observation time; reaching here means a listing
      // bypassed the guard. Treat it as drift, because that is what it is.
      const report = this.#recordDrift(
        ctx.serverId,
        scope,
        "tool",
        toolName,
        pin.hash,
        live,
        pin.definition,
      );
      return this.#block([this.#driftFinding(report, "/name")]);
    }

    if (pin === undefined && live !== undefined && !stale && this.#mode === "tofu") {
      // Never listed through this guard but observed since: adopt under TOFU and allow.
      this.#adopt(ctx, scope, "tool", toolName, live);
      return ALLOW;
    }

    const reason = stale
      ? `the server announced ${LIST_CHANGED_NOTIFICATION} and has not re-listed since, so the ` +
        "cached definition no longer describes what it is advertising"
      : pin === undefined
        ? live === undefined
          ? "no pin exists for it and no definition for it has been observed on this connection"
          : "no pin exists for it and this guard is in strict mode, so it will not adopt a " +
            "definition on its own"
        : "it is pinned but no live definition has been observed on this connection, so the pin " +
          "cannot be checked against what the server is currently advertising";

    const unverifiable = finding({
      ruleId: "toolwall/pin-unverifiable",
      severity: "medium",
      message: `"${toolName}" cannot be verified against a pin before it is called: ${reason}`,
      locus: "/name",
      remediation:
        "Re-list the server's tools and approve the definition, or deny the call. Verification " +
        "before every call is the control; a call that cannot be verified gets a decision, not " +
        "an assumption.",
      evidence: {
        serverId: ctx.serverId,
        scope,
        toolName,
        hasPin: pin !== undefined,
        hasObservedDefinition: live !== undefined,
        catalogueStale: stale,
        // A pin for this tool under a DIFFERENT credential is the common benign explanation for
        // "no pin here": the operator changed tokens. Surfacing it turns an unexplained prompt
        // into one the operator can answer in a second.
        pinnedUnderOtherScopes: this.#store
          .listForSubject(ctx.serverId, "tool", toolName)
          .filter((r) => r.scope !== scope)
          .map((r) => r.scope),
      },
    });
    this.#emit(stale ? "stale" : "unverifiable", ctx.serverId, scope, "tool", toolName, reason);

    switch (this.#onUnverifiable) {
      case "block":
        return this.#block([unverifiable]);
      case "allow":
        return ALLOW;
      case "confirm":
      default:
        return { action: "confirm", findings: [unverifiable] };
    }
  }

  // -------------------------------------------------------------------------
  // Quarantine and re-approval
  // -------------------------------------------------------------------------

  /** Drift reports awaiting a human decision. Everything listed here is blocked. */
  listQuarantined(): DriftReport[] {
    return [...this.#quarantine.values()];
  }

  getQuarantined(
    serverId: string,
    kind: PinKind,
    subject: string,
    scope: PinScope = DEFAULT_PIN_SCOPE,
  ): DriftReport | undefined {
    return this.#quarantine.get(quarantineKey(serverId, scope, kind, subject));
  }

  /**
   * Accept drifted metadata after a human reviewed the diff. The only way out of quarantine.
   * `decision.by` must name a person; `PinStore.approveDrift` rejects anything automated.
   *
   * The approval applies to **one authorization scope**. Approving a change seen under one
   * credential says nothing about the same tool under another, and silently widening the approval
   * would recreate exactly the bug the scope key exists to prevent.
   */
  approveQuarantined(
    serverId: string,
    kind: PinKind,
    subject: string,
    decision: { by: string; note?: string; at?: string },
    scope: PinScope = DEFAULT_PIN_SCOPE,
  ): DriftReport {
    const key = quarantineKey(serverId, scope, kind, subject);
    const report = this.#quarantine.get(key);
    if (report === undefined) {
      throw new Error(
        `nothing is quarantined for ${serverId}/${kind}:${subject}` +
          (scope === DEFAULT_PIN_SCOPE ? "" : ` under scope ${scope}`),
      );
    }
    const pinDecision: PinDecision = {
      kind: "drift-re-approval",
      at: decision.at ?? this.#now().toISOString(),
      by: decision.by,
      ...(decision.note === undefined ? {} : { note: decision.note }),
    };
    this.#store.approveDrift({
      serverId,
      scope,
      kind,
      subject,
      era: this.#era,
      hash: report.liveHash,
      definition: report.liveDefinition,
      decision: pinDecision,
    });
    this.#quarantine.delete(key);
    return report;
  }

  /** Reject drifted metadata: the quarantine entry is cleared and the old pin stands. */
  rejectQuarantined(
    serverId: string,
    kind: PinKind,
    subject: string,
    scope: PinScope = DEFAULT_PIN_SCOPE,
  ): boolean {
    return this.#quarantine.delete(quarantineKey(serverId, scope, kind, subject));
  }

  /** True when the server has announced a change we have not seen a listing for. */
  isCatalogueStale(serverId: string): boolean {
    return this.#live.get(serverId)?.stale === true;
  }

  // -------------------------------------------------------------------------
  // Internals
  // -------------------------------------------------------------------------

  #stateFor(serverId: string): ServerState {
    let state = this.#live.get(serverId);
    if (state === undefined) {
      state = { entries: new Map(), stale: false };
      this.#live.set(serverId, state);
    }
    return state;
  }

  #markStale(serverId: string, scope: PinScope): void {
    const state = this.#stateFor(serverId);
    if (state.stale) return;
    state.stale = true;
    this.#emit(
      "stale",
      serverId,
      scope,
      "tool",
      "*",
      "server announced tools/list_changed; cached definitions are stale until it re-lists",
    );
  }

  /**
   * Record what the listing said about caching.
   *
   * `ListToolsResult` requires `ttlMs` and `cacheScope` under `2026-07-28`. Both matter to a proxy
   * and neither is enforceable by one, so they are recorded rather than acted on:
   *
   *   - A non-zero `ttlMs` means **the client may cache the listing and the proxy will not see
   *     every fetch.** Any design that assumed "a listing precedes every call" is wrong under it.
   *     This guard never made that assumption — verification happens before every `tools/call`
   *     from the cached-and-pinned definition, which is precisely the case a TTL creates — but the
   *     event exists so the assumption cannot creep back in unnoticed.
   *   - `cacheScope: "public"` means an intermediary MAY serve this listing **across
   *     authorization contexts**. Scope-keyed pins protect us from mistaking that for tampering;
   *     they do not stop a shared cache from handing a broad-credential listing to a narrow one.
   *     That is someone else's cache and outside our data path, so it is reported, not blocked.
   */
  #noteCacheDirectives(result: unknown, ctx: GuardContext, scope: PinScope): void {
    if (result === null || typeof result !== "object" || Array.isArray(result)) return;
    const record = result as Record<string, unknown>;

    const ttlMs = record["ttlMs"];
    if (typeof ttlMs === "number" && Number.isFinite(ttlMs) && ttlMs > 0) {
      this.#emit(
        "cache-ttl",
        ctx.serverId,
        scope,
        "tool",
        "*",
        `listing declares ttlMs=${ttlMs}; the client may cache it, so toolwall will not see every ` +
          "fetch. Per-call verification against the pin is what covers the gap",
      );
    }

    if (record["cacheScope"] === "public") {
      this.#emit(
        "cache-public",
        ctx.serverId,
        scope,
        "tool",
        "*",
        'listing declares cacheScope="public", so an intermediary may serve it across ' +
          "authorization contexts; a listing fetched under one credential can reach another",
      );
    }
  }

  #reconcile(
    ctx: GuardContext,
    scope: PinScope,
    kind: PinKind,
    subject: string,
    definition: Record<string, unknown>,
    locus: string,
    box: AssessmentBox = { assessment: undefined },
  ): { blocked: boolean; finding?: Finding } {
    let hash: string;
    let detached: unknown;
    try {
      const { canonical, hash: computed } = canonicalizeAndHash(
        definition,
        this.#canonicalizeOptions,
      );
      hash = computed;
      // Reparsing the canonical form gives a copy that is detached from the live payload (the
      // guard contract forbids retaining or mutating it) and already NFC-normalized, so a
      // stored pin and a fresh observation are compared on identical terms.
      detached = JSON.parse(canonical);
    } catch (error) {
      const message =
        error instanceof CanonicalizationError ? `${error.message} [${error.code}]` : String(error);
      this.#emit("malformed", ctx.serverId, scope, kind, subject, message);
      return {
        blocked: true,
        finding: finding({
          ruleId: "toolwall/pin-uncanonicalizable",
          severity: "high",
          message: `"${subject}" has no canonical form and therefore no stable identity: ${message}`,
          locus,
          remediation:
            "Reject this definition; toolwall cannot pin or verify something it cannot " +
            "canonicalize, and will not guess.",
          evidence: { serverId: ctx.serverId, scope, kind, subject },
        }),
      };
    }

    const live: LiveEntry = { hash, definition: detached, observedAt: this.#now().toISOString() };
    this.#stateFor(ctx.serverId).entries.set(subjectKey(scope, kind, subject), live);

    const pin = this.#store.get(ctx.serverId, kind, subject, scope);

    if (pin === undefined) {
      if (this.#mode === "tofu") {
        this.#adopt(ctx, scope, kind, subject, live, box);
        return { blocked: false };
      }
      /*
       * Strict mode. This finding IS the decision surface: it routes through the confirmation
       * provider, so its `message` is what a human reads before they approve a server they have
       * never seen. Handing them a hash and the word "unpinned" and calling that a decision is
       * what the pin-time assessment exists to stop, so the whole report goes in the message.
       *
       * Only on the first unpinned subject of the listing (`box` is emptied after it is used):
       * the assessment is about the listing, and repeating it once per tool would bury it.
       */
      const assessment = box.assessment;
      box.assessment = undefined;
      const report = assessment === undefined ? undefined : assessmentFinding(assessment, locus);
      return {
        blocked: false,
        finding: finding({
          ruleId: "toolwall/pin-unpinned",
          severity: "medium",
          message:
            `"${subject}" has never been approved and strict mode does not adopt definitions on its own` +
            (report === undefined ? "" : `\n\n${report.message}`),
          locus,
          remediation: "Review this definition and approve it before the tool can be called.",
          evidence: {
            serverId: ctx.serverId,
            scope,
            kind,
            subject,
            hash,
            ...(report?.evidence === undefined ? {} : { assessment: report.evidence }),
          },
        }),
      };
    }

    if (pin.canonicalizationVersion !== CANONICALIZATION_VERSION) {
      // Hashes from two different canonicalization versions are not comparable, whether or not
      // they happen to match. Say so rather than pass.
      this.#emit(
        "algorithm-changed",
        ctx.serverId,
        scope,
        kind,
        subject,
        `pin was created under canonicalization v${pin.canonicalizationVersion}`,
      );
      return {
        blocked: false,
        finding: finding({
          ruleId: "toolwall/pin-algorithm-changed",
          severity: "medium",
          message:
            `"${subject}" was pinned under canonicalization v${pin.canonicalizationVersion} but ` +
            `this build produces v${CANONICALIZATION_VERSION}; the two hashes are not comparable`,
          locus,
          remediation:
            "Re-approve this definition to re-establish a usable baseline. This is a toolwall " +
            "upgrade artefact, not evidence of an attack.",
          evidence: {
            serverId: ctx.serverId,
            scope,
            kind,
            subject,
            pinnedVersion: pin.canonicalizationVersion,
            currentVersion: CANONICALIZATION_VERSION,
          },
        }),
      };
    }

    if (pin.hash === hash) {
      this.#store.markVerified(ctx.serverId, kind, subject, this.#now(), scope);
      this.#emit("verified", ctx.serverId, scope, kind, subject, "definition matches its pin");
      return { blocked: false };
    }

    const report = this.#recordDrift(
      ctx.serverId,
      scope,
      kind,
      subject,
      pin.hash,
      live,
      pin.definition,
    );
    return { blocked: true, finding: this.#driftFinding(report, locus) };
  }

  #adopt(
    ctx: GuardContext,
    scope: PinScope,
    kind: PinKind,
    subject: string,
    live: LiveEntry,
    box: AssessmentBox = { assessment: undefined },
  ): void {
    this.#store.pinIfAbsent({
      serverId: ctx.serverId,
      scope,
      kind,
      subject,
      era: ctx.era,
      hash: live.hash,
      definition: live.definition,
      decision: {
        kind: "trust-on-first-use",
        at: live.observedAt,
        by: "auto:tofu",
        note:
          "adopted on first sighting; TOFU cannot distinguish a benign definition from one " +
          "that was already hostile when first seen",
      },
    });
    /*
     * The assessment rides on the first `pinned` event of the listing and its headline is folded
     * into the message, so it reaches the audit log and every existing `onPinEvent` consumer
     * without a new event kind and without anyone having to opt in. Emptied after one use: the
     * report describes the listing, not the tool, and printing it once per tool would bury it.
     */
    const assessment = box.assessment;
    box.assessment = undefined;
    this.#emit(
      "pinned",
      ctx.serverId,
      scope,
      kind,
      subject,
      assessment === undefined
        ? "pinned on first sighting (TOFU)"
        : `pinned on first sighting (TOFU) · ${assessment.headline}`,
      assessment,
    );
  }

  // -------------------------------------------------------------------------
  // Pin-time assessment plumbing
  // -------------------------------------------------------------------------

  /** The most recent pin-time assessment for a server, for an operator UI that wants to re-read it. */
  lastAssessment(serverId: string): PinRiskAssessment | undefined {
    return this.#assessments.get(serverId);
  }

  /**
   * Run the assessment, remember it, and never let it break the listing path.
   *
   * A thrown assessment would take a `tools/list` down with it, which would turn an advisory
   * evidence sheet into an availability bug. It is wrapped for that reason and for no other; the
   * function itself is written not to throw.
   */
  #assess1(ctx: GuardContext, candidate: PinCandidate): PinRiskAssessment | undefined {
    try {
      const instructions = this.#instructions.get(ctx.serverId);
      const assessment = assessPinCandidate({
        ...candidate,
        ...(candidate.instructions === undefined && instructions !== undefined ? { instructions } : {}),
      });
      this.#assessments.set(ctx.serverId, assessment);
      return assessment;
    } catch {
      return undefined;
    }
  }

  /** Advisory ATR findings for this payload, when the operator supplied a scanner. */
  #atr(payload: unknown, ctx: GuardContext): { atrFindings?: readonly Finding[] } {
    if (this.#assess === false || this.#assess.atrFindings === undefined) return {};
    try {
      return { atrFindings: this.#assess.atrFindings(payload, ctx) };
    } catch {
      return {};
    }
  }

  /** The completed T-09 report, when the operator opted in and it has finished. */
  #prov(ctx: GuardContext): { provenance?: ProvenanceReport } {
    if (this.#assess === false || this.#assess.provenance === undefined) return {};
    try {
      const report = this.#assess.provenance(ctx.serverId);
      return report === undefined ? {} : { provenance: report };
    } catch {
      return {};
    }
  }

  #recordDrift(
    serverId: string,
    scope: PinScope,
    kind: PinKind,
    subject: string,
    pinnedHash: string,
    live: LiveEntry,
    pinnedDefinition: unknown,
  ): DriftReport {
    const diffs = diffValues(pinnedDefinition, live.definition);
    // Is this exact definition already approved under another credential? If so the operator is
    // looking at an authorization change, not a rug pull, and the alert has to say so.
    const alsoPinnedUnderScopes = this.#store
      .listForSubject(serverId, kind, subject)
      .filter((r: PinRecord) => r.scope !== scope && r.hash === live.hash)
      .map((r: PinRecord) => r.scope);
    const report: DriftReport = {
      serverId,
      scope,
      pinKind: kind,
      subject,
      pinnedHash,
      liveHash: live.hash,
      pinnedDefinition,
      liveDefinition: live.definition,
      diffs,
      detectedAt: this.#now().toISOString(),
      rendered: renderFieldDiffs(diffs),
      alsoPinnedUnderScopes,
    };
    this.#quarantine.set(quarantineKey(serverId, scope, kind, subject), report);
    this.#emit(
      "drift",
      serverId,
      scope,
      kind,
      subject,
      `definition changed in ${diffs.length} field${diffs.length === 1 ? "" : "s"}`,
    );
    return report;
  }

  /**
   * The alert a human actually reads.
   *
   * `message` is the full `renderDriftAlert` block, not a hash pair: "hash mismatch" gives an
   * operator nothing to decide with, and the decision they are being asked for is whether *this
   * change* is one they expected. The block is headline-first, impact-ranked and bounded — see the
   * "alert-fatigue constraint" section in `diff.ts` for the rules and the research behind them.
   *
   * Note this message quotes the untrusted server's text. That is correct and safe at this layer:
   * contract C-9's `redactFindingForClient` withholds `message` and `evidence` from the JSON-RPC
   * error and relays only toolwall-authored fields, so the alert reaches stderr and the audit log
   * without the block delivering the payload to the model it was protecting.
   */
  #driftFinding(report: DriftReport, locus: string): Finding {
    // `report.subject` is the tool NAME, which the untrusted server chose. It used to be
    // interpolated raw into the alert headline an operator reads before deciding whether their
    // server was swapped — the same shape as the round-3 pin-assessment finding, on the drift
    // surface. The tag sanitizes it; the static words around it are source code.
    const what: Rendered =
      report.pinKind === "server" ? rendered`server instructions` : rendered`tool "${report.subject}"`;
    const invisible = report.diffs.some((d) => d.invisibleOnly === true);
    const scopeChange = report.alsoPinnedUnderScopes.length > 0;

    const message = renderDriftAlert({
      subject: what,
      serverId: report.serverId,
      pinnedHash: report.pinnedHash,
      liveHash: report.liveHash,
      diffs: report.diffs,
      // A scope is derived from the credential the listing was fetched with, and a
      // `alsoPinnedUnderScopes` entry is one of those read back from the pin file. Neither is a
      // string toolwall wrote, so both are rendered rather than trusted.
      scope: renderText(report.scope, 120),
      alsoPinnedUnderScopes: report.alsoPinnedUnderScopes.map(sc => renderText(sc, 120)),
    });

    return finding({
      ruleId: "toolwall/pin-drift",
      // A change whose exact bytes are already approved under another credential is an
      // authorization event, not a rug pull. It still blocks — approval is per scope and this
      // scope has not approved it — but calling it `critical` alongside a real mutation is how a
      // severity field stops carrying information.
      severity: scopeChange ? "medium" : "critical",
      message,
      locus,
      remediation: scopeChange
        ? "Confirm you changed credentials, then approve this definition for this authorization " +
          "scope. Approval is per credential on purpose: a tool approved under a broad token is " +
          "not thereby approved under a different one."
        : "The call is blocked and the tool is quarantined. Review the diff and either re-approve " +
          "the new definition explicitly or remove the server; toolwall will not re-pin it on its own.",
      evidence: {
        serverId: report.serverId,
        scope: report.scope,
        kind: report.pinKind,
        subject: report.subject,
        pinnedHash: report.pinnedHash,
        liveHash: report.liveHash,
        // Impact-ranked, so a triage tool sorts the same way the human-readable block does.
        changedPaths: [...report.diffs]
          .sort((a, b) => classifyChange(b).rank - classifyChange(a).rank)
          .map((d) => d.path),
        invisibleOnlyChange: invisible,
        alsoPinnedUnderScopes: report.alsoPinnedUnderScopes,
        // The COMPLETE diff, not the bounded one the block prints. The alert is bounded for a
        // reader; the record must not be.
        diffs: report.diffs,
        renderedDiff: report.rendered,
      },
    });
  }

  #block(findings: readonly Finding[]): Verdict {
    return { action: "block", findings, code: this.#blockCode };
  }

  #emit(
    kind: PinEventKind,
    serverId: string,
    scope: PinScope,
    pinKind: PinKind,
    subject: string,
    message: string,
    assessment?: PinRiskAssessment,
  ): void {
    this.#onEvent({
      kind,
      serverId,
      scope,
      pinKind,
      subject,
      message,
      ...(assessment === undefined ? {} : { assessment }),
    });
  }
}
