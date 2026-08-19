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
 */
import type { CanonicalizeOptions } from "./canonicalize.js";
import { CANONICALIZATION_VERSION, CanonicalizationError, canonicalizeAndHash } from "./canonicalize.js";
import type { FieldDiff } from "./diff.js";
import { diffValues, renderFieldDiffs } from "./diff.js";
import type { PinKind } from "./surface.js";
import {
  SERVER_INSTRUCTIONS_SUBJECT,
  extractServerSurface,
  extractToolSurface,
  readCallToolName,
  readToolList,
} from "./surface.js";
import type { PinDecision, PinStore } from "../../audit/manifest.js";
import type { Finding, Guard, GuardContext, ProtocolEra, Verdict } from "../../types/protocol.js";
import { ALLOW, TOOLWALL_BLOCKED } from "../../types/protocol.js";

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
  | "malformed";

export interface PinEvent {
  readonly kind: PinEventKind;
  readonly serverId: string;
  readonly pinKind: PinKind;
  readonly subject: string;
  readonly message: string;
}

export interface DriftReport {
  readonly serverId: string;
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
}

interface LiveEntry {
  readonly hash: string;
  /** Detached, NFC-normalized copy of the definition. Never aliases the live payload. */
  readonly definition: unknown;
  readonly observedAt: string;
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

function quarantineKey(serverId: string, kind: PinKind, subject: string): string {
  return `${serverId}\u0000${kind}\u0000${subject}`;
}

function subjectKey(kind: PinKind, subject: string): string {
  return `${kind}\u0000${subject}`;
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

  /** serverId -> last observed definitions and their hashes. */
  readonly #live = new Map<string, ServerState>();
  /** Drift reports awaiting a human decision. Nothing listed here is callable. */
  readonly #quarantine = new Map<string, DriftReport>();

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
        this.#markStale(ctx.serverId);
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
        this.#emit("malformed", ctx.serverId, "tool", "<unknown>", (error as Error).message);
        continue;
      }

      seen.add(toolName);
      const outcome = this.#reconcile(ctx, "tool", toolName, definition, locus);
      if (outcome.finding !== undefined) findings.push(outcome.finding);
      if (outcome.blocked) blocked = true;
    }

    // A pinned tool that vanished from the listing is not itself dangerous — it cannot be
    // called — but it is a state change worth surfacing. Reported as an event, not a verdict.
    for (const record of this.#store.list({ serverId: ctx.serverId, kind: "tool" })) {
      if (!seen.has(record.subject)) {
        this.#emit(
          "withdrawn",
          ctx.serverId,
          "tool",
          record.subject,
          "a pinned tool is no longer advertised by this server",
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
    const outcome = this.#reconcile(
      ctx,
      "server",
      SERVER_INSTRUCTIONS_SUBJECT,
      definition,
      "/instructions",
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

    const quarantined = this.#quarantine.get(quarantineKey(ctx.serverId, "tool", toolName));
    if (quarantined !== undefined) {
      return this.#block([this.#driftFinding(quarantined, "/name")]);
    }

    const pin = this.#store.get(ctx.serverId, "tool", toolName);
    const state = this.#live.get(ctx.serverId);
    const live = state?.entries.get(subjectKey("tool", toolName));
    const stale = state?.stale === true;

    if (pin !== undefined && live !== undefined && !stale) {
      if (pin.hash === live.hash) {
        this.#store.markVerified(ctx.serverId, "tool", toolName, this.#now());
        return ALLOW;
      }
      // Should already have been caught at observation time; reaching here means a listing
      // bypassed the guard. Treat it as drift, because that is what it is.
      const report = this.#recordDrift(ctx.serverId, "tool", toolName, pin.hash, live, pin.definition);
      return this.#block([this.#driftFinding(report, "/name")]);
    }

    if (pin === undefined && live !== undefined && !stale && this.#mode === "tofu") {
      // Never listed through this guard but observed since: adopt under TOFU and allow.
      this.#adopt(ctx, "tool", toolName, live);
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
        toolName,
        hasPin: pin !== undefined,
        hasObservedDefinition: live !== undefined,
        catalogueStale: stale,
      },
    });
    this.#emit(stale ? "stale" : "unverifiable", ctx.serverId, "tool", toolName, reason);

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

  getQuarantined(serverId: string, kind: PinKind, subject: string): DriftReport | undefined {
    return this.#quarantine.get(quarantineKey(serverId, kind, subject));
  }

  /**
   * Accept drifted metadata after a human reviewed the diff. The only way out of quarantine.
   * `decision.by` must name a person; `PinStore.approveDrift` rejects anything automated.
   */
  approveQuarantined(
    serverId: string,
    kind: PinKind,
    subject: string,
    decision: { by: string; note?: string; at?: string },
  ): DriftReport {
    const key = quarantineKey(serverId, kind, subject);
    const report = this.#quarantine.get(key);
    if (report === undefined) {
      throw new Error(`nothing is quarantined for ${serverId}/${kind}:${subject}`);
    }
    const pinDecision: PinDecision = {
      kind: "drift-re-approval",
      at: decision.at ?? this.#now().toISOString(),
      by: decision.by,
      ...(decision.note === undefined ? {} : { note: decision.note }),
    };
    this.#store.approveDrift({
      serverId,
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
  rejectQuarantined(serverId: string, kind: PinKind, subject: string): boolean {
    return this.#quarantine.delete(quarantineKey(serverId, kind, subject));
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

  #markStale(serverId: string): void {
    const state = this.#stateFor(serverId);
    if (state.stale) return;
    state.stale = true;
    this.#emit(
      "stale",
      serverId,
      "tool",
      "*",
      "server announced tools/list_changed; cached definitions are stale until it re-lists",
    );
  }

  #reconcile(
    ctx: GuardContext,
    kind: PinKind,
    subject: string,
    definition: Record<string, unknown>,
    locus: string,
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
      this.#emit("malformed", ctx.serverId, kind, subject, message);
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
          evidence: { serverId: ctx.serverId, kind, subject },
        }),
      };
    }

    const live: LiveEntry = { hash, definition: detached, observedAt: this.#now().toISOString() };
    this.#stateFor(ctx.serverId).entries.set(subjectKey(kind, subject), live);

    const pin = this.#store.get(ctx.serverId, kind, subject);

    if (pin === undefined) {
      if (this.#mode === "tofu") {
        this.#adopt(ctx, kind, subject, live);
        return { blocked: false };
      }
      return {
        blocked: false,
        finding: finding({
          ruleId: "toolwall/pin-unpinned",
          severity: "medium",
          message: `"${subject}" has never been approved and strict mode does not adopt definitions on its own`,
          locus,
          remediation: "Review this definition and approve it before the tool can be called.",
          evidence: { serverId: ctx.serverId, kind, subject, hash },
        }),
      };
    }

    if (pin.canonicalizationVersion !== CANONICALIZATION_VERSION) {
      // Hashes from two different canonicalization versions are not comparable, whether or not
      // they happen to match. Say so rather than pass.
      this.#emit(
        "algorithm-changed",
        ctx.serverId,
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
            kind,
            subject,
            pinnedVersion: pin.canonicalizationVersion,
            currentVersion: CANONICALIZATION_VERSION,
          },
        }),
      };
    }

    if (pin.hash === hash) {
      this.#store.markVerified(ctx.serverId, kind, subject, this.#now());
      this.#emit("verified", ctx.serverId, kind, subject, "definition matches its pin");
      return { blocked: false };
    }

    const report = this.#recordDrift(ctx.serverId, kind, subject, pin.hash, live, pin.definition);
    return { blocked: true, finding: this.#driftFinding(report, locus) };
  }

  #adopt(ctx: GuardContext, kind: PinKind, subject: string, live: LiveEntry): void {
    this.#store.pinIfAbsent({
      serverId: ctx.serverId,
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
    this.#emit("pinned", ctx.serverId, kind, subject, "pinned on first sighting (TOFU)");
  }

  #recordDrift(
    serverId: string,
    kind: PinKind,
    subject: string,
    pinnedHash: string,
    live: LiveEntry,
    pinnedDefinition: unknown,
  ): DriftReport {
    const diffs = diffValues(pinnedDefinition, live.definition);
    const report: DriftReport = {
      serverId,
      pinKind: kind,
      subject,
      pinnedHash,
      liveHash: live.hash,
      pinnedDefinition,
      liveDefinition: live.definition,
      diffs,
      detectedAt: this.#now().toISOString(),
      rendered: renderFieldDiffs(diffs),
    };
    this.#quarantine.set(quarantineKey(serverId, kind, subject), report);
    this.#emit(
      "drift",
      serverId,
      kind,
      subject,
      `definition changed in ${diffs.length} field${diffs.length === 1 ? "" : "s"}`,
    );
    return report;
  }

  /**
   * The alert a human actually reads. `message` carries the rendered field-level diff inline,
   * not just the two hashes: "hash mismatch" gives an operator nothing to decide with, and the
   * decision they are being asked for is whether this change is one they expected.
   */
  #driftFinding(report: DriftReport, locus: string): Finding {
    const what =
      report.pinKind === "server"
        ? `server instructions for ${report.serverId}`
        : `tool "${report.subject}"`;
    const invisible = report.diffs.some((d) => d.invisibleOnly === true);
    const count = report.diffs.length;

    const lines: string[] = [
      `${what} no longer matches the definition that was approved ` +
        `(${count} field${count === 1 ? "" : "s"} changed).`,
      "",
      `  pinned hash : ${report.pinnedHash}`,
      `  live hash   : ${report.liveHash}`,
      "",
      report.rendered,
    ];
    if (invisible) {
      lines.push(
        "",
        "At least one change consists only of characters that do not render. Read the escaped " +
          "values above, not the raw text.",
      );
    }

    return finding({
      ruleId: "toolwall/pin-drift",
      severity: "critical",
      message: lines.join("\n"),
      locus,
      remediation:
        "The call is blocked and the tool is quarantined. Review the diff and either re-approve " +
        "the new definition explicitly or remove the server; toolwall will not re-pin it on its own.",
      evidence: {
        serverId: report.serverId,
        kind: report.pinKind,
        subject: report.subject,
        pinnedHash: report.pinnedHash,
        liveHash: report.liveHash,
        changedPaths: report.diffs.map((d) => d.path),
        invisibleOnlyChange: invisible,
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
    pinKind: PinKind,
    subject: string,
    message: string,
  ): void {
    this.#onEvent({ kind, serverId, pinKind, subject, message });
  }
}
