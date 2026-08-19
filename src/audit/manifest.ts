/**
 * The pin store — toolwall's security state.
 *
 * A pin binds `(serverId, scope, kind, subject)` to the SHA-256 of the RFC 8785 canonical form of
 * a tool definition (or of a server's `instructions`), together with the decision that approved
 * it. `scope` is the authorization context the listing was obtained under — see {@link PinScope}
 * for why it is part of the key and not metadata hanging off it.
 * It is the entire basis for the rug-pull claim, so this file is written as security state,
 * not as a cache: restrictive permissions, atomic replacement, integrity self-check on load,
 * fail-closed on anything unexpected, and **no code path anywhere that silently accepts a
 * changed hash.**
 *
 * ## The one rule
 *
 * `pin()` and `pinIfAbsent()` can only ever *create*. The single function that can replace an
 * existing hash is `approveDrift()`, which requires a `PinDecision` naming who approved it and
 * why, and which files the superseded hash into `history`. There is no `upsert`, no
 * `force: true`, no "same file, must be fine" shortcut.
 *
 * That shape is not defensive style, it is CVE-2025-54136 ("MCPoison", CVSS 7.2) written as an
 * API constraint: Cursor keyed MCP approval on *file identity* rather than on *content*, so
 * swapping the contents of an already-approved config gave persistent RCE with no new prompt.
 * The same class of bug is Repello's 2026-06 finding that Claude Code keys approvals by server
 * name rather than by command. Approval must attach to bytes, and changed bytes must mean a
 * new decision.
 *
 * ## Tamper-evidence, stated honestly
 *
 * The file carries an `integrity` digest over its own canonical form and a `revision` /
 * `previousIntegrity` chain. This is **keyless**. It reliably detects truncation, partial
 * writes, careless hand-editing and bit rot, and it makes a silent edit take deliberate effort.
 * It does **not** stop an attacker who can write the file: they can recompute the digest. Real
 * forgery resistance needs a key held outside the file (OS keychain / TPM) and is out of scope
 * for Week 1 — the chain fields exist so that when the file is under version control or backup,
 * an external witness makes rollback detectable. Do not describe this as tamper-proof.
 */
import { createHash } from "node:crypto";
import { chmod, mkdir, open, readFile, rename, stat, unlink } from "node:fs/promises";
import { dirname, resolve as resolvePath } from "node:path";

import { CANONICALIZATION_VERSION, canonicalize } from "../guards/metadata/canonicalize.js";
import type { PinKind } from "../guards/metadata/surface.js";
import type { ProtocolEra } from "../types/protocol.js";

export const PIN_FILE_FORMAT = "toolwall/pins";
/**
 * Bumped 1 -> 2 in week 2 when `scope` entered the pin key (see {@link PinScope}). A v1 file is
 * still readable: every record in it is adopted at {@link DEFAULT_PIN_SCOPE}, which is exactly what
 * it meant before the field existed. Writing always produces v2.
 */
export const PIN_FILE_SCHEMA_VERSION = 2;
/** Schema versions this build can read. Writing is always at {@link PIN_FILE_SCHEMA_VERSION}. */
export const READABLE_PIN_FILE_SCHEMA_VERSIONS: readonly number[] = [1, 2];
export const DEFAULT_PIN_FILE = ".toolwall/pins.json";

// ---------------------------------------------------------------------------
// Authorization scope (RESEARCH-BRIEF §4.5 item 6)
// ---------------------------------------------------------------------------

/**
 * The authorization context a listing was obtained under.
 *
 * ## Why the pin key needs this
 *
 * `2026-07-28` says `tools/list` **MUST NOT** vary per-connection but **MAY vary by the
 * authorization presented**. Those two clauses together are what makes a scope-blind pin store
 * wrong rather than merely incomplete: the same server, reached with a narrower token, legitimately
 * returns fewer tools and narrower schemas — and against a single-key pin store every one of those
 * differences is a hash mismatch. The operator gets a critical rug-pull alarm for doing the exact
 * thing security advice tells them to do, which is the fastest way to teach someone to ignore
 * rug-pull alarms. `docs/RESEARCH-BRIEF.md` §4.3: human confirmation is a **13.6%** control at
 * best, and it goes to zero once the alarms are known to be wrong.
 *
 * So a pin is keyed by `(serverId, scope, kind, subject)`. Under a different credential the same
 * tool is a *different pin*, adopted on its own first sighting, and narrowing scope produces new
 * pins rather than drift on old ones.
 *
 * ## What may go into a scope id — and what may never
 *
 * **Structure is identity, secrets are not.** This is the same rule `src/audit/identity.ts` applies
 * to `serverId`, and it applies here for a stronger reason: the pin file is long-lived security
 * state that gets committed, backed up and copied between machines. A token value, or a hash of
 * one, has no business in it.
 *
 * Therefore {@link deriveScopeId} accepts only non-secret descriptors — issuer, subject, client id,
 * audience, granted scope *names*, and an operator-chosen label — and there is deliberately no
 * overload that takes a raw credential. If all you have is an opaque bearer token, name it
 * yourself via `label`. A caller who wants scope keying must be able to say what the scope *is*,
 * and if they cannot, keying on it would not be meaningful anyway.
 */
export type PinScope = string;

/**
 * The scope every pin lives at when no authorization context is supplied: a single-credential
 * connection, which is what stdio always is and what most HTTP setups are. Empty string so a v1
 * pin file migrates to it with no transformation.
 */
export const DEFAULT_PIN_SCOPE: PinScope = "";

/**
 * Non-secret facts identifying an authorization context. Every field is optional; whichever are
 * present contribute, in a fixed order, so the same context always yields the same id.
 */
export interface ScopeDescriptor {
  /** OAuth issuer / IdP, e.g. `"https://login.example.com"`. */
  readonly issuer?: string;
  /** Subject or principal identifier. A user id, not a token. */
  readonly subject?: string;
  /** OAuth client id. Public by definition. */
  readonly clientId?: string;
  /** Resource indicator / audience the credential is bound to. */
  readonly audience?: string;
  /** Granted scope NAMES, e.g. `["repo:read", "issues:write"]`. Order-insensitive. */
  readonly scopes?: readonly string[];
  /** Free-form operator label, for credentials that carry no claims worth keying on. */
  readonly label?: string;
}

/** Keys hashed into a scope id, in a fixed order. */
const SCOPE_FIELDS = ["issuer", "subject", "clientId", "audience", "label"] as const;

/**
 * Derive a stable, non-secret scope id. Returns {@link DEFAULT_PIN_SCOPE} for an empty descriptor,
 * so callers with no authorization context need no special case.
 *
 * @throws when a field looks like a credential rather than an identifier. The check is a coarse
 *   shape heuristic (JWT-shaped, or a long high-entropy opaque string) and it is deliberately
 *   noisy-in-the-safe-direction: refusing a legitimate but odd-looking label costs an operator one
 *   config edit, while accepting a token writes it into a file that outlives the session.
 */
export function deriveScopeId(descriptor: ScopeDescriptor): PinScope {
  const parts: string[] = [];
  for (const field of SCOPE_FIELDS) {
    const value = descriptor[field];
    if (value === undefined || value === "") continue;
    assertNotCredentialShaped(field, value);
    parts.push(`${field}=${value}`);
  }
  if (descriptor.scopes !== undefined && descriptor.scopes.length > 0) {
    for (const s of descriptor.scopes) assertNotCredentialShaped("scopes", s);
    // Sorted: the grant is a set, and a server returning the same grant in a different order is
    // not a different authorization context.
    parts.push(`scopes=${[...descriptor.scopes].sort().join(",")}`);
  }
  if (parts.length === 0) return DEFAULT_PIN_SCOPE;
  const digest = createHash("sha256").update(parts.join(" "), "utf8").digest("hex");
  return `scope_${digest.slice(0, 16)}`;
}

/** JWT shape: three base64url segments. Unmistakable, and unmistakably a credential. */
const JWT_SHAPED = /^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$/;
/** A long run of credential-alphabet characters with no structure a human would write. */
const OPAQUE_SECRET_SHAPED = /^[A-Za-z0-9_\-+/=]{40,}$/;

function assertNotCredentialShaped(field: string, value: string): void {
  if (JWT_SHAPED.test(value) || OPAQUE_SECRET_SHAPED.test(value)) {
    throw new Error(
      `ScopeDescriptor.${field} looks like a credential, not an identifier. Scope ids are derived ` +
        "from non-secret structure only — issuer, subject, client id, audience, granted scope " +
        "names, or an operator-chosen label. Never pass a token, even hashed: the pin file " +
        "outlives the session and gets copied around.",
    );
  }
}

// ---------------------------------------------------------------------------
// Server identity (T-04)
// ---------------------------------------------------------------------------

/**
 * Re-exported, not re-implemented. `deriveServerId` moved to `./identity.js` so that
 * `src/transport/` and `src/audit/` share one implementation: `MetadataPinGuard` looks pins up
 * by `GuardContext.serverId`, which the transport derives, and two implementations that
 * disagree would orphan every pin on disk and silently restart trust-on-first-use. See the
 * header of `./identity.js`. This module's public API is unchanged.
 */
export { deriveServerId } from "./identity.js";
export type { HttpServerIdentity, ServerIdentity, StdioServerIdentity } from "./identity.js";

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------

export type PinDecisionKind =
  /** No pin existed; the first observation was adopted. Weakest form — see Deadbugz. */
  | "trust-on-first-use"
  /** A human approved this definition before it was pinned. */
  | "explicit-approval"
  /** A human reviewed a diff against an existing pin and accepted the new definition. */
  | "drift-re-approval";

export interface PinDecision {
  readonly kind: PinDecisionKind;
  /** ISO 8601. */
  readonly at: string;
  /** Who decided: `"auto:tofu"`, `"cli"`, `"user:alice"`. Never blank. */
  readonly by: string;
  readonly note?: string;
}

export interface PinRecord {
  readonly serverId: string;
  /**
   * The authorization context this pin was observed under. {@link DEFAULT_PIN_SCOPE} when there is
   * none. Part of the key: see {@link PinScope} for why.
   */
  readonly scope: PinScope;
  readonly kind: PinKind;
  /** Tool name, or `"instructions"` for a server-level pin. */
  readonly subject: string;
  readonly era: ProtocolEra;
  /** `sha256:<hex>` of the canonical form. */
  readonly hash: string;
  readonly canonicalizationVersion: number;
  readonly firstSeen: string;
  readonly lastVerified: string;
  readonly decision: PinDecision;
  /**
   * The pinned surface itself. Stored because a hash cannot be diffed: without the pinned
   * definition, a drift alert can only say "hash mismatch", which tells the operator nothing
   * they can act on.
   */
  readonly definition: unknown;
  /** Superseded pins, newest first. The audit trail of every re-approval. */
  readonly history: readonly SupersededPin[];
}

export interface SupersededPin {
  readonly hash: string;
  readonly supersededAt: string;
  readonly definition: unknown;
  readonly decision: PinDecision;
}

export interface PinInput {
  readonly serverId: string;
  /** Authorization context. Defaults to {@link DEFAULT_PIN_SCOPE}. */
  readonly scope?: PinScope;
  readonly kind: PinKind;
  readonly subject: string;
  readonly era: ProtocolEra;
  readonly hash: string;
  readonly definition: unknown;
  readonly decision: PinDecision;
  readonly canonicalizationVersion?: number;
}

export class PinConflictError extends Error {
  override readonly name = "PinConflictError";
  readonly existing: PinRecord;
  readonly attemptedHash: string;
  constructor(existing: PinRecord, attemptedHash: string) {
    super(
      `a pin already exists for ${describeKey(existing.serverId, existing.scope, existing.kind, existing.subject)} ` +
        `with a different hash (pinned ${existing.hash}, attempted ${attemptedHash}). Changing a ` +
        "pin requires approveDrift() and an explicit human decision.",
    );
    this.existing = existing;
    this.attemptedHash = attemptedHash;
  }
}

export class PinStoreIntegrityError extends Error {
  override readonly name = "PinStoreIntegrityError";
  readonly path: string;
  constructor(path: string, message: string) {
    super(`${message} (${path})`);
    this.path = path;
  }
}

// ---------------------------------------------------------------------------
// On-disk document
// ---------------------------------------------------------------------------

interface PinFileDocument {
  format: string;
  schemaVersion: number;
  canonicalizationVersion: number;
  revision: number;
  previousIntegrity: string | null;
  updatedAt: string;
  pins: PinRecord[];
  integrity: string;
}

/** Integrity is computed over the canonical form of the document *without* the integrity field. */
function computeIntegrity(doc: Omit<PinFileDocument, "integrity">): string {
  return `sha256:${createHash("sha256").update(canonicalize(doc), "utf8").digest("hex")}`;
}

const isRecord = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

export interface PinStoreOptions {
  /** Path to `pins.json`. Default `.toolwall/pins.json` under `cwd`. */
  readonly path?: string;
  readonly cwd?: string;
  /** Injected clock, for deterministic tests. */
  readonly now?: () => Date;
  /**
   * Load the file even when its integrity digest does not verify. For recovery tooling only —
   * never set this on the enforcement path. Defaults to `false` (fail closed).
   */
  readonly acceptIntegrityMismatch?: boolean;
}

export interface IntegrityStatus {
  readonly ok: boolean;
  readonly expected: string;
  readonly actual: string;
}

export interface PinFilter {
  readonly serverId?: string;
  readonly kind?: PinKind;
  /** Restrict to one authorization context. Omit to list across every scope. */
  readonly scope?: PinScope;
}

/** Human-readable key, for messages an operator reads. */
function describeKey(serverId: string, scope: PinScope, kind: PinKind, subject: string): string {
  return scope === DEFAULT_PIN_SCOPE
    ? `${serverId}/${kind}:${subject}`
    : `${serverId}@${scope}/${kind}:${subject}`;
}

function mapKey(serverId: string, scope: PinScope, kind: PinKind, subject: string): string {
  // NUL cannot occur in a tool name, a scope id or a serverId, so the key is unambiguous
  // under concatenation.
  return `${serverId}\u0000${scope}\u0000${kind}\u0000${subject}`;
}

export class PinStore {
  readonly path: string;
  /** Non-fatal problems found while loading, e.g. over-permissive file mode. */
  readonly warnings: readonly string[];

  #pins = new Map<string, PinRecord>();
  #revision: number;
  #previousIntegrity: string | null;
  #dirty = false;
  #now: () => Date;

  private constructor(
    path: string,
    pins: Map<string, PinRecord>,
    revision: number,
    previousIntegrity: string | null,
    warnings: string[],
    now: () => Date,
  ) {
    this.path = path;
    this.#pins = pins;
    this.#revision = revision;
    this.#previousIntegrity = previousIntegrity;
    this.warnings = warnings;
    this.#now = now;
  }

  /** Open (or create in memory) the pin store. Never writes; call `flush()` to persist. */
  static async open(options: PinStoreOptions = {}): Promise<PinStore> {
    const path = resolvePath(options.cwd ?? process.cwd(), options.path ?? DEFAULT_PIN_FILE);
    const now = options.now ?? (() => new Date());
    const warnings: string[] = [];

    let raw: string;
    try {
      raw = await readFile(path, "utf8");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") {
        return new PinStore(path, new Map(), 0, null, warnings, now);
      }
      throw error;
    }

    await PinStore.#auditPermissions(path, warnings);

    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch (error) {
      throw new PinStoreIntegrityError(
        path,
        `pin file is not valid JSON (${(error as Error).message}); refusing to continue with ` +
          "unknown security state",
      );
    }
    if (!isRecord(parsed)) throw new PinStoreIntegrityError(path, "pin file is not an object");
    if (parsed["format"] !== PIN_FILE_FORMAT) {
      throw new PinStoreIntegrityError(
        path,
        `unexpected format ${JSON.stringify(parsed["format"])}, expected ${PIN_FILE_FORMAT}`,
      );
    }
    const schemaVersion = parsed["schemaVersion"];
    if (
      typeof schemaVersion !== "number" ||
      !READABLE_PIN_FILE_SCHEMA_VERSIONS.includes(schemaVersion)
    ) {
      throw new PinStoreIntegrityError(
        path,
        `pin file schemaVersion ${String(schemaVersion)} is not supported by this build ` +
          `(readable: ${READABLE_PIN_FILE_SCHEMA_VERSIONS.join(", ")}; written: ${PIN_FILE_SCHEMA_VERSION})`,
      );
    }
    if (schemaVersion < PIN_FILE_SCHEMA_VERSION) {
      // Migration is read-only and lossless: v1 had no `scope`, and "no scope" is exactly
      // DEFAULT_PIN_SCOPE. Nothing is rewritten on disk until the caller flushes, and the
      // integrity digest below is still checked against the v1 bytes as they were written.
      warnings.push(
        `pin file is schemaVersion ${schemaVersion}; its pins were adopted at the default ` +
          `authorization scope and the file will be rewritten as v${PIN_FILE_SCHEMA_VERSION} on ` +
          "the next flush",
      );
    }

    const stored = parsed["integrity"];
    const withoutIntegrity = { ...parsed };
    delete (withoutIntegrity as Record<string, unknown>)["integrity"];
    const recomputed = computeIntegrity(withoutIntegrity as unknown as Omit<PinFileDocument, "integrity">);
    if (stored !== recomputed) {
      if (options.acceptIntegrityMismatch !== true) {
        throw new PinStoreIntegrityError(
          path,
          `integrity digest does not match its contents (recorded ${String(stored)}, computed ` +
            `${recomputed}). The pin file has been modified outside toolwall. Review it before ` +
            "reusing it; do not re-approve pins you cannot account for",
        );
      }
      warnings.push(
        `integrity digest mismatch accepted under acceptIntegrityMismatch (recorded ` +
          `${String(stored)}, computed ${recomputed})`,
      );
    }

    const pins = new Map<string, PinRecord>();
    const rawPins = parsed["pins"];
    if (!Array.isArray(rawPins)) throw new PinStoreIntegrityError(path, "`pins` is not an array");
    for (const entry of rawPins) {
      const record = coercePinRecord(entry, path);
      pins.set(mapKey(record.serverId, record.scope, record.kind, record.subject), record);
    }

    const revision = typeof parsed["revision"] === "number" ? parsed["revision"] : 0;
    return new PinStore(path, pins, revision, typeof stored === "string" ? stored : null, warnings, now);
  }

  static async #auditPermissions(path: string, warnings: string[]): Promise<void> {
    if (process.platform === "win32") return; // POSIX mode bits are not meaningful here
    try {
      const info = await stat(path);
      const mode = info.mode & 0o777;
      if ((mode & 0o077) !== 0) {
        warnings.push(
          `pin file mode was 0${mode.toString(8)} (readable or writable beyond the owner); ` +
            "tightened to 0600. Anything that could read it could also plan around your pins",
        );
        await chmod(path, 0o600);
      }
    } catch {
      // stat/chmod failure is not fatal; the integrity check is the real control.
    }
  }

  get dirty(): boolean {
    return this.#dirty;
  }

  get revision(): number {
    return this.#revision;
  }

  get size(): number {
    return this.#pins.size;
  }

  /**
   * `scope` defaults to {@link DEFAULT_PIN_SCOPE}, so a caller with no authorization context — every
   * stdio connection, most HTTP ones — reads and writes exactly the pins it did before scope
   * existed. The parameter is last and optional for that reason: adding scope keying must not
   * silently change the meaning of an existing call site.
   */
  get(
    serverId: string,
    kind: PinKind,
    subject: string,
    scope: PinScope = DEFAULT_PIN_SCOPE,
  ): PinRecord | undefined {
    return this.#pins.get(mapKey(serverId, scope, kind, subject));
  }

  has(
    serverId: string,
    kind: PinKind,
    subject: string,
    scope: PinScope = DEFAULT_PIN_SCOPE,
  ): boolean {
    return this.#pins.has(mapKey(serverId, scope, kind, subject));
  }

  /**
   * Every pin for one subject, across all authorization scopes.
   *
   * This is what makes a scope-related drift alert legible instead of alarming. When a definition
   * fails to match its pin, the useful question is whether the *same bytes* are already pinned
   * under a different credential — if they are, what the operator is looking at is an
   * authorization change, not tampering, and the drift report says so.
   */
  listForSubject(serverId: string, kind: PinKind, subject: string): PinRecord[] {
    const out: PinRecord[] = [];
    for (const record of this.#pins.values()) {
      if (record.serverId === serverId && record.kind === kind && record.subject === subject) {
        out.push(record);
      }
    }
    return out.sort((a, b) => a.scope.localeCompare(b.scope));
  }

  list(filter: PinFilter = {}): PinRecord[] {
    const out: PinRecord[] = [];
    for (const record of this.#pins.values()) {
      if (filter.serverId !== undefined && record.serverId !== filter.serverId) continue;
      if (filter.kind !== undefined && record.kind !== filter.kind) continue;
      if (filter.scope !== undefined && record.scope !== filter.scope) continue;
      out.push(record);
    }
    return out.sort(
      (a, b) =>
        a.serverId.localeCompare(b.serverId) ||
        a.scope.localeCompare(b.scope) ||
        a.kind.localeCompare(b.kind) ||
        a.subject.localeCompare(b.subject),
    );
  }

  /**
   * Create a pin. Throws {@link PinConflictError} if one already exists with a different hash.
   * Re-pinning an identical hash is a no-op and returns the existing record.
   */
  pin(input: PinInput): PinRecord {
    const scope = input.scope ?? DEFAULT_PIN_SCOPE;
    const key = mapKey(input.serverId, scope, input.kind, input.subject);
    const existing = this.#pins.get(key);
    if (existing !== undefined) {
      if (existing.hash !== input.hash) throw new PinConflictError(existing, input.hash);
      return existing;
    }
    const at = input.decision.at;
    const record: PinRecord = {
      serverId: input.serverId,
      scope,
      kind: input.kind,
      subject: input.subject,
      era: input.era,
      hash: input.hash,
      canonicalizationVersion: input.canonicalizationVersion ?? CANONICALIZATION_VERSION,
      firstSeen: at,
      lastVerified: at,
      decision: input.decision,
      definition: input.definition,
      history: [],
    };
    this.#pins.set(key, record);
    this.#dirty = true;
    return record;
  }

  /** Trust-on-first-use: pin only if nothing is pinned yet. Never overwrites, never throws on conflict. */
  pinIfAbsent(input: PinInput): { created: boolean; record: PinRecord } {
    const existing = this.#pins.get(
      mapKey(input.serverId, input.scope ?? DEFAULT_PIN_SCOPE, input.kind, input.subject),
    );
    if (existing !== undefined) return { created: false, record: existing };
    return { created: true, record: this.pin(input) };
  }

  /**
   * Replace an existing pin after a human reviewed the drift. The **only** mutation path for a
   * pinned hash. The superseded pin is retained in `history`; nothing is ever quietly discarded.
   *
   * @throws when there is no existing pin (use `pin()`), or when the decision is not a
   *   `drift-re-approval` — a re-approval must be recorded as one so the audit trail cannot be
   *   made to look like a first-time pin.
   */
  approveDrift(input: PinInput): PinRecord {
    const scope = input.scope ?? DEFAULT_PIN_SCOPE;
    const key = mapKey(input.serverId, scope, input.kind, input.subject);
    const existing = this.#pins.get(key);
    if (existing === undefined) {
      throw new Error(
        `no existing pin for ${describeKey(input.serverId, scope, input.kind, input.subject)}; ` +
          "use pin() to create one",
      );
    }
    if (input.decision.kind !== "drift-re-approval") {
      throw new Error(
        `approveDrift requires a decision of kind "drift-re-approval", got ` +
          `"${input.decision.kind}"`,
      );
    }
    if (input.decision.by.trim() === "" || input.decision.by.startsWith("auto:")) {
      throw new Error(
        "drift re-approval must name a human decider; automated re-approval is the " +
          "CVE-2025-54136 failure mode and is not supported",
      );
    }
    const superseded: SupersededPin = {
      hash: existing.hash,
      supersededAt: input.decision.at,
      definition: existing.definition,
      decision: existing.decision,
    };
    const record: PinRecord = {
      serverId: existing.serverId,
      scope: existing.scope,
      kind: existing.kind,
      subject: existing.subject,
      era: input.era,
      hash: input.hash,
      canonicalizationVersion: input.canonicalizationVersion ?? CANONICALIZATION_VERSION,
      firstSeen: existing.firstSeen,
      lastVerified: input.decision.at,
      decision: input.decision,
      definition: input.definition,
      history: [superseded, ...existing.history],
    };
    this.#pins.set(key, record);
    this.#dirty = true;
    return record;
  }

  /**
   * Record that the pinned definition was re-verified. Called on the hot path, so it mutates
   * memory only; the timestamp reaches disk on the next `flush()`. Marking verified can never
   * change a hash.
   */
  markVerified(
    serverId: string,
    kind: PinKind,
    subject: string,
    at?: Date,
    scope: PinScope = DEFAULT_PIN_SCOPE,
  ): boolean {
    const key = mapKey(serverId, scope, kind, subject);
    const existing = this.#pins.get(key);
    if (existing === undefined) return false;
    this.#pins.set(key, { ...existing, lastVerified: (at ?? this.#now()).toISOString() });
    this.#dirty = true;
    return true;
  }

  remove(
    serverId: string,
    kind: PinKind,
    subject: string,
    scope: PinScope = DEFAULT_PIN_SCOPE,
  ): boolean {
    const removed = this.#pins.delete(mapKey(serverId, scope, kind, subject));
    if (removed) this.#dirty = true;
    return removed;
  }

  /**
   * Re-read the pin file from disk and check that its recorded digest still matches its
   * contents. Useful for a periodic check while the proxy is running: `open()` verifies once,
   * but the file lives on disk for the whole session and nothing stops another process from
   * rewriting it afterwards.
   *
   * Keyless, so see the file header: this detects modification, it does not prevent forgery.
   */
  async verifyFileIntegrity(): Promise<IntegrityStatus> {
    let parsed: unknown;
    try {
      parsed = JSON.parse(await readFile(this.path, "utf8"));
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      return {
        ok: false,
        expected: "<unreadable>",
        actual: code === "ENOENT" ? "<missing>" : `<${(error as Error).message}>`,
      };
    }
    if (!isRecord(parsed)) return { ok: false, expected: "<object>", actual: "<not an object>" };
    const recorded = typeof parsed["integrity"] === "string" ? parsed["integrity"] : "<absent>";
    const withoutIntegrity = { ...parsed };
    delete (withoutIntegrity as Record<string, unknown>)["integrity"];
    const computed = computeIntegrity(
      withoutIntegrity as unknown as Omit<PinFileDocument, "integrity">,
    );
    return { ok: recorded === computed, expected: computed, actual: recorded };
  }

  #document(): Omit<PinFileDocument, "integrity"> {
    return {
      format: PIN_FILE_FORMAT,
      schemaVersion: PIN_FILE_SCHEMA_VERSION,
      canonicalizationVersion: CANONICALIZATION_VERSION,
      revision: this.#revision + (this.#dirty ? 1 : 0),
      previousIntegrity: this.#previousIntegrity,
      updatedAt: this.#now().toISOString(),
      // Sorted so the file has a stable diff in version control and a stable integrity digest.
      pins: this.list(),
    };
  }

  /**
   * Persist atomically: write a sibling temp file with mode 0600, fsync it, then rename over
   * the target. A crash mid-write leaves the previous pin file intact — a truncated pin file
   * would fail its own integrity check and take the proxy offline.
   */
  async flush(): Promise<void> {
    const dir = dirname(this.path);
    await mkdir(dir, { recursive: true, mode: 0o700 });

    const doc = this.#document();
    const integrity = computeIntegrity(doc);
    const full: PinFileDocument = { ...doc, integrity };
    const body = `${JSON.stringify(full, null, 2)}\n`;

    const tmp = `${this.path}.${process.pid}.${Date.now()}.tmp`;
    const handle = await open(tmp, "wx", 0o600);
    try {
      await handle.writeFile(body, "utf8");
      await handle.sync();
    } finally {
      await handle.close();
    }
    try {
      await rename(tmp, this.path);
    } catch (error) {
      await unlink(tmp).catch(() => undefined);
      throw error;
    }
    if (process.platform !== "win32") await chmod(this.path, 0o600);

    this.#revision = doc.revision;
    this.#previousIntegrity = integrity;
    this.#dirty = false;
  }
}

function coercePinRecord(entry: unknown, path: string): PinRecord {
  if (!isRecord(entry)) throw new PinStoreIntegrityError(path, "a pin entry is not an object");
  const required = ["serverId", "kind", "subject", "era", "hash", "firstSeen", "lastVerified"];
  for (const field of required) {
    if (typeof entry[field] !== "string") {
      throw new PinStoreIntegrityError(path, `a pin entry has no string \`${field}\``);
    }
  }
  const kind = entry["kind"];
  if (kind !== "tool" && kind !== "server") {
    throw new PinStoreIntegrityError(path, `a pin entry has unknown kind ${JSON.stringify(kind)}`);
  }
  const decision = entry["decision"];
  if (!isRecord(decision) || typeof decision["kind"] !== "string" || typeof decision["by"] !== "string") {
    throw new PinStoreIntegrityError(path, "a pin entry has no usable `decision`");
  }
  const history = entry["history"];
  // v1 records have no `scope`. Absent means "no authorization context", which is exactly
  // DEFAULT_PIN_SCOPE, so the migration is the default and needs no rewrite. A `scope` that is
  // present but not a string is a corrupt record, not a v1 one, and fails closed.
  const rawScope = entry["scope"];
  if (rawScope !== undefined && typeof rawScope !== "string") {
    throw new PinStoreIntegrityError(path, "a pin entry has a non-string `scope`");
  }
  return {
    serverId: entry["serverId"] as string,
    scope: rawScope ?? DEFAULT_PIN_SCOPE,
    kind,
    subject: entry["subject"] as string,
    era: entry["era"] as ProtocolEra,
    hash: entry["hash"] as string,
    canonicalizationVersion:
      typeof entry["canonicalizationVersion"] === "number" ? entry["canonicalizationVersion"] : 0,
    firstSeen: entry["firstSeen"] as string,
    lastVerified: entry["lastVerified"] as string,
    decision: decision as unknown as PinDecision,
    definition: entry["definition"],
    history: Array.isArray(history) ? (history as SupersededPin[]) : [],
  };
}
