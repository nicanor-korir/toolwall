/**
 * The pin store — toolwall's security state.
 *
 * A pin binds `(serverId, kind, subject)` to the SHA-256 of the RFC 8785 canonical form of a
 * tool definition (or of a server's `instructions`), together with the decision that approved
 * it. It is the entire basis for the rug-pull claim, so this file is written as security state,
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
export const PIN_FILE_SCHEMA_VERSION = 1;
export const DEFAULT_PIN_FILE = ".toolwall/pins.json";

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
      `a pin already exists for ${existing.serverId}/${existing.kind}:${existing.subject} with a ` +
        `different hash (pinned ${existing.hash}, attempted ${attemptedHash}). Changing a pin ` +
        "requires approveDrift() and an explicit human decision.",
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
}

function mapKey(serverId: string, kind: PinKind, subject: string): string {
  // NUL cannot occur in a tool name and cannot be produced by a serverId, so the key is
  // unambiguous under concatenation.
  return `${serverId}\u0000${kind}\u0000${subject}`;
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
    if (parsed["schemaVersion"] !== PIN_FILE_SCHEMA_VERSION) {
      throw new PinStoreIntegrityError(
        path,
        `pin file schemaVersion ${String(parsed["schemaVersion"])} is not supported by this ` +
          `build (expected ${PIN_FILE_SCHEMA_VERSION})`,
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
      pins.set(mapKey(record.serverId, record.kind, record.subject), record);
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

  get(serverId: string, kind: PinKind, subject: string): PinRecord | undefined {
    return this.#pins.get(mapKey(serverId, kind, subject));
  }

  has(serverId: string, kind: PinKind, subject: string): boolean {
    return this.#pins.has(mapKey(serverId, kind, subject));
  }

  list(filter: PinFilter = {}): PinRecord[] {
    const out: PinRecord[] = [];
    for (const record of this.#pins.values()) {
      if (filter.serverId !== undefined && record.serverId !== filter.serverId) continue;
      if (filter.kind !== undefined && record.kind !== filter.kind) continue;
      out.push(record);
    }
    return out.sort(
      (a, b) =>
        a.serverId.localeCompare(b.serverId) ||
        a.kind.localeCompare(b.kind) ||
        a.subject.localeCompare(b.subject),
    );
  }

  /**
   * Create a pin. Throws {@link PinConflictError} if one already exists with a different hash.
   * Re-pinning an identical hash is a no-op and returns the existing record.
   */
  pin(input: PinInput): PinRecord {
    const key = mapKey(input.serverId, input.kind, input.subject);
    const existing = this.#pins.get(key);
    if (existing !== undefined) {
      if (existing.hash !== input.hash) throw new PinConflictError(existing, input.hash);
      return existing;
    }
    const at = input.decision.at;
    const record: PinRecord = {
      serverId: input.serverId,
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
    const existing = this.#pins.get(mapKey(input.serverId, input.kind, input.subject));
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
    const key = mapKey(input.serverId, input.kind, input.subject);
    const existing = this.#pins.get(key);
    if (existing === undefined) {
      throw new Error(
        `no existing pin for ${input.serverId}/${input.kind}:${input.subject}; use pin() to ` +
          "create one",
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
  markVerified(serverId: string, kind: PinKind, subject: string, at?: Date): boolean {
    const key = mapKey(serverId, kind, subject);
    const existing = this.#pins.get(key);
    if (existing === undefined) return false;
    this.#pins.set(key, { ...existing, lastVerified: (at ?? this.#now()).toISOString() });
    this.#dirty = true;
    return true;
  }

  remove(serverId: string, kind: PinKind, subject: string): boolean {
    const removed = this.#pins.delete(mapKey(serverId, kind, subject));
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
  return {
    serverId: entry["serverId"] as string,
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
