/**
 * The append-only, hash-chained audit log — and the destination for contract **C-2**.
 *
 * ## Why this file exists (C-2)
 *
 * Dev 1's `Verdict` type is `{ action: "allow" }` with no payload, deliberately: `allow` is the
 * hot path and must not allocate. But the runtime guards (Dev 3) produce records on the allow
 * path that matter precisely because they are *not* blocks:
 *
 *   - "an unresolvable `$ref` meant this subschema was NOT enforced"
 *   - "the server's `pattern` regex was refused as unsafe, so the argument was NOT validated"
 *   - "a symlink was traversed; its target stayed inside a granted root"
 *   - "this URL carries embedded credentials; the host matched was the host, not the userinfo"
 *
 * Each of those is a statement about a gap in our own coverage. `docs/THREAT-MODEL.md` §3 rule 2
 * forbids ever letting a checked-and-skipped thing read as "safe", so dropping them is not a
 * cosmetic loss. Dev 3 emits them to an injected `AuditSink` instead of widening Dev 1's type,
 * and `docs/ARCHITECTURE.md` C-2 makes wiring that sink the integrator's job. This is the wire.
 *
 * ## What the hash chain is and is not
 *
 * Each record carries `previousHash` and `hash = SHA-256(JCS(record without hash))`, so removing
 * or reordering a record in the middle of the file breaks every subsequent link and
 * `verifyChain()` reports the first index that fails. This is **keyless**, exactly like the pin
 * file's integrity digest: it detects truncation, partial writes and careless editing, and it
 * makes a silent edit take deliberate effort. It does **not** stop an attacker who can write the
 * file — they can recompute the chain. Do not describe it as tamper-proof.
 *
 * ## Hot-path cost
 *
 * `record()` hashes one small object. File writes are queued behind a single promise and never
 * awaited by the caller, so a slow disk cannot add latency to a `tools/call`. Guards that return
 * `allow` with no findings never reach this file at all — `SchemaGuard`/`CapabilityGuard` call
 * the sink only when `findings.length > 0`.
 *
 * ## Zero telemetry
 *
 * This writes to a local file or to nothing. There is no network path here and there must never
 * be one; the zero-telemetry guarantee is a product differentiator, not a preference
 * (`docs/ARCHITECTURE.md` non-negotiable 3).
 */
import { createHash } from "node:crypto";
import { appendFile, mkdir } from "node:fs/promises";
import { dirname, resolve as resolvePath } from "node:path";

import { canonicalize } from "../guards/metadata/canonicalize.js";
import type { AuditSink } from "../policy/contract.js";
import type { Finding, GuardContext, GuardDirection } from "../types/protocol.js";

export const AUDIT_FILE_FORMAT = "toolwall/audit";

/*
 * There is deliberately no DEFAULT_AUDIT_FILE.
 *
 * One used to sit here — `".toolwall/audit.jsonl"` — and nothing read it: the CLI writes a file
 * only when `--audit-log <file>` names one, and `docs/configuration.md` documents the default as
 * "none (in-memory)". A constant that looks like a default but is not one is a trap for the next
 * reader, who wires it up believing they are restoring intended behaviour and quietly changes what
 * every session writes to disk. The default is in-memory on purpose: the audit log keeps the
 * untrusted server's text verbatim (that is its job — the operator wants the bytes), and a
 * security proxy that starts writing that into the working directory of whatever spawned it,
 * unasked, is making a decision that belongs to the operator. Name the file and it is written.
 */

export type AuditRecordKind =
  /** Non-blocking findings from a guard that returned `allow` — the C-2 records. */
  | "finding"
  /** A guard blocked. The request never reached the far side. */
  | "blocked"
  /** A guard rewrote the payload before forwarding it. */
  | "annotated"
  /** The pinning engine changed state: pinned, verified, drifted, stale, withdrawn. */
  | "pin"
  /** A child process was spawned. The spec asks stdio proxies to log all usage (T-07). */
  | "spawn"
  /** Session lifecycle: started, upstream closed, client closed, guard crashed. */
  | "lifecycle";

export interface AuditRecord {
  /** 1-based, monotonic within one log. */
  readonly seq: number;
  /** ISO 8601. */
  readonly at: string;
  readonly kind: AuditRecordKind;
  readonly serverId: string;
  readonly method?: string;
  readonly direction?: GuardDirection;
  readonly findings?: readonly Finding[];
  /** Structured, JSON-serializable context. MUST NOT contain secrets. */
  readonly detail?: Readonly<Record<string, unknown>>;
  /** `hash` of the previous record, or `null` for the first. */
  readonly previousHash: string | null;
  /** `sha256:<hex>` over the JCS form of this record without `hash`. */
  readonly hash: string;
}

export interface AuditLogOptions {
  /** Append every record to this JSONL file. Omit for memory only. */
  readonly file?: string;
  readonly cwd?: string;
  /** Injected clock, for deterministic tests. */
  readonly now?: () => Date;
  /**
   * How many records to retain in memory. The file, when configured, keeps everything; this cap
   * only bounds the in-process buffer so a long session cannot grow without limit.
   */
  readonly maxRetained?: number;
  /** Called when a file append fails. Never given payload contents. */
  readonly onWriteError?: (error: unknown) => void;
}

export interface AuditEntry {
  readonly kind: AuditRecordKind;
  readonly serverId: string;
  readonly method?: string;
  readonly direction?: GuardDirection;
  readonly findings?: readonly Finding[];
  readonly detail?: Readonly<Record<string, unknown>>;
}

const DEFAULT_MAX_RETAINED = 1000;

function hashOf(record: Omit<AuditRecord, "hash">): string {
  return `sha256:${createHash("sha256").update(canonicalize(record), "utf8").digest("hex")}`;
}

export class AuditLog {
  readonly path: string | undefined;

  readonly #records: AuditRecord[] = [];
  readonly #now: () => Date;
  readonly #maxRetained: number;
  readonly #onWriteError: (error: unknown) => void;
  #seq = 0;
  #lastHash: string | null = null;
  /** Serializes file appends so records cannot interleave mid-line. */
  #writes: Promise<void> = Promise.resolve();

  constructor(options: AuditLogOptions = {}) {
    this.path =
      options.file === undefined
        ? undefined
        : resolvePath(options.cwd ?? process.cwd(), options.file);
    this.#now = options.now ?? (() => new Date());
    this.#maxRetained = options.maxRetained ?? DEFAULT_MAX_RETAINED;
    this.#onWriteError = options.onWriteError ?? (() => undefined);
  }

  /** Records retained in memory, oldest first. */
  get records(): readonly AuditRecord[] {
    return this.#records;
  }

  get length(): number {
    return this.#seq;
  }

  /** Append one record. Synchronous by design: the file write is queued, never awaited here. */
  record(entry: AuditEntry): AuditRecord {
    this.#seq += 1;
    const base: Omit<AuditRecord, "hash"> = {
      seq: this.#seq,
      at: this.#now().toISOString(),
      kind: entry.kind,
      serverId: entry.serverId,
      ...(entry.method === undefined ? {} : { method: entry.method }),
      ...(entry.direction === undefined ? {} : { direction: entry.direction }),
      ...(entry.findings === undefined ? {} : { findings: entry.findings }),
      ...(entry.detail === undefined ? {} : { detail: entry.detail }),
      previousHash: this.#lastHash,
    };
    const record: AuditRecord = { ...base, hash: hashOf(base) };
    this.#lastHash = record.hash;

    this.#records.push(record);
    if (this.#records.length > this.#maxRetained) {
      this.#records.splice(0, this.#records.length - this.#maxRetained);
    }
    this.#append(record);
    return record;
  }

  /**
   * The `AuditSink` the runtime guards take as `opts.audit`. This is the C-2 wire: without it
   * every informational finding a guard produces on the allow path is discarded.
   */
  sink(): AuditSink {
    return (findings: readonly Finding[], ctx: GuardContext): void => {
      if (findings.length === 0) return;
      this.record({
        kind: "finding",
        serverId: ctx.serverId,
        method: ctx.method,
        direction: ctx.direction,
        findings,
        detail: { era: ctx.era },
      });
    };
  }

  /**
   * Re-hash every retained record and report the first link that does not verify.
   *
   * Keyless — see the file header. `firstBadIndex` is an index into `records`, not a `seq`.
   */
  verifyChain(): { ok: true } | { ok: false; firstBadIndex: number; reason: string } {
    let previous: string | null = this.#records[0]?.previousHash ?? null;
    for (let i = 0; i < this.#records.length; i++) {
      const record = this.#records[i];
      if (record === undefined) continue;
      if (record.previousHash !== previous) {
        return { ok: false, firstBadIndex: i, reason: "previousHash does not match the preceding record" };
      }
      const { hash, ...rest } = record;
      if (hashOf(rest) !== hash) {
        return { ok: false, firstBadIndex: i, reason: "record hash does not match its contents" };
      }
      previous = hash;
    }
    return { ok: true };
  }

  /** Wait for every queued file append to land. Call before the process exits. */
  async flush(): Promise<void> {
    await this.#writes;
  }

  #append(record: AuditRecord): void {
    const path = this.path;
    if (path === undefined) return;
    const line = `${JSON.stringify(record)}\n`;
    this.#writes = this.#writes
      .then(async () => {
        await mkdir(dirname(path), { recursive: true, mode: 0o700 });
        await appendFile(path, line, { encoding: "utf8", mode: 0o600 });
      })
      .catch((error: unknown) => {
        // A failed audit write must not take the proxy down, but it must not be invisible
        // either. The caller decides what to do; the CLI prints it on stderr.
        this.#onWriteError(error);
      });
  }
}
