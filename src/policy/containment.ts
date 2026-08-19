import * as path from "node:path";
import * as fs from "node:fs";
import * as os from "node:os";

/**
 * Canonical path resolution and containment.
 *
 * ## The two CVEs this file exists to not repeat
 *
 * **CVE-2025-53110 "EscapeRoute"** — Anthropic's own `server-filesystem` decided containment with
 * `resolved.startsWith(allowedDir)`. Allowed root `/tmp/allow_dir` therefore also admitted
 * `/tmp/allow_dir_sensitive_credentials`, because that string does start with that string. String
 * prefixes are not path containment. This module compares **path segments**, so
 * `["tmp","allow_dir"]` vs `["tmp","allow_dir_sensitive_credentials"]` differ at index 1 and the
 * check fails. There is no `startsWith` anywhere in this file.
 *
 * **CVE-2025-53109** — symlink escape. A path is resolved link-by-link, so a symlink inside an
 * allowed root that points outside it is caught. Resolution happens BEFORE containment, never
 * after.
 *
 * ## Why the walk is segment-by-segment instead of `path.resolve` + `fs.realpathSync`
 *
 * `path.resolve` collapses `..` **lexically**, which is not what the kernel does. Given a symlink
 * `<root>/link -> /elsewhere`, the kernel resolves `<root>/link/../etc` to `/etc`, while
 * `path.resolve` produces `<root>/etc` — a path that looks contained and is not. So `..` must be
 * applied only *after* the preceding component has been link-resolved. And `fs.realpathSync`
 * throws `ENOENT` on any path that does not exist yet, which would block every file creation; here
 * resolution simply stops resolving links at the first missing component (correctly — a component
 * that does not exist cannot be a symlink) and continues structurally.
 */

/** Injectable filesystem probe, so tests can drive exotic link topologies deterministically. */
export interface FsProbe {
  isSymbolicLink(p: string): boolean;
  /** MUST throw if `p` does not exist. */
  readLink(p: string): string;
  exists(p: string): boolean;
}

export const nodeFsProbe: FsProbe = {
  isSymbolicLink(p) {
    try {
      return fs.lstatSync(p).isSymbolicLink();
    } catch {
      return false;
    }
  },
  readLink(p) {
    return fs.readlinkSync(p);
  },
  exists(p) {
    try {
      fs.lstatSync(p);
      return true;
    } catch {
      return false;
    }
  },
};

export interface CanonicalizeOptions {
  /** Base directory for relative inputs. Must be absolute. */
  readonly base: string;
  readonly probe?: FsProbe;
  /** Home directory `~` expands to. Injectable so the check is testable without touching $HOME. */
  readonly home?: string;
}

/**
 * Expand a leading `~` to the home directory.
 *
 * **This is a containment fix, not a convenience.** Without it, `~/.ssh/id_rsa` — the single most
 * frequently used payload in this repository's own attack corpus — is not an absolute path, so it
 * gets joined onto `baseDir` and canonicalizes to `<workspace>/~/.ssh/id_rsa`, which is *inside*
 * every granted root. Containment then reports "permitted" for the exact string the attack corpus
 * exists to describe. The tool on the other side, meanwhile, expands `~` for real: shells do,
 * Python's `os.path.expanduser` does, Node tooling does. Treating it as a literal directory named
 * `~` inside the workspace is a fail-OPEN caused by modelling the path differently from the process
 * that will actually open it.
 *
 * Only bare `~` and a leading `~/` (or `~\` on Windows) are expanded. `~otheruser/...` is left
 * alone deliberately: we cannot resolve another account's home directory without consulting the
 * password database, and a wrong guess would be a false root. It therefore stays relative and stays
 * contained — a documented gap, not a covered case.
 */
function expandTilde(input: string, home: string | undefined): string {
  if (input !== "~" && !input.startsWith("~/") && !input.startsWith("~\\")) return input;
  const h = home ?? os.homedir();
  if (h === "" || !path.isAbsolute(h)) return input;
  return input === "~" ? h : h + path.sep + input.slice(2);
}

export type Canonical =
  | {
      readonly ok: true;
      readonly path: string;
      /** Every component existed; nothing was resolved structurally past a missing segment. */
      readonly existed: boolean;
      /** At least one symlink was traversed. Recorded for the audit trail. */
      readonly traversedSymlink: boolean;
    }
  | {
      readonly ok: false;
      readonly reason: "not-a-string" | "empty" | "nul-byte" | "device-path" | "symlink-loop" | "too-many-segments";
      readonly detail: string;
    };

/** Bounded so a hostile link topology cannot spin the guard. */
const MAX_SYMLINK_HOPS = 40;
const MAX_SEGMENTS = 4096;

function splitSegments(p: string): { root: string; segments: string[] } {
  const parsed = path.parse(p);
  const rest = p.slice(parsed.root.length);
  const segments = rest.split(/[\\/]+/).filter((s) => s !== "" && s !== ".");
  return { root: parsed.root, segments };
}

function join(root: string, cur: string, seg: string): string {
  return cur === root ? root + seg : cur + path.sep + seg;
}

function parentOf(root: string, cur: string): string {
  if (cur === root) return root;
  const d = path.dirname(cur);
  return d.length < root.length ? root : d;
}

/**
 * Resolve `input` to a canonical absolute path with all symlinks followed and all `..` applied in
 * kernel order. Never throws.
 */
export function canonicalizePath(input: unknown, opts: CanonicalizeOptions): Canonical {
  if (typeof input !== "string") return { ok: false, reason: "not-a-string", detail: typeof input };
  if (input.length === 0) return { ok: false, reason: "empty", detail: "" };
  if (input.includes("\u0000")) return { ok: false, reason: "nul-byte", detail: "argument contains NUL" };
  // Windows device namespace bypasses normalization entirely; we refuse rather than pretend.
  if (input.startsWith("\\\\?\\") || input.startsWith("\\\\.\\")) {
    return { ok: false, reason: "device-path", detail: input.slice(0, 4) };
  }

  const probe = opts.probe ?? nodeFsProbe;
  const expanded = expandTilde(input, opts.home);
  const absolute = path.isAbsolute(expanded) ? expanded : opts.base + path.sep + expanded;
  const start = splitSegments(absolute);

  const root = start.root === "" ? path.sep : start.root;
  const pending: string[] = start.segments;
  let cur = root;
  let existed = true;
  let traversedSymlink = false;
  let hops = 0;
  let steps = 0;

  while (pending.length > 0) {
    if (++steps > MAX_SEGMENTS) return { ok: false, reason: "too-many-segments", detail: String(steps) };
    const seg = pending.shift();
    if (seg === undefined) break;

    if (seg === "..") {
      // Applied only now — after everything to its left has already been link-resolved.
      cur = parentOf(root, cur);
      continue;
    }

    const next = join(root, cur, seg);

    if (!existed) {
      cur = next;
      continue;
    }

    if (!probe.exists(next)) {
      existed = false;
      cur = next;
      continue;
    }

    if (probe.isSymbolicLink(next)) {
      if (++hops > MAX_SYMLINK_HOPS) return { ok: false, reason: "symlink-loop", detail: `>${MAX_SYMLINK_HOPS} hops` };
      traversedSymlink = true;
      let target: string;
      try {
        target = probe.readLink(next);
      } catch {
        existed = false;
        cur = next;
        continue;
      }
      const t = splitSegments(target);
      if (path.isAbsolute(target)) {
        cur = t.root === "" ? root : t.root;
      }
      // Relative target: `cur` already is the link's parent directory, which is the correct base.
      pending.unshift(...t.segments);
      continue;
    }

    cur = next;
  }

  return { ok: true, path: cur, existed, traversedSymlink };
}

/**
 * True when `target` is `root` itself or lies beneath it.
 *
 * Segment-wise comparison. This is the CVE-2025-53110 fix, and it is deliberately not expressed as
 * `startsWith(root + sep)` — that formulation is correct but one refactor away from the bug, and
 * it silently disagrees with the root-equals-target case.
 */
export function contains(root: string, target: string, caseInsensitive = defaultCaseInsensitive()): boolean {
  const r = splitSegments(root);
  const t = splitSegments(target);
  if (!eq(r.root, t.root, caseInsensitive)) return false;
  if (t.segments.length < r.segments.length) return false;
  for (let i = 0; i < r.segments.length; i++) {
    if (!eq(r.segments[i] ?? "", t.segments[i] ?? "", caseInsensitive)) return false;
  }
  return true;
}

function eq(a: string, b: string, caseInsensitive: boolean): boolean {
  return caseInsensitive ? a.toLowerCase() === b.toLowerCase() : a === b;
}

/**
 * macOS (APFS default) and Windows are case-insensitive. Comparing case-sensitively there would
 * let `/Users/x/Allowed/../ALLOWED_OTHER` read as a different directory to the kernel's view.
 */
export function defaultCaseInsensitive(): boolean {
  return process.platform === "darwin" || process.platform === "win32";
}

/**
 * Canonicalize a policy root at load time. A root that cannot be canonicalized is a policy error,
 * not a runtime one — we fail loading rather than silently enforcing a root that does not mean
 * what the operator wrote.
 */
export function canonicalizeRoot(root: string, probe: FsProbe = nodeFsProbe): { ok: true; path: string } | { ok: false; detail: string } {
  if (!path.isAbsolute(root)) return { ok: false, detail: `root must be absolute: ${root}` };
  const c = canonicalizePath(root, { base: path.sep, probe });
  if (!c.ok) return { ok: false, detail: `${root}: ${c.reason} ${c.detail}` };
  return { ok: true, path: c.path };
}
