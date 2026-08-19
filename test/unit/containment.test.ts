import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { canonicalizePath, canonicalizeRoot, contains } from "../../src/policy/containment.js";

/**
 * TRUE-POSITIVE tests for the two CVEs this module exists to not repeat. A 0% false-positive rate
 * is trivially achievable by a guard that does nothing; these are the tests that make the FP number
 * mean something.
 */

let tmp: string;
let allow: string;
let sibling: string;
let outside: string;

beforeAll(() => {
  tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "toolwall-containment-")));
  allow = path.join(tmp, "allow_dir");
  // The EscapeRoute directory, verbatim from CVE-2025-53110.
  sibling = path.join(tmp, "allow_dir_sensitive_credentials");
  outside = path.join(tmp, "outside");
  for (const d of [allow, sibling, outside]) fs.mkdirSync(d, { recursive: true });
  fs.writeFileSync(path.join(sibling, "creds.txt"), "secret\n");
  fs.writeFileSync(path.join(outside, "passwd"), "root:x:0:0\n");
  fs.mkdirSync(path.join(allow, "sub"), { recursive: true });
  fs.writeFileSync(path.join(allow, "sub", "ok.txt"), "fine\n");
});

afterAll(() => fs.rmSync(tmp, { recursive: true, force: true }));

const canon = (p: string): string => {
  const c = canonicalizePath(p, { base: tmp });
  if (!c.ok) throw new Error(`canonicalize failed: ${c.reason}`);
  return c.path;
};

describe("CVE-2025-53110 EscapeRoute — prefix matching is not containment", () => {
  it("does NOT admit a sibling directory that shares a string prefix with the allowed root", () => {
    const target = canon(path.join(sibling, "creds.txt"));

    // The vulnerable formulation, reproduced to show the two disagree.
    expect(target.startsWith(allow)).toBe(true);
    expect(contains(allow, target)).toBe(false);
  });

  it("admits the allowed root itself", () => {
    expect(contains(allow, canon(allow))).toBe(true);
  });

  it("admits a path beneath the allowed root", () => {
    expect(contains(allow, canon(path.join(allow, "sub", "ok.txt")))).toBe(true);
  });

  it("admits a trailing-separator form of the root", () => {
    expect(contains(allow, canon(allow + path.sep))).toBe(true);
  });

  it("rejects a parent of the allowed root", () => {
    expect(contains(allow, canon(tmp))).toBe(false);
  });
});

describe("CVE-2025-53109 — symlink escape", () => {
  it("rejects a symlink inside the root whose target is outside it", () => {
    const link = path.join(allow, "escape");
    if (!fs.existsSync(link)) fs.symlinkSync(outside, link, "dir");
    const target = canon(path.join(link, "passwd"));
    expect(target).toBe(path.join(outside, "passwd"));
    expect(contains(allow, target)).toBe(false);
  });

  it("accepts a symlink whose target stays inside the root", () => {
    const link = path.join(allow, "inner-link");
    if (!fs.existsSync(link)) fs.symlinkSync(path.join(allow, "sub"), link, "dir");
    const target = canon(path.join(link, "ok.txt"));
    expect(contains(allow, target)).toBe(true);
  });

  it("applies `..` AFTER symlink resolution, matching the kernel rather than path.resolve", () => {
    // `<allow>/escape` -> `<outside>`. The kernel resolves `<allow>/escape/../passwd` relative to
    // `<outside>`, i.e. to `<tmp>/passwd`. `path.resolve` would collapse `..` lexically and produce
    // `<allow>/passwd`, which looks contained and is not. This is the bug the segment walk avoids.
    const link = path.join(allow, "escape");
    if (!fs.existsSync(link)) fs.symlinkSync(outside, link, "dir");

    const lexical = path.resolve(`${link}/../passwd`);
    expect(contains(allow, lexical)).toBe(true); // the wrong answer

    // NB: built by concatenation, not path.join — path.join would collapse `..` lexically before
    // the walker ever saw it, which is precisely the bug under test.
    const target = canon(`${link}/../passwd`);
    expect(target).toBe(path.join(tmp, "passwd"));
    expect(contains(allow, target)).toBe(false); // the right one
  });

  it("terminates on a symlink loop instead of spinning", () => {
    const a = path.join(tmp, "loop-a");
    const b = path.join(tmp, "loop-b");
    if (!fs.existsSync(a)) fs.symlinkSync(b, a, "dir");
    if (!fs.existsSync(b)) fs.symlinkSync(a, b, "dir");
    const c = canonicalizePath(path.join(a, "x"), { base: tmp });
    expect(c.ok).toBe(false);
    if (!c.ok) expect(c.reason).toBe("symlink-loop");
  });
});

describe("traversal and normalization", () => {
  it("rejects a plain ../ escape", () => {
    expect(contains(allow, canon(`${allow}/../outside/passwd`))).toBe(false);
  });

  it("accepts ../ that normalizes back inside the root", () => {
    expect(contains(allow, canon(`${allow}/sub/../sub/ok.txt`))).toBe(true);
  });

  it("resolves a path whose deepest components do not exist yet", () => {
    const c = canonicalizePath(path.join(allow, "not", "created", "yet.txt"), { base: tmp });
    expect(c.ok).toBe(true);
    if (c.ok) {
      expect(c.existed).toBe(false);
      expect(contains(allow, c.path)).toBe(true);
    }
  });

  it("rejects escapes through a not-yet-existing directory", () => {
    const c = canonicalizePath(`${allow}/nope/../../outside/passwd`, { base: tmp });
    expect(c.ok).toBe(true);
    if (c.ok) expect(contains(allow, c.path)).toBe(false);
  });

  it("rejects a NUL byte", () => {
    const c = canonicalizePath(`${allow}/ok.txt` + "\u0000" + ".png", { base: tmp });
    expect(c.ok).toBe(false);
    if (!c.ok) expect(c.reason).toBe("nul-byte");
  });

  it("rejects a non-string", () => {
    expect(canonicalizePath(42, { base: tmp }).ok).toBe(false);
    expect(canonicalizePath(null, { base: tmp }).ok).toBe(false);
  });

  it("resolves relative input against the declared base", () => {
    const c = canonicalizePath("sub/ok.txt", { base: allow });
    expect(c.ok).toBe(true);
    if (c.ok) expect(c.path).toBe(path.join(allow, "sub", "ok.txt"));
  });
});

describe("canonicalizeRoot", () => {
  it("rejects a relative root at policy-load time", () => {
    expect(canonicalizeRoot("./relative").ok).toBe(false);
  });

  it("resolves a symlinked root to its real location", () => {
    const linkRoot = path.join(tmp, "root-link");
    if (!fs.existsSync(linkRoot)) fs.symlinkSync(allow, linkRoot, "dir");
    const r = canonicalizeRoot(linkRoot);
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.path).toBe(allow);
  });
});
