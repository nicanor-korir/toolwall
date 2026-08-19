/**
 * Pin store tests.
 *
 * Two things are being defended here, and they are different:
 *
 *   1. **The API cannot be made to auto-accept drift.** `pin()` only creates; only
 *      `approveDrift()` can replace a hash, and only with a named human decider. This is
 *      CVE-2025-54136 ("MCPoison", CVSS 7.2) expressed as a type signature — Cursor keyed
 *      approval on file identity rather than content, so a swapped config inherited the
 *      approval. Every test in "never auto-accept" is an attempt to get a changed hash
 *      accepted without a decision.
 *   2. **The file is treated as security state**, not as a cache: 0600, atomic replacement,
 *      integrity self-check on load, and a hard failure rather than a shrug when it does not
 *      verify.
 */
import { chmod, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  PIN_FILE_FORMAT,
  PinConflictError,
  PinStore,
  PinStoreIntegrityError,
  deriveServerId,
} from "../../src/audit/manifest.js";
import type { PinInput } from "../../src/audit/manifest.js";

let dir: string;
const pinPath = (): string => join(dir, ".toolwall", "pins.json");

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "toolwall-pins-"));
});
afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

const openStore = (): Promise<PinStore> => PinStore.open({ cwd: dir });

function input(overrides: Partial<PinInput> = {}): PinInput {
  return {
    serverId: "srv_test",
    kind: "tool",
    subject: "add",
    era: "2025-11-25",
    hash: "sha256:aaaa",
    definition: { name: "add", description: "Adds two integers." },
    decision: { kind: "trust-on-first-use", at: "2026-08-19T00:00:00.000Z", by: "auto:tofu" },
    ...overrides,
  };
}

// ---------------------------------------------------------------------------

describe("deriveServerId — identity is how you launched it, not what it calls itself (T-04)", () => {
  it("is stable across calls", () => {
    const id = deriveServerId({ transport: "stdio", command: "node", args: ["server.js"] });
    expect(deriveServerId({ transport: "stdio", command: "node", args: ["server.js"] })).toBe(id);
    expect(id).toMatch(/^srv_[0-9a-f]{32}$/);
  });

  it("separates servers that differ in command, args or working directory", () => {
    const base = { transport: "stdio", command: "node", args: ["a.js"], cwd: "/x" } as const;
    const ids = new Set([
      deriveServerId(base),
      deriveServerId({ ...base, command: "bun" }),
      deriveServerId({ ...base, args: ["b.js"] }),
      deriveServerId({ ...base, cwd: "/y" }),
    ]);
    expect(ids.size).toBe(4);
  });

  it("uses environment variable NAMES but never their values", () => {
    const withToken = deriveServerId({
      transport: "stdio",
      command: "node",
      args: ["s.js"],
      env: { API_TOKEN: "secret-v1" },
    });
    const rotated = deriveServerId({
      transport: "stdio",
      command: "node",
      args: ["s.js"],
      env: { API_TOKEN: "secret-v2" },
    });
    const renamed = deriveServerId({
      transport: "stdio",
      command: "node",
      args: ["s.js"],
      env: { OTHER_TOKEN: "secret-v1" },
    });
    // A rotated credential must not orphan every pin for this server: a new serverId means the
    // next tools/list is trusted on first use again, which is a rug-pull window opened by
    // routine key rotation.
    expect(rotated).toBe(withToken);
    expect(renamed).not.toBe(withToken);
  });

  it("applies the same rule to HTTP query strings", () => {
    const a = deriveServerId({ transport: "http", url: "https://Example.COM/mcp?key=v1" });
    const b = deriveServerId({ transport: "http", url: "https://example.com/mcp?key=v2" });
    const c = deriveServerId({ transport: "http", url: "https://example.com/mcp?other=v1" });
    const d = deriveServerId({ transport: "http", url: "https://example.com/other" });
    expect(a).toBe(b); // host case-folded, credential value ignored
    expect(c).not.toBe(a);
    expect(d).not.toBe(a);
  });

  it("takes no server-supplied input at all", () => {
    // There is deliberately no code path that lets `serverInfo.name` reach a serverId: the spec
    // says it is not unique and SHOULD NOT be relied on, and it is self-reported by the
    // untrusted side, so keying pins on it would let a server inherit another's approvals.
    expect(Object.keys(deriveServerId)).not.toContain("serverInfo");
    expect(deriveServerId.length).toBe(1);
  });
});

describe("pinning", () => {
  it("creates a pin recording era, first-seen, last-verified and the approving decision", async () => {
    const store = await openStore();
    const record = store.pin(input());
    expect(record).toMatchObject({
      serverId: "srv_test",
      kind: "tool",
      subject: "add",
      era: "2025-11-25",
      hash: "sha256:aaaa",
      firstSeen: "2026-08-19T00:00:00.000Z",
      lastVerified: "2026-08-19T00:00:00.000Z",
      canonicalizationVersion: 1,
      history: [],
    });
    expect(record.decision.kind).toBe("trust-on-first-use");
  });

  it("keys pins by (serverId, subject) so two servers cannot shadow each other", async () => {
    const store = await openStore();
    store.pin(input({ serverId: "srv_a" }));
    store.pin(input({ serverId: "srv_b", hash: "sha256:bbbb" }));
    expect(store.get("srv_a", "tool", "add")?.hash).toBe("sha256:aaaa");
    expect(store.get("srv_b", "tool", "add")?.hash).toBe("sha256:bbbb");
  });

  it("keeps tool pins and server-instruction pins in separate namespaces", async () => {
    const store = await openStore();
    store.pin(input({ kind: "tool", subject: "instructions" }));
    store.pin(input({ kind: "server", subject: "instructions", hash: "sha256:cccc" }));
    expect(store.get("srv_test", "tool", "instructions")?.hash).toBe("sha256:aaaa");
    expect(store.get("srv_test", "server", "instructions")?.hash).toBe("sha256:cccc");
  });

  it("pinIfAbsent adopts once and never again", async () => {
    const store = await openStore();
    expect(store.pinIfAbsent(input()).created).toBe(true);
    const second = store.pinIfAbsent(input({ hash: "sha256:zzzz" }));
    expect(second.created).toBe(false);
    expect(second.record.hash).toBe("sha256:aaaa");
  });

  it("markVerified updates the timestamp and nothing else", async () => {
    const store = await openStore();
    store.pin(input());
    expect(store.markVerified("srv_test", "tool", "add", new Date("2026-09-01T00:00:00Z"))).toBe(true);
    const record = store.get("srv_test", "tool", "add");
    expect(record?.lastVerified).toBe("2026-09-01T00:00:00.000Z");
    expect(record?.hash).toBe("sha256:aaaa");
    expect(record?.firstSeen).toBe("2026-08-19T00:00:00.000Z");
  });
});

describe("never auto-accept — the CVE-2025-54136 constraint expressed as an API", () => {
  it("refuses to re-pin the same subject with a different hash", async () => {
    const store = await openStore();
    store.pin(input());
    expect(() => store.pin(input({ hash: "sha256:bbbb" }))).toThrow(PinConflictError);
    expect(store.get("srv_test", "tool", "add")?.hash).toBe("sha256:aaaa");
  });

  it("treats re-pinning an identical hash as a no-op, not an error", async () => {
    const store = await openStore();
    const first = store.pin(input());
    expect(store.pin(input())).toBe(first);
  });

  it("has no path that replaces a hash except approveDrift", async () => {
    const store = await openStore();
    store.pin(input());
    // The whole public surface, exercised against a changed hash. If any of these silently
    // updated the pin, a rug pull would be self-approving.
    expect(() => store.pin(input({ hash: "sha256:evil" }))).toThrow(PinConflictError);
    expect(store.pinIfAbsent(input({ hash: "sha256:evil" })).record.hash).toBe("sha256:aaaa");
    store.markVerified("srv_test", "tool", "add");
    expect(store.get("srv_test", "tool", "add")?.hash).toBe("sha256:aaaa");
  });

  it("refuses drift re-approval that is not recorded as one", async () => {
    const store = await openStore();
    store.pin(input());
    expect(() =>
      store.approveDrift(
        input({
          hash: "sha256:bbbb",
          decision: { kind: "explicit-approval", at: "2026-08-20T00:00:00Z", by: "alice" },
        }),
      ),
    ).toThrow(/drift-re-approval/);
  });

  it("refuses drift re-approval by an automated decider", async () => {
    const store = await openStore();
    store.pin(input());
    for (const by of ["auto:tofu", "auto:policy", "  "]) {
      expect(() =>
        store.approveDrift(
          input({
            hash: "sha256:bbbb",
            decision: { kind: "drift-re-approval", at: "2026-08-20T00:00:00Z", by },
          }),
        ),
      ).toThrow(/human/);
    }
    expect(store.get("srv_test", "tool", "add")?.hash).toBe("sha256:aaaa");
  });

  it("refuses to re-approve something that was never pinned", async () => {
    const store = await openStore();
    expect(() =>
      store.approveDrift(
        input({
          decision: { kind: "drift-re-approval", at: "2026-08-20T00:00:00Z", by: "alice" },
        }),
      ),
    ).toThrow(/no existing pin/);
  });

  it("records the superseded pin in history and keeps the original first-seen", async () => {
    const store = await openStore();
    store.pin(input());
    const updated = store.approveDrift(
      input({
        hash: "sha256:bbbb",
        definition: { name: "add", description: "Adds two integers. And exfiltrates." },
        decision: {
          kind: "drift-re-approval",
          at: "2026-08-20T00:00:00.000Z",
          by: "alice",
          note: "vendor confirmed the copy change",
        },
      }),
    );
    expect(updated.hash).toBe("sha256:bbbb");
    expect(updated.firstSeen).toBe("2026-08-19T00:00:00.000Z");
    expect(updated.lastVerified).toBe("2026-08-20T00:00:00.000Z");
    expect(updated.history).toHaveLength(1);
    expect(updated.history[0]).toMatchObject({
      hash: "sha256:aaaa",
      supersededAt: "2026-08-20T00:00:00.000Z",
    });
    expect(updated.decision.by).toBe("alice");
  });
});

describe("the file is security state", () => {
  it("writes 0600 inside a 0700 directory", async () => {
    const store = await openStore();
    store.pin(input());
    await store.flush();
    expect((await stat(pinPath())).mode & 0o777).toBe(0o600);
    expect((await stat(join(dir, ".toolwall"))).mode & 0o777).toBe(0o700);
  });

  it("round-trips every field through disk", async () => {
    const store = await openStore();
    store.pin(input());
    store.pin(input({ kind: "server", subject: "instructions", hash: "sha256:cccc" }));
    await store.flush();

    const reopened = await openStore();
    expect(reopened.size).toBe(2);
    expect(reopened.get("srv_test", "tool", "add")).toMatchObject({
      hash: "sha256:aaaa",
      era: "2025-11-25",
      firstSeen: "2026-08-19T00:00:00.000Z",
      definition: { name: "add", description: "Adds two integers." },
    });
    expect(reopened.warnings).toEqual([]);
  });

  it("writes a self-describing document with an integrity digest", async () => {
    const store = await openStore();
    store.pin(input());
    await store.flush();
    const doc = JSON.parse(await readFile(pinPath(), "utf8")) as Record<string, unknown>;
    expect(doc["format"]).toBe(PIN_FILE_FORMAT);
    expect(doc["schemaVersion"]).toBe(1);
    expect(doc["canonicalizationVersion"]).toBe(1);
    expect(doc["revision"]).toBe(1);
    expect(doc["integrity"]).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(await store.verifyFileIntegrity()).toMatchObject({ ok: true });
  });

  it("refuses to load a file whose contents no longer match its digest", async () => {
    const store = await openStore();
    store.pin(input());
    await store.flush();

    const doc = JSON.parse(await readFile(pinPath(), "utf8")) as {
      pins: Array<{ hash: string }>;
    };
    // Exactly the attack the digest exists for: swap a pinned hash for the attacker's.
    doc.pins[0]!.hash = "sha256:evil";
    await writeFile(pinPath(), JSON.stringify(doc), { mode: 0o600 });

    await expect(openStore()).rejects.toThrow(PinStoreIntegrityError);
    await expect(openStore()).rejects.toThrow(/modified outside toolwall/);
  });

  it("detects tampering that happens while the proxy is already running", async () => {
    const store = await openStore();
    store.pin(input());
    await store.flush();
    expect((await store.verifyFileIntegrity()).ok).toBe(true);

    await writeFile(pinPath(), (await readFile(pinPath(), "utf8")).replace("aaaa", "evil"), {
      mode: 0o600,
    });
    expect((await store.verifyFileIntegrity()).ok).toBe(false);
  });

  it("only ignores a bad digest when explicitly told to, and says that it did", async () => {
    const store = await openStore();
    store.pin(input());
    await store.flush();
    await writeFile(pinPath(), (await readFile(pinPath(), "utf8")).replace("aaaa", "beef"), {
      mode: 0o600,
    });

    const recovered = await PinStore.open({ cwd: dir, acceptIntegrityMismatch: true });
    expect(recovered.size).toBe(1);
    expect(recovered.warnings.join(" ")).toMatch(/integrity digest mismatch accepted/);
  });

  it("refuses a file that is not valid JSON rather than starting with no pins", async () => {
    const store = await openStore();
    store.pin(input());
    await store.flush();
    await writeFile(pinPath(), "{ this is not json", { mode: 0o600 });
    // Starting empty would silently re-enter trust-on-first-use for every tool.
    await expect(openStore()).rejects.toThrow(PinStoreIntegrityError);
  });

  it("refuses a file written by a future schema version", async () => {
    const store = await openStore();
    store.pin(input());
    await store.flush();
    const doc = JSON.parse(await readFile(pinPath(), "utf8")) as Record<string, unknown>;
    doc["schemaVersion"] = 99;
    await writeFile(pinPath(), JSON.stringify(doc), { mode: 0o600 });
    await expect(openStore()).rejects.toThrow(/schemaVersion/);
  });

  it("tightens an over-permissive file mode and warns about it", async () => {
    const store = await openStore();
    store.pin(input());
    await store.flush();
    // `mode` on writeFile only applies when the file is created, so widen it explicitly.
    await chmod(pinPath(), 0o644);
    expect((await stat(pinPath())).mode & 0o777).toBe(0o644);

    const reopened = await openStore();
    expect(reopened.warnings.join(" ")).toMatch(/readable or writable beyond the owner/);
    expect((await stat(pinPath())).mode & 0o777).toBe(0o600);
  });

  it("starts empty when there is no file yet, and leaves nothing behind until flushed", async () => {
    const store = await openStore();
    expect(store.size).toBe(0);
    expect(store.dirty).toBe(false);
    await expect(stat(pinPath())).rejects.toThrow();
  });

  it("chains revisions so a file under version control shows its own history", async () => {
    const store = await openStore();
    store.pin(input());
    await store.flush();
    const first = JSON.parse(await readFile(pinPath(), "utf8")) as Record<string, unknown>;

    store.pin(input({ subject: "subtract", hash: "sha256:dddd" }));
    await store.flush();
    const second = JSON.parse(await readFile(pinPath(), "utf8")) as Record<string, unknown>;

    expect(second["revision"]).toBe(2);
    expect(second["previousIntegrity"]).toBe(first["integrity"]);
  });

  it("leaves no temp files behind", async () => {
    const store = await openStore();
    store.pin(input());
    await store.flush();
    const { readdir } = await import("node:fs/promises");
    expect((await readdir(join(dir, ".toolwall"))).filter((f) => f.endsWith(".tmp"))).toEqual([]);
  });
});
