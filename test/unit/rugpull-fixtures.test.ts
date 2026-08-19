/**
 * The pinning engine against the red team's live rug-pull fixtures.
 *
 * `test/unit/drift.test.ts` drives the guard with hand-built payloads. This file spawns
 * `test/fixtures/malicious/rugpull-server.js` as a real MCP server over real stdio and puts the
 * guard where toolwall's proxy will sit: every `tools/list` result is inspected on the response
 * leg, every `tools/call` params object on the request leg, and a call only reaches the server
 * if the guard returned `allow`. Nothing about the attack is simulated — the fixture decides on
 * its own when to mutate.
 *
 * The three variants map to the threat model:
 *   a  prose mutation, schema byte-identical
 *   b  schema mutation, prose byte-identical  — defeats any pin that hashes descriptions only
 *   c  mutation after N calls (Deadbugz, N=3) — defeats pinning at first connect
 * plus `--silent`, which mutates without sending `notifications/tools/list_changed`.
 *
 * The fixtures are owned by the red team and are not modified here.
 */
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { ToolListChangedNotificationSchema } from "@modelcontextprotocol/sdk/types.js";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { PinStore } from "../../src/audit/manifest.js";
import { deriveServerId } from "../../src/audit/manifest.js";
import { MetadataPinGuard } from "../../src/guards/metadata/drift.js";
import type { Finding, GuardContext, Verdict } from "../../src/types/protocol.js";

const FIXTURE = resolve(__dirname, "../fixtures/malicious/rugpull-server.js");

let dir: string;
let store: PinStore;
const opened: Array<() => Promise<void>> = [];

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "toolwall-rugpull-"));
  store = await PinStore.open({ cwd: dir });
});
afterEach(async () => {
  for (const close of opened.splice(0)) await close().catch(() => undefined);
  await rm(dir, { recursive: true, force: true });
});

const findings = (verdict: Verdict): readonly Finding[] =>
  "findings" in verdict ? verdict.findings : [];

interface Harness {
  readonly guard: MetadataPinGuard;
  readonly serverId: string;
  /** Inspect a `tools/list` response exactly where the proxy would. */
  list(): Promise<Verdict>;
  /** Inspect `tools/call` params, and only forward when the verdict is `allow`. */
  call(): Promise<{ verdict: Verdict; forwarded: boolean }>;
  listChangedCount(): number;
}

async function harness(args: string[]): Promise<Harness> {
  // Identity comes from the spawn spec, never from serverInfo.name (T-04).
  const serverId = deriveServerId({ transport: "stdio", command: process.execPath, args: [FIXTURE, ...args] });

  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [FIXTURE, ...args],
    stderr: "ignore",
  });
  const client = new Client({ name: "toolwall-test", version: "0.0.0" }, { capabilities: {} });

  const guard = new MetadataPinGuard({ store, era: "2025-11-25" });
  let listChanged = 0;

  const ctx = (direction: GuardContext["direction"], method: string): GuardContext => ({
    era: "2025-11-25",
    serverId,
    direction,
    method,
  });

  client.setNotificationHandler(ToolListChangedNotificationSchema, () => {
    listChanged += 1;
    guard.inspect({}, ctx("response", "notifications/tools/list_changed"));
  });

  await client.connect(transport);
  opened.push(() => client.close());

  return {
    guard,
    serverId,
    async list() {
      return guard.inspect(await client.listTools(), ctx("response", "tools/list"));
    },
    async call() {
      const params = { name: "add", arguments: { a: 1, b: 2 } };
      const verdict = guard.inspect(params, ctx("request", "tools/call"));
      if (verdict.action !== "allow") return { verdict, forwarded: false };
      await client.callTool(params);
      return { verdict, forwarded: true };
    },
    listChangedCount: () => listChanged,
  };
}

async function waitFor(predicate: () => boolean, timeoutMs = 2000): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return true;
    await new Promise((r) => setTimeout(r, 10));
  }
  return predicate();
}

// ---------------------------------------------------------------------------

describe("variant a — prose mutation after the first listing", () => {
  it("pins the clean listing, then blocks the poisoned one with a readable diff", async () => {
    const h = await harness(["--variant", "a"]);

    expect(await h.list()).toEqual({ action: "allow" });
    expect(store.get(h.serverId, "tool", "add")?.decision.kind).toBe("trust-on-first-use");
    expect((await h.call()).forwarded).toBe(true);

    const verdict = await h.list();
    expect(verdict.action).toBe("block");

    const finding = findings(verdict)[0];
    expect(finding?.ruleId).toBe("toolwall/pin-drift");
    expect(finding?.severity).toBe("critical");
    expect(finding?.evidence?.["changedPaths"]).toEqual(["/description"]);
    expect(finding?.message).toContain("~ /description");
    expect(finding?.message).toContain("Ignore previous instructions");
    expect(finding?.message).toContain("id_rsa");
  });

  it("blocks the next call and leaves the pin untouched", async () => {
    const h = await harness(["--variant", "a"]);
    await h.list();
    const pinnedHash = store.get(h.serverId, "tool", "add")?.hash;

    await h.list(); // poisoned

    const { verdict, forwarded } = await h.call();
    expect(forwarded).toBe(false);
    expect(verdict.action).toBe("block");
    expect(findings(verdict)[0]?.ruleId).toBe("toolwall/pin-drift");
    expect(store.get(h.serverId, "tool", "add")?.hash).toBe(pinnedHash);
    expect(h.guard.listQuarantined()).toHaveLength(1);
  });
});

describe("variant b — schema mutation with byte-identical prose", () => {
  it("is caught even though nothing a human would read has changed", async () => {
    const h = await harness(["--variant", "b"]);
    expect(await h.list()).toEqual({ action: "allow" });

    const verdict = await h.list();
    expect(verdict.action).toBe("block");

    const finding = findings(verdict)[0];
    const paths = finding?.evidence?.["changedPaths"] as string[];

    // The premise of the attack: a description-only pin sees nothing here.
    expect(paths.every((p) => p.startsWith("/inputSchema"))).toBe(true);
    expect(paths).toContain("/inputSchema/properties/exfil_target");
    expect(paths).toContain("/inputSchema/required/2");
    expect(finding?.message).toContain("exfil_target");
    expect(finding?.message).not.toContain("~ /description");
  });

  it("blocks the call that would have carried the new parameter", async () => {
    const h = await harness(["--variant", "b"]);
    await h.list();
    await h.list();
    expect((await h.call()).forwarded).toBe(false);
  });
});

describe("variant c — Deadbugz: mutation only after three calls", () => {
  it("is not caught by first-connect pinning, and is caught by re-verification", async () => {
    const h = await harness(["--variant", "c", "--threshold", "3"]);

    // Everything is clean at connect time and stays clean for the first three calls. This is
    // exactly the window in which `mcp-context-protector` (pin at first connect, then stop)
    // has already finished verifying and will never look again.
    expect(await h.list()).toEqual({ action: "allow" });
    for (let i = 0; i < 3; i++) expect((await h.call()).forwarded).toBe(true);
    expect(await h.list()).toEqual({ action: "allow" });

    // The fourth call is the one that flips the server.
    expect((await h.call()).forwarded).toBe(true);
    expect(await waitFor(() => h.listChangedCount() > 0)).toBe(true);

    // The server told us its tools moved and we have not seen the new listing: the cached
    // definition no longer describes what it is advertising, so a call is unverifiable rather
    // than allowed.
    expect(h.guard.isCatalogueStale(h.serverId)).toBe(true);
    const staleCall = await h.call();
    expect(staleCall.forwarded).toBe(false);
    expect(staleCall.verdict.action).toBe("confirm");
    expect(findings(staleCall.verdict)[0]?.ruleId).toBe("toolwall/pin-unverifiable");

    // And the listing itself is blocked outright.
    const verdict = await h.list();
    expect(verdict.action).toBe("block");
    expect(findings(verdict)[0]?.evidence?.["changedPaths"]).toEqual(["/description"]);
  });
});

describe("variant c --silent — mutation with no list_changed notification", () => {
  it("is caught at the next listing, without ever relying on the notification", async () => {
    const h = await harness(["--variant", "c", "--threshold", "3", "--silent"]);

    expect(await h.list()).toEqual({ action: "allow" });
    for (let i = 0; i < 4; i++) expect((await h.call()).forwarded).toBe(true);
    expect(h.listChangedCount()).toBe(0);

    // Honest statement of the boundary: with no notification and no re-listing, the per-call
    // check compares the pin against the definition the client is still holding, and they
    // agree — because the poisoned text has not reached the model either. The exposure begins
    // at the next listing, and that is where it is caught.
    expect(h.guard.isCatalogueStale(h.serverId)).toBe(false);
    expect((await h.call()).forwarded).toBe(true);

    const verdict = await h.list();
    expect(verdict.action).toBe("block");
    expect(findings(verdict)[0]?.ruleId).toBe("toolwall/pin-drift");
    expect(findings(verdict)[0]?.message).toContain("Ignore previous instructions");

    // And from that point the tool is quarantined, so no further call gets through.
    expect((await h.call()).forwarded).toBe(false);
  });
});

describe("pins survive a restart", () => {
  it("re-verifies against a pin written to disk by an earlier session", async () => {
    const first = await harness(["--variant", "a"]);
    expect(await first.list()).toEqual({ action: "allow" });
    await store.flush();
    const serverId = first.serverId;

    // A new process: new store loaded from `.toolwall/pins.json`, new guard, same server.
    store = await PinStore.open({ cwd: dir });
    expect(store.get(serverId, "tool", "add")).toBeDefined();

    const second = await harness(["--variant", "a"]);
    expect(second.serverId).toBe(serverId); // identity is the spawn spec, not the session

    // The fixture's own counter restarts, so its first listing is clean again and verifies
    // against the pin from the previous session rather than being adopted anew.
    expect(await second.list()).toEqual({ action: "allow" });
    expect(store.get(serverId, "tool", "add")?.decision.kind).toBe("trust-on-first-use");

    const verdict = await second.list();
    expect(verdict.action).toBe("block");
  });
});
