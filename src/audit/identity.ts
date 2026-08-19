/**
 * Server identity (T-04) — **the single source of truth**.
 *
 * ## Why this file exists
 *
 * Week 1 ended with two independent `deriveServerId` implementations: one in
 * `src/audit/manifest.ts` (Dev 2, keys the pin store) and one in `src/transport/spawn.ts`
 * (Dev 1, keys `GuardContext.serverId`). They produced different strings for the same spawn
 * spec — different prefixes, different digest lengths, and different material (the transport's
 * ignored environment-variable names, the pin store's did not; the transport folded an absent
 * `cwd` into `process.cwd()`, the pin store kept it absent).
 *
 * Nothing had wired the two together yet, so nothing was failing. The moment the pipeline is
 * assembled, though, the divergence is not a tidiness problem: `MetadataPinGuard` looks pins up
 * by `ctx.serverId`, which comes from the transport. If those two strings ever disagree, every
 * pin on disk becomes unreachable, `pinIfAbsent` adopts the live definition under
 * trust-on-first-use, and the rug-pull control silently restarts from zero on a server it has
 * already approved. That is a security regression that looks exactly like normal operation.
 *
 * So there is now exactly one implementation, here, and both modules import it.
 *
 * ## The rule: structure is identity, secrets are not
 *
 * (Dev 2's rule, kept verbatim.) This function takes **no** server-supplied input. The spec is
 * explicit (RESEARCH-BRIEF §1.8): *"The server `name` (from `serverInfo`) is not guaranteed to
 * be unique and SHOULD NOT be relied upon."* It is also self-reported by the untrusted side, so
 * keying pins on it hands an attacker the ability to inherit another server's approvals by
 * claiming its name — exactly the shadowing in T-04, and exactly the Repello finding about
 * Claude Code. Identity comes from how the operator launched the connection.
 *
 * Environment variables and URL query parameters contribute their **names** but never their
 * **values**, because those values are where credentials live. If a token rotates, the id must
 * not change — a changed id means every pin for that server silently disappears and the next
 * `tools/list` is trusted on first use again, which is a rug-pull window opened by a routine
 * credential rotation.
 *
 * `cwd` contributes only when the operator actually specified one. Folding an absent `cwd` into
 * `process.cwd()` would make the id depend on the directory the *client* happened to be
 * launched from, so starting Claude Desktop from a different folder would orphan every pin.
 */
import { createHash } from "node:crypto";
import { resolve as resolvePath } from "node:path";

import { canonicalize } from "../guards/metadata/canonicalize.js";

export interface StdioServerIdentity {
  readonly transport: "stdio";
  readonly command: string;
  readonly args?: readonly string[];
  readonly cwd?: string;
  /** Only the *names* of environment variables are used — see the file header. */
  readonly env?: Readonly<Record<string, string>>;
  /**
   * Additional environment-variable **names** the child will see, for callers that pass through
   * variables by name without ever holding their values (`--pass-env NAME`). Unioned with the
   * keys of `env`. Exists so a caller can contribute names without having to invent values.
   */
  readonly envKeys?: readonly string[];
}

export interface HttpServerIdentity {
  readonly transport: "http";
  readonly url: string;
}

export type ServerIdentity = StdioServerIdentity | HttpServerIdentity;

/** Derive a stable per-connection server id. See the file header for the rules. */
export function deriveServerId(identity: ServerIdentity): string {
  let material: Record<string, unknown>;
  if (identity.transport === "stdio") {
    const envKeys = [
      ...new Set([...Object.keys(identity.env ?? {}), ...(identity.envKeys ?? [])]),
    ].sort();
    material = {
      transport: "stdio",
      command: identity.command,
      args: [...(identity.args ?? [])],
      cwd: identity.cwd === undefined ? null : resolvePath(identity.cwd),
      envKeys,
    };
  } else {
    const url = new URL(identity.url);
    material = {
      transport: "http",
      protocol: url.protocol.toLowerCase(),
      host: url.host.toLowerCase(),
      pathname: url.pathname,
      queryKeys: [...new Set([...url.searchParams.keys()])].sort(),
    };
  }
  const digest = createHash("sha256").update(canonicalize(material), "utf8").digest("hex");
  return `srv_${digest.slice(0, 32)}`;
}
