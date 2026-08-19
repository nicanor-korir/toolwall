import { evaluateHost, evaluateUrl, extractUrls, type UrlDecision } from "./hosts.js";
import type { EgressPolicy, NetworkGrant } from "./schema.js";

/**
 * Egress evaluation — where a tool call may be *directed*.
 *
 * ## The honest scope, stated once and repeated in the README
 *
 * toolwall is a JSON-RPC proxy between the client and the server. It reads the messages; it does
 * not own the server's sockets. So this module constrains **what the MODEL can direct a tool to
 * reach**, which is the leg every documented 2025–26 exfiltration incident travelled on: the model
 * is injected, it calls a legitimate HTTP/webhook/database tool, and the destination is written in
 * an argument that crosses this proxy. Denying that argument denies the exfiltration.
 *
 * It does **not** constrain **what a compromised server does on its own**. A server with code
 * execution opens whatever socket it likes and never tells us. RESEARCH-BRIEF §4.2's F-1 0.995
 * figure is from observing *actual network traffic*; reproducing it requires a network namespace,
 * a sandbox or an eBPF hook, and toolwall is none of those (`docs/THREAT-MODEL.md` §2: "We are not
 * a sandbox"). Run a per-server network namespace or `docker mcp gateway` alongside if that is
 * your threat.
 *
 * ## Two layers, intersected
 *
 * 1. **Server egress** (`servers[id].egress`) — deny-by-default once declared, an upper bound on
 *    every tool on that server.
 * 2. **Tool network grant** (`...tools[name].network`) — narrows further.
 *
 * A target must pass BOTH. The tool layer can never widen the server layer: if it could, a
 * per-tool entry would be a hole in the allowlist, which is the opposite of a capability model.
 */

export type EgressTargetKind = "url" | "host";
/** How the destination was found. `"scan"` is the only heuristic one; it is opt-in. */
export type EgressDiscovery = "role" | "scan";

export interface EgressTarget {
  /** JSON Pointer into the arguments object. */
  readonly pointer: string;
  readonly value: unknown;
  readonly kind: EgressTargetKind;
  readonly discovery: EgressDiscovery;
}

export interface EgressOutcome {
  readonly target: EgressTarget;
  readonly decision: UrlDecision;
  /** Which allowlist rejected it. `undefined` when the decision is `ok`. */
  readonly layer: "server" | "tool" | undefined;
}

function decide(target: EgressTarget, list: Parameters<typeof evaluateUrl>[1]): UrlDecision {
  return target.kind === "host" ? evaluateHost(target.value, list) : evaluateUrl(target.value, list);
}

/**
 * Evaluate one destination against the server allowlist and then the tool grant.
 *
 * Order matters for the message the operator reads: the server layer is reported first because it
 * is the one they most likely need to edit, and because a tool grant is meaningless while the
 * server-level bound already rejects the host.
 */
export function evaluateEgressTarget(target: EgressTarget, server: EgressPolicy | undefined, tool: NetworkGrant | undefined): EgressOutcome {
  if (server !== undefined && server.enforce !== "off") {
    const d = decide(target, server);
    if (!d.ok) return { target, decision: d, layer: "server" };
  }
  if (tool !== undefined) {
    const d = decide(target, tool);
    if (!d.ok) return { target, decision: d, layer: "tool" };
    return { target, decision: d, layer: undefined };
  }
  if (server !== undefined && server.enforce !== "off") {
    return { target, decision: decide(target, server), layer: undefined };
  }
  // Nothing to enforce against. The caller decides what an unenforceable capability costs
  // (`grant.undeclaredCapability`); this module does not invent a verdict out of no policy.
  return { target, decision: { ok: true, hostname: "", scheme: "", matchedBy: "exact", notes: [] }, layer: undefined };
}

/**
 * `enforce: "scan"` — pull absolute URLs out of EVERY string in the arguments, not only the ones
 * bound to a role.
 *
 * This is the only part of the runtime area that looks at the *content* of an argument it was not
 * told to look at, and the threat model is explicit about what that costs. It exists because the
 * role-bound view has a real blind spot: an exfil destination pasted into a free-text field of a
 * tool whose schema declares no URI property is invisible to every deterministic check we have.
 * The trade is stated, tier-gated, off by default, and measured — see the FP harness.
 */
export function scanForUrls(args: unknown, maxNodes = 5_000, maxUrls = 64): EgressTarget[] {
  const out: EgressTarget[] = [];
  if (args === null || typeof args !== "object") return out;

  let nodes = 0;
  const stack: Array<{ v: unknown; segs: string[] }> = [{ v: args, segs: [] }];
  while (stack.length > 0 && out.length < maxUrls) {
    const frame = stack.pop();
    if (frame === undefined) break;
    if (++nodes > maxNodes) break;
    const v = frame.v;
    if (typeof v === "string") {
      for (const u of extractUrls(v, maxUrls - out.length)) {
        out.push({ pointer: "/" + frame.segs.join("/"), value: u, kind: "url", discovery: "scan" });
      }
    } else if (Array.isArray(v)) {
      for (let i = 0; i < v.length; i++) stack.push({ v: v[i], segs: [...frame.segs, String(i)] });
    } else if (v !== null && typeof v === "object") {
      for (const [k, sub] of Object.entries(v as Record<string, unknown>)) {
        stack.push({ v: sub, segs: [...frame.segs, k.replace(/~/g, "~0").replace(/\//g, "~1")] });
      }
    }
  }
  return out;
}

/** Deduplicate by (pointer, value) so one URL repeated in a body is reported once. */
export function dedupeTargets(targets: readonly EgressTarget[]): EgressTarget[] {
  const seen = new Set<string>();
  const out: EgressTarget[] = [];
  for (const t of targets) {
    const key = `${t.kind} ${t.pointer} ${String(t.value)}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(t);
  }
  return out;
}
