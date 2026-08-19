# toolwall — Architecture

> Read `docs/RESEARCH-BRIEF.md` and `docs/THREAT-MODEL.md` first. This document assumes both.

## Product thesis, in one paragraph

Every MCP security tool either scans **once, before you start** (Snyk agent-scan, Cisco mcp-scanner,
the old `toolwall`) or pins **once, at first connect** (Trail of Bits `mcp-context-protector`).
Pillar's Deadbugz campaign mutates after **three tool calls** specifically to walk through that gap.
**toolwall re-verifies the cryptographic identity of a tool definition before every single
`tools/call`**, locally, offline, with no account and no telemetry — a capability Snyk deliberately
deleted, the spec has rejected seven times, and no shipping tool provides.

## Decisions taken (2026-08-19)

| Decision | Choice | Rationale |
|---|---|---|
| Name | **toolwall** | `toolwall` taken on npm AND crates.io. `toolwall` free on npm/crates/PyPI. Generalizes beyond MCP |
| Scope | Differentiated wedge | Transport proxying is commodity (5M dl/mo); pinning is unmet |
| Protocol | `2025-11-25` primary, era-adapter | The SDK and every real client are on 2025-11-25; spec is 2026-07-28 |
| Detection rules | **Compose `agent-threat-rules`** (MIT, 85 tool-poisoning rules, TS engine) | Do not write our own regex list |
| Classifier | `@stackone/defender` optional, off by default | Deterministic core; no LLM in the hot path |
| Canonicalization | **RFC 8785 JCS + SHA-256** | Forward-compatible with SEP-3140 if it ever lands |

## Module map and ownership

```
                    ┌──────────────────── toolwall ────────────────────┐
[ LLM Client ] ────►│  transport/        (Dev 1 · stream-engine)       │────► [ MCP Server ]
   stdio            │    era adapter · passthrough · spawn hardening   │        (untrusted)
                    │                      │                           │
                    │            ┌─────────┴─────────┐                 │
                    │            ▼                   ▼                 │
                    │  guards/metadata/       guards/runtime/          │
                    │  (Dev 2 · prompt-guard) (Dev 3 · execution-guard)│
                    │   · canonical hashing    · capability policy     │
                    │   · pin store / TOFU     · schema enforcement    │
                    │   · drift detection      · HITL confirmation     │
                    │   · unicode evasion      · RESULT-leg guarding   │
                    │            └─────────┬─────────┘                 │
                    │                      ▼                           │
                    │              audit/  (append-only, hash-chained) │
                    └──────────────────────────────────────────────────┘
```

| Path | Owner | Agent |
|---|---|---|
| `src/transport/`, `src/cli/`, `src/types/protocol.ts` | Dev 1 | `stream-engine` |
| `src/guards/metadata/`, `src/audit/manifest.ts` | Dev 2 | `prompt-guard` |
| `src/guards/runtime/`, `src/policy/` | Dev 3 | `execution-guard` |
| `test/attacks/`, `test/fixtures/malicious/` | Red team | `red-team` |
| `src/index.ts`, `test/integration/`, `bench/`, packaging | Integration | `integrator` |

**Cross-boundary edits are forbidden.** Need a change next door? State the interface change instead.

## The one interface everything hangs off

```ts
/** Protocol era. Isolates 2025-11-25 vs 2026-07-28 so the latter is a module, not a rewrite. */
export type ProtocolEra = "2025-11-25" | "2026-07-28";

export interface GuardContext {
  readonly era: ProtocolEra;
  readonly serverId: string;        // stable per-connection identity, NOT serverInfo.name (T-04)
  readonly direction: "request" | "response";
  readonly method: string;
}

export type Verdict =
  | { action: "allow" }
  | { action: "annotate"; payload: unknown; findings: Finding[] }   // modified, forwarded
  | { action: "confirm";  findings: Finding[] }                     // needs a human (T-06)
  | { action: "block";    findings: Finding[]; code: number };      // JSON-RPC error to client

export interface Guard {
  readonly name: string;
  /** MUST be pure and synchronous where possible — this is the sub-5ms hot path. */
  inspect(payload: unknown, ctx: GuardContext): Verdict;
}
```

**Fail-closed rule:** a `block` verdict can never be overridden by a transport error path.
**Transparency rule:** any method with no registered guard is forwarded **byte-identical**. Build the
passthrough on the SDK's `fallbackRequestHandler` / `fallbackNotificationHandler`
(verified present at `dist/esm/shared/protocol.js:274,285`). Do not enumerate methods.

## Pinning design (the differentiator) — Dev 2

1. **Canonicalize** the tool definition with **RFC 8785 (JCS)**: stable key order, defined Unicode
   normalization (NFC), explicit absent-vs-empty handling. Cover `name`, `title`, `description`,
   `inputSchema`, `outputSchema`, `annotations`, and server `instructions`.
   *A hash that changes on irrelevant reserialization is a bug that destroys user trust via false
   rug-pull alarms. Property-test canonicalization against reserialization.*
2. **Pin** `SHA-256(canonical)` per `(serverId, toolName)` into `.toolwall/pins.json`, with era, first-seen,
   last-verified, and the approving decision. Restrictive file permissions; tamper-evident.
3. **Re-verify before every `tools/call`** — not at handshake, not at first connect. This is the point.
4. **On drift:** block, quarantine the tool, surface a diff a human can actually read, require explicit
   re-approval. Never auto-accept. `CVE-2025-54136` is exactly the auto-accept failure.
5. **Provenance (T-09):** verify npm SLSA/Sigstore attestations and `server.json` `fileSha256` where
   available. Cheap, deterministic, no key, no LLM, genuinely unshipped by anyone.

## Performance

Budget: **sub-5ms p99 added overhead**. Hot path is `tools/call`, which does a canonicalize + hash +
map lookup. Do not re-serialize untouched payloads. Do not deep-clone large results.
`integrator` measures against a direct connection and **reports the real number**, pass or fail.

## Build order (mapped to the 2-week roadmap, re-prioritized by threat rank)

**Week 1 — parallel, non-blocking**
- Dev 1: stdio passthrough on the fallback hooks + era adapter + spawn hardening (T-07). Benign traffic
  must be byte-identical end-to-end.
- Dev 2: canonicalization + hashing + pin store. Property tests before detectors.
- Dev 3: policy schema + capability model + schema enforcement. Benign-corpus FP harness first.

**Week 2**
- Dev 1: reconnect/buffer/retry; `-32603` on exhaustion; era negotiation.
- Dev 2: drift detection + quarantine + diff UX; unicode-evasion detectors; compose `agent-threat-rules`.
- Dev 3: HITL confirmation; **response-leg guarding (T-03)**; egress control.
- Red team: continuous from day 3, not a week-2 phase.
- Integrator: e2e against a real client, benchmarks, npm packaging.

## Non-negotiables

1. No fabricated benchmarks, coverage numbers, or catch rates. Run it or omit it.
2. Every detector reports a measured FP rate on a benign corpus.
3. Zero telemetry. No network calls in the default path. This is a differentiator, not a preference.
4. The README states the §2 out-of-scope list plainly. We do not imply sandbox-grade containment.
5. We credit prior art honestly — Trail of Bits, Invariant, JanuScope — and state where we differ.

---

## Cross-module contracts discovered during Week 1

These emerged from implementation and are NOT in the original design. They are binding.

### C-1 · Schema enforcement MUST read from the pin store, not from live `tools/list` — SECURITY CRITICAL
Raised by Dev 3. If `schema-guard` validates arguments against the schema the server just sent, an
attacker **widens their own schema first and then sends arguments that are now "valid."** The rug pull
legalises the payload. `ToolDefinitionSource` must therefore be backed by Dev 2's **pinned** definition,
so argument validation is always against the approved contract, not the live one.
This makes T-02 (pinning) a dependency of T-05 (argument validation), not a parallel feature.

### C-2 · `{ action: "allow" }` carries no findings — audit records need a side channel
Dev 3 emits informational records to an injected `AuditSink` (`opts.audit`) rather than widening Dev 1's
`Verdict` type. **Integrator: wire this to `src/audit/` or those records are silently dropped.**
If `allow` ever gains `findings?`, the sink becomes redundant — revisit then.

### C-3 · Guard invariants (Dev 1's pipeline enforces these)
- A guard that **throws is treated as a block**, never an allow.
- Guards **MUST NOT mutate** the payload they receive — return `annotate` with a new value.
- Block codes in `-32020..-32099` are **rewritten to `-32600`** (that range is reserved for the MCP
  spec, §1.9). Pick codes outside it. Current usage: `-32602` for genuinely invalid params
  (schema violations), `-32600`/`TOOLWALL_BLOCKED` for well-formed but not permitted (capability).
- A `confirm` verdict **fails closed** until a `ConfirmationProvider` is wired (Dev 3, Week 2).
  Implementations MUST NOT write to stdout — that is the protocol channel.

### C-4 · Guard direction semantics
`"request"` = travelling toward the untrusted server. `"response"` = travelling toward the trusted
client. A server→client `sampling/createMessage` is inspected on the **`"response"`** leg (it is
attacker-controlled data); the client's answer to it is inspected on the `"request"` leg.

### C-5 · Two SDK behaviours a transparent proxy must work around
- **`Client.connect()` is unusable here.** It synthesizes the `InitializeResult` instead of relaying it,
  which would replace the downstream server's `instructions` with toolwall's own — blanking a
  top-ranked injection surface (§1.5). Use `Protocol.prototype.connect` directly and relay verbatim.
- **`Protocol`'s constructor pre-registers handlers that shadow the fallback hook** (`notifications/
  cancelled`, `notifications/progress`, `ping`; `Server` adds `initialize`, `notifications/initialized`).
  Left in place, **progress notifications are dropped entirely**. Remove all but `notifications/
  cancelled`, which is kept deliberately to thread `extra.signal` into the outbound request.

### C-6 · Byte-identity is bounded, and the bound is documented
The SDK's stdio codec is **not** byte-preserving — `ReadBuffer` parses with zod, which rebuilds objects
with declared keys first, on every peer's read path. Raw wire bytes ARE identical for `initialize`,
`tools/list`, `tools/call`, unknown methods and errors. The single deviation is **`_meta` hoisting** when
`_meta` is not in first key position; a dedicated test asserts the raw bytes differ but are identical
post-parse, so a client cannot observe it. Do not claim unqualified byte-identity in docs.

### C-7 · Known gaps, stated so they are not mistaken for coverage
- Relative path arguments resolve against a single `baseDir`; repo-relative pathspecs (e.g.
  `git_diff.paths`) must NOT be bound to a path role — a wrong binding is a self-inflicted FP.
  Per-argument resolution bases are a follow-up.
- **No DNS resolution**, so an allowlisted hostname resolving to a private address is not caught.
  Deliberate: hot path + the zero-network guarantee, and DNS rebinding would defeat it anyway.
- `path.resolve` collapses `..` **lexically**, so it cannot be used for symlink containment: given
  `<root>/link -> /elsewhere`, it turns `<root>/link/../etc` into `<root>/etc`, which looks contained
  and is not. Containment must walk segment-by-segment, resolving links link-by-link.

### C-8 · Measured baselines (re-measure, do not copy forward)
Transport-only added latency, 1000 sequential `tools/call`, zero guards:
`p50 +0.140ms · p95 +0.172ms · p99 +0.421ms` against a 5ms budget.
Benign-corpus false positives, 59 cases: **balanced (default) = 0.0% blocked, 0.0% friction**;
strict + policy = 1.7% blocked / 47.5% friction; **strict + no policy = 100% blocked** (tier sets
`unknownTool: "block"`; `parsePolicy` warns). Strict must never be the default.

---

## Integration outcomes (2026-08-19) — how the Week-1 contracts were resolved

### C-0 · `deriveServerId` was implemented twice, and the two disagreed — RESOLVED
Week 1 shipped `deriveServerId` in **both** `src/transport/spawn.ts` (`stdio:<16 hex>`; ignored
environment-variable names; folded an absent `cwd` into `process.cwd()`) and `src/audit/manifest.ts`
(`srv_<32 hex>`; env NAMES contribute; absent `cwd` stays absent). Nothing failed, because nothing
had wired them together.

`MetadataPinGuard` looks pins up by `ctx.serverId`, which the **transport** derives; `PinStore`
stores them under the id its own caller derived. Assembled, a mismatch means `store.get()` returns
`undefined`, `pinIfAbsent` adopts whatever the server just said, and the rug-pull control reports
success while re-running trust-on-first-use on a server it had already approved — invisible in
exactly the wrong way.

There is now **one** implementation, in `src/audit/identity.ts`. `manifest.ts` re-exports it;
`spawn.ts` adapts a `SpawnSpec` onto it via `serverIdentityForSpawn()`. Dev 2's rule is kept and
is now the only rule: **structure is identity, secrets are not** — env var and query-parameter
NAMES contribute, values never do, and `cwd` contributes only when the operator specified one.
`test/integration/server-identity.test.ts` asserts transport-derived === manifest-derived across
the spec shapes. **The id format changed for transport callers** (`stdio:…` → `srv_…`), which
invalidates any pin file written by a pre-integration build.

### C-1 · Wired — schema enforcement reads the pin store
`src/index.ts` exports `PinnedToolDefinitionSource`, backed by `PinRecord.definition`, and hands it
to `SchemaGuard` (and to `CapabilityGuard` for its `format: "uri"` role derivation). A pin whose
stored definition is not a usable tool object returns `undefined` rather than a guess, which routes
into `requireKnownSchema`: recorded at `balanced`, fail-closed at `strict`. Never a fallback to the
live listing. `test/integration/schema-pin-binding.test.ts` runs the attack both ways — the same
guard with a live-backed source **allows** the widened-schema call that the pinned source blocks.

### C-2 · Wired — `src/audit/log.ts`
`AuditLog.sink()` is the `AuditSink` passed as `opts.audit` to both runtime guards. Records are
hash-chained (`sha256(JCS(record without hash))` + `previousHash`), optionally appended to a local
JSONL file at mode 0600, and never sent anywhere. Blocked/annotated proxy events, pin-engine state
changes and the T-07 spawn record go to the same log. Keyless, so it detects modification and does
not prevent forgery — do not describe it as tamper-proof.

### C-9 · A block must not relay the payload it blocked — NEW, found by wiring it up
`GuardBlockedError` used to put `findings[0].message` in the JSON-RPC error string and the whole
`Finding[]` (with `message` and `evidence`) in `error.data`. On a `tools/list` drift block, that
error carries the attacker's injected text **verbatim** — and a JSON-RPC error goes to the LLM
client, which routinely surfaces error text to the model. The alarm delivered the payload.

Fixed at the seam: `redactFindingForClient()` sends the client `ruleId`, `severity`, `locus` and
`remediation` (all toolwall-authored) and withholds `message` and `evidence` (both quote the
untrusted server). The full finding still reaches `onEvent` — the CLI's stderr — and the audit log,
which are operator channels. Guard authors may therefore keep writing rich, quoting findings; the
transport decides what is safe to relay.

### C-10 · Order of guards on `tools/call` is a security decision, not a preference
`MetadataPinGuard` → `SchemaGuard` → `CapabilityGuard`. Identity before content: if the definition
drifted, the schema and annotations the other two would read are attacker-controlled as of that
moment. Capability last because it is the only one that touches the filesystem. The pipeline
short-circuits on the first block, so this order also makes the finding a user sees name the most
fundamental problem rather than a symptom.

Guards are registered per `(direction, method)`, never with `ANY_METHOD`, so `hasGuards()` stays
false for `prompts/*`, `resources/*`, `ping`, `sampling/*` and every unknown or future method, and
those forward by reference with no work done on them.

### C-11 · Measured end-to-end latency with the full guard stack
`npm run bench` (which builds first and benchmarks `dist/`, not `src/`). 1000 sequential
`tools/call` after 100 warmup, one request in flight, same fixture server per configuration,
Node v25.2.1 on darwin/x64. Three consecutive runs:

| added vs direct | p50 | p95 | p99 |
|---|---|---|---|
| proxy, zero guards | +0.136 / +0.151 / +0.230 ms | +0.197 / +0.188 / +0.314 ms | +0.529 / +0.266 / +0.387 ms |
| **full guard stack** | **+0.216 / +0.210 / +0.275 ms** | **+0.258 / +0.244 / +0.341 ms** | **+0.594 / +0.319 / +0.403 ms** |
| guard stack alone (vs zero-guard proxy) | +0.080 / +0.059 / +0.046 ms | +0.062 / +0.056 / +0.027 ms | +0.065 / +0.053 / +0.016 ms |

**Within the 5ms p99 budget by roughly an order of magnitude.** The guard stack itself costs
~0.05–0.08ms at p50; the bulk of the added latency is the extra process hop, which is inherent to
proxying and not to guarding. Run-to-run p99 spread is larger than the guard cost, so treat the
p99 delta as a range, not a point.

Not measured, and therefore not claimed: concurrency, large payloads, a cold pin store on a slow
disk, and the `tools/list` cold path (canonicalize + hash per tool), which is where the real work
happens and which a session pays once per listing rather than per call.

---

## Week-2 contracts from the runtime area (Dev 3) — binding

### C-12 · The response leg needs a registration, and it is not `ANY_METHOD`
`ResultGuard` (`src/guards/runtime/result-guard.ts`) must be registered on **six** `(direction,
method)` pairs, and on the request leg as well as the response leg:

```ts
const resultGuard = new ResultGuard({ policy, tools /* the PINNED source */, audit: sink });
for (const m of RESULT_METHODS)          // tools/call, resources/read, prompts/get
  pipeline.register({ direction: 'response', method: m, guard: resultGuard });
for (const m of SERVER_REQUEST_METHODS)  // elicitation/create, sampling/createMessage
  pipeline.register({ direction: 'response', method: m, guard: resultGuard });
pipeline.register({ direction: 'request', method: 'tools/call', guard: resultGuard });
```

The **request-leg** registration is not optional and it is not a convenience: it is where the
guard learns which tool a result belongs to, and where the ATPA sequence check runs. Registering
only the response leg silently disables `outputSchema` enforcement (nothing to correlate against)
and ATPA entirely, with no error. Order relative to the other `tools/call` request guards does not
matter — `ResultGuard` reads the params, never mutates them, and its only request-leg block is the
ATPA one.

`hasGuards()` stays false for every other method, so the transparency guarantee is unchanged for
`resources/*` subscriptions, `completion/complete`, `roots/list`, `ping` and future methods.

### C-13 · `GuardContext` has no correlation id, and one result leg needs one — REQUEST TO DEV 1
`GuardContext` is `{ era, serverId, direction, method }`. A `tools/call` RESULT therefore does not
say which tool produced it. `ResultGuard` correlates by tracking outbound calls per server and
matching a result to the single call in flight; when more than one is in flight it declines to
guess and emits `toolwall/result.uncorrelated` (`info`) rather than enforcing `outputSchema`
against the wrong tool. **This is a real gap under concurrent tool calls.** The clean fix is an
additive field on `GuardContext` — the JSON-RPC id, or any stable per-exchange token — carried
identically on the request and response legs. Dev 1 owns that type; nothing was changed here.

### C-14 · A `confirm` verdict is now resolvable, and the resolution is bounded
`BudgetedConfirmationProvider` (`src/guards/runtime/confirm.ts`) implements Dev 1's
`ConfirmationProvider`. Wiring notes for the integrator:

- Construct it with `policy.confirmation` (new on `ResolvedPolicy`) and `ttyChannel()`.
  `ttyChannel()` returns `undefined` when there is no controlling terminal; pass it through
  anyway — an absent channel is the fail-closed path, not an error.
- It **never writes to stdout** (C-3). Prompts go to `/dev/tty`; `onDecision` is the operator
  channel for stderr.
- The budget is per provider instance, i.e. **per session**. Do not construct one per call.
- It renders only `ruleId` / `severity` / `locus` / `remediation` — the same allowlist as
  `redactFindingForClient()` (C-9), so a poisoned server cannot compose its own approval dialog.
- Rules not on `confirmation.promptableRules` are denied **without** prompting. That is the design,
  not a bug: 86.4% approval on substituted harmful commands means the scarce thing is attention.

### C-15 · `ResolvedPolicy` gained three members — additive, but they are not optional
`egressFor(serverId)`, `responseFor(serverId)` and `confirmation`. Any hand-rolled `ResolvedPolicy`
in a test or a caller must supply all three; `defaultPolicy(tier)` and `parsePolicy()` already do.

### C-16 · Egress is a proxy-level control and the README says what it does not cover
Per-server `egress` constrains **what the model can direct a tool to reach**. It does not and
cannot constrain what a compromised server opens on its own sockets — toolwall reads JSON-RPC
messages, it does not own the server's network namespace. The F-1 0.995 figure in
RESEARCH-BRIEF §4.2 comes from observing actual traffic and is **not** a number this control earns.
That distinction is stated in `src/policy/egress.ts`, in `src/policy/schema.ts`, and in the README
under both "Egress allowlisting" and "What toolwall does NOT do". Do not let it be dropped from any
of the four.
