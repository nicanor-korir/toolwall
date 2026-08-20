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
`remediation` and withholds `message` and `evidence` (both quote the untrusted server).
**This paragraph originally called all four "toolwall-authored"; that was wrong for `locus` and
`remediation`, and C-14a records the bypass it allowed and the sanitization that closes it.** The full finding still reaches `onEvent` — the CLI's stderr — and the audit log,
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
  `redactFindingForClient()` (C-9). **Correction, see C-14a:** two of those four are NOT
  toolwall-authored, and red team round 2 proved a server could forge dialog rows through `locus`.
  Both sinks now sanitize; the guarantee is that the row count and frame are toolwall's, not that
  no server-chosen name appears.
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

---

## Week-2 integration outcomes (2026-08-19) — how the Week-2 contracts were resolved

### C-17 · ITEM ZERO: the whole of Week 2 was dead code in the shipped path — RESOLVED
`assembleToolwall()` registered exactly three guards: `MetadataPinGuard` → `SchemaGuard` →
`CapabilityGuard`. `ResultGuard`, `UnicodeHygieneGuard` and `AtrAdvisoryGuard` existed on disk,
were exported from their barrels, and were covered by passing unit tests. **None of them ran.**
Every response-leg control — ATPA, MRTR `inputRequests`, credential elicitation, `outputSchema`,
result bounds, `__proto__` rejection, invisible-character rejection — was unreachable from the
request path, and nothing failed, because a guard that is never registered raises no error.

This is exactly the failure the integrator mandate names: *a unit test proving a detector works
does not prove it is wired into the request path.* Two structural changes so it cannot recur:

1. **`assembleToolwall()` throws at assembly time** if `ResultGuard`'s registration count is not
   the six C-12 requires. A miscount is now a startup crash, not a silent no-op.
2. **`test/integration/response-guards-e2e.test.ts`** drives every Week-2 control through the
   assembled proxy against real spawned child processes. A guard that is implemented but not
   registered fails these tests, as does one registered on the wrong leg.

The startup banner (`toolwall: guards=[...]`) is asserted verbatim in `test/integration/cli.test.ts`,
so the operator-facing list cannot drift from what is actually registered.

### C-12 · Wired — six registrations, and the count is enforced
```
response  tools/call · resources/read · prompts/get      (RESULT_METHODS)
response  elicitation/create · sampling/createMessage    (SERVER_REQUEST_METHODS, per C-4)
request   tools/call                                     (correlation + ATPA)
```
`ResultGuard` is registered **last** among the `tools/call` request guards. C-12 says order is
free there, and last is chosen so a call the pin/schema/capability guards blocked is never recorded
as in-flight for a result that will never arrive.

Proven end to end, not asserted: `outputSchema` violation recorded at `balanced` and blocked at
`response.outputSchema = "enforce"`; the ATPA retry blocked with the private key never leaving;
MRTR `systemPrompt` + `tools[]` blocked; credential elicitation refused on the response leg with
the server receiving the error and the client never seeing a dialog.

### C-13 · Confirmed by wiring, not changed — MRTR routes by embedded method
`ToolwallProxy.#liftInputRequests` inspects each `inputRequests` entry as
`("response", <embedded method>)`, so the `sampling/createMessage` and `elicitation/create`
registrations fire on the live `2025-11-25` server→client request AND on the `2026-07-28` copy
embedded in a `tools/call` result, with no era branch in any guard. `roots/list` is deliberately
left unregistered: no guard has a check for it, and the outer `("response","tools/call")`
registration already records every MRTR input request including `roots/list`.

**The correlation gap C-13 requested of Dev 1 is still open.** `GuardContext` still carries no
per-exchange id, so `ResultGuard` still declines to enforce `outputSchema` when more than one call
is in flight, and still emits `toolwall/result.uncorrelated`. Fail-safe, and still a real gap.

### C-14 · Wired — one `BudgetedConfirmationProvider` per session
Constructed in `assembleToolwall()` from `policy.confirmation` and `ttyChannel()`, once, and passed
to `DefaultGuardPipeline`. `ttyChannel()` returning `undefined` is passed through unchanged — an
absent channel is the fail-closed path, not an error. `ToolwallOptions.confirmationChannel` accepts
`null` to say "non-interactive" explicitly; the integration harness defaults to it, because a test
runner started from a terminal CAN open `/dev/tty` and a promptable verdict would otherwise block
the suite for the full timeout.

Observable change: a `confirm` verdict no longer produces `toolwall/no-confirmation-provider`. It
is now resolved by the provider and denied — `not-promptable` for any rule outside
`confirmation.promptableRules`, which is the load-bearing half of the budget design. Still a block;
different finding. `test/integration/guards-e2e.test.ts` asserts the new shape.

### C-14a · The confirmation dialog was server-spoofable — PROVEN BYPASS, FIXED
Found by red team round 2 (`test/attacks/confirm-dialog-injection.test.ts`).

C-14 and `confirm.ts`'s header both claimed the dialog is composed "exclusively from
toolwall-authored fields — `ruleId`, `severity`, `locus`, `remediation`". **That claim was false.**
A `locus` is a JSON Pointer *into an attacker-controlled payload*, so its segments are names the
untrusted side chose; under `deriveUrlSelectors` (on at the `balanced` default) the URL role binds
to a `format: "uri"` property whose NAME the server picks, and RFC 6901 escapes only `~` and `/`.
A property name containing newlines therefore rendered as extra rows of convincing dialog chrome —
*"Routine read-only lookup — safe to approve"*, *"pre-approved by security team"* — printed
directly above the dialog's own promise that nothing above came from the server. The same string
crossed to the LLM client through `redactFindingForClient`, which withholds `message` and
`evidence` and passed `locus` through untouched. Reachable in the shipped configuration: TOFU pins
a first-sighting-malicious definition as-is, so no rug pull is needed.

At the measured 13.6% human catch rate this is worse than a leak — a dialog an attacker can write
into recruits the rubber stamp it was designed to avoid.

Fixed at **both** sinks with one shared pair of functions on the `Finding` contract
(`src/types/protocol.ts`, so neither `transport/` nor `guards/` depends on the other):

- `sanitizeLocus()` percent-escapes everything outside `[A-Za-z0-9_-./~]`, per UTF-8 byte, and
  truncates at 200 characters. Single-line by construction, still reads as a pointer.
- `sanitizeRenderedText()` collapses whitespace runs, strips C0/C1 controls and box-drawing
  characters, and truncates. Applied to `ruleId` and `remediation` — `remediation` interpolates a
  tool name and a denied hostname for the good reason that a remediation which will not name the
  thing to fix is useless.

The invariant is structural rather than lexical, because a lexical one is not available (no
escaping stops a server naming a property `safe_to_approve`): **the row count and the frame of the
dialog are toolwall's and cannot be changed by anything a guard puts in a finding.** The dialog's
closing line now says what is actually true. `redactFindingForClient`'s doc comment, `confirm.ts`'s
header and the C-9 wording above are corrected accordingly — C-9's "all four written by toolwall"
was wrong for two of the four.

### C-15 · Wired — nothing hand-rolls a `ResolvedPolicy` in the shipped path
`assembleToolwall()` takes `ResolvedPolicy` whole from `defaultPolicy()` or `parsePolicy()`, both of
which supply `egressFor()`, `responseFor()` and `confirmation`. The integration tests build policies
through `parsePolicy()` for the same reason.

### C-16 · Egress verified end to end, and its FP story verified with it
Three e2e cases against a real spawned server: a non-allowlisted host **blocked on the request leg**
before the server ran; an allowlisted host untouched; and — the claim `docs/POSITIONING.md` rests
on — **no policy file means nothing is denied**, because `enforce: "off"` until an operator declares
a block is what keeps the day-zero false-positive rate at 0.0%.

The URL role came from the tool's own `format: "uri"`, never from guessing that a property named
`url` holds one (`evidence.discovery === "role"`).

One honest note: the denied **hostname** does reach the client, inside `remediation` ("add
`attacker.example` to `servers[...].egress.hosts`"). That is deliberate — an operator cannot act on
a remediation that will not name the host — and bounded, because the value survived URL parsing and
so is a syntactically valid hostname that cannot carry prose. It is now also `sanitizeRenderedText`d.

### C-18 · `ToolDefinitionSource.get()` had no scope parameter — RESOLVED
Raised by Dev 2. Pins are keyed on `(serverId, scope, kind, subject)` and `PinStore.get()` defaults
`scope` to `DEFAULT_PIN_SCOPE`, so `PinnedToolDefinitionSource` could only ever read the default
scope. Correct **today**, because scope keying is opt-in and nothing sets a non-default scope — but
the moment an operator enables it, every lookup returns `undefined` and every call routes into
`requireKnownSchema`. Fail-safe rather than fail-open, and still a schema layer that has quietly
stopped enforcing anything.

Closed in two halves, because the scope arrives from two places:

- **Per session.** `ToolDefinitionSource.get(serverId, toolName, scope?)` now takes a scope, and
  `assembleToolwall({ pinScope })` sets `PinnedToolDefinitionSource.defaultScope` and
  `MetadataPinGuard.resolveScope` **from the same value**, so the two sides of C-1 cannot drift.
  A stdio server is launched with one credential and keeps it for the life of the process, which is
  the realistic case.
- **Per call.** Still open, and it is Dev 1's to close: `GuardContext` has no authorization field.
  When the additive `authorizationScope?: string` requested in `MetadataPinGuardOptions.resolveScope`
  lands, the guards forward `ctx.authorizationScope` into the third parameter and nothing else
  changes. The parameter is optional, so no existing implementation breaks.

### C-19 · `resources/read` and `prompts/get` results pop the `tools/call` correlation queue — RESOLVED (Week 3)
Surfaced by wiring C-12, not by unit tests. `ResultGuard.#onResult()` calls `#correlate(ctx)`
unconditionally, but `#onResult` now handles all three of `RESULT_METHODS`. A `resources/read`
result arriving while a `tools/call` is in flight pops the pending `tools/call` entry, so that call's
result is then uncorrelated and `outputSchema` is silently not enforced against it.

Bounded, and fail-safe: it is unreachable with sequential traffic (the queue is drained by each
`tools/call` result), and under concurrency the outcome is identical to the gap C-13 already
documents — the guard declines to enforce and emits `toolwall/result.uncorrelated`. So this widens
a known gap rather than opening a new one, and it does not change fail-open/fail-closed.

The fix is the one line Dev 3 specified, now in `ResultGuard.#onResult`:
```ts
const correlated = ctx.method === "tools/call" ? this.#correlate(ctx) : undefined;
```
Three tests in `test/unit/result-guard.test.ts` cover it, and two of them **fail against the old
line** — verified by reverting it — so they capture the defect rather than describing it: a
`resources/read` result and a `prompts/get` result each arriving mid-flight no longer consume the
pending `tools/call`, whose `outputSchema` is still enforced when its own result lands. The third
asserts the scoping is confined to correlation: the size caps and the `__proto__` scan still run on
all three result methods, because they need no correlation to be meaningful.

### C-20 · Replay of "read-only" methods is not free, and the comment said it was — CORRECTED
`src/transport/reconnect.ts` described the replayed methods as having re-execution that is
"observationally free". **False against an untrusted peer**, as red team round 2 pointed out:
`prompts/get`, `resources/read` and `completion/complete` are read-only *by contract*, and the
contract is the untrusted party's. A hostile server can charge, count or advance a state machine
inside any of them.

The default `replayInFlight: "read-only-methods"` **stands**, on a comparison rather than a claim of
safety: the blast radius is confined to what a server does to its own state (`tools/call` — the
method that reaches the user's money, disk and accounts — is excluded at every setting); a server
that wants re-execution does not need this path; and the alternative default makes every upstream
blip a user-visible failure, which is how a security proxy gets uninstalled. What is accepted is
at-most-twice execution of server-side-only effects, in exchange for session continuity.
`--replay-in-flight none` is documented for operators who do not accept it. The file header, the
`READ_ONLY_METHODS` doc comment and the CLI help all now say this.

### C-11 (re-measured) · Latency with the ACTUAL full stack
Week 1's table measured a **9-byte** echo through request-leg guards only. Week 2 put work on the
RESULT: `measure()` (bounded 200k nodes) and `hasProtoKey()` each walk every `tools/call`,
`resources/read` and `prompts/get` result, and `scanSurface()` walks every listing. A 9-byte probe
hides that entirely, so `bench/latency.ts` now measures **two payload sizes** and reports both.

`npm run bench`, Node v25.2.1 on darwin/x64, 1000 sequential `tools/call` after 100 warmup, one in
flight. Added latency vs a direct connection, four consecutive runs:

| workload | added p50 | added p95 | added p99 |
|---|---|---|---|
| small (9 B) | +0.148 … +0.294 ms | +0.170 … +0.366 ms | +0.225 … +0.483 ms |
| **large (64 KiB)** | **+0.706 … +0.889 ms** | **+1.065 … +1.772 ms** | **+0.698 … +4.348 ms** |

Guard stack alone (guarded minus zero-guard proxy), so the process hop is excluded:

| workload | p50 | p95 | p99 |
|---|---|---|---|
| small | +0.050 … +0.140 ms | +0.038 … +0.185 ms | −0.053 … +0.216 ms |
| large | +0.057 … +0.263 ms | +0.142 … +0.792 ms | +0.125 … +3.199 ms |

**Within the 5 ms p99 budget on every run — but the Week-1 characterisation "within budget by
roughly an order of magnitude" no longer holds.** On a 64 KiB result the worst observed added p99
was **4.348 ms against a 5 ms budget**: about 0.65 ms of headroom, not 4.4 ms. The p50 is stable and
small; the p99 is where the two full walks of a large payload show up.

Reported honestly rather than filtered: two earlier runs on the same host reported added p99 of
44.6 ms and 138.4 ms, and are **discarded as host noise, not as toolwall's cost** — the *direct*
baseline in those runs showed p99 of 24 ms and 87 ms and maxima of 111–264 ms, and the zero-guard
proxy showed 173 ms. The machine was running three other agents concurrently (`load average 61`).
The four runs tabulated above were taken on the same host under the same load with maxima of
2.7–7.2 ms, which is the regime where the deltas mean anything.

Two follow-ups this measurement earns, for Dev 3:
- `measure()` and `hasProtoKey()` traverse the same payload twice. One fused walk would roughly
  halve the large-result cost, which is where all the headroom went.
- Neither walk is needed when `responseFor(serverId).enabled` is false; the early return already
  covers that, but the bounds check runs unconditionally when it is true, even where every bound is
  larger than any result the server can produce.

Still not measured, and therefore still not claimed: concurrency, a cold pin store on a slow disk,
and the `tools/list` cold path.

### C-21 · The advisory ATR detector is opt-in, and there is now a way to opt in
`AtrAdvisoryGuard` is **never constructed by `assembleToolwall()`**. There is deliberately no
boolean toggle for it: the caller supplies a pre-built `AtrScanner` via `ToolwallOptions.atr`, or it
does not exist. The CLI exposes `--advisory-rules <enforce|alert|hunt>`, which is the only way an
operator gets it, and the banner names it only when it is actually registered.

The measured reason (`test/unit/atr-fp.test.ts`, printed on every test run): the `enforce` lane
catches **0 of 8** published tool-poisoning payloads at 0.0% FP; `alert` catches 5 of 8 at 6.5% FP.
Shipping the enforcing lane on by default would block nothing that matters while being loud about
the rest — theatre. The mode is `advisory` regardless of lane: findings reach stderr and the audit
log, the verdict stays `allow`.

---

## Week-3 integration outcomes (2026-08-19) — inference, provenance, and the recurrence

### C-22 · ITEM ZERO, THIRD OCCURRENCE: `infer.ts` and `provenance.ts` were dead code — RESOLVED
`grep inferredPolicy src/index.ts` and `grep provenanceObserver src/index.ts` both returned
nothing. `src/policy/infer.ts` (827 lines) and `src/audit/provenance.ts` (1,621 lines) were not
imported, not exported and not reachable from any request path. Both had green unit tests. Nothing
failed, because a module nobody imports raises no error.

That is the same failure as C-17 (the whole Week-2 response leg) and the same failure as the Week-1
double `deriveServerId` (C-0). Three occurrences is not a lapse, it is a missing check.

**Wired:**
- `assembleToolwall()` now builds `policy` **after** `tools`, because inference must read the
  PINNED `inputSchema` per C-1, and wraps it: `inferredPolicy(base, tools, { roots: [baseDir] })`.
  Default-ON, `observation` left `"off"`.
- `provenanceObserver({ identity, audit: audit.sink(), provenance }).observe` is wired into
  `MetadataPinGuardOptions.onEvent`, constructed only when `ToolwallOptions.provenance` is given.
- Both modules are re-exported from `src/index.ts`; the CLI gained `--no-inference` and the five
  provenance flags, and `parseProvenanceArgs` is called on the argv slice **before** `--` so a
  flag belonging to the upstream server's own command line cannot switch ours on.

**The structural fix, generalised — `test/integration/wiring-completeness.test.ts`.** C-17's
assembly-time throw is kept (it fails at startup, which is stronger than failing in a test run) but
it knows about exactly one guard. The general form is a manifest: every module under `src/guards/`,
`src/policy/` and `src/audit/` must be classified `assembled`, `opt-in`, `support` or `barrel`, and
the classification is verified against the code:

| claim | verified by |
|---|---|
| `assembled` | import-reachable from `src/index.ts`, a symbol of it appears inside `assembleToolwall()`, and it is on the public export surface |
| `opt-in` | all of the above, **plus** the `ToolwallOptions` field that enables it exists in `src/index.ts` — "opt-in" cannot quietly mean "unreachable" |
| `support` | import-reachable from `src/index.ts` |
| `barrel` | contains no runtime code |

A new file under those directories fails the suite until somebody classifies it; a module that is
neither reachable nor declared opt-in fails it. **Both Week-3 modules would have failed the
reachability check on the day they landed.** Verified by adding a dead `src/policy/dead-experiment.ts`
and watching the suite go red, then removing it.

What it does not claim: that a reachable module is correct, or that a guard is registered on the
right leg. `response-guards-e2e.test.ts` and `inference-provenance-e2e.test.ts` prove behaviour.
This file proves only that nothing on disk was silently forgotten.

### C-23 · Inference is wired, default-ON, and proven end to end
`test/integration/inference-provenance-e2e.test.ts` drives a real spawned fixture
(`test/fixtures/capability-server.mjs` — an entirely legitimate server) through the assembled
proxy. Every "with inference" assertion is **paired with the same call under
`enable: { inference: false }`**, so the improvement is measured against the real day-zero
baseline rather than asserted against nothing:

| call, with NO policy file | inference ON | inference OFF (what Week 2 shipped) |
|---|---|---|
| `read_file({ path: "/etc/passwd" })` | **blocked on the request leg** | allowed, `read:/etc/passwd` returned |
| `write_file({ destination: "/etc/cron.d/backdoor" })` | **blocked** | allowed, `wrote:` returned |
| `fetch_url({ url: "file:///etc/passwd" })` | **blocked** (scheme) | allowed, `fetched:` returned |
| `fetch_url({ url: "https://attacker.example/collect" })` | allowed — the documented gap | allowed |

The last row is asserted as a **miss**, not omitted: inference cannot invent a host allowlist, and
a declared `egress` block is still what catches exfiltration to an unlisted host. The same test
proves that block works, so the README's "inference is a floor, not a ceiling" is a measured claim.

False-positive side, also through the assembled proxy: a read inside the workspace root, a
two-number `add`, `http://127.0.0.1:3000`, and the C-7 `git_diff` anchor case are all untouched.
The full suite — 846 tests including the 59-case benign corpus and the whole Week-1/2 e2e set —
passes unchanged with inference default-ON, which is the strongest available restatement of the
0.0% false-positive measurement.

**Precedence verified through the assembled path, not against the module.** A policy declaring
`filesystem.read: ["/etc"]` for this server makes `read_file({ path: "/etc/passwd" })` succeed, and
in the same session `fetch_url({ url: "file://..." })` is still blocked — inference stands down per
capability, not wholesale.

### C-24 · Provenance is opt-in, and the default path makes zero network calls
Asserted against the **real global `fetch`**, replaced with a recorder for the duration of a full
assembled session, rather than against an injected `fetchImpl`. An injected stub cannot observe a
call made by something that never took one, and the claim being defended is about the binary.

- No `provenance` option: `toolwall.provenance` is `undefined`, no `toolwall/provenance-*` finding
  appears anywhere, zero fetch attempts.
- `provenance: { network: "offline" }`: a real `pinned` event from the real pin guard drives the
  observer, `toolwall/provenance-not-checked` reaches the real audit sink, zero fetch attempts.
- A `server.json` `fileSha256` against a real local artifact produces
  `provenance-file-hash-verified`, and against tampered bytes `provenance-file-hash-mismatch`
  (`critical`) — fully offline, fully deterministic, and the one check in the module entitled to
  the word "verified".
- `network: "allow-registry-lookups"` changes the `not-checked` **reason** from *"registry lookups
  are off"* to *"no package could be resolved from the spawn spec"*, which is what proves the flag
  propagated through argv → `parseProvenanceArgs` → `assembleToolwall` → the observer rather than
  being dropped somewhere in between.

`--provenance-bundle` alone turns the feature on and leaves the network off; the CLI banner says
which of the two postures you are in, and `test/integration/cli.test.ts` asserts both strings.

### C-11 (re-measured, Week 3) · The 5 ms budget is MISSED on a node-heavy result
The C-11 follow-up asked for `measure()` and `hasProtoKey()` to be fused, predicting it "would
roughly halve the large-result cost". **The prediction was wrong, for a reason worth recording:**
`bench/latency.ts`'s `large` workload is 64 KiB arriving as ONE string inside two objects — about
six nodes. Both walks finish it in microseconds however many times they run. The response-leg cost
scales with a result's **node count**, not its byte size, and the benchmark had no node-heavy case.

So the benchmark gained a third workload, `wide`: 2,000 structured rows (~12k nodes, ~219 KiB),
which is what a SQL, search or directory-listing tool actually returns.

`npm run bench`, Node v25.2.1 on darwin/x64, 1000 sequential `tools/call` after 100 warmup, one in
flight, **four consecutive runs** at load average 6–13. Added latency vs a direct connection:

| workload | added p50 | added p95 | added p99 | budget |
|---|---|---|---|---|
| small (9 B) | +0.177 … +0.289 ms | +0.269 … +0.368 ms | +0.349 … +0.401 ms | within |
| large (64 KiB, ~6 nodes) | +0.822 … +0.920 ms | +1.524 … +1.736 ms | +0.907 … +1.722 ms | within |
| **wide (~12k nodes)** | **+4.235 … +4.448 ms** | **+4.657 … +5.745 ms** | **+5.123 … +7.260 ms** | **OVER on all four runs** |

Guard stack alone (guarded minus zero-guard proxy), so the process hop is excluded:

| workload | p50 | p95 | p99 |
|---|---|---|---|
| small | −0.176 … +0.103 ms | −0.366 … +0.074 ms | −0.809 … +0.071 ms |
| large | +0.105 … +0.176 ms | +0.495 … +0.688 ms | +0.469 … +0.726 ms |
| wide | +1.346 … +1.577 ms | +1.472 … +2.532 ms | +0.175 … +3.305 ms |

The negative `small` figures are noise, not a discovery: on a 9-byte echo the guarded proxy and the
zero-guard proxy differ by less than the run-to-run spread, and in one of the four runs the
zero-guard proxy happened to be the slower of the two. Reported as measured rather than clipped
at zero.

**Read the two tables together.** On the `wide` workload the *zero-guard* proxy alone adds p99
+3.955 … +5.515 ms — the extra process hop and the JSON re-serialization of a 219 KiB structured
payload consume most or all of the budget before a single guard runs. The guard stack's own p50
contribution is ~1.3–1.6 ms. **`npm run bench` now exits non-zero, and that is correct: the
sub-5 ms p99 claim does not hold for large structured results and should not be made.** It holds
comfortably for the small and byte-heavy cases, which is what the earlier tables measured.

**Did the fusion help? Yes, but not where C-11 predicted, and not measurably in the full-stack
benchmark.** The end-to-end run-to-run variance on `wide` (±2 ms on the guard-stack delta at load
8–13) is an order of magnitude larger than the effect, so the full-stack bench cannot resolve it —
before/after runs there were indistinguishable. Isolated, 20,000 iterations after 2,000 warmup on
the same host:

| payload | two walks (`measure` + `hasProtoKey`) | one walk (`measureAndScan`) | change |
|---|---|---|---|
| 64 KiB in ONE string (~6 nodes) | mean 0.0014 ms | mean 0.0014 ms | **−2.8%, i.e. nothing** |
| 12,007 nodes / 219 KiB | mean 1.0411 ms, p99 1.3881 ms | mean 0.8313 ms, p99 1.0515 ms | **−20.2% mean, −24% p99** |

`measureAndScan` also drops the per-node `{ v, d }` frame allocation in favour of two parallel
stacks, and turns the `__proto__` check into one `hasOwnProperty` call per object instead of a
second traversal and a second `getOwnPropertyNames` allocation. The proto scan now shares
`measure`'s 200k node cap rather than its own 50k one, which is four times the coverage in the same
fail-open direction. `hasProtoKey` stays exported and tested; it is simply no longer on the hot
path.

Still not measured, and therefore still not claimed: concurrency, a cold pin store on a slow disk,
and the `tools/list` cold path.

---

## Week-4 transport outcomes (2026-08-19) — correlation and Streamable HTTP (Dev 1)

### C-13 · CLOSED — `GuardContext` carries a correlation id on both legs
`MessageCorrelation` gained **`correlationId`**, and `ToolwallProxy` populates it on every context
it builds. Two ids, because there are two questions:

| question | field | reused? |
|---|---|---|
| "which REQUEST does this RESULT answer?" | **`correlationId`** | never |
| "which logical exchange is this, retries included?" | `exchangeId` | yes, by an MRTR retry — that is its purpose |

`exchangeId` alone was never a pairing key: an `input_required` retry deliberately reuses it, so two
live messages can share one. `correlationId` is minted per request/response round trip from a
separate counter with a different prefix (`c1`, `c2`… vs `x1`, `x2`…) so the two id spaces cannot be
confused in a log or a debugger.

**Populated on:** both legs of a client→server request; both legs of a server→client request; every
relayed notification; every payload lifted out of `inputRequests` (which carries the *enclosing*
round trip's id — an embedded request has no round trip of its own, and `inputRequestKey`
distinguishes siblings); and the synthetic post-reconnect re-verification. `#context()` now takes
correlation as a **required** parameter, so a new leg cannot omit it by accident.

The field is optional in the *type* only, so the one out-of-transport caller that hand-rolls a
`MessageCorrelation` (`provenanceObserver`) and every unit test that builds a `GuardContext` literal
keep compiling. Read it with `correlationIdOf(ctx)`, or narrow with `isCorrelated(ctx)` to
`CorrelatedGuardContext`.

**Proven, not asserted:** `test/integration/correlation.test.ts` runs a real proxy against
`test/fixtures/concurrent-server.mjs`, which answers **out of order**. Five `tools/call`s with
descending delays are all in flight at once and come back reversed; every result is matched to the
call whose tag it carries.

### C-13a · REQUEST TO DEV 3 — `ResultGuard` can stop skipping, and one more thing
The transport side is done. Two changes in `src/guards/runtime/result-guard.ts` follow from it:

1. **Replace `#correlate()`'s queue with a map keyed on `ctx.correlation.correlationId`.** Record on
   the request leg, look up and delete on the response leg. No ordering assumption, no ambiguity,
   and `toolwall/result.uncorrelated` stops firing under concurrency — measured today as **4 of 5**
   concurrent results uncorrelated, i.e. four results whose `outputSchema` was silently not enforced.
   C-19's `ctx.method === "tools/call"` guard becomes unnecessary (a `resources/read` result cannot
   pop a `tools/call` entry when the key is the round trip), though keeping it costs nothing. Bound
   the map and evict oldest-first: a request whose upstream call throws never reaches the response
   leg, so entries can accumulate.
2. **Key `#lastError` by TOOL, not one slot per server.** This is not a correlation fix; it is what
   correlation makes *sound*. Today an interposed unrelated call consumes the record before the ATPA
   retry is inspected, and an error result arriving with another call in flight is recorded against
   `toolName: ""` and matches nothing afterwards. Correlation fixes the second; keying by tool fixes
   the first. `test/integration/correlation.test.ts` contains a reference implementation
   (`CorrelatingProbe`) that catches `flaky:debug_context` through an ATPA sequence with a `plain`
   call and a `tools/list` interleaved between the error and the retry, alongside `QueueProbe` — the
   current algorithm reproduced exactly — which catches nothing on the same traffic.

### C-25 · Streamable HTTP — what is live, what is not
**Live: the client-facing leg.** `src/transport/listener.ts` (`StreamableHttpListener`) implements
`Transport`, so it drops into `assembleToolwall({ clientTransport })` where `StdioServerTransport`
went. The CLI constructs it under `--listen`. **stdio remains the default and is unchanged.**

Security, none of it optional and all of it tested in `test/integration/http.test.ts`:

| control | behaviour | why |
|---|---|---|
| Origin + Host validation | **403** | CVE-2025-66414 shipped DNS-rebinding protection OFF by default in the TS SDK *and simultaneously in the Python, Go, Java, Rust and Ruby SDKs*. Verified in the vendored tree: `webStandardStreamableHttp.js:79` reads `?? false` |
| loopback bind | `127.0.0.1` default, loud warning otherwise | CVE-2025-49596 (Inspector, 9.4), CVE-2026-23744 (MCPJam, 9.8, exploited from Feb 2026) |
| bearer token | **401**, generated when not supplied, **no flag disables it** | we must not become the unauthenticated local control plane the spec warns stdio proxies about |
| header/body agreement | **400 + `-32020`**, sentinel decoded first | Akamai header confusion: policy on the header, execution on the body |

Check order is a security decision: path → Origin/Host → auth → era shape → body → header agreement.
Origin **before** credentials, so a hostile page cannot use the refusal as an auth oracle.

**`src/transport/headers.ts` is no longer `exported-only`.** It was classified that way in
`test/integration/wiring-completeness.test.ts` precisely so "complete control, no live consumer"
had a test behind it; wiring it made that classification false and the inverse check failed until it
was corrected to `support`. **No module claims `exported-only` today.**

**Not live: the upstream leg from the CLI.** `createUpstreamHttpTransport()` is complete and proven
end to end against a real HTTP MCP server (`test/integration/http.test.ts` drives a real
`ToolwallProxy` over it, with a guard blocking on the request leg), but `assembleToolwall()` takes a
`SpawnSpec` and builds a stdio child unconditionally, and `src/index.ts` is the integrator's.
**Request to the integrator:** one additive option —
`ToolwallOptions.upstream?: { kind: "http"; url: string } | { kind: "stdio"; spec: SpawnSpec }` —
with `createUpstreamHttpTransport` supplying the transport and the `serverId` exactly as
`createUpstreamStdioTransport` does. Until it lands, `toolwall --server` cannot point at a remote
URL and the README says so.

### C-26 · The two HTTP eras are two implementations, and one of them is ours
`2025-11-25` delegates to the SDK's `StreamableHTTPServerTransport`: sessions, the standalone `GET`
SSE stream, `DELETE`, resumability.

`2026-07-28` does **not**, and the reason is a hard SDK property read out of the vendored tree:
`webStandardStreamableHttp.js:174` throws *"Stateless transport cannot be reused across requests"*
the second time a transport with no `sessionIdGenerator` handles anything. The SDK's stateless mode
is one transport per HTTP request, which cannot be the client leg of a long-lived proxy session. The
POST-only shape is small enough to own: one message per POST, `202` for a notification, `405` on
GET/DELETE, no sessions, no resumability.

**Stated limitation of that lane, not discovered later:** a server→client message that is not the
answer to an in-flight POST — a relayed `notifications/message`, `notifications/progress`, a sampling
request — has no channel on a POST-only endpoint. It is reported on the operator channel and
dropped. Under `2025-11-25` those ride the `GET` stream and are delivered normally, and `2025-11-25`
is what every shipping client speaks. Carrying them under `2026-07-28` needs the POST response to
become an SSE stream keyed on `relatedRequestId`; that is the next piece of work and is not
pretended to exist.

### C-27 · `wiring-completeness` now walks two entry points, for transports only
`src/index.ts` is the library entry; `src/cli/index.ts` is the `bin`. The Streamable HTTP listener is
constructed only by the binary, so a walk rooted at the library entry alone would call it dead.
Transport modules are therefore checked against **both** roots, in a test that says so in its name.
`guards/`, `policy/` and `audit/` are deliberately still checked against `src/index.ts` alone — that
is where `assembleToolwall` lives and where all three dead-code recurrences happened, and widening
their root set would weaken exactly the assertion C-22 exists to make.

### C-28 · The flat 5 ms budget is retired and replaced with a measured curve
`C-11 (re-measured, Week 3)` reported the `wide` workload OVER a 5 ms p99 budget and attributed most of
the cost to "the extra process hop and the JSON re-serialization". Half of that attribution was wrong,
and the benchmark now proves it with a fourth configuration.

**`pipe`** is a raw byte relay: two `PassThrough`s splicing the child's stdio to the client, parsing
nothing and guarding nothing. Same topology, same process, same stream primitives as the zero-guard
proxy, with the JSON-RPC codec deleted. It is the physical floor for interposition, and it decomposes
added latency into three layers with three different owners:

| workload | KiB | nodes | relay | codec | guards | total added mean |
|---|---|---|---|---|---|---|
| small | 0.0 | 5 | −0.37 | +0.14 | +0.12 | ≈0 |
| large | 64.0 | 5 | +0.03 | +0.68 | +1.06 | +1.76 ms |
| narrow | 52.2 | 3 007 | +0.01 | +0.57 | +0.26 | +0.84 ms |
| wide | 212.6 | 12 007 | −0.32 | +3.48 | +2.70 | **+5.85 ms** |
| huge | 860.1 | 48 007 | +0.45 | +9.24 | +7.10 | **+16.80 ms** |

**The process hop is not the cost. `relay` is ±0.45 ms across a 9-byte-to-860-KiB range, with no
trend — interposition is free.** The cost is the codec: one extra parse and one extra re-serialize per
leg. On `huge` that alone is **+9.24 ms with every guard removed**, so a proxy that parses MCP traffic
and forwards it unchanged misses a 5 ms budget by 94% while guarding nothing. There is no proxy design
in any language that both reads a payload and avoids this. **A flat sub-5 ms budget was below the floor,
not merely unmet**, and it survived three weeks only because no workload had enough nodes to expose it.

The replacement is a function of payload shape, with constants fixed in source and not refitted per run:

```
added mean ≤ 0.70 ms + 0.03 ms/KiB + 0.16 ms per 1 000 nodes
```

Two further decisions, both of which are about making the budget *believed*:

- **The mean gates; p99 is printed, not enforced.** p99 over 1000 samples is ten samples across four
  process configurations and a GC. The `direct` baseline — nothing of ours in the path — recorded a
  42.7 ms max on `wide` and the raw relay 94.7 ms on `huge`. Run-to-run p99 moved by more than the
  entire guard cost being measured. Gating on it would manufacture exactly the unreproducible red that
  teaches a team to stop reading CI.
- **The benchmark detects its own contamination.** Run at load average 42 it reported `relay` at
  −5.03 ms: a byte splice apparently faster than no splice, which is impossible and means the baseline
  was squeezed while the guarded runs were not. Every derived number in such a run is meaningless and
  *plausible*, which is the dangerous combination. `npm run bench` now exits non-zero with
  `RUN CONTAMINATED` when `relay < −0.75 ms` rather than printing a summary table someone might quote.

CI runs the benchmark and never gates on it (`.github/workflows/ci.yml`), for the same reason.

### C-29 · REQUEST TO DEV 3 — two measured findings in `capability-guard.ts`
Both are in `src/guards/runtime/`, so they are reported rather than patched.

**1. The node cap fails OPEN, and the header says so.** `walk()` stops at `nodeCap` (200 000) with
`break`, returning a partial `ScannedShape`. Two consequences, both silent: `protoKey` is `false`
rather than "unknown", so a `__proto__` key beyond the cap is not reported; and `totalBytes` is
under-measured, so `resultBoundsFindings` cannot fire `maxTotalBytes` on the very payloads most likely
to breach it. A result large enough to defeat inspection is currently trusted *more* than a small one.
The fix is to surface truncation on the returned shape and let `ResultGuard` treat it as a finding —
fail safe, not fail open. This is the one place where "bounded so measurement cannot be weaponised"
(T-08) and "fail closed" currently disagree.

**2. `Buffer.byteLength` is ~34% of the walk, and is avoidable.** Measured on the `wide` payload
(12 007 nodes, 217 749 bytes), 3 000 iterations after 300 warmup, same host as the table above:

| variant | p50 | p99 | mean | vs current |
|---|---|---|---|---|
| current (`Buffer.byteLength` per string and per key) | 0.8236 | 1.1334 | 0.8590 | — |
| memoise key lengths in a `Map` | 0.5896 | 1.0844 | 0.6217 | −27.6% |
| **manual UTF-8 length, ASCII fast path** | **0.5319** | **0.7643** | **0.5657** | **−34.1%** |
| memo + manual | 0.5469 | 0.7786 | 0.5835 | −32.1% |
| memo + manual + level-order traversal | 0.5074 | 0.7919 | 0.5406 | −37.1% |

All four variants were checked to return byte-identical `ScannedShape` output to the current
implementation on the test payload before being timed. The winner on simplicity-per-gain is the third:
replace `Buffer.byteLength(s, "utf8")` with a hand-rolled length that adds 1 for `< 0x800`, 2 otherwise,
and 2 with an index skip for a high surrogate. The key memo is redundant once that lands (keys are short
and ASCII), and the level-order rewrite buys 3% more for a structural change — not worth it.

**Expected end-to-end effect, stated so it is not oversold:** the walk is ~1.0 ms of the +2.70 ms guard
column on `wide`, so −34% of it is ≈0.35 ms off a 5.85 ms total. Real, free, and small. It does not
change the C-28 conclusion, because the codec — which is not ours — is the term that dominates.

**Measured and rejected:** skipping the response-leg re-serialization when no guard mutated the payload.
`JSON.stringify` of the 219 KiB `wide` result is 0.33 ms p50 / 0.65 ms p99 against a codec cost of
3.48 ms mean, so forwarding the original bytes would recover under 10% of the layer it targets while
requiring the transport to retain every raw frame. Not worth the coupling. Recorded here so it is not
re-proposed as an obvious win.
