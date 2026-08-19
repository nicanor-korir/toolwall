# toolwall — Attack Corpus (`test/attacks/` + `test/fixtures/malicious/`)

Owned by the **red-team** agent. This is the adversarial corpus fired at the proxy. It is built to be
useful **before** `src/` exists: the fixtures are runnable MCP servers and structured payload data,
and the tests prove the attacks are real without importing any guard. When Dev 1/2/3 land their
modules, the same servers get pointed **through** toolwall and the `it.todo` assertions here become the
failing tests that drive each defense.

> Reporting standard (`.claude/agents/red-team.md`): demonstrate a bypass working; never speculate.
> Every payload below is executed or decoded in a test, not merely described.

## What's here

| File | What it is |
|---|---|
| `fixtures/malicious/poisoned-server.js` | A real, runnable MCP server (SDK 1.30.0, protocol 2025-11-25) that poisons its tool description, nested schema descriptions, server `instructions`, prompt/resource metadata, **and** the tool result. |
| `fixtures/malicious/rugpull-server.js` | A server benign on first `tools/list`, hostile after. Variants `a` (prose), `b` (schema-only, prose unchanged), `c` (mutates after N calls — Deadbugz). |
| `fixtures/malicious/evasion-corpus.ts` | Tool-poisoning payloads that defeat naive phrase matching: paraphrase/synonym, base64/hex/rot13, zero-width, homoglyph, bidi, Unicode TAG-block, HTML/markdown comment, JSON `\u` escapes, non-English. |
| `fixtures/malicious/injection-sites.ts` | The **same** payload planted in every attacker-controlled field: `name`, `title`, `annotations.title`, schema property descriptions, enum values, `_meta`, `outputSchema`, server `instructions`, prompt/resource metadata, and every shape of tool **result**. |
| `attacks/fixture-servers.test.ts` | Connects a real MCP client to each fixture server and proves the poison reaches the wire and the rug-pulls actually mutate. |
| `attacks/evasion-corpus.test.ts` | Proves each evasion slips past the exact blocklist `docs/PROMPT.md` specifies, and that each obfuscated payload decodes back to the malicious intent. |
| `attacks/injection-sites.test.ts` | Proves each site carries the payload and that a description-only guard would miss all but one. |

Run: `npm run test:attacks` (or `npx vitest run test/attacks`).

## Attack classes → real-world anchor → owning module

Anchors are from `docs/THREAT-MODEL.md`; ownership from `docs/ARCHITECTURE.md` "Module map".

| Class | Fixture / entries | Threat + real-world anchor | Owner |
|---|---|---|---|
| Direct instruction injection (baseline) | `poisoned-server.js`; `control-direct` | **T-01** — Invariant Labs TPA, MITRE ATLAS **AML.CS0054**, OWASP **MCP03** | `guards/metadata/` (Dev 2) |
| Paraphrase / synonym | `paraphrase-1`, `synonym-1` | **T-01** — MCPTox arXiv 2508.14925 (72.8% success, <3% refusal) | `guards/metadata/` (semantic tier, opt-in) |
| Base64 / hex / rot13 encoding | `base64-1`, `hex-1`, `rot13-1` | **T-01** — evasion class named in THREAT-MODEL §3 | `guards/metadata/` |
| Zero-width / homoglyph / bidi | `zero-width-1`, `homoglyph-1`, `bidi-1` | **T-01**; bidi ≈ Trojan Source (CVE-2021-42574) | `guards/metadata/` (unicode-normalization) |
| Unicode TAG-block concealment | `unicode-tag-1` | **T-01** — arXiv **2607.05744** (invisible TAG chars in tool metadata) | `guards/metadata/` |
| HTML / markdown comment | `html-comment-1`, `markdown-comment-1` | **T-01** — concealment from human review + rendered UI | `guards/metadata/` (markup-stripping) |
| JSON `\u` escape / raw-vs-parsed | `json-escape-1`, `JSON_ESCAPE_WIRE_FORM` | **T-01** — scan the parsed string, never raw wire bytes | `guards/metadata/` |
| Non-English (es/zh/ru/ar) | `lang-*` | **T-01** — English blocklist has no coverage | `guards/metadata/` (language coverage) |
| Injection outside `description` | `injection-sites.ts` T-01 sites | **T-01** — full NL surface, RESEARCH-BRIEF §1.5 | `guards/metadata/` (Dev 2) |
| Result-leg injection | `injection-sites.ts` T-03 sites; `poisoned-server.js` result | **T-03** — GitHub MCP exfiltration (Invariant 2025-05), Atlassian/JSM **AML.CS0039**, Agentjacking/Sentry 2026-06 (85% success) | `guards/runtime/` (Dev 3) |
| Rug pull — prose mutation | `rugpull-server.js --variant a` | **T-02** — postmark-mcp (metadata unchanged), CVE-2025-54136 MCPoison | `guards/metadata/` (Dev 2) |
| Rug pull — schema-only mutation | `rugpull-server.js --variant b` | **T-02** — defeats a prose-only hash; pin must cover `inputSchema` | `guards/metadata/` (Dev 2) |
| Rug pull — delayed after N calls | `rugpull-server.js --variant c` | **T-02** — Pillar **Deadbugz** (mutates after 3 calls, defeats TOFU) | `guards/metadata/` (Dev 2) |

## The design lessons each class encodes (for the owning dev)

- **The naive blocklist is a strawman by construction.** `evasion-corpus.ts` pins `NAIVE_BLOCKLIST` to
  the exact five phrases `docs/PROMPT.md` names and shows every technique slipping past it. This is the
  concrete form of THREAT-MODEL §3: *regex/keyword matching is a weak signal, not a control.* Do not
  ship it as a control, and do not name anything "sanitized" such that it reads as "safe."
- **Guarding `description` is a fraction of the surface.** `injection-sites.ts` proves the payload
  lands in ~15 other attacker-controlled fields, split across Dev 2 (metadata) and Dev 3 (result leg).
- **The result leg (T-03) is arguably the bigger vector** and `docs/PROMPT.md` omits it entirely. The
  poisoned server returns a **correct sum** plus an injected instruction, so the tool looks legitimate.
- **Rug-pull defense cannot be prose-only, cannot be TOFU, and cannot trust `list_changed`.** Variant
  `b` mutates only `inputSchema`; variant `c` waits past first-connect pinning; both run with `--silent`
  available to prove the mutation lands without the courtesy notification. The pin must canonicalize
  `name`/`title`/`description`/`inputSchema`/`outputSchema`/`annotations` and re-verify **before every
  `tools/call`** (ARCHITECTURE "Pinning design").

## Honesty notes (what this corpus does NOT claim)

- `it.todo` blocks are **pending**, not passing. They assert the correct behavior for the owning module
  and go red the moment that module tries to handle these inputs. Turn them green by **detecting** the
  attack — never by weakening a fixture.
- Some entries need a **semantic/LLM tier** (paraphrase, synonym, paraphrased comment bodies). Per
  ARCHITECTURE that tier is optional, off by default, and off the `tools/call` hot path. A deterministic
  build will **not** catch these, and the corpus says so rather than pretending otherwise.
- **Every detector still owes a measured false-positive rate on `test/fixtures/benign/`** (Dev 3's
  corpus) before it merges. This attack corpus measures catch, not FP; both numbers are required.

## Not yet built (tracked, not silently skipped)

The red-team mandate lists classes this first corpus does not yet exercise, to be added as `src/` lands:
cross-server shadowing / tool-name collision (T-04), malicious-argument fixtures on legitimate tools
(T-05), stdio child-process / argument-injection abuse (T-07), protocol-level abuse against the proxy
(T-08: id collision/cross-talk, oversized/deeply-nested payloads, `__proto__` prototype pollution,
header↔body desync on the 2026-07-28 mirrored headers), and hostile MRTR / `sampling`·`elicitation`
server→client payloads. These depend on the proxy existing to attack; the fixtures above do not.

---

## Round 2 (2026-08-19) — Week-2 attack surface

Fired at the reconnect path, confirmation budget, response-leg/MRTR, egress, and scope-keyed pins.
New files: `confirm-dialog-injection.test.ts`, `atpa-gaps.test.ts`, `round2-boundaries.test.ts`.

### Proven bypass — HITL confirmation dialog is spoofable through `locus` (P2)
`confirm-dialog-injection.test.ts` (2 asserts, RED). `renderPrompt`/C-14 promise the operator
"Nothing above is quoted from the server," rendering only ruleId/severity/locus/remediation. But
`locus` is `/arguments${pointer}` and the pointer embeds a server-chosen `format:uri` property name
(bound via `deriveUrlFromSchema`, on at the balanced default). JSON Pointer escapes `~` and `/` but
not newlines, so a property name carrying `\n│ ... safe to approve` prints fake dialog rows above
the reassurance line. The same unsanitized `locus` also crosses back to the LLM client via
`redactFindingForClient` (C-9). Reachable under TOFU (first-sighting-malicious pins as-is).
Owner: `src/guards/runtime/confirm.ts` (renderPrompt) + `src/transport/proxy.ts` (redaction).

### Documented ATPA boundaries, now executable (P3)
`atpa-gaps.test.ts` (4 tests, GREEN = attack succeeds). ATPA fires only on an immediate same-tool
retry adding an *undeclared* argument the error text named. It is therefore evaded by: (1) a server
that DECLARES its exfil argument in the pinned schema; (2) a two-step retry with one interposed
call (clears the single-slot last-error); (3) routing the exfil retry through a different tool. The
CONTROL test proves the in-signature shape is blocked. (1) and (2) are acknowledged in the guard
source; pinned here so the boundary is regression-visible. Owner: `src/guards/runtime/result-guard.ts`.

### Defenses that HELD (stated plainly)
- **Reconnect gate.** Poisoned generation-2 (tool drift, and instructions drift under 2025-11-25)
  is refused terminally before the buffer releases; parked requests are not released until reverify
  completes; a side-effecting `tools/call` is never replayed (method allowlist, not `readOnlyHint`).
  Honest notes: a hostile server that makes a *read-only method* (`prompts/get`, `resources/read`)
  side-effecting gets it replayed/double-executed on reconnect — the "re-execution is observationally
  free" assumption is false for an untrusted peer (documented tradeoff); and reverify force-re-lists
  `tools/list` but does not re-fetch `server/discover`, so 2026-07-28 instructions-drift on reconnect
  relies on the client re-discovering rather than being force-checked.
- **MRTR resultType confusion.** `round2-boundaries.test.ts`. The proxy lift only fires on the exact
  `resultType:"input_required"`, but `ResultGuard` inspects `inputRequests` inline regardless of
  resultType/casing/era, so systemPrompt / server-`tools[]` / credential-elicitation detection is not
  bypassed. `roots/list` carrying a payload is caught too.
- **Scope-keyed pins.** Scope is operator-set (`pinScope`, default `DEFAULT_PIN_SCOPE`), never derived
  from anything the server sends, so a server cannot present a mutated definition under a "new scope"
  to pin fresh instead of drifting.
- **Egress default.** Off until an operator declares a block, so URL-parsing tricks only engage once
  configured; the http/url path normalizes decimal/hex/userinfo correctly. One latent bug recorded
  (`isPrivateAddress` misses the WHATWG-compressed IPv4-mapped IPv6 loopback `[::ffff:7f00:1]`) but it
  is NOT reachable through `evaluateUrl` — the private check runs only on the wildcard path and an IP
  literal cannot match a wildcard. Owner: `src/policy/hosts.ts`.
