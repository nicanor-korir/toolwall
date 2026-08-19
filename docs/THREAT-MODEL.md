# toolwall — Threat Model

Derived from verified research in `docs/RESEARCH-BRIEF.md`. Every threat below is anchored to a real
documented incident. **If a threat has no real-world anchor, it does not belong in this document.**

## 0. Trust boundary

```
[ LLM Client ]  --trusted--  [ toolwall ]  ==UNTRUSTED==  [ MCP Server ]
   Claude Desktop / Cursor        us              everything past here is hostile input
```
**Everything the server sends is attacker-controlled data, never instruction.** That includes tool
descriptions, tool names, schema field descriptions, enum values, server `instructions`, tool results,
resource contents, progress messages, error strings, and `_meta`.

We do **not** trust: server-supplied `ToolAnnotations` (spec: *"Clients should never make tool use
decisions based on ToolAnnotations received from untrusted servers"*), `serverInfo` (self-reported),
registry "verified" badges, or GitHub stars/forks (see T-09).

---

## 1. In scope — what toolwall defends against

### T-01 · Tool poisoning (injection in tool metadata)
Hidden instructions in `description`, `name`, `title`, schema field descriptions, enum values, or
`_meta`, which the client concatenates into the system prompt.
**Anchor:** Invariant Labs TPA research; MITRE **ATLAS AML.CS0054**; OWASP **MCP03**.
**Defense:** structural constraints + provenance + detection signals. **Explicitly NOT "sanitization
makes it safe"** — see §3.

### T-02 · Rug pull (post-approval mutation) — **PRIMARY THREAT, our wedge**
A tool is benign when approved and mutates later.
**Anchors:** **CVE-2025-54136 "MCPoison"** (Cursor ≤1.2.4, CVSS 7.2 — approval keyed on file identity,
not content, so an approved config could be silently swapped); **postmark-mcp** (backdoor in v1.0.16,
~300 orgs, **registry metadata never changed** — invisible to every pre-install scanner);
Pillar **Deadbugz** (mutates instructions **after three tool calls**, specifically defeating TOFU);
MITRE **ATLAS AML.T0111** (reputation inflation before rug pull).
**Defense:** canonical SHA-256 pinning **re-verified before every `tools/call`** — not at handshake,
not at first connect. This is the one place we beat all existing tooling.

### T-03 · Indirect prompt injection via tool RESULTS
Injection in returned content, not metadata. `PROMPT.md` does not cover this leg; it is arguably the
more common vector in the wild.
**Anchors:** **GitHub MCP exfiltration** (Invariant, 2025-05 — attacker files a public issue, agent
reads it and opens a PR leaking private-repo contents; GitHub confirmed it is *not* a server-side bug:
*"a fundamental architectural issue that must be addressed at the agent system level"*);
**Atlassian/JSM "Living off AI"** (ATLAS **AML.CS0039** — injected support ticket executes with the
internal user's privileges, *"the support engineer acted as a proxy"*); **Supabase/Cursor** SQL
exfiltration; **Agentjacking** (Sentry MCP, 2026-06 — a public write-only DSN injects into error
events; Claude Code, Cursor and Codex all executed attacker commands; **85% success across 100+
targets**, 2,388 orgs exposed; Datadog/PagerDuty/Jira identically exposed).
**Defense:** guard the response leg; cut the exfiltration edge of the lethal trifecta.

### T-04 · Cross-server shadowing & tool-name collision
One server redefining or impersonating another's tools.
**Anchors:** Docker MCP Gateway **GHSA-m5m2-mrxf-7j7q** (tool-name shadowing across aggregated
servers); spec guidance that `serverInfo.name` **SHOULD NOT** be relied on for disambiguation.
**Defense:** per-server provenance and namespacing; pin identity to the *connection*, not the name.

### T-05 · Malicious arguments on legitimate tools
A hijacked model calls a safe tool with hostile arguments (path traversal, exfil URLs, injected SQL).
**Anchors:** **CVE-2025-53109/53110 "EscapeRoute"** (Anthropic filesystem server — `startsWith` prefix
matching admits `/allow_dir_sensitive_credentials`; symlink escape); Postgres MCP **stacked-statement
SQLi** (`COMMIT; DROP SCHEMA public CASCADE;` escapes the read-only transaction entirely).
**Defense:** capability policy + strict schema enforcement. **Not** character blocklists — see §3.

### T-06 · Destructive / irreversible actions
**Defense:** human-in-the-loop, which the spec mandates (*"there SHOULD always be a human in the loop
with the ability to deny tool invocations"*). Never trust `destructiveHint` — attacker-controlled, and
note the spec default for an *unannotated* tool is `destructiveHint: true`, `openWorldHint: true`.

### T-07 · Stdio child-process abuse — **we are the vulnerable component here**
**Anchor:** OX Security "MCP by Design" (2026-04) — `StdioServerParameters` spawns from caller-supplied
`command`/`args` **with no sanitization in every official SDK**; 30+ disclosures, 10–14 Critical/High
CVEs (LiteLLM, Flowise, Windsurf, LangBot, Upsonic, DocsGPT…), ~7,000 exposed servers / up to 200,000
vulnerable instances. **Anthropic declined to fix — classified as by design.**
Allowlisting the binary is insufficient: `{"command":"npx","args":["-c","<payload>"]}` defeats it.
**Defense:** argument-level validation, not just command allowlisting; sandboxing; log every spawn.

### T-08 · Protocol-level abuse against the proxy itself
ID collision/cross-talk, malformed JSON-RPC, oversized/deeply-nested payloads, prototype pollution,
notification flooding, header↔body desync.
**Anchors:** **CVE-2026-25536** (TS SDK — shared transport ⇒ **JSON-RPC ID collision and cross-client
response leakage**, ≤1.25.3); **CVE-2025-6515** (oatpp-mcp — session ID was the object's **heap pointer**,
reused after free ⇒ session hijacking); **CVE-2025-66414** (TS SDK — DNS-rebinding protection **off by
default**, same default shipped simultaneously in Python/Go/Java/Rust/Ruby).
**Plus the 2026-07-28 header-mirroring split:** policy read from `Mcp-Name` while execution uses the
body. The spec tells intermediaries to reject unvalidated headers; a proxy that doesn't is exploitable
by construction. **Required red-team case.**

### T-09 · Supply-chain / provenance
**Anchors:** **V.A.P.E. / ChainDrop** (2026-08 — first payload delivered through the **official MCP
Registry**; the PyPI package is *clean*, malware lives in the linked GitHub repo as `.vscode/` and
`.claude/` settings; registry entry published **35 seconds** after the PyPI upload, so no scanning
window exists; **still listed `status: "active"` 11 days after disclosure while GitHub has taken the
repo down** — takedown signals do not propagate); **FakeGit/AgentBaiting** (2026-07 — ~7,600 fake repos,
>800 posing as MCP servers, >600 registry listings; **Claude Code, Gemini and ChatGPT independently
recommended campaign repos**, because reputation signals are optimized for an *LLM's* credibility
heuristics); **SmartLoader/Oura** (5 fake GitHub personas cross-forking for ~3 months);
UpGuard: **10–16% of servers across registries are lookalikes**; MCP.so 17,000+ servers unmoderated.
**Defense:** verify the integrity signals that already exist and nobody reads — npm SLSA/Sigstore
attestations and `server.json` `fileSha256`.

---

## 2. Explicitly OUT of scope — state these in the README, do not silently imply coverage

- **We are not a sandbox.** We do not contain a malicious server that already has code execution.
  Docker MCP Gateway does that better; recommend it alongside.
- **We do not stop a determined LLM that has already been convinced.** We reduce and log, not prevent.
- **We do not audit server source code.** That is Snyk agent-scan / Cisco mcp-scanner territory.
- **We are not an identity/authz gateway.** agentgateway and IBM ContextForge own that.
- **We cannot fix the lethal trifecta.** Where private data + untrusted content + an exfil channel
  coexist, we narrow the exfil edge; we do not eliminate the class. GitHub's own position on their MCP
  server: *"it's not really a vulnerability in the conventional sense."*
- **We do not defend the client's own config files.** `.claude/settings.json` hook injection
  (CVE-2025-59536, Mini-Shai-Hulud persistence) happens outside our data path.

---

## 3. Defenses we ship but must NOT overstate — mandatory honesty section

**Regex/keyword matching on descriptions is a weak signal, not a control.** Trivially bypassed by
paraphrase, encoding, homoglyphs, zero-width characters, and non-English text.
**Character blocklists on arguments are worse** — high false-positive, and legitimate tools routinely
receive semicolons, URLs and paths.

The measured reality, both directions:
- **MCPTox** (arXiv 2508.14925 — 45 live servers, 353 real tools, 1,312 attacks, 20 agents):
  **72.8% attack success** vs o1-mini; **<3% refusal even for Claude-3.7-Sonnet.** Attacks work.
- **False positives:** an AppSec Santa audit found only **6 of 27** Cisco mcp-scanner detections
  genuine (~78% FP). One paper reports FPR climbing **0% → 36%** at max-security config.

**Therefore, binding rules for this codebase:**
1. Every detector ships with a measured false-positive rate on a benign corpus. No FP number, no merge.
2. Never log or name anything such that a "sanitized" description reads as "safe."
3. Prefer **flag + quarantine + human decision** over silent mutation.
4. Deterministic core. Any LLM classification is strictly optional, off by default, and never in the
   `tools/call` hot path (latency + network + billing dependency on every invocation).

## 4. Ranking (build order)

| Rank | Threat | Why |
|---|---|---|
| 1 | **T-02 rug pull** | Our differentiator; deterministic; unsolved by everyone incl. Trail of Bits |
| 2 | **T-03 result injection** | Most common real-world vector; `PROMPT.md` misses it entirely |
| 3 | **T-06 / T-05 destructive + args** | Only reliable control (HITL) plus capability policy |
| 4 | **T-07 / T-08 self-defense** | We are a security tool; our own CVEs are unacceptable |
| 5 | **T-09 provenance** | Cheap, deterministic, genuinely unshipped |
| 6 | **T-01 metadata heuristics** | Real value, lowest tier, loudest failure mode |
