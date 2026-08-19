# toolwall

**A local-first guardrail proxy for MCP.** It sits between your LLM client and untrusted MCP servers,
and re-verifies the cryptographic identity of every tool definition **before every call** — not once at
install, not once at first connect.

> Status: in development. See `docs/ARCHITECTURE.md` for the design and `docs/THREAT-MODEL.md` for what
> this does and explicitly does **not** defend against.

## Why this exists

Existing MCP security tools scan once before you start, or pin once at first connect. Pillar's
*Deadbugz* campaign mutates server instructions **after three tool calls**, specifically to walk through
that gap. `CVE-2025-54136` ("MCPoison") was a persistent RCE because Cursor keyed approval on file
identity rather than content. The `postmark-mcp` backdoor shipped in v1.0.16 with **registry metadata
unchanged**, invisible to every pre-install scanner.

Continuous verification catches all three. Nothing shipping today does it.

Tool-definition signing has been proposed to the MCP spec **seven times since June 2025** and rejected
or stalled every time; the 2026 roadmap does not include signing, identity, or provenance. The official
registry's own moderation policy says *"consumers should assume minimal-to-no moderation"* and lists
**"servers with security vulnerabilities"** under what it does *not* remove.

## Usage

toolwall sits between your client and the server, so wherever your client config says

```
node ./path/to/server.js
```

it instead says

```
toolwall --server "node ./path/to/server.js"
```

Everything else is optional:

```
# capability policy + a hash-chained local audit log
toolwall --policy ./toolwall-policy.json --audit-log ./toolwall-audit.jsonl \
         --server "node ./path/to/server.js"

# restrict the spawnable binary; the args after -- are the server command line
toolwall --allow-command node -- node ./path/to/server.js

# never adopt a definition without a human: an unapproved tool is refused, not pinned
toolwall --pin-mode strict --server "node ./path/to/server.js"
```

`toolwall --help` lists every flag. Diagnostics — the spawn record, guard findings, drift diffs —
go to **stderr**; stdout is the JSON-RPC channel and carries nothing else.

State lives in two local files and nowhere else: `.toolwall/pins.json` (mode 0600) holds the
approved tool definitions, and `--audit-log` appends a hash-chained JSONL record of every spawn,
pin, block and skipped check.

### What it does on the wire

| Method | Leg | What happens |
|---|---|---|
| `initialize` | server → client | Server `instructions` are canonicalized, hashed and pinned |
| `tools/list` | server → client | Every tool definition is pinned; drift is blocked and quarantined |
| `notifications/tools/list_changed` | server → client | Marks the cached catalogue stale |
| `tools/call` | client → server | Pin re-verified, then arguments validated **against the pinned schema**, then capability policy |
| everything else | either | Forwarded by reference. No inspection, no clone, no re-serialization |

Measured added latency on `tools/call` with the full guard stack, against a direct connection to
the same server (1000 sequential calls, Node v25.2.1, darwin/x64, three runs):
**p50 +0.21…0.29ms · p95 +0.24…0.34ms · p99 +0.32…0.59ms**, against a 5ms budget. Reproduce with
`npm run bench`.

## Principles

- **No account, no telemetry, no network calls** in the default path.
- **Deterministic core.** Any LLM classification is optional, off by default, never in the hot path.
- **Every detector reports a measured false-positive rate.** Heuristics are signals, not guarantees.
- **We credit prior art** — Invariant Labs, Trail of Bits' `mcp-context-protector`, JanuScope — and say
  plainly where we differ.

## What toolwall does NOT do

Stated plainly, because a security tool that lets you infer coverage it does not have is worse
than no tool. The full list is `docs/THREAT-MODEL.md` §2.

- **It is not a sandbox.** It does not contain a malicious server that already has code
  execution. Docker MCP Gateway does that; run it alongside.
- **It does not stop a model that has already been convinced.** It reduces and logs, not prevents.
- **It does not audit server source code.** That is Snyk agent-scan / Cisco mcp-scanner territory.
- **It is not an identity or authorization gateway.** agentgateway and IBM ContextForge own that.
- **It cannot fix the lethal trifecta.** Where private data, untrusted content and an exfiltration
  channel coexist, it narrows the exfiltration edge; it does not eliminate the class.
- **It does not defend your client's own config files.** `.claude/settings.json` hook injection
  happens outside toolwall's data path.

Two limits specific to what ships today:

- **Trust-on-first-use is the default, and TOFU cannot tell a benign first sighting from a tool
  that was already hostile when you first saw it.** Pinning answers "did this change since you
  approved it" with certainty and says nothing about whether the original was safe. `--pin-mode
  strict` is the honest setting for a server you have not reviewed.
- **`_meta` is not pinned.** It is the designated carrier for transport bookkeeping and changes
  legitimately between two identical listings, so pinning it would trade a narrow coverage gap
  for a broad false-alarm surface. Set `unpinnedFields: []` to pin it and accept the churn.

## License

MIT
