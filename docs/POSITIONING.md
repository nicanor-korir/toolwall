# toolwall — Positioning correction (2026-08-19)

> Decision taken after Week 2 launched, before Week 3 is scoped. This document overrides the
> emphasis in `docs/ARCHITECTURE.md` §"Product thesis". The engineering is unchanged; what the
> product **leads with** changes.

## The problem with our original framing

We chose **continuous tool-definition pinning** as the product because it is defensible positioning:
nobody ships it, seven SEPs died trying to standardise it, and it is deterministic rather than
heuristic. All true. But it answers *"did this change?"* — not *"can this hurt me?"*

Two pieces of evidence say we optimised for the wrong axis.

### Evidence 1 — the CVE mass is somewhere else

313 catalogued MCP CVEs, mapped to OWASP MCP categories:

| Category | CVEs | Do we address it? |
|---|---|---|
| MCP05 Command Injection & Execution | **131** | No — lives inside servers |
| MCP07 Insufficient AuthN/AuthZ | **72** | No — server-side |
| MCP02 Privilege Escalation | 42 | Partly (capability policy) |
| MCP01 + MCP04 Token & Supply Chain | 30 | Partly (T-09, unbuilt) |
| MCP06 Prompt Injection | 7 | Partly (response leg) |
| MCP10 Context Injection | 5 | Partly |
| **MCP03 Tool Poisoning** | **2** | **Yes — our headline** |

**Honest counter-argument, which is real but bounded:** tool poisoning is systematically *under*-counted
because there is no vendor to assign a CVE to. GitHub said so on the record about their own MCP server —
*"it's not really a vulnerability in the conventional sense."* So 2/313 understates it. It does not
understate it by two orders of magnitude.

### Evidence 2 — the real incidents were not tool poisoning

GitHub MCP exfiltration, Supabase/Cursor, Atlassian JSM, Agentjacking/Sentry — every headline 2025–26
incident came through **tool results plus over-privileged credentials**. In every single case the actual
remediation was capability reduction: read-only mode, stop using `service_role`, lockdown mode.
Not a filter. Not a pin. **Our pinning engine would have stopped none of them.**

And the measured efficacy ranking (brief §4.4) puts egress/network-behaviour control at **F-1 0.995**
against **0.03–0.17** for description scanning.

### Evidence 3 — the adoption problem is the product-killer

Our default tier measures **0.0% false positives**. But with no policy file written, it also blocks
approximately nothing — the capability model only bites once someone declares per-tool filesystem roots
and allowed hosts. **Nobody writes policy files.** `mcp-proxy` does **5M downloads/month with zero
security**, which is what the market actually installs. Every tool in our prior-art table that required
configuration is sitting at hundreds of downloads.

A control that requires configuration to do anything is a control that protects nobody.

## The corrected positioning

**Lead with: constrain what an injected model can DO. Prove integrity underneath it.**

| Layer | Role | Status |
|---|---|---|
| **Capability + egress constraint** | **The product.** Makes an injected model *harmless* | Egress is Week 2; inference is Week 3 |
| **Continuous pinning** | The **integrity substrate** — proves the contract being enforced is the approved one | Shipped Week 1 |
| Metadata heuristics | Advisory signal only | Week 2, advisory-tier |

The framing that survived all the research:

> **You cannot make an injected model safe. You can make it harmless — by ensuring that whatever it
> has been told to do, it lacks the capability to do it.** Every control that survived scrutiny is of
> the second kind.

Note this is not a retreat from pinning. C-1 already makes pinning **load-bearing for capability
enforcement**: without a pinned contract, an attacker widens their own schema and the malicious
arguments become "valid". Pinning is what makes the capability layer trustworthy. It is the foundation,
not the facade — it just should not be the pitch.

## What changes in Week 3

1. **Inferred capability policy, default-ON.** Derive capability from the tool's own `inputSchema`
   (a `format: "uri"` argument means network; a path-shaped argument means filesystem), from
   `annotations` (as a signal, never authorization), and from observed behaviour across a session.
   A calculator that has never touched the filesystem must not require a hand-written rule saying it
   cannot. **Learn-then-enforce beats declare-then-enforce for adoption.**
   The hand-written policy file stays, as the override for people who want it — not as the entry price.
2. **README leads with capability + egress**, with pinning presented as the integrity guarantee
   underneath. Rewrite the opening.
3. **T-09 provenance** — verify npm SLSA/Sigstore attestations and `server.json` `fileSha256`.
   Cheap, deterministic, no account, and genuinely unshipped by anyone. `@modelcontextprotocol/sdk` and
   the official servers ship attestations; `mcp-remote` — the CVSS 9.6 RCE package — does not. Surfacing
   that distinction is free.
4. **Say plainly that we are one layer.** Docker MCP Gateway does containment better than we will;
   recommend it alongside us. We constrain what the MODEL can direct a tool to reach — we cannot
   intercept a compromised server's own sockets. That is the difference between a proxy and a sandbox.
5. **Red team round 2** across the whole Week 2 surface, with particular attention to the reconnect
   path: a reconnect must never become a route around a guard.

## What we are explicitly NOT doing

Not chasing MCP05/MCP07 (command injection and auth inside servers). That is 65% of the CVE mass and it
is not addressable from a proxy — it needs server-side fixes or sandboxing. Saying so is more useful to
a user than implying coverage we do not have.
