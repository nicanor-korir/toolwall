/**
 * The structural shape both `NetworkGrant` (per tool) and `EgressPolicy` (per server) satisfy, so
 * the same matcher enforces both. They are intersected, never unioned: a per-tool grant may narrow
 * what the server-level allowlist permits and can never widen it.
 */
export interface HostAllowlist {
  readonly hosts: readonly string[];
  readonly schemes: readonly string[];
  readonly allowPrivateNetwork: boolean;
  readonly allowIpLiterals: boolean;
}

/**
 * Host and URL capability matching — the egress leg.
 *
 * ## What this does and does not claim
 *
 * It decides whether a URL argument names a host the operator granted. It is a **literal** check
 * on the URL as written, after WHATWG normalization. It deliberately performs **no DNS
 * resolution**: resolving would (a) put a network round-trip in the sub-5ms `tools/call` hot path,
 * (b) violate the zero-network-calls guarantee that is a stated product differentiator, and
 * (c) be defeated by DNS rebinding anyway — the name we resolve is not necessarily the name the
 * HTTP client resolves. Consequence, stated plainly: **a hostname on the allowlist that resolves
 * to a private address is not caught here.** That is a documented gap, not a covered case.
 *
 * Matching is on the parsed `hostname`, never on the raw URL string. `https://good.com@evil.tld/`
 * has hostname `evil.tld`, and substring matching on the raw string is precisely how that
 * confusion becomes a bypass.
 */

export type UrlDecision =
  | {
      readonly ok: true;
      readonly hostname: string;
      readonly scheme: string;
      readonly matchedBy: "exact" | "wildcard";
      /** Non-blocking observations for the audit record (e.g. embedded credentials). */
      readonly notes: readonly string[];
    }
  | {
      readonly ok: false;
      readonly reason: "unparseable" | "scheme-not-granted" | "host-not-granted" | "ip-literal" | "private-network";
      readonly detail: string;
      readonly hostname?: string;
      readonly scheme?: string;
    };

/** `*.example.com` matches strict subdomains only; `example.com` must be listed separately. */
function matchesWildcard(pattern: string, hostname: string): boolean {
  if (!pattern.startsWith("*.")) return false;
  const suffix = pattern.slice(2).toLowerCase();
  if (suffix.length === 0) return false;
  const h = hostname.toLowerCase();
  if (h.length <= suffix.length) return false;
  // Label-boundary comparison. `example.com.evil.io` and `evil-example.com` both fail:
  // the former because the suffix is not at the end, the latter because the character
  // preceding the suffix is not a dot.
  if (!h.endsWith("." + suffix)) return false;
  return true;
}

const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

export function isIpLiteral(hostname: string): boolean {
  if (IPV4.test(hostname)) return true;
  // WHATWG URL reports IPv6 hosts bracketed.
  return hostname.startsWith("[") && hostname.endsWith("]");
}

/**
 * Private / loopback / link-local / unspecified / CGNAT literals. WHATWG URL already normalizes
 * the classic obfuscations (`http://2130706433/` -> `127.0.0.1`, `http://0x7f.1/` -> `127.0.0.1`),
 * so this operates on the normalized form rather than trying to enumerate encodings.
 */
export function isPrivateAddress(hostname: string): boolean {
  const h = hostname.toLowerCase();
  if (h === "localhost" || h.endsWith(".localhost")) return true;

  const v4 = IPV4.exec(h);
  if (v4) {
    const o = [v4[1], v4[2], v4[3], v4[4]].map((s) => Number(s ?? NaN));
    const [a, b] = [o[0] ?? -1, o[1] ?? -1];
    if (o.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return true; // malformed => treat as unsafe
    if (a === 10 || a === 127 || a === 0) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 169 && b === 254) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
    return false;
  }

  if (h.startsWith("[") && h.endsWith("]")) {
    const inner = h.slice(1, -1);
    if (inner === "::1" || inner === "::") return true;
    if (inner.startsWith("fe8") || inner.startsWith("fe9") || inner.startsWith("fea") || inner.startsWith("feb")) return true;
    if (inner.startsWith("fc") || inner.startsWith("fd")) return true;
    // IPv4-mapped, e.g. ::ffff:127.0.0.1
    const mapped = inner.split(":").pop() ?? "";
    if (IPV4.test(mapped)) return isPrivateAddress(mapped);
    return false;
  }

  return false;
}

export function evaluateUrl(raw: unknown, grant: HostAllowlist): UrlDecision {
  if (typeof raw !== "string") return { ok: false, reason: "unparseable", detail: `expected string, got ${typeof raw}` };

  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return { ok: false, reason: "unparseable", detail: "not an absolute URL" };
  }

  const scheme = url.protocol.replace(/:$/, "").toLowerCase();
  const hostname = url.hostname.toLowerCase();

  if (!grant.schemes.includes(scheme)) {
    return { ok: false, reason: "scheme-not-granted", detail: scheme, hostname, scheme };
  }

  const notes: string[] = [];
  if (url.username !== "" || url.password !== "") {
    // Not a block: credentials-in-URL is legal and occasionally legitimate. It IS the shape of the
    // `https://trusted.com@attacker.tld/` confusion, so it goes in the audit record every time.
    notes.push("url-contains-userinfo");
  }

  const exact = grant.hosts.some((h) => !h.startsWith("*.") && h.toLowerCase() === hostname);
  const wildcard = !exact && grant.hosts.some((h) => matchesWildcard(h, hostname));

  if (!exact && !wildcard) {
    return { ok: false, reason: "host-not-granted", detail: hostname, hostname, scheme };
  }

  // An exact entry is an explicit operator grant and always wins. Otherwise `127.0.0.1` written
  // into the allowlist would be silently overridden by the SSRF default — a surprise that costs
  // more trust than it buys safety, since the operator already said the quiet part out loud.
  if (exact) {
    return { ok: true, hostname, scheme, matchedBy: "exact", notes };
  }

  if (isIpLiteral(hostname) && !grant.allowIpLiterals) {
    return { ok: false, reason: "ip-literal", detail: hostname, hostname, scheme };
  }
  if (isPrivateAddress(hostname) && !grant.allowPrivateNetwork) {
    return { ok: false, reason: "private-network", detail: hostname, hostname, scheme };
  }

  return { ok: true, hostname, scheme, matchedBy: "wildcard", notes };
}

/**
 * Evaluate a BARE host argument — `api.example.com`, `db.internal:5432`, `10.0.0.4` — against the
 * same allowlist. Used for arguments bound to the `host` role, where the tool supplies the scheme
 * itself (database, SSH, SMTP, webhook clients) so there is no scheme in the value to check.
 *
 * Parsed through the WHATWG URL parser with a synthetic scheme rather than by splitting on `:`,
 * so that the same normalization applies: IDNA, case folding, `2130706433` -> `127.0.0.1`, and
 * the `good.com@evil.tld` userinfo confusion resolving to `evil.tld` rather than to `good.com`.
 */
export function evaluateHost(raw: unknown, grant: HostAllowlist): UrlDecision {
  if (typeof raw !== "string") return { ok: false, reason: "unparseable", detail: `expected string, got ${typeof raw}` };
  const trimmed = raw.trim();
  if (trimmed === "") return { ok: false, reason: "unparseable", detail: "empty host" };
  // A value that already carries a scheme is a URL; evaluate it as one so the scheme is checked.
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)) return evaluateUrl(trimmed, grant);
  // `toolwall-host` is a placeholder authority-bearing scheme; the WHATWG parser treats unknown
  // schemes as "not special", which still populates `hostname` for `scheme://host` input.
  return evaluateUrl(`toolwall-host://${trimmed}`, { ...grant, schemes: [...grant.schemes, "toolwall-host"] });
}

/**
 * Absolute-URL extraction for `enforce: "scan"`.
 *
 * Deliberately narrow: it requires `scheme://`, which means it finds the shape that can actually
 * be dialled and ignores the bare domain names, email addresses and package specifiers that make
 * up most of the "URL-like" text in a benign argument. It is still the highest-false-positive
 * thing in this module — a commit message, a code comment or a Jira description legitimately
 * contains links to hosts nobody allowlisted — which is why `scan` is opt-in at every tier and why
 * the FP harness measures it separately.
 */
const URL_IN_TEXT = /\b([a-z][a-z0-9+.-]{1,31}):\/\/([^\s"'`<>\\)\]}|^]{1,2048})/gi;

/** Schemes worth extracting. `file:`/`data:` have no host and are not an egress destination. */
const SCANNED_SCHEMES = new Set(["http", "https", "ws", "wss", "ftp", "ftps", "sftp", "ssh", "smtp", "gopher", "ldap", "ldaps"]);

export function extractUrls(text: string, limit = 64): string[] {
  const out: string[] = [];
  URL_IN_TEXT.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = URL_IN_TEXT.exec(text)) !== null) {
    if (out.length >= limit) break;
    const scheme = (m[1] ?? "").toLowerCase();
    if (!SCANNED_SCHEMES.has(scheme)) continue;
    // Trim trailing punctuation that is prose, not URL: "see https://x.dev/a." / "(https://x.dev)"
    let candidate = m[0];
    while (candidate.length > 0 && /[.,;:!?'"]$/.test(candidate)) candidate = candidate.slice(0, -1);
    try {
      const u = new URL(candidate);
      if (u.hostname !== "") out.push(candidate);
    } catch {
      /* not a URL after all */
    }
  }
  return out;
}
