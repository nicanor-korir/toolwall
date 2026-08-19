import type { NetworkGrant } from "./schema.js";

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

export function evaluateUrl(raw: unknown, grant: NetworkGrant): UrlDecision {
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
