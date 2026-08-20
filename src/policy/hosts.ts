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
  /**
   * Permit the destinations in {@link deniedDestination} — cloud instance-metadata endpoints and
   * link-local address space. **Optional, and absent means DENY**, so every allowlist that existed
   * before this field gained the protection without being edited. See {@link DeniedDestination}
   * for what is on the list and what is deliberately kept off it.
   */
  readonly allowMetadataEndpoints?: boolean;
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
      readonly reason: "unparseable" | "scheme-not-granted" | "host-not-granted" | "ip-literal" | "private-network" | "denied-destination";
      readonly detail: string;
      readonly hostname?: string;
      readonly scheme?: string;
    };

/**
 * The one token that matches any host: `"*"`.
 *
 * It exists for **inferred** policy (`src/policy/infer.ts`), which can read a tool's `format: "uri"`
 * declaration off the pinned schema but cannot possibly know which hosts your deployment considers
 * legitimate. Guessing an allowlist would be either useless or an outage, so an inferred network
 * grant says so explicitly: any host, but only the granted **schemes**, which is what stops
 * `file:///etc/passwd` and `gopher://…` being handed to a fetch tool.
 *
 * It is matched as a WILDCARD, never as an exact entry, so the IP-literal and private-network
 * checks still apply on top of it — `"*"` disables host matching, not the rest of the allowlist.
 *
 * An operator may write it, and `parsePolicy` warns when they do. It is not a wildcard *pattern*:
 * `"*"` is compared literally, so it cannot be smuggled in as `"*.something"` behaviour.
 */
export const ANY_HOST = "*";

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

/**
 * WHATWG "special" schemes. The distinction is load-bearing rather than trivia: the URL parser
 * only runs the IPv4 parser and IDNA ToASCII for these. For any other scheme it applies **opaque
 * host parsing**, which percent-encodes and otherwise leaves the host alone — so
 * `gopher://2130706433/` keeps the hostname `2130706433` and `ssh://0x7f000001/` keeps
 * `0x7f000001`. Both are loopback, and both would sail past an address check written against the
 * normalized form. `evaluateHost` used exactly such a scheme (`toolwall-host://`) for every bare
 * `host`-role argument, so the whole host-role leg was reading un-normalized hosts.
 * {@link canonicalHostname} closes that by re-parsing through a special scheme.
 */
const SPECIAL_SCHEMES: ReadonlySet<string> = new Set(["http", "https", "ws", "wss", "ftp", "file"]);

/**
 * The single normalization every host comparison in this module runs on first.
 *
 * Four things, all of them bypasses if skipped:
 *  1. **Case.** Hosts are case-insensitive; opaque host parsing does not fold case.
 *  2. **Trailing dots.** `metadata.google.internal.` is the same host as `metadata.google.internal`
 *     to every resolver on earth, and is a different string to `===`. Stripping it matters far more
 *     for the DENY list than for the allow list — an unstripped trailing dot merely fails an allow
 *     match (fail-closed), but it would walk straight through a deny match (fail-OPEN).
 *  3. **Alternate IPv4 encodings** (`2130706433`, `0x7f.1`, `0177.0.0.1`) and
 *  4. **IDN/percent-encoded labels** (`еxample.com` with a Cyrillic `е` -> `xn--xample-2of.com`,
 *     `%31%32%37.0.0.1` -> `127.0.0.1`).
 *
 * 3 and 4 are free for special schemes because the platform parser already did them; for every
 * other scheme they are obtained by re-parsing the host through `http://`. That re-parse is the
 * only way to get the platform's own IPv4/IDNA implementation rather than hand-rolling a second,
 * subtly-different one — and a hand-rolled host parser is how these bugs are born in the first
 * place. If the re-parse fails the host is returned as-is: it then matches no allowlist entry,
 * which is the fail-closed direction.
 */
export function canonicalHostname(hostname: string, scheme?: string): string {
  const raw = hostname.trim();
  if (raw === "") return "";
  // IPv6 literals are parsed identically for special and non-special schemes, and the parser
  // already emits the canonical compressed lowercase form.
  if (raw.startsWith("[")) return raw.toLowerCase();

  const stripped = raw.replace(/\.+$/u, "");
  if (stripped === "") return "";
  if (scheme !== undefined && SPECIAL_SCHEMES.has(scheme)) return stripped.toLowerCase();

  try {
    const reparsed = new URL(`http://${stripped}/`).hostname;
    if (reparsed === "") return stripped.toLowerCase();
    if (reparsed.startsWith("[")) return reparsed.toLowerCase();
    return reparsed.replace(/\.+$/u, "").toLowerCase();
  } catch {
    return stripped.toLowerCase();
  }
}

export function isIpLiteral(hostname: string): boolean {
  if (IPV4.test(hostname)) return true;
  // WHATWG URL reports IPv6 hosts bracketed.
  return hostname.startsWith("[") && hostname.endsWith("]");
}

/**
 * Eight hextets, or `undefined` if this is not an IPv6 literal.
 *
 * Written out rather than pattern-matched on the string because **string prefixes are exactly how
 * the old implementation got this wrong**: it tested `inner.split(":").pop()` for a dotted quad,
 * and the WHATWG parser had already rewritten `[::ffff:127.0.0.1]` to `[::ffff:7f00:1]`, whose
 * last group is `1`. The address family checks below are arithmetic on the hextets, so no
 * textual form of an address can present differently from any other.
 */
export function parseIpv6(literal: string): number[] | undefined {
  let s = literal.trim().toLowerCase();
  if (s.startsWith("[") && s.endsWith("]")) s = s.slice(1, -1);
  if (s === "") return undefined;
  // A zone id (`fe80::1%eth0`) is not part of the address.
  const pct = s.indexOf("%");
  if (pct !== -1) s = s.slice(0, pct);

  // A trailing dotted quad contributes the last two hextets.
  let tail: number[] = [];
  const lastColon = s.lastIndexOf(":");
  const afterLastColon = lastColon === -1 ? "" : s.slice(lastColon + 1);
  if (afterLastColon.includes(".")) {
    const m = IPV4.exec(afterLastColon);
    if (m === null) return undefined;
    const o = [m[1], m[2], m[3], m[4]].map((x) => Number(x));
    if (o.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return undefined;
    tail = [((o[0] as number) << 8) | (o[1] as number), ((o[2] as number) << 8) | (o[3] as number)];
    s = s.slice(0, lastColon + 1) + "0";
  }

  const parts = s.split("::");
  if (parts.length > 2) return undefined;
  const toHextets = (chunk: string): number[] | undefined => {
    if (chunk === "") return [];
    const out: number[] = [];
    for (const g of chunk.split(":")) {
      if (g === "" || g.length > 4 || !/^[0-9a-f]+$/u.test(g)) return undefined;
      out.push(Number.parseInt(g, 16));
    }
    return out;
  };
  const head = toHextets(parts[0] as string);
  if (head === undefined) return undefined;
  if (parts.length === 1) {
    // No compression: the dotted-quad placeholder `0` we appended stands in for two hextets.
    const full = tail.length > 0 ? [...head.slice(0, -1), ...tail] : head;
    return full.length === 8 ? full : undefined;
  }
  const rear = toHextets(parts[1] as string);
  if (rear === undefined) return undefined;
  const rearFull = tail.length > 0 ? [...rear.slice(0, -1), ...tail] : rear;
  const fill = 8 - head.length - rearFull.length;
  if (fill < 0) return undefined;
  return [...head, ...new Array<number>(fill).fill(0), ...rearFull];
}

/**
 * The IPv4 address an IPv6 literal carries, in every form that actually routes to one.
 *
 * `::ffff:a.b.c.d` (IPv4-mapped), `::ffff:0:a.b.c.d` (IPv4-translated / SIIT), `::a.b.c.d`
 * (deprecated IPv4-compatible), `64:ff9b::a.b.c.d` (NAT64 well-known prefix) and `2002:a.b.c.d::`
 * (6to4) all end at the same IPv4 host. Enumerating them is finite and deterministic; ignoring
 * them means `[::ffff:a9fe:a9fe]` is a live route to `169.254.169.254`.
 */
export function embeddedIpv4(hextets: readonly number[]): string | undefined {
  const dot = (hi: number, lo: number): string => `${hi >> 8}.${hi & 0xff}.${lo >> 8}.${lo & 0xff}`;
  const zero = (from: number, to: number): boolean => hextets.slice(from, to).every((x) => x === 0);
  if (hextets.length !== 8) return undefined;
  // ::ffff:a.b.c.d
  if (zero(0, 5) && hextets[5] === 0xffff) return dot(hextets[6] as number, hextets[7] as number);
  // ::ffff:0:a.b.c.d
  if (zero(0, 4) && hextets[4] === 0xffff && hextets[5] === 0) return dot(hextets[6] as number, hextets[7] as number);
  // 64:ff9b::a.b.c.d and 64:ff9b:1::/48-style NAT64
  if (hextets[0] === 0x64 && hextets[1] === 0xff9b && zero(2, 6)) return dot(hextets[6] as number, hextets[7] as number);
  // 2002:a.b.c.d::/16 — 6to4
  if (hextets[0] === 0x2002) return dot(hextets[1] as number, hextets[2] as number);
  // ::a.b.c.d — deprecated IPv4-compatible. `::` and `::1` are handled as their own cases first.
  if (zero(0, 6) && !(hextets[6] === 0 && (hextets[7] as number) <= 1)) return dot(hextets[6] as number, hextets[7] as number);
  return undefined;
}

/** Private / loopback / link-local / unspecified / CGNAT, for a dotted-quad IPv4 literal. */
function isPrivateIpv4(h: string): boolean {
  const v4 = IPV4.exec(h);
  if (v4 === null) return false;
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

/**
 * Private / loopback / link-local / unspecified / CGNAT literals.
 *
 * Pass the output of {@link canonicalHostname} — for a URL with a non-special scheme the raw
 * `url.hostname` is not normalized and this will read `0x7f000001` as an ordinary domain name.
 */
export function isPrivateAddress(hostname: string): boolean {
  const h = hostname.toLowerCase();
  if (h === "localhost" || h.endsWith(".localhost")) return true;
  if (IPV4.test(h)) return isPrivateIpv4(h);

  if (h.startsWith("[") && h.endsWith("]")) {
    const hex = parseIpv6(h);
    if (hex === undefined) return true; // an IPv6 literal we cannot parse is not one we can clear
    if (hex.every((x) => x === 0)) return true; // ::
    if (hex.slice(0, 7).every((x) => x === 0) && hex[7] === 1) return true; // ::1
    if (((hex[0] as number) & 0xffc0) === 0xfe80) return true; // fe80::/10 link-local
    if (((hex[0] as number) & 0xfe00) === 0xfc00) return true; // fc00::/7 unique-local
    const v4 = embeddedIpv4(hex);
    if (v4 !== undefined) return isPrivateIpv4(v4);
    return false;
  }

  return false;
}

/* ---------------------------------------------------------------- */
/* The default deny list                                              */
/* ---------------------------------------------------------------- */

/**
 * **Destinations no legitimate MCP tool argument targets, denied by default.**
 *
 * Everything else in this module is an *allowlist*: nothing is reachable until an operator says
 * so, which is the right structure but produces nothing at zero configuration, because the
 * inferred network grant (`src/policy/infer.ts`) has to permit `ANY_HOST` — no evidence on the
 * wire says which hosts your deployment trusts. That left `http://169.254.169.254/latest/
 * meta-data/iam/security-credentials/` allowed at day zero: an injected model reads the instance's
 * IAM credentials through an ordinary `fetch` tool, and every 2025-26 incident ended at exactly
 * such a credential.
 *
 * A deny list is the complement of an allowlist and inherits the opposite failure mode — it is
 * only as good as its enumeration — so it is used **only where the enumeration is closed**:
 *
 *  - **Cloud instance-metadata endpoints.** A fixed, published, small set of magic addresses and
 *    names — including the single-label short forms that a cloud instance's DNS search domain
 *    resolves to the same service, because denying only the FQDN denies a spelling rather than a
 *    destination. The MCP specification mandates blocking this exact class for OAuth metadata
 *    discovery (RESEARCH-BRIEF §7), so a proxy that forwards it to a tool argument is weaker than
 *    the spec.
 *  - **Link-local space** (`169.254.0.0/16`, `fe80::/10`). Autoconfiguration address space. There
 *    is no legitimate reason for a tool argument to name it, and every cloud's IMDS lives in it.
 *
 * **What is deliberately NOT here, and why the list would be worthless if it were:** loopback and
 * RFC1918. `http://127.0.0.1:3000` and `http://localhost:8080` are a large share of what a
 * developer's MCP traffic actually is, and the benign corpus carries them for that reason. Denying
 * them by default would be a false positive on one of the commonest benign destinations there is,
 * and a control that everyone disables protects nobody. Those stay governed by `allowPrivateNetwork`,
 * which an operator can set in a policy file. Measured cost of this list on the 63-case benign
 * corpus: **0 blocked, 0 friction** — and four of those 63 are single-label internal service
 * names added specifically so the short-form entries could fail against them.
 *
 * Escape hatch: `allowMetadataEndpoints: true`, plus an exact host entry, which — consistently
 * with the rest of this module — is an explicit operator grant and always wins.
 */
export interface DeniedDestination {
  /** Stable identifier, used as the `toolwall/egress.denied-destination` finding's evidence. */
  readonly rule: "cloud-metadata-host" | "cloud-metadata-address" | "link-local";
  readonly label: string;
}

/** Metadata service *names*. Matched exactly and as a parent zone (`*.zone`). */
const METADATA_HOSTS: ReadonlyMap<string, string> = new Map([
  ["metadata.google.internal", "Google Cloud instance metadata service"],
  ["metadata.goog", "Google Cloud instance metadata service"],
  ["instance-data.ec2.internal", "AWS EC2 instance metadata service (legacy alias)"],
  ["metadata.platformequinix.com", "Equinix Metal instance metadata service"],
  ["metadata.packet.net", "Equinix Metal instance metadata service (legacy name)"],
]);

/**
 * **Single-label short forms of the names above.**
 *
 * A cloud instance's DNS search domain appends the metadata zone, so inside a GCE VM
 * `http://metadata/computeMetadata/v1/instance/service-accounts/default/token` reaches the same
 * endpoint as the FQDN and returns the instance's service-account bearer token. Google's own
 * documentation uses the short form. EC2 has the same relationship between `instance-data` and
 * `instance-data.ec2.internal`. Denying the FQDN while allowing its short form denies a spelling,
 * not a destination — which is what round 3 found.
 *
 * **Matched EXACTLY, and never as a parent zone.** `METADATA_HOSTS` is checked with
 * `endsWith("." + zone)` because `anything.metadata.goog` really is the metadata service; applying
 * that to a single label would deny `foo.metadata` and `build.instance-data`, which are ordinary
 * internal names with no relationship to any IMDS. Separate map, separate matching rule.
 *
 * **Only these two, and only because they are documented.** A single-label deny is the highest
 * false-positive shape in this module — `metadata` is a plausible internal service name — so it is
 * confined to short forms with published cloud-vendor provenance. Azure, Alibaba and Oracle have
 * no DNS name for their metadata services at all (`169.254.169.254`, `100.100.100.200` and
 * `192.0.0.192` are addressed by IP and are covered above), so there is nothing to add for them
 * and nothing was invented. Speculative additions like `imds` or `metadata-service` would widen
 * the false-positive surface with no attack behind them.
 *
 * Measured cost of these two entries on the benign corpus: see `test/unit/fp-harness.test.ts`,
 * which carries four cases written specifically to collide with this rule if it were sloppy —
 * including a bare `host`-role argument of `db` and a URL to `http://metadata-service:8080`.
 */
const METADATA_SHORT_HOSTS: ReadonlyMap<string, string> = new Map([
  ["metadata", "Google Cloud instance metadata service (search-domain short form of metadata.google.internal)"],
  ["instance-data", "AWS EC2 instance metadata service (search-domain short form of instance-data.ec2.internal)"],
]);

/** Metadata service *addresses* that sit outside link-local space and so need naming. */
const METADATA_ADDRESSES: ReadonlyMap<string, string> = new Map([
  ["100.100.100.200", "Alibaba Cloud instance metadata service"],
  ["192.0.0.192", "Oracle Cloud Classic instance metadata service"],
]);

/** AWS's IPv6 instance-metadata address, `fd00:ec2::254` — inside fc00::/7, so not link-local. */
const AWS_IPV6_IMDS = [0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254];

/**
 * The one entry point. `hostname` must already be {@link canonicalHostname}-normalized; passing a
 * raw `url.hostname` from a non-special scheme is how `metadata.google.internal.` or
 * `0x64646464c8` would slip past.
 */
export function deniedDestination(hostname: string): DeniedDestination | undefined {
  const h = hostname;
  if (h === "") return undefined;

  const named = METADATA_HOSTS.get(h);
  if (named !== undefined) return { rule: "cloud-metadata-host", label: named };
  // Exact only — see METADATA_SHORT_HOSTS on why this must not become a suffix test.
  const short = METADATA_SHORT_HOSTS.get(h);
  if (short !== undefined) return { rule: "cloud-metadata-host", label: short };
  for (const [zone, label] of METADATA_HOSTS) {
    if (h.endsWith(`.${zone}`)) return { rule: "cloud-metadata-host", label };
  }

  let v4: string | undefined = IPV4.test(h) ? h : undefined;
  if (h.startsWith("[") && h.endsWith("]")) {
    const hex = parseIpv6(h);
    if (hex !== undefined) {
      if ((((hex[0] as number) & 0xffc0) === 0xfe80)) return { rule: "link-local", label: "IPv6 link-local address space (fe80::/10)" };
      if (hex.every((x, i) => x === AWS_IPV6_IMDS[i])) return { rule: "cloud-metadata-address", label: "AWS EC2 IPv6 instance metadata service" };
      v4 = embeddedIpv4(hex);
    }
  }

  if (v4 !== undefined) {
    const m = IPV4.exec(v4);
    if (m !== null && Number(m[1]) === 169 && Number(m[2]) === 254) {
      return {
        rule: "link-local",
        label:
          v4 === "169.254.169.254"
            ? "cloud instance metadata service (AWS/Azure/GCP/DigitalOcean/OpenStack IMDS)"
            : "IPv4 link-local address space (169.254.0.0/16), where every cloud's metadata service lives",
      };
    }
    const addr = METADATA_ADDRESSES.get(v4);
    if (addr !== undefined) return { rule: "cloud-metadata-address", label: addr };
  }

  return undefined;
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
  // Normalized before ANY comparison — allow, deny, IP-literal and private-network alike. For a
  // non-special scheme (`ssh:`, `gopher:`, `ldap:`, and the synthetic scheme `evaluateHost` uses)
  // `url.hostname` is the un-normalized opaque host, so this is what makes `gopher://0x7f000001/`
  // and `metadata.google.internal.` comparable at all.
  const hostname = canonicalHostname(url.hostname, scheme);

  if (!grant.schemes.includes(scheme)) {
    return { ok: false, reason: "scheme-not-granted", detail: scheme, hostname, scheme };
  }

  const notes: string[] = [];
  if (url.username !== "" || url.password !== "") {
    // Not a block: credentials-in-URL is legal and occasionally legitimate. It IS the shape of the
    // `https://trusted.com@attacker.tld/` confusion, so it goes in the audit record every time.
    notes.push("url-contains-userinfo");
  }

  const exact = grant.hosts.some((h) => h !== ANY_HOST && !h.startsWith("*.") && h.toLowerCase() === hostname);
  // `ANY_HOST` counts as a wildcard match, never an exact one, so the IP-literal and
  // private-network checks below still run against it.
  const wildcard = !exact && grant.hosts.some((h) => h === ANY_HOST || matchesWildcard(h, hostname));

  if (!exact && !wildcard) {
    return { ok: false, reason: "host-not-granted", detail: hostname, hostname, scheme };
  }

  // An exact entry is an explicit operator grant and always wins. Otherwise `127.0.0.1` written
  // into the allowlist would be silently overridden by the SSRF default — a surprise that costs
  // more trust than it buys safety, since the operator already said the quiet part out loud.
  //
  // That applies to the deny list too, and deliberately: the deny list defends against an
  // ATTACKER-chosen argument, not against an operator-chosen policy, and an operator who types
  // `169.254.169.254` into their own allowlist has done something no injected model can do for
  // them. It is noted rather than silently honoured, so it appears in the audit record.
  if (exact) {
    const denied = deniedDestination(hostname);
    return {
      ok: true,
      hostname,
      scheme,
      matchedBy: "exact",
      notes: denied === undefined ? notes : [...notes, "exact-grant-admits-denied-destination"],
    };
  }

  // The deny list runs BEFORE — and independently of — `allowIpLiterals` / `allowPrivateNetwork`,
  // because those two both default to `true` in an inferred grant (real developer traffic is full
  // of `http://127.0.0.1:3000`) and gating the deny behind either would make it dead code in the
  // exact configuration it exists for.
  if (grant.allowMetadataEndpoints !== true) {
    const denied = deniedDestination(hostname);
    if (denied !== undefined) {
      return { ok: false, reason: "denied-destination", detail: `${hostname} (${denied.label})`, hostname, scheme };
    }
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
 * so that the `good.com@evil.tld` userinfo confusion resolves to `evil.tld` rather than to
 * `good.com`. The synthetic scheme is deliberately NOT a "special" one, which means the parser
 * applies opaque host parsing and does **not** fold case, run IDNA, or normalize `2130706433` to
 * `127.0.0.1`. {@link canonicalHostname}, called inside `evaluateUrl`, is what supplies those —
 * this comment previously claimed the parser did, and it did not.
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
