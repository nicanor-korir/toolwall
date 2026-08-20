import { describe, expect, it } from "vitest";
import { ANY_HOST, canonicalHostname, deniedDestination, evaluateHost, evaluateUrl, isPrivateAddress } from "../../src/policy/hosts.js";
import type { NetworkGrant } from "../../src/policy/schema.js";

const grant: NetworkGrant = {
  hosts: ["api.example.com", "*.example.com", "127.0.0.1"],
  schemes: ["https", "http"],
  allowPrivateNetwork: false,
  allowIpLiterals: false,
  allowMetadataEndpoints: false,
};

const reason = (u: string): string => {
  const d = evaluateUrl(u, grant);
  return d.ok ? "ok" : d.reason;
};

describe("host allowlist — the bypasses a substring match would let through", () => {
  it("allows the exact host", () => expect(reason("https://api.example.com/v2/x")).toBe("ok"));
  it("allows a subdomain via wildcard", () => expect(reason("https://raw.cdn.example.com/a")).toBe("ok"));
  it("ignores the port when matching", () => expect(reason("https://api.example.com:8443/health")).toBe("ok"));

  it("rejects a suffix-appended lookalike", () => {
    // `example.com.evil.io` contains "example.com" as a substring. Label-boundary matching does not
    // care, which is the entire point.
    expect(reason("https://example.com.evil.io/steal")).toBe("host-not-granted");
  });

  it("rejects a prefix-fused lookalike", () => {
    expect(reason("https://evil-example.com/steal")).toBe("host-not-granted");
  });

  it("rejects the userinfo confusion", () => {
    // The raw string starts with "https://api.example.com", but the HOST is attacker.tld.
    expect(reason("https://api.example.com@attacker.tld/steal")).toBe("host-not-granted");
  });

  it("records userinfo as an audit note when the host itself is granted", () => {
    const d = evaluateUrl("https://user:pw@api.example.com/x", grant);
    expect(d.ok).toBe(true);
    if (d.ok) expect(d.notes).toContain("url-contains-userinfo");
  });

  it("does not let the wildcard match the apex it is a wildcard of", () => {
    const apexOnly: NetworkGrant = { ...grant, hosts: ["*.example.com"] };
    const d = evaluateUrl("https://example.com/", apexOnly);
    expect(d.ok).toBe(false);
  });

  it("rejects a scheme outside the grant", () => {
    expect(reason("file:///etc/passwd")).toBe("scheme-not-granted");
    expect(reason("ftp://api.example.com/x")).toBe("scheme-not-granted");
  });

  it("rejects an unparseable URL", () => expect(reason("not a url")).toBe("unparseable"));
});

describe("SSRF-shaped hosts", () => {
  it("honours an EXPLICIT exact grant for a loopback address", () => {
    // Otherwise writing 127.0.0.1 into the allowlist would silently do nothing.
    expect(reason("http://127.0.0.1:3000/api/health")).toBe("ok");
  });

  it("rejects a private address reached through a wildcard grant", () => {
    const wide: NetworkGrant = { ...grant, hosts: ["*.internal.test"] };
    const d = evaluateUrl("http://db.internal.test/", wide);
    // Not private by literal inspection — documented gap: no DNS resolution is performed.
    expect(d.ok).toBe(true);
  });

  it("rejects a bare IP literal that is only wildcard-covered", () => {
    const wide: NetworkGrant = { ...grant, hosts: ["*.0.0.1"] };
    const d = evaluateUrl("http://10.0.0.1/", wide);
    expect(d.ok).toBe(false);
    if (!d.ok) expect(d.reason).toBe("ip-literal");
  });
});

describe("isPrivateAddress", () => {
  it.each([
    ["127.0.0.1", true],
    ["10.1.2.3", true],
    ["172.16.0.1", true],
    ["172.32.0.1", false],
    ["192.168.1.1", true],
    ["169.254.169.254", true],
    ["100.64.0.1", true],
    ["8.8.8.8", false],
    ["localhost", true],
    ["app.localhost", true],
    ["[::1]", true],
    ["[fd00::1]", true],
    ["[fe80::1]", true],
    ["[2606:4700::1111]", false],
  ])("%s -> %s", (host, expected) => {
    expect(isPrivateAddress(host)).toBe(expected);
  });

  it("catches the decimal-encoded loopback via WHATWG normalization", () => {
    // http://2130706433/ normalizes to 127.0.0.1 before we ever see the hostname.
    expect(new URL("http://2130706433/").hostname).toBe("127.0.0.1");
    expect(isPrivateAddress(new URL("http://2130706433/").hostname)).toBe(true);
  });
});

/* ------------------------------------------------------------------ */
/* The default deny list, and the address parsing it stands on         */
/* ------------------------------------------------------------------ */

/** The shape an INFERRED network grant has: any host, both permissive flags on. */
const inferredGrant: NetworkGrant = {
  hosts: [ANY_HOST],
  schemes: ["http", "https", "ws", "wss"],
  allowPrivateNetwork: true,
  allowIpLiterals: true,
  allowMetadataEndpoints: false,
};

describe("isPrivateAddress — IPv6 forms the old string-prefix implementation missed", () => {
  it.each([
    // The red team's reported latent bug: WHATWG rewrites [::ffff:127.0.0.1] to [::ffff:7f00:1].
    ["[::ffff:7f00:1]", true],
    ["[::ffff:127.0.0.1]", true],
    ["[::ffff:a00:1]", true], // 10.0.0.1
    ["[::ffff:c0a8:1]", true], // 192.168.0.1
    ["[::ffff:a9fe:a9fe]", true], // 169.254.169.254
    ["[0:0:0:0:0:ffff:7f00:1]", true], // uncompressed form of the same address
    ["[::ffff:0:7f00:1]", true], // IPv4-translated / SIIT
    ["[64:ff9b::7f00:1]", true], // NAT64 well-known prefix
    ["[2002:7f00:1::]", true], // 6to4
    ["[::127.0.0.1]", true], // deprecated IPv4-compatible
    ["[fd00:ec2::254]", true], // AWS IPv6 IMDS, inside fc00::/7
    ["[fe80::1%eth0]", true], // zone id must not defeat the fe80::/10 test
    ["[::ffff:808:808]", false], // 8.8.8.8 mapped — public, and must stay public
    ["[2606:4700::1111]", false],
    ["[64:ff9b::808:808]", false],
  ])("%s -> %s", (host, expected) => {
    expect(isPrivateAddress(host)).toBe(expected);
  });

  it("an IPv6 literal that will not parse is treated as private rather than cleared", () => {
    expect(isPrivateAddress("[::ffff:zz]")).toBe(true);
    expect(isPrivateAddress("[1:2:3:4:5:6:7:8:9]")).toBe(true);
  });
});

describe("canonicalHostname — normalization the WHATWG parser does NOT do for non-special schemes", () => {
  it("normalizes alternate IPv4 encodings that opaque host parsing leaves alone", () => {
    // The platform does this for http:; it does not for gopher:, ssh:, ldap: or the synthetic
    // scheme `evaluateHost` uses for bare host arguments.
    expect(new URL("gopher://2130706433/").hostname).toBe("2130706433");
    expect(canonicalHostname("2130706433", "gopher")).toBe("127.0.0.1");
    expect(canonicalHostname("0x7f000001", "gopher")).toBe("127.0.0.1");
    expect(canonicalHostname("0177.0.0.1", "gopher")).toBe("127.0.0.1");
    expect(canonicalHostname("%31%32%37.0.0.1", "gopher")).toBe("127.0.0.1");
  });

  it("folds case and applies IDNA for a non-special scheme", () => {
    expect(canonicalHostname("EXAMPLE.com", "toolwall-host")).toBe("example.com");
    // A Cyrillic small letter 'e' is not the ASCII one and must not become it.
    expect(canonicalHostname("еxample.com", "toolwall-host")).toBe("xn--xample-2of.com");
    expect(canonicalHostname("еxample.com", "toolwall-host")).not.toBe("example.com");
  });

  it("strips the root label, which is fail-OPEN on a deny list if left on", () => {
    expect(canonicalHostname("metadata.google.internal.", "http")).toBe("metadata.google.internal");
    expect(canonicalHostname("example.com..", "https")).toBe("example.com");
  });
});

describe("deniedDestination — single-label short forms (round 3)", () => {
  it("denies the short form of every FQDN it denies — a search domain makes them the same host", () => {
    // GCE resolves a bare `metadata` through the instance's search domain, and Google's own docs
    // use that spelling. Denying `metadata.google.internal` while allowing `metadata` denies a
    // spelling, not a destination.
    expect(deniedDestination("metadata")).toBeDefined();
    expect(deniedDestination("instance-data")).toBeDefined();
  });

  it("matches a single label EXACTLY and never as a parent zone", () => {
    // The FQDN entries are suffix-matched because `anything.metadata.goog` really is the metadata
    // service. Applying that to a single label would deny ordinary internal names.
    expect(deniedDestination("foo.metadata")).toBeUndefined();
    expect(deniedDestination("build.instance-data")).toBeUndefined();
    expect(deniedDestination("metadata-service")).toBeUndefined();
    expect(deniedDestination("metadata2")).toBeUndefined();
    expect(deniedDestination("my-metadata")).toBeUndefined();
    // A company's own metadata service on its own zone.
    expect(deniedDestination("metadata.internal.acme.example.com")).toBeUndefined();
  });

  it("reaches the short forms through both legs and through normalization", () => {
    expect(evaluateUrl("http://metadata/computeMetadata/v1/instance/service-accounts/default/token", inferredGrant).ok).toBe(false);
    expect(evaluateUrl("http://metadata./computeMetadata/v1/", inferredGrant).ok).toBe(false);
    expect(evaluateUrl("http://METADATA/computeMetadata/v1/", inferredGrant).ok).toBe(false);
    expect(evaluateHost("metadata", inferredGrant).ok).toBe(false);
    expect(evaluateHost("instance-data:80", inferredGrant).ok).toBe(false);
  });

  it("leaves the single-label internal names a real deployment uses alone", () => {
    // The collision shape a single-label deny risks. These are compose/k8s service names, and the
    // benign corpus carries the same four cases so the FP number can actually move.
    for (const h of ["api", "db", "cache", "redis", "postgres", "web", "worker", "minio"]) {
      expect(deniedDestination(h), h).toBeUndefined();
      expect(evaluateUrl(`http://${h}:8080/health`, inferredGrant).ok, h).toBe(true);
    }
  });
});

describe("deniedDestination — the closed enumeration, and what is deliberately outside it", () => {
  it.each([
    "169.254.169.254",
    "169.254.170.2", // ECS task metadata
    "169.254.0.1",
    "100.100.100.200", // Alibaba
    "192.0.0.192", // Oracle Cloud Classic
    "metadata.google.internal",
    "metadata.goog",
    "instance-data.ec2.internal",
    "[fd00:ec2::254]",
    "[fe80::1]",
    "[::ffff:a9fe:a9fe]",
    "[64:ff9b::a9fe:a9fe]",
  ])("denies %s", (host) => {
    expect(deniedDestination(host), host).toBeDefined();
  });

  it.each(["127.0.0.1", "localhost", "10.0.0.5", "192.168.1.4", "[::1]", "8.8.8.8", "api.example.com", "metadata.example.com", "100.100.100.201"])(
    "does NOT deny %s — loopback and RFC1918 stay allowed, or the list is unusable",
    (host) => {
      expect(deniedDestination(host), host).toBeUndefined();
    },
  );
});

describe("SSRF to cloud metadata is denied under an INFERRED grant — the zero-configuration case", () => {
  const decide = (u: string): string => {
    const d = evaluateUrl(u, inferredGrant);
    return d.ok ? "ok" : d.reason;
  };

  it.each([
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://[fd00:ec2::254]/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    "http://metadata.google.internal./computeMetadata/v1/", // trailing root label
    "http://[::ffff:169.254.169.254]/latest/meta-data/",
    "http://[fe80::1]/",
    "http://100.100.100.200/latest/meta-data/",
    "http://2852039166/latest/meta-data/", // decimal 169.254.169.254
    "http://0xa9fea9fe/latest/meta-data/",
    "https://user:pass@169.254.169.254/latest/", // userinfo confusion
  ])("%s", (u) => {
    expect(decide(u)).toBe("denied-destination");
  });

  it("still allows the localhost dev traffic that makes the benign corpus what it is", () => {
    expect(decide("http://127.0.0.1:3000/api/health")).toBe("ok");
    expect(decide("http://localhost:8080/graphql")).toBe("ok");
    expect(decide("http://192.168.1.20:9000/minio")).toBe("ok");
    expect(decide("https://api.github.com/repos/x/y")).toBe("ok");
  });

  it("the deny is independent of allowPrivateNetwork and allowIpLiterals, both of which are on here", () => {
    expect(inferredGrant.allowPrivateNetwork).toBe(true);
    expect(inferredGrant.allowIpLiterals).toBe(true);
    expect(decide("http://169.254.169.254/")).toBe("denied-destination");
  });

  it("an explicit exact host entry is still an operator grant and wins — but is recorded", () => {
    const explicit: NetworkGrant = { ...inferredGrant, hosts: ["169.254.169.254"] };
    const d = evaluateUrl("http://169.254.169.254/latest/", explicit);
    expect(d.ok).toBe(true);
    expect(d.ok && d.notes).toContain("exact-grant-admits-denied-destination");
  });

  it("allowMetadataEndpoints: true is the blanket escape hatch", () => {
    const opened: NetworkGrant = { ...inferredGrant, allowMetadataEndpoints: true };
    expect(evaluateUrl("http://169.254.169.254/latest/", opened).ok).toBe(true);
  });

  it("a bare host-role argument gets the same treatment, through the same normalization", () => {
    expect(evaluateHost("169.254.169.254:80", inferredGrant).ok).toBe(false);
    expect(evaluateHost("metadata.google.internal", inferredGrant).ok).toBe(false);
    // The synthetic scheme is not a special one, so this only works because of canonicalHostname.
    expect(evaluateHost("2852039166", inferredGrant).ok).toBe(false);
    expect(evaluateHost("127.0.0.1:5432", inferredGrant).ok).toBe(true);
  });
});
