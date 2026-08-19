import { describe, expect, it } from "vitest";
import { evaluateUrl, isPrivateAddress } from "../../src/policy/hosts.js";
import type { NetworkGrant } from "../../src/policy/schema.js";

const grant: NetworkGrant = {
  hosts: ["api.example.com", "*.example.com", "127.0.0.1"],
  schemes: ["https", "http"],
  allowPrivateNetwork: false,
  allowIpLiterals: false,
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
