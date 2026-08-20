/**
 * ROUND 3 · Priority 3 — the cloud-metadata deny-list in `src/policy/hosts.ts`.
 *
 * FINDING (proven gap). The deny-list is keyed on FULLY-QUALIFIED metadata names and on the
 * link-local address space, but not on the **single-label short forms** that resolve to the very
 * same endpoints inside a cloud instance, because the instance's DNS search domain appends the
 * zone. On GCE, `http://metadata/computeMetadata/v1/instance/service-accounts/default/token` is a
 * documented, working way to read the instance's OAuth token — it is the short form of
 * `metadata.google.internal`, which IS denied. The same holds for EC2's legacy `instance-data`
 * alias, whose FQDN `instance-data.ec2.internal` IS denied.
 *
 * Exact payload:   http://metadata/computeMetadata/v1/instance/service-accounts/default/token
 * Observed:        { ok: true, matchedBy: "wildcard" }  — allowed
 * Expected:        { ok: false, reason: "denied-destination" } — same as its own FQDN
 *
 * Reachability is precisely the configuration the deny-list exists to backstop. `hosts.ts` states
 * it runs "BEFORE — and independently of — allowIpLiterals / allowPrivateNetwork, because those two
 * both default to true in an inferred grant ... gating the deny behind either would make it dead
 * code in the exact configuration it exists for." An inferred grant permits `ANY_HOST`, so the
 * allowlist does not stop this and the deny-list is the only control in the path — and it misses.
 *
 * Severity: medium-high on a cloud-hosted agent (instance credential theft, the classic IMDS SSRF),
 * nil on a laptop. Owning module: src/policy/hosts.ts (`METADATA_HOSTS`).
 *
 * The first test asserts the SECURE behaviour and therefore FAILS today — that is the finding.
 * The rest lock in the very large amount this deny-list already gets right.
 */
import { describe, expect, it } from 'vitest';

import { ANY_HOST, canonicalHostname, deniedDestination, evaluateHost, evaluateUrl, type HostAllowlist } from '../../src/policy/hosts.js';

/** What an inferred network grant looks like: no host evidence, so everything is permitted. */
const INFERRED_GRANT: HostAllowlist = {
    hosts: [ANY_HOST],
    schemes: ['http', 'https', 'toolwall-host'],
    allowPrivateNetwork: true,
    allowIpLiterals: true
} as HostAllowlist;

describe('Round 3 · single-label metadata short forms are not denied', () => {
    it('BYPASS — `http://metadata/…` reaches GCE instance credentials while its own FQDN is denied', () => {
        const short = evaluateUrl('http://metadata/computeMetadata/v1/instance/service-accounts/default/token', INFERRED_GRANT);
        const fqdn = evaluateUrl('http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token', INFERRED_GRANT);

        // The FQDN is correctly refused — proving the control is engaged on this exact path.
        expect(fqdn.ok).toBe(false);
        expect(fqdn.ok === false && fqdn.reason).toBe('denied-destination');

        // SECURE behaviour: the short form of the same host reaches the same service and must be
        // refused identically. Fails today.
        expect(short.ok).toBe(false);
    });

    it('BYPASS — the EC2 legacy `instance-data` short form is likewise allowed', () => {
        expect(evaluateUrl('http://instance-data.ec2.internal/latest/meta-data/', INFERRED_GRANT).ok).toBe(false);
        // SECURE behaviour: fails today.
        expect(evaluateUrl('http://instance-data/latest/meta-data/', INFERRED_GRANT).ok).toBe(false);
    });

    it('BYPASS — the host-role leg has the same gap, so a bare `host` argument carries it too', () => {
        // SECURE behaviour: fails today.
        expect(evaluateHost('metadata', INFERRED_GRANT).ok).toBe(false);
    });
});

describe('Round 3 · what the deny-list already gets right (defense held — do not regress)', () => {
    const denied = (host: string): boolean => deniedDestination(canonicalHostname(host, 'toolwall-host')) !== undefined;

    it('catches every alternate IPv4 encoding of 169.254.169.254', () => {
        // Dotted, decimal, octal, hex, and a trailing dot. All normalize to the same address.
        for (const form of ['169.254.169.254', '2852039166', '0251.0376.0251.0376', '0xa9fea9fe', '169.254.169.254.']) {
            expect(denied(form), form).toBe(true);
        }
    });

    it('catches IPv6 embeddings of the IMDS address, including NAT64 and 6to4', () => {
        for (const form of [
            '[::ffff:169.254.169.254]', // IPv4-mapped, decimal tail
            '[::ffff:a9fe:a9fe]', // IPv4-mapped, compressed hextets
            '[::a9fe:a9fe]', // IPv4-compatible (deprecated but still parsed)
            '[64:ff9b::169.254.169.254]', // NAT64 well-known prefix — a real-world SSRF bypass
            '[64:ff9b::a9fe:a9fe]',
            '[2002:a9fe:a9fe::]' // 6to4
        ]) {
            expect(denied(form), form).toBe(true);
        }
    });

    it('catches the non-link-local metadata addresses and AWS IPv6 IMDS', () => {
        expect(denied('100.100.100.200')).toBe(true); // Alibaba
        expect(denied('0144.0144.0144.0310')).toBe(true); // ...in octal
        expect(denied('192.0.0.192')).toBe(true); // Oracle Classic
        expect(denied('[fd00:ec2::254]')).toBe(true); // AWS IPv6 IMDS
        expect(denied('[fe80::1]')).toBe(true); // IPv6 link-local
    });

    it('catches metadata FQDNs with trailing dots and as parent zones', () => {
        expect(denied('metadata.google.internal.')).toBe(true);
        expect(denied('anything.metadata.goog')).toBe(true);
        expect(denied('instance-data.ec2.internal')).toBe(true);
    });
});
