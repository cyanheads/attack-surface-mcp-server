/**
 * @fileoverview SSRF guard — blocks outbound requests to private, loopback, link-local, and
 * cloud-metadata addresses for user-supplied targets. This is the security spine of a server that
 * connects to arbitrary user-named hosts: every DNS resolution, TLS handshake, and HTTP GET against
 * a user-supplied target must pass through one of the exported assertions before connecting.
 *
 * Entry points:
 *  - `assertSafeDomain(domain)` — bare host inputs (assert-only)
 *  - `resolveSafeHost(host)`    — assert + return a validated IP to *pin* the connection to,
 *                                 closing the DNS-rebinding window between check and connect
 *  - `assertSafeUrl(rawUrl)`    — URL inputs (HTTP probe / RDAP redirect hops); also enforces
 *                                 the http/https scheme. Re-call on every redirect hop.
 *  - `assertSafeResolverIp(ip)` — resolver IP validation (direct IP, no DNS lookup)
 *
 * **DNS-rebinding (TOCTOU) note.** An assert-then-connect-by-name pattern re-resolves the hostname
 * at connect time, so a hostile authoritative DNS can answer "public" to the guard and "private" to
 * the connect. Socket-based callers (TLS handshake, WHOIS port-43) defeat this by dialing the
 * validated IP from `resolveSafeHost` while still presenting the original hostname for SNI / vhost
 * routing. The HTTP probe uses the platform `fetch`, which has no portable IP-pinning hook across
 * stdio/HTTP/Worker runtimes; it re-checks via `assertSafeUrl` on every hop, leaving a narrow
 * rebinding residual. Acceptable for a passive recon tool whose worst case is one bounded GET to an
 * internal address with no credentials attached and the response surfaced as posture data.
 *
 * Opt-out: set `ATTACKSURFACE_ALLOW_PRIVATE_TARGETS=true` to disable all checks, for local/trusted
 * deployments where assessing internal-network assets is the intended use case.
 * @module utils/ssrf-guard
 */

import { lookup } from 'node:dns/promises';

/** CIDR blocks that are non-routable or typically internal. */
const PRIVATE_RANGES: Array<{ base: bigint; mask: bigint; label: string }> = (() => {
  function ipv4ToBigInt(ip: string): bigint {
    return ip.split('.').reduce((acc, octet) => (acc << 8n) | BigInt(parseInt(octet, 10)), 0n);
  }

  function cidr4(cidr: string, label: string) {
    const [ip, bits] = cidr.split('/') as [string, string];
    const base = ipv4ToBigInt(ip);
    const mask = ~((1n << BigInt(32 - parseInt(bits, 10))) - 1n) & 0xffff_ffffn;
    return { base: base & mask, mask, label };
  }

  return [
    cidr4('0.0.0.0/8', 'unspecified / this-network'),
    cidr4('127.0.0.0/8', 'loopback'),
    cidr4('10.0.0.0/8', 'private (RFC 1918)'),
    cidr4('172.16.0.0/12', 'private (RFC 1918)'),
    cidr4('192.168.0.0/16', 'private (RFC 1918)'),
    cidr4('169.254.0.0/16', 'link-local / cloud-metadata'),
    cidr4('100.64.0.0/10', 'shared address space (RFC 6598)'),
    cidr4('192.0.0.0/24', 'IETF protocol assignments'),
    cidr4('192.0.2.0/24', 'TEST-NET-1 (RFC 5737)'),
    cidr4('198.18.0.0/15', 'benchmarking (RFC 2544)'),
    cidr4('198.51.100.0/24', 'TEST-NET-2 (RFC 5737)'),
    cidr4('203.0.113.0/24', 'TEST-NET-3 (RFC 5737)'),
    cidr4('224.0.0.0/4', 'multicast (RFC 5771)'),
    cidr4('240.0.0.0/4', 'reserved (RFC 1112)'),
  ];
})();

/**
 * IPv6 prefixes that are non-public. Matched against the first hextet group so a public address
 * is not rejected for merely sharing leading hex characters (e.g. `fe00::` link-local vs a public
 * `fec0:`-led address — both start with `fe`, only the former is reserved). Each entry is the set
 * of leading hextet values that classify as the labeled range.
 */
const PRIVATE_IPV6_GROUP_PREFIXES: Array<{ test: (firstGroup: string) => boolean; label: string }> =
  [
    // Unique local fc00::/7 — first hextet fc00–fdff.
    { test: (g) => /^f[cd]/.test(g), label: 'unique local (RFC 4193)' },
    // Link-local fe80::/10 — first hextet fe80–febf.
    { test: (g) => /^fe[89ab]/.test(g), label: 'link-local' },
    // Multicast ff00::/8 — first hextet ff00–ffff.
    { test: (g) => /^ff/.test(g), label: 'multicast' },
  ];

/** Returns the range label if the IPv4 address string falls in a private/reserved range, else null. */
function isPrivateIPv4(ip: string): string | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  if (parts.some((p) => Number.isNaN(parseInt(p, 10)) || parseInt(p, 10) > 255)) return null;
  const val = parts.reduce((acc, p) => (acc << 8n) | BigInt(parseInt(p, 10)), 0n);
  for (const { base, mask, label } of PRIVATE_RANGES) {
    if ((val & mask) === base) return label;
  }
  return null;
}

/** Hex hextet pair (e.g. "7f00", "0001") → dotted IPv4 ("127.0.0.1"). */
function hextetsToDottedV4(hi: string, lo: string): string {
  const h = parseInt(hi, 16);
  const l = parseInt(lo, 16);
  return `${(h >> 8) & 0xff}.${h & 0xff}.${(l >> 8) & 0xff}.${l & 0xff}`;
}

/** Returns the range label if the IPv6 address string falls in a private/reserved range, else null. */
function isPrivateIPv6(ip: string): string | null {
  const normalized = ip.toLowerCase().replace(/^\[/, '').replace(/\]$/, '').replace(/%.*$/, '');

  // Loopback and unspecified — exact only (avoid rejecting public addresses ending in these).
  if (normalized === '::1') return 'loopback';
  if (normalized === '::') return 'unspecified';

  // IPv4-mapped/embedded with a trailing dotted v4 quad (::ffff:10.0.0.1, ::ffff:0:10.0.0.1,
  // 64:ff9b::10.0.0.1). Defer the embedded address to the v4 classifier so private v4 space
  // tunneled through v6 notation is still blocked.
  const dottedTail = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/.exec(normalized);
  if (dottedTail?.[1]) {
    const label = isPrivateIPv4(dottedTail[1]);
    if (label) return `IPv4-embedded ${label}`;
  }

  // IPv4-mapped in pure-hex form (::ffff:7f00:1 == 127.0.0.1). Reconstruct the embedded v4 and
  // classify it — this is the form that bypassed the old dotted-only check.
  const hexMapped = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(normalized);
  if (hexMapped?.[1] && hexMapped[2]) {
    const label = isPrivateIPv4(hextetsToDottedV4(hexMapped[1], hexMapped[2]));
    if (label) return `IPv4-mapped ${label}`;
  }

  // Range classification on the first hextet group.
  const firstGroup = normalized.startsWith('::') ? '0' : (normalized.split(':')[0] ?? '');
  for (const { test, label } of PRIVATE_IPV6_GROUP_PREFIXES) {
    if (test(firstGroup)) return label;
  }
  return null;
}

/** Check a single IP string (v4 or v6). Returns the range label if blocked, null if public. */
function checkIp(ip: string): string | null {
  if (ip.includes(':')) return isPrivateIPv6(ip);
  return isPrivateIPv4(ip);
}

/**
 * Resolve a hostname and throw if any resolved IP is private. A literal IP is checked directly.
 * Returns the validated public IPs (every resolved address, all confirmed public) so a caller can
 * connect to a checked IP rather than re-resolving the name — closing the TOCTOU/DNS-rebinding gap
 * between this check and the connect. Returns an empty array when the input was a literal IP (the
 * caller already holds it) or when DNS resolution failed (let the connect fail naturally).
 */
async function resolveAndCheck(hostname: string, context: string): Promise<string[]> {
  const stripped = hostname.replace(/^\[/, '').replace(/\]$/, '');

  // Literal IP target — check directly without a DNS round-trip.
  const literalLabel = checkIp(stripped);
  if (literalLabel) {
    throw new Error(
      `SSRF_BLOCKED: ${context} is a ${literalLabel} address. ` +
        `Requests to private, loopback, or cloud-metadata addresses are not permitted. ` +
        `Set ATTACKSURFACE_ALLOW_PRIVATE_TARGETS=true to allow internal-network assessment.`,
    );
  }
  // If it parsed as any IP literal (public), no DNS lookup is needed.
  if (/^\d+\.\d+\.\d+\.\d+$/.test(stripped) || stripped.includes(':')) return [];

  let addresses: import('node:dns').LookupAddress[];
  try {
    addresses = await lookup(hostname, { all: true });
  } catch {
    // DNS failure is not a security issue — let the downstream fetch/connect fail naturally.
    return [];
  }

  for (const { address } of addresses) {
    const label = checkIp(address);
    if (label) {
      throw new Error(
        `SSRF_BLOCKED: ${context} resolves to ${address} (${label}). ` +
          `Requests to private, loopback, or cloud-metadata addresses are not permitted. ` +
          `Set ATTACKSURFACE_ALLOW_PRIVATE_TARGETS=true to allow internal-network assessment.`,
      );
    }
  }
  return addresses.map((a) => a.address);
}

/** True when the operator has explicitly enabled private-target access. */
function privateTargetsAllowed(): boolean {
  return process.env.ATTACKSURFACE_ALLOW_PRIVATE_TARGETS?.toLowerCase() === 'true';
}

/**
 * Assert that a raw URL is safe to fetch. Enforces http/https scheme and rejects hostnames that
 * resolve to a non-public address. Throws with an `SSRF_BLOCKED` prefix on rejection.
 * No-ops when `ATTACKSURFACE_ALLOW_PRIVATE_TARGETS=true`.
 */
export async function assertSafeUrl(rawUrl: string): Promise<void> {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new Error(`SSRF_BLOCKED: Invalid URL "${rawUrl}".`);
  }

  const scheme = parsed.protocol.toLowerCase();
  if (scheme !== 'http:' && scheme !== 'https:') {
    throw new Error(
      `SSRF_BLOCKED: Scheme "${scheme}" is not permitted. Only http:// and https:// are allowed.`,
    );
  }

  if (privateTargetsAllowed()) return;
  await resolveAndCheck(parsed.hostname, `URL "${rawUrl}"`);
}

/**
 * Assert that a bare domain or IP (no protocol) is safe to connect to. Throws with an
 * `SSRF_BLOCKED` prefix if it resolves to a non-public address.
 * No-ops when `ATTACKSURFACE_ALLOW_PRIVATE_TARGETS=true`.
 */
export async function assertSafeDomain(domain: string): Promise<void> {
  if (privateTargetsAllowed()) return;
  await resolveAndCheck(domain, `Host "${domain}"`);
}

/**
 * Validate a bare host and return a public IP to connect to, pinning the connection to an address
 * that was actually checked (closes the DNS-rebinding window between check and connect). Returns
 * `null` when the caller should connect by hostname instead: a literal-IP input (already the target),
 * a DNS failure (let the connect surface it), or when private targets are explicitly allowed.
 * Throws `SSRF_BLOCKED` when the host resolves to a non-public address. The caller must still send
 * the original hostname as TLS SNI / HTTP Host so certificate validation and vhost routing hold.
 */
export async function resolveSafeHost(host: string): Promise<string | null> {
  if (privateTargetsAllowed()) return null;
  const validated = await resolveAndCheck(host, `Host "${host}"`);
  return validated[0] ?? null;
}

/**
 * Assert that a resolver IP address is not in a private range (direct IP, no DNS involved).
 * Throws with an `SSRF_BLOCKED` prefix if the IP is private.
 * No-ops when `ATTACKSURFACE_ALLOW_PRIVATE_TARGETS=true`.
 */
export function assertSafeResolverIp(ip: string): void {
  if (privateTargetsAllowed()) return;
  const label = checkIp(ip);
  if (label) {
    throw new Error(
      `SSRF_BLOCKED: Resolver IP "${ip}" is in a private range (${label}). ` +
        `Only public DNS resolvers are permitted. ` +
        `Set ATTACKSURFACE_ALLOW_PRIVATE_TARGETS=true to allow private resolvers.`,
    );
  }
}
