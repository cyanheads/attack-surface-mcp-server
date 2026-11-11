/**
 * @fileoverview SSRF guard — blocks outbound requests to private, loopback, link-local, and
 * cloud-metadata addresses for user-supplied targets. This is the security spine of a server that
 * connects to arbitrary user-named hosts: check TLS, WHOIS and HTTP connection targets, and
 * validate resolver IPs before collecting DNS evidence.
 *
 * Entry points:
 *  - `assertSafeDomain(domain)` — bare host inputs (assert-only)
 *  - `resolveSafeHost(host)`    — assert + return a validated IP to *pin* the connection to,
 *                                 closing the DNS-rebinding window between check and connect
 *  - `assertSafeUrl(rawUrl, signal?)` — URL inputs (HTTP probe / RDAP redirect hops); also enforces
 *                                       the http/https scheme. Re-call on every redirect hop.
 *  - `assertSafeResolverIp(ip)` — resolver IP validation (direct IP, no DNS lookup)
 *
 * Socket-based callers (TLS handshake, WHOIS port-43) dial the validated IP from `resolveSafeHost`
 * while preserving the requested hostname for TLS identity and SNI. HTTP uses platform `fetch`,
 * whose portable API cannot pin DNS across supported runtimes. Each redirect target is rechecked,
 * but HTTP DNS validation and connection resolution remain separate operations.
 *
 * Opt-out: `ATTACKSURFACE_ALLOW_PRIVATE_TARGETS=true` permits non-public target ranges for trusted
 * internal-network assessment. URL parsing and http/https scheme checks remain enforced.
 * @module utils/ssrf-guard
 */

import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import { getServerConfig, parseResolverList } from '@/config/server-config.js';
import {
  DnsValidationError,
  dnsErrorCode,
  isDnsAbsent,
  withConfiguredResolver,
} from '@/services/dns/configured-resolver.js';

const DNS_TIMEOUT_MS = 5000;

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

/** Parse a validated IPv6 literal into its 128-bit value, independent of spelling. */
function ipv6Value(ip: string): bigint {
  let normalized = ip;
  const lastColon = ip.lastIndexOf(':');
  const tail = ip.slice(lastColon + 1);
  if (tail.includes('.')) {
    const v4 = tail.split('.').reduce((value, octet) => (value << 8n) | BigInt(octet), 0n);
    normalized = `${ip.slice(0, lastColon + 1)}${(v4 >> 16n).toString(16)}:${(v4 & 0xffffn).toString(16)}`;
  }
  const [left = '', right] = normalized.split('::');
  const leading = left ? left.split(':') : [];
  const trailing = right ? right.split(':') : [];
  const groups =
    right === undefined
      ? leading
      : [...leading, ...Array<string>(8 - leading.length - trailing.length).fill('0'), ...trailing];
  return groups.reduce((value, group) => (value << 16n) | BigInt(`0x${group}`), 0n);
}

/** Non-public IPv6 CIDRs, compared numerically (IANA special-purpose registry and RFC 3879). */
const PRIVATE_IPV6_RANGES = (
  [
    ['::', 128, 'unspecified'],
    ['::1', 128, 'loopback'],
    ['100::', 64, 'discard-only'],
    ['100:0:0:1::', 64, 'dummy IPv6 prefix'],
    ['64:ff9b:1::', 48, 'local IPv4-IPv6 translation'],
    ['2001:2::', 48, 'benchmarking'],
    ['2001:db8::', 32, 'documentation'],
    ['3fff::', 20, 'documentation'],
    ['5f00::', 16, 'segment routing SIDs'],
    ['fc00::', 7, 'unique local (RFC 4193)'],
    ['fe80::', 10, 'link-local'],
    ['fec0::', 10, 'deprecated site-local (RFC 3879)'],
    ['ff00::', 8, 'multicast'],
  ] as const
).map(([base, bits, label]) => ({
  base: ipv6Value(base),
  shift: BigInt(128 - bits),
  label,
}));

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

/** Returns the range label if the IPv6 address string falls in a private/reserved range, else null. */
function isPrivateIPv6(ip: string): string | null {
  const normalized = ip.toLowerCase().replace(/^\[/, '').replace(/\]$/, '').replace(/%.*$/, '');
  if (isIP(normalized) !== 6) return null;
  const value = ipv6Value(normalized);
  for (const { base, shift, label } of PRIVATE_IPV6_RANGES) {
    if (value >> shift === base >> shift) return label;
  }
  // Only standardized IPv4 embedding layouts receive an IPv4 classification.
  const prefix = value >> 32n;
  if (prefix === 0xffffn || prefix === 0xffff0000n || prefix === ipv6Value('64:ff9b::') >> 32n) {
    const v4 = value & 0xffff_ffffn;
    const dotted = [24n, 16n, 8n, 0n].map((shift) => String((v4 >> shift) & 255n)).join('.');
    const label = isPrivateIPv4(dotted);
    if (label) return `IPv4-embedded ${label}`;
  }
  return null;
}

/** Check a single IP string (v4 or v6). Returns the range label if blocked, null if public. */
function checkIp(ip: string): string | null {
  if (ip.includes(':')) return isPrivateIPv6(ip);
  return isPrivateIPv4(ip);
}

/** Resolve using the OS. Its lookup API cannot cancel the underlying getaddrinfo call. */
async function lookupSystem(hostname: string, signal?: AbortSignal): Promise<string[]> {
  signal?.throwIfAborted();
  let abort: (() => void) | undefined;
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const result = await Promise.race([
      lookup(hostname, { all: true }),
      new Promise<never>((_resolve, reject) => {
        abort = () => reject(signal?.reason);
        signal?.addEventListener('abort', abort, { once: true });
        if (signal?.aborted) abort();
        timer = setTimeout(
          () => reject(new DnsValidationError('System DNS lookup timed out.', 'ETIMEOUT')),
          DNS_TIMEOUT_MS,
        );
      }),
    ]);
    signal?.throwIfAborted();
    return result.map(({ address }) => address);
  } catch (error) {
    signal?.throwIfAborted();
    if (isDnsAbsent(error)) return [];
    if (error instanceof DnsValidationError) throw error;
    throw new DnsValidationError('System DNS lookup failed.', dnsErrorCode(error) ?? 'EAI_FAIL');
  } finally {
    if (abort) signal?.removeEventListener('abort', abort);
    clearTimeout(timer);
  }
}

/** Check configured DNS before touching the OS resolver, then validate the OS connection IPs. */
async function resolveAndCheck(
  hostname: string,
  context: string,
  signal?: AbortSignal,
): Promise<string[]> {
  signal?.throwIfAborted();
  const stripped = hostname.replace(/^\[/, '').replace(/\]$/, '');

  // Literal IP target — check directly without a DNS round-trip.
  if (isIP(stripped)) {
    const label = checkIp(stripped);
    if (label) {
      throw new Error(
        `SSRF_BLOCKED: ${context} is a ${label} address. Requests to private, loopback, or cloud-metadata addresses are not permitted. Set ATTACKSURFACE_ALLOW_PRIVATE_TARGETS=true to allow internal-network assessment.`,
      );
    }
    return [];
  }

  function checkAddresses(addresses: string[]) {
    if (addresses.some((ip) => !isIP(ip) || checkIp(ip))) {
      throw new Error(
        `SSRF_BLOCKED: ${context} resolved to an address that is not permitted. Set ATTACKSURFACE_ALLOW_PRIVATE_TARGETS=true to allow internal-network assessment.`,
      );
    }
  }

  const [resolverIp] = getValidatedDefaultResolvers();
  const results = await withConfiguredResolver(
    resolverIp,
    { timeout: DNS_TIMEOUT_MS, tries: 1 },
    signal,
    (resolver) => Promise.allSettled([resolver.resolve4(hostname), resolver.resolve6(hostname)]),
  );
  const publicAnswers: string[] = [];
  for (const result of results) {
    if (result.status === 'fulfilled') publicAnswers.push(...result.value);
    else if (!isDnsAbsent(result.reason)) {
      throw new DnsValidationError(
        'Configured DNS safety check failed.',
        dnsErrorCode(result.reason) ?? 'EAI_FAIL',
      );
    }
  }
  if (publicAnswers.length === 0) {
    throw new DnsValidationError(
      `${context} has no A or AAAA records from the configured resolver.`,
      'ENOTFOUND',
    );
  }
  checkAddresses(publicAnswers);

  const addresses = await lookupSystem(hostname, signal);
  if (addresses.length === 0) {
    throw new DnsValidationError(
      `${context} has no addresses from the system resolver.`,
      'ENOTFOUND',
    );
  }
  checkAddresses(addresses);
  return addresses;
}

/** True when the operator has explicitly enabled private-target access. */
function privateTargetsAllowed(): boolean {
  return process.env.ATTACKSURFACE_ALLOW_PRIVATE_TARGETS?.toLowerCase() === 'true';
}

/**
 * Assert that a raw URL is safe to fetch. Enforces http/https scheme and rejects hostnames that
 * resolve to a non-public address. Throws with an `SSRF_BLOCKED` prefix on rejection and accepts an
 * optional signal so callers can include DNS validation in their request budget.
 * The private-target opt-out skips only target-range checks; URL and scheme checks always apply.
 */
export async function assertSafeUrl(rawUrl: string, signal?: AbortSignal): Promise<void> {
  signal?.throwIfAborted();
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
  await resolveAndCheck(parsed.hostname, `Host "${parsed.hostname}"`, signal);
}

/**
 * Assert that a bare domain or IP (no protocol) is safe to connect to. Throws with an
 * `SSRF_BLOCKED` prefix if it resolves to a non-public address.
 * No-ops when `ATTACKSURFACE_ALLOW_PRIVATE_TARGETS=true`.
 */
export async function assertSafeDomain(domain: string, signal?: AbortSignal): Promise<void> {
  signal?.throwIfAborted();
  if (privateTargetsAllowed()) return;
  await resolveAndCheck(domain, `Host "${domain}"`, signal);
}

/**
 * Validate a bare host and return a public IP to connect to, pinning the connection to an address
 * that was actually checked (closes the DNS-rebinding window between check and connect). A
 * dual-stack host pins to IPv4: resolver order is runtime-dependent (Bun lists AAAA first), and a
 * client network without an IPv6 route — Docker's default bridge included — cannot dial the AAAA.
 * Returns `null` when the caller should connect by hostname instead: a literal-IP input (already the
 * target), or when private targets are explicitly
 * allowed. Throws `SSRF_BLOCKED` when the host resolves to a non-public address. The caller must
 * still send the original hostname as TLS SNI / HTTP Host so certificate validation and vhost
 * routing hold.
 */
export async function resolveSafeHost(host: string, signal?: AbortSignal): Promise<string | null> {
  signal?.throwIfAborted();
  if (privateTargetsAllowed()) return null;
  const validated = await resolveAndCheck(host, `Host "${host}"`, signal);
  return validated.find((ip) => !ip.includes(':')) ?? validated[0] ?? null;
}

/**
 * Assert that a resolver IP address is not in a private range (direct IP, no DNS involved).
 * Throws with an `SSRF_BLOCKED` prefix if the IP is private.
 * No-ops when `ATTACKSURFACE_ALLOW_PRIVATE_TARGETS=true`.
 */
export function assertSafeResolverIp(ip: string): void {
  if (!isIP(ip) || ip.includes('%')) throw new Error(`Invalid DNS resolver IP "${ip}".`);
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

/** Validate the whole configured resolver list before using any of its entries. */
export function getValidatedDefaultResolvers(): [string, ...string[]] {
  const [first, ...rest] = parseResolverList(getServerConfig().defaultResolvers);
  if (!first) throw new Error('ATTACKSURFACE_DEFAULT_RESOLVERS must contain a DNS resolver IP.');
  assertSafeResolverIp(first);
  for (const ip of rest) assertSafeResolverIp(ip);
  return [first, ...rest];
}
