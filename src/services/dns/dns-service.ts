/**
 * @fileoverview DNS resolution service — multi-resolver enumeration and reverse PTR via
 * node:dns/promises. Per-resolver reporting surfaces propagation gaps. Every host is SSRF-guarded
 * (rejects hosts resolving to private/loopback/metadata ranges) and every resolver IP is validated
 * against private ranges before use. Pure-runtime: no upstream auth, only per-query timeouts.
 * @module services/dns/dns-service
 */

import { Resolver } from 'node:dns/promises';
import { performance } from 'node:perf_hooks';
import { assertSafeDomain, assertSafeResolverIp } from '@/utils/ssrf-guard.js';
import {
  ALL_RECORD_TYPES,
  type DnsRecordType,
  type HostDnsResult,
  type ResolverResult,
  type ReverseResult,
} from './types.js';

const DEFAULT_TIMEOUT_MS = 5000;

/** Resolve one record type using one resolver; returns sorted string values. */
async function resolveOne(
  resolver: Resolver,
  host: string,
  type: DnsRecordType,
): Promise<string[]> {
  switch (type) {
    case 'A':
      return (await resolver.resolve4(host)).sort();
    case 'AAAA':
      return (await resolver.resolve6(host)).sort();
    case 'CNAME':
      return (await resolver.resolveCname(host)).sort();
    case 'NS':
      return (await resolver.resolveNs(host)).sort();
    case 'MX': {
      const records = await resolver.resolveMx(host);
      // RFC 7505 null MX is "0 ." on the wire; node:dns reports the root label as an empty
      // exchange, which would render as a bare "0 ". Restore the dot so the "accepts no mail"
      // signal is explicit rather than a dangling priority.
      return records.map((r) => `${r.priority} ${r.exchange || '.'}`).sort();
    }
    case 'TXT': {
      const records = await resolver.resolveTxt(host);
      return records.map((r) => r.join('')).sort();
    }
    case 'CAA': {
      const records = await resolver.resolveCaa(host);
      return records
        .map((r) => {
          if (r.issue !== undefined) return `${r.critical} issue "${r.issue}"`;
          if (r.issuewild !== undefined) return `${r.critical} issuewild "${r.issuewild}"`;
          if (r.iodef !== undefined) return `${r.critical} iodef "${r.iodef}"`;
          return JSON.stringify(r);
        })
        .sort();
    }
  }
}

/** Query one resolver for all requested record types. */
async function queryResolver(
  resolverIp: string,
  host: string,
  types: DnsRecordType[],
  timeoutMs: number,
): Promise<ResolverResult> {
  const resolver = new Resolver({ timeout: timeoutMs, tries: 2 });
  resolver.setServers([resolverIp]);

  const start = performance.now();
  const records: Partial<Record<DnsRecordType, string[]>> = {};
  let firstError: string | null = null;

  await Promise.allSettled(
    types.map(async (type) => {
      try {
        const vals = await resolveOne(resolver, host, type);
        if (vals.length > 0) records[type] = vals;
      } catch (err) {
        const code = (err as NodeJS.ErrnoException).code;
        // NODATA/NOTFOUND/NXDOMAIN are normal "no records of this type" — not a resolver failure.
        if (code !== 'ENODATA' && code !== 'ENOTFOUND' && code !== 'ESERVFAIL') {
          if (!firstError) firstError = (err as Error).message;
        }
      }
    }),
  );

  return {
    resolver: resolverIp,
    latencyInMs: Math.round(performance.now() - start),
    records,
    queryError: firstError,
  };
}

/** Detect record types where resolvers returned different value sets. */
function findMismatches(
  resolverResults: ResolverResult[],
  types: DnsRecordType[],
): DnsRecordType[] {
  const mismatches: DnsRecordType[] = [];
  for (const type of types) {
    const serialized = resolverResults.map((r) => JSON.stringify(r.records[type] ?? []));
    const first = serialized[0];
    if (serialized.some((s) => s !== first)) mismatches.push(type);
  }
  return mismatches;
}

export class DnsService {
  /** Resolve DNS records for multiple hosts across multiple resolvers, with optional reverse PTR. */
  async resolveHosts(
    hosts: string[],
    types: DnsRecordType[],
    resolverIps: string[],
    reverse: boolean,
    timeoutMs = DEFAULT_TIMEOUT_MS,
  ): Promise<HostDnsResult[]> {
    // SSRF guard: validate resolver IPs directly (caller-controlled, no DNS needed).
    for (const ip of resolverIps) assertSafeResolverIp(ip);

    const results = await Promise.allSettled(
      hosts.map(async (host) => {
        // SSRF guard: reject hosts resolving to private/loopback/metadata ranges.
        await assertSafeDomain(host);
        return this.resolveOneHost(host, types, resolverIps, reverse, timeoutMs);
      }),
    );

    return results.map((r, i) =>
      r.status === 'fulfilled'
        ? r.value
        : {
            host: hosts[i] ?? 'unknown',
            records: {},
            resolverResults: [],
            propagationMismatches: [],
            resolved: false,
            hostError: (r.reason as Error).message,
          },
    );
  }

  private async resolveOneHost(
    host: string,
    types: DnsRecordType[],
    resolverIps: string[],
    reverse: boolean,
    timeoutMs: number,
  ): Promise<HostDnsResult> {
    const resolverResults = await Promise.all(
      resolverIps.map((ip) => queryResolver(ip, host, types, timeoutMs)),
    );

    const primary = resolverResults[0]?.records ?? {};
    const mismatches = findMismatches(resolverResults, types);
    const resolved = Boolean(primary.A?.length || primary.AAAA?.length);

    let reverseResults: ReverseResult[] | undefined;
    if (reverse) {
      const ips = [...new Set([...(primary.A ?? []), ...(primary.AAAA ?? [])])];
      reverseResults = await this.reverseLookup(ips, timeoutMs);
    }

    const anyError = resolverResults.find((r) => r.queryError)?.queryError ?? null;

    return {
      host,
      records: primary,
      resolverResults,
      propagationMismatches: mismatches,
      ...(reverseResults ? { reverse: reverseResults } : {}),
      resolved,
      hostError: anyError,
    };
  }

  /** Reverse-resolve (PTR) a list of IPs using the system resolver. */
  async reverseLookup(ips: string[], timeoutMs = DEFAULT_TIMEOUT_MS): Promise<ReverseResult[]> {
    const resolver = new Resolver({ timeout: timeoutMs, tries: 2 });
    return await Promise.all(
      ips.map(async (ip) => {
        try {
          const hostnames = await resolver.reverse(ip);
          return { ip, hostnames: hostnames.sort(), lookupError: null };
        } catch (err) {
          const code = (err as NodeJS.ErrnoException).code;
          // No PTR record is a normal answer, not an error.
          if (code === 'ENOTFOUND' || code === 'ENODATA') {
            return { ip, hostnames: [], lookupError: null };
          }
          return { ip, hostnames: [], lookupError: (err as Error).message };
        }
      }),
    );
  }

  /**
   * Lightweight liveness probe used by enumerate/map: resolve A/AAAA for a host via the system
   * resolver. Returns the resolved IPs (empty when the host does not resolve). SSRF-guarded.
   */
  async resolveAddresses(host: string, timeoutMs = DEFAULT_TIMEOUT_MS): Promise<string[]> {
    await assertSafeDomain(host);
    const resolver = new Resolver({ timeout: timeoutMs, tries: 1 });
    const out: string[] = [];
    await Promise.allSettled([
      resolver.resolve4(host).then((a) => out.push(...a)),
      resolver.resolve6(host).then((a) => out.push(...a)),
    ]);
    return [...new Set(out)];
  }
}

// --- Init/accessor pattern ---

let _service: DnsService | undefined;

export function initDnsService(): void {
  _service = new DnsService();
}

export function getDnsService(): DnsService {
  if (!_service) throw new Error('DnsService not initialized — call initDnsService() in setup()');
  return _service;
}

export { ALL_RECORD_TYPES };
