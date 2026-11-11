/**
 * @fileoverview DNS resolution service — multi-resolver enumeration and reverse PTR via
 * node:dns/promises. Per-resolver reporting surfaces propagation gaps. Every resolver IP is
 * validated before use. Answer addresses are DNS evidence and are never dialed by this service.
 * @module services/dns/dns-service
 */

import type { Resolver } from 'node:dns/promises';
import { performance } from 'node:perf_hooks';
import { assertSafeResolverIp, getValidatedDefaultResolvers } from '@/utils/ssrf-guard.js';
import { isDnsAbsent, withConfiguredResolver } from './configured-resolver.js';
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
  checkOmittedAddresses: boolean,
  signal?: AbortSignal,
): Promise<{ result: ResolverResult; addresses: string[] }> {
  const start = performance.now();
  const records: Partial<Record<DnsRecordType, string[]>> = {};
  let firstError: string | null = null;
  const queryTypes: DnsRecordType[] = checkOmittedAddresses ? [...types, 'A', 'AAAA'] : types;
  await withConfiguredResolver(resolverIp, { timeout: timeoutMs, tries: 2 }, signal, (resolver) =>
    Promise.all(
      queryTypes.map(async (type) => {
        try {
          const vals = await resolveOne(resolver, host, type);
          if (vals.length > 0) records[type] = vals;
        } catch (error) {
          if (!firstError && !isDnsAbsent(error)) firstError = (error as Error).message;
        }
      }),
    ),
  );
  const addresses = [...new Set([...(records.A ?? []), ...(records.AAAA ?? [])])];
  if (checkOmittedAddresses) {
    delete records.A;
    delete records.AAAA;
  }

  return {
    result: {
      resolver: resolverIp,
      latencyInMs: Math.round(performance.now() - start),
      records,
      queryError: firstError,
    },
    addresses,
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
    signal?: AbortSignal,
  ): Promise<HostDnsResult[]> {
    signal?.throwIfAborted();
    const [primaryIp, ...secondaryIps] = resolverIps;
    if (!primaryIp) throw new Error('Provide at least one DNS resolver IP.');
    // SSRF guard: validate resolver IPs directly (caller-controlled, no DNS needed).
    for (const ip of resolverIps) assertSafeResolverIp(ip);

    const results = await Promise.allSettled(
      hosts.map((host) =>
        this.resolveOneHost(host, types, primaryIp, secondaryIps, reverse, timeoutMs, signal),
      ),
    );
    signal?.throwIfAborted();

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
    primaryIp: string,
    secondaryIps: string[],
    reverse: boolean,
    timeoutMs: number,
    signal?: AbortSignal,
  ): Promise<HostDnsResult> {
    const [primary, ...secondary] = await Promise.all([
      queryResolver(
        primaryIp,
        host,
        types,
        timeoutMs,
        !types.includes('A') && !types.includes('AAAA'),
        signal,
      ),
      ...secondaryIps.map((ip) => queryResolver(ip, host, types, timeoutMs, false, signal)),
    ]);
    const resolverResults = [primary.result, ...secondary.map(({ result }) => result)];
    const mismatches = findMismatches(resolverResults, types);
    const reverseResults = reverse
      ? await this.reverseLookup(primary.addresses, timeoutMs, signal, primaryIp)
      : undefined;

    const anyError = resolverResults.find((r) => r.queryError)?.queryError ?? null;

    return {
      host,
      records: primary.result.records,
      resolverResults,
      propagationMismatches: mismatches,
      ...(reverseResults ? { reverse: reverseResults } : {}),
      resolved: primary.addresses.length > 0,
      hostError: anyError,
    };
  }

  /** Reverse-resolve addresses with the primary resolver from the forward query. */
  async reverseLookup(
    ips: string[],
    timeoutMs = DEFAULT_TIMEOUT_MS,
    signal?: AbortSignal,
    resolverIp = getValidatedDefaultResolvers()[0],
  ): Promise<ReverseResult[]> {
    signal?.throwIfAborted();
    if (ips.length === 0) return [];
    assertSafeResolverIp(resolverIp);
    return await withConfiguredResolver(
      resolverIp,
      { timeout: timeoutMs, tries: 2 },
      signal,
      (resolver) =>
        Promise.all(
          ips.map(async (ip) => {
            try {
              const hostnames = await resolver.reverse(ip);
              return { ip, hostnames: hostnames.sort(), lookupError: null };
            } catch (error) {
              const lookupError = isDnsAbsent(error) ? null : (error as Error).message;
              return { ip, hostnames: [], lookupError };
            }
          }),
        ),
    );
  }

  /**
   * Lightweight liveness probe using the first configured resolver.
   * Returns the resolved IPs, or an empty list when there are no address answers.
   */
  async resolveAddresses(host: string, timeoutMs = DEFAULT_TIMEOUT_MS): Promise<string[]> {
    return (await this.resolveAddressStatus(host, timeoutMs)).addresses;
  }

  /** Address-family successes and operational failures retained independently. */
  async resolveAddressStatus(
    host: string,
    timeoutMs = DEFAULT_TIMEOUT_MS,
    signal?: AbortSignal,
  ): Promise<{ addresses: string[]; addressError: string | null }> {
    signal?.throwIfAborted();
    const [resolverIp] = getValidatedDefaultResolvers();
    const out: string[] = [];
    const results = await withConfiguredResolver(
      resolverIp,
      { timeout: timeoutMs, tries: 1 },
      signal,
      (resolver) =>
        Promise.allSettled([
          resolver.resolve4(host).then((a) => out.push(...a)),
          resolver.resolve6(host).then((a) => out.push(...a)),
        ]),
    );
    const errors = results.flatMap((r, i) => {
      if (r.status === 'fulfilled' || isDnsAbsent(r.reason)) return [];
      return [`${i === 0 ? 'A' : 'AAAA'}: ${(r.reason as Error).message}`];
    });
    return { addresses: [...new Set(out)], addressError: errors.length ? errors.join('; ') : null };
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
