/**
 * @fileoverview DNS domain types — record types, per-resolver results, reverse lookups.
 * @module services/dns/types
 */

/** DNS record types this server enumerates. */
export type DnsRecordType = 'A' | 'AAAA' | 'CNAME' | 'MX' | 'NS' | 'TXT' | 'CAA';

/** The full set of record types, used when the caller does not narrow. */
export const ALL_RECORD_TYPES: DnsRecordType[] = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'CAA'];

/** One resolver's answer for one host across the requested record types. */
export interface ResolverResult {
  /** Resolver-level error message, or null when the query succeeded (NODATA/NXDOMAIN are not errors). */
  error: string | null;
  /** Round-trip latency in milliseconds. */
  latencyInMs: number;
  /** Record values keyed by type; absent types omitted. */
  records: Partial<Record<DnsRecordType, string[]>>;
  /** Resolver IP queried. */
  resolver: string;
}

/** A reverse-DNS (PTR) lookup result for one IP. */
export interface ReverseResult {
  /** Error message, or null on success. */
  error: string | null;
  /** PTR hostnames, or empty when none. */
  hostnames: string[];
  /** The IP that was reverse-resolved. */
  ip: string;
}

/** Aggregate DNS result for a single host across all queried resolvers. */
export interface HostDnsResult {
  /** First host-level error (e.g. SSRF rejection), or null. */
  error: string | null;
  /** The host queried. */
  host: string;
  /** Record types where resolvers disagreed. */
  propagationMismatches: DnsRecordType[];
  /** Merged records from the first resolver that answered (canonical view). */
  records: Partial<Record<DnsRecordType, string[]>>;
  /** Whether the host resolved to at least one A/AAAA address. */
  resolved: boolean;
  /** Per-resolver breakdown, surfacing propagation gaps. */
  resolverResults: ResolverResult[];
  /** Reverse-DNS results for resolved A/AAAA addresses (present when `reverse` requested). */
  reverse?: ReverseResult[];
}
