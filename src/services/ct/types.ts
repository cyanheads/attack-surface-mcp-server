/**
 * @fileoverview Certificate Transparency domain types — subdomain discovery from issued certs.
 * @module services/ct/types
 */

/** Which CT source supplied a subdomain name. */
export type CtSource = 'crt.sh' | 'certspotter' | 'tls-san';

/** Per-source outcome, surfaced so the agent can assess completeness. */
export interface CtSourceStatus {
  /** Count of names this source contributed (after scoping/dedup at the source level). */
  count: number;
  /** Whether the source answered successfully. */
  ok: boolean;
  /** Source name. */
  source: CtSource;
  /** Error message when the source failed, else null. */
  sourceError: string | null;
}

/** A discovered subdomain with the source(s) that surfaced it. */
export interface DiscoveredName {
  /** Fully-qualified subdomain name (wildcard prefix stripped). */
  name: string;
  /** Sources that observed this name. */
  sources: CtSource[];
}

/** Aggregate CT enumeration result. */
export interface CtEnumerationResult {
  /** The apex domain queried. */
  domain: string;
  /** Discovered subdomain names with provenance. */
  names: DiscoveredName[];
  /** Per-source status (which answered, which failed, counts). */
  sourceStatuses: CtSourceStatus[];
}
