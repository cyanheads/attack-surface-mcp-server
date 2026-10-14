/**
 * @fileoverview Certificate Transparency domain types — subdomain discovery from issued certs.
 * @module services/ct/types
 */

/** Which CT source supplied a subdomain name. */
export type CtSource = 'crt.sh' | 'certspotter' | 'tls-san';

/** Per-source outcome, surfaced so the agent can assess completeness. */
export interface CtSourceStatus {
  /** True only when the provider's result was exhausted. */
  complete?: boolean;
  /** Count of names this source contributed (after scoping/dedup at the source level). */
  count: number;
  /** Why coverage ended before exhaustion. */
  incompleteReason?: string | null;
  /** Whether the source answered successfully. */
  ok: boolean;
  /** Successfully read pages, including an empty terminal page. */
  pagesFetched?: number;
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
