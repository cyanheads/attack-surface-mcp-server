/**
 * @fileoverview Shodan domain types — host intelligence and faceted search.
 * @module services/shodan/types
 */

/** One service/banner observed by Shodan on a host. */
export interface ShodanService {
  /** Banner excerpt (truncated), when reported. */
  banner?: string;
  /** ISO 8601 timestamp of Shodan's last observation of this service. */
  observedAt?: string;
  /** Open port. */
  port: number;
  /** Detected product/software, when reported. */
  product?: string;
  /** Transport (tcp/udp), when reported. */
  transport?: string;
  /** Software version, when reported. */
  version?: string;
}

/** Single-host Shodan lookup result. */
export interface ShodanHostResult {
  /** Autonomous system number, when reported. */
  asn?: string;
  /** Two-letter country code, when reported. */
  country?: string;
  /** Hostnames Shodan associates with the IP. */
  hostnames: string[];
  /** IP queried. */
  ip: string;
  /** ISO 8601 timestamp of Shodan's most recent scan of this host. */
  lastUpdate?: string;
  /** ISP/organization, when reported. */
  org?: string;
  /** Open ports observed. */
  ports: number[];
  /** Per-service banners. */
  services: ShodanService[];
}

/** One match in a faceted search. */
export interface ShodanSearchMatch {
  /** Country code, when reported. */
  country?: string;
  /** IP of the match. */
  ip: string;
  /** Org/ISP, when reported. */
  org?: string;
  /** Port of the match. */
  port: number;
  /** Detected product, when reported. */
  product?: string;
}

/** Faceted-search result. */
export interface ShodanSearchResult {
  /** Facet aggregations: facet name → [{value, count}]. */
  facets: Record<string, Array<{ value: string; count: number }>>;
  /** Returned matches (page 1). */
  matches: ShodanSearchMatch[];
  /** Total matches reported by Shodan. */
  total: number;
}
