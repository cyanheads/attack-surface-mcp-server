/**
 * @fileoverview Registration/ownership domain types — RDAP (JSON) and WHOIS (text) results.
 * @module services/registration/types
 */

/** Which source answered the registration lookup. */
export type RegistrationSource = 'rdap' | 'whois';

/** A registration event (registration, expiration, last-changed, etc.). */
export interface RegistrationEvent {
  /** Event action (e.g. "registration", "expiration", "last changed"). */
  action: string;
  /** ISO 8601 timestamp. */
  date: string;
}

/** Domain registration record. All fields optional — RDAP/WHOIS data is frequently redacted/sparse. */
export interface DomainRegistration {
  /** Whether DNSSEC is signed, when the registry reports it. */
  dnssecSigned?: boolean;
  /** Registration lifecycle events. */
  events: RegistrationEvent[];
  kind: 'domain';
  /** Nameserver hostnames. */
  nameservers: string[];
  /** Registrar name, when disclosed. */
  registrar?: string;
  /** RDAP/registry status codes (e.g. "client transfer prohibited"). */
  statuses: string[];
  /** The domain queried. */
  target: string;
}

/** IP / netblock registration record. All fields optional — RDAP fields are sparse. */
export interface IpRegistration {
  /** Allocation CIDR(s) for the netblock. */
  cidrs: string[];
  /** Two-letter country code, when present (often null at the registry level). */
  country?: string;
  /** Network lifecycle events. */
  events: RegistrationEvent[];
  kind: 'ip';
  /** Network/handle name, when present. */
  networkName?: string;
  /** Origin AS number(s), when present. */
  originAsns: number[];
  /** RDAP/registry status codes. */
  statuses: string[];
  /** The IP or CIDR queried. */
  target: string;
}

/** A complete registration lookup result. */
export interface RegistrationResult {
  /** Notes (e.g. "RDAP timed out, fell back to WHOIS"). */
  notes: string[];
  /** Raw WHOIS text when the WHOIS fallback answered (null for RDAP). */
  rawWhois: string | null;
  /** The parsed registration record (domain or IP). */
  registration: DomainRegistration | IpRegistration;
  /** Source that answered. */
  source: RegistrationSource;
}
