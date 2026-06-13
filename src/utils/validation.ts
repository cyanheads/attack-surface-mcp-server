/**
 * @fileoverview Edge input validation for host/domain shapes. Malformed *input* throws (the one
 * thing tools reject); reachability/posture failures degrade per-target downstream. These are
 * structural sanity checks, not allow-listing — the SSRF guard enforces the network boundary.
 * @module utils/validation
 */

import { isIP } from 'node:net';

/** Hostname per RFC 1123 (labels, optional trailing dot, total ≤253). Permits underscores (DNS-used). */
const HOSTNAME_RE =
  /^(?=.{1,253}\.?$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z]{2,63}\.?$/i;

/** True when the string is a syntactically valid registrable domain or subdomain. */
export function isValidDomain(value: string): boolean {
  return HOSTNAME_RE.test(value.trim());
}

/** True when the string is a valid hostname or an IP literal. */
export function isValidHost(value: string): boolean {
  const v = value.trim();
  return v.length > 0 && (isIP(v) !== 0 || HOSTNAME_RE.test(v));
}

/** True when the string is an IP, CIDR, or domain — the accepted shape for a registration target. */
export function isValidRegistrationTarget(value: string): boolean {
  const v = value.trim();
  const [addr, bits] = v.split('/');
  if (bits !== undefined) {
    const prefix = Number.parseInt(bits, 10);
    const ipKind = isIP(addr ?? '');
    if (ipKind === 4) return prefix >= 0 && prefix <= 32;
    if (ipKind === 6) return prefix >= 0 && prefix <= 128;
    return false;
  }
  return isValidHost(v);
}

/** Normalize a domain: lower-case, strip scheme/path if a URL was passed, strip trailing dot. */
export function normalizeDomain(value: string): string {
  let v = value.trim().toLowerCase();
  if (v.includes('://')) {
    try {
      v = new URL(v).hostname;
    } catch {
      // leave as-is; validation will reject it
    }
  }
  return v.replace(/\/.*$/, '').replace(/\.$/, '');
}
