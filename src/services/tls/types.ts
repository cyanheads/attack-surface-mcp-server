/**
 * @fileoverview TLS inspection domain types — handshake posture, certificate chain, validation.
 * @module services/tls/types
 */

/** One certificate in the presented chain. */
export interface CertInfo {
  /** Days until expiry; negative when already expired. */
  daysUntilExpiry: number;
  /** Extended key usages, mapped from OID to a readable label where known. */
  extendedKeyUsages: string[];
  /** SHA-256 fingerprint. */
  fingerprintSha256: string;
  /** Issuer common name (falls back to issuer organization). */
  issuerCommonName: string;
  /** Issuer organization, when present. */
  issuerOrganization?: string;
  /** Certificate serial number (hex string). */
  serialNumber: string;
  /** Subject Alternative Names (DNS:/IP: prefixes stripped). */
  subjectAltNames: string[];
  /** Subject common name. */
  subjectCommonName: string;
  /** Not-before validity bound (ISO 8601). */
  validFrom: string;
  /** Not-after validity bound (ISO 8601). */
  validTo: string;
}

/** TLS/SSL posture for a single host:port. */
export interface TlsResult {
  /** Leaf certificate, or null when no certificate was presented. */
  certificate: CertInfo | null;
  /** Depth of the presented chain (1 = leaf only). */
  chainDepth: number;
  /** ISO 8601 timestamp of the inspection. */
  checkedAt: string;
  /** Negotiated cipher suite (IANA standard name preferred), or null. */
  cipher: string | null;
  /** Connection/handshake error message, or null on success. */
  error: string | null;
  /** Observed posture findings (expiry windows, weak protocol, self-signed, etc.). */
  findings: string[];
  /** Host inspected. */
  host: string;
  /** Port inspected. */
  port: number;
  /** Negotiated protocol (e.g. "TLSv1.3"), or null when the handshake failed. */
  protocol: string | null;
  /** Whether the chain validated against the system trust store. */
  validationAuthorized: boolean;
  /** Validation error string when `validationAuthorized` is false and a reason was given. */
  validationError: string | null;
}
