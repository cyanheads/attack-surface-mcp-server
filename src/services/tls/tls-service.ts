/**
 * @fileoverview TLS inspection service — pure node:tls read-only handshake. Connects with
 * `rejectUnauthorized: false` so invalid/expired/self-signed certificates are *inspected and
 * reported* rather than throwing (posture findings are the point). Extracts negotiated protocol +
 * cipher, the full certificate chain, SANs, validity window, days-to-expiry, issuer, validation
 * status, and extended key usages (OID → readable). Every host is SSRF-validated before connecting,
 * and the socket is pinned to the validated IP (SNI keeps the hostname) so a DNS-rebinding answer
 * cannot redirect the handshake to an internal address between check and connect.
 * @module services/tls/tls-service
 */

import * as tls from 'node:tls';
import { resolveSafeHost } from '@/utils/ssrf-guard.js';
import type { CertInfo, TlsResult } from './types.js';

const DEFAULT_TIMEOUT_MS = 8000;
const DEFAULT_PORT = 443;

/** Common Extended Key Usage OIDs → readable labels (per RFC 5280 §4.2.1.12 + common extensions). */
const EKU_OID_LABELS: Record<string, string> = {
  '1.3.6.1.5.5.7.3.1': 'serverAuth',
  '1.3.6.1.5.5.7.3.2': 'clientAuth',
  '1.3.6.1.5.5.7.3.3': 'codeSigning',
  '1.3.6.1.5.5.7.3.4': 'emailProtection',
  '1.3.6.1.5.5.7.3.8': 'timeStamping',
  '1.3.6.1.5.5.7.3.9': 'OCSPSigning',
};

/** Map an EKU OID string to a readable label, preserving the OID for transparency. */
function labelEku(oid: string): string {
  const label = EKU_OID_LABELS[oid];
  return label ? `${label} (${oid})` : oid;
}

/** tls cert fields can be string | string[]; coerce to a single string. */
function firstString(value: string | string[] | undefined, fallback: string): string {
  if (Array.isArray(value)) return value[0] ?? fallback;
  return value ?? fallback;
}

/** Parse SAN string ("DNS:a.com, DNS:b.com, IP Address:1.2.3.4") into a clean array. */
function parseSans(raw: string | string[] | undefined): string[] {
  if (!raw) return [];
  const str = Array.isArray(raw) ? raw.join(', ') : raw;
  const out: string[] = [];
  for (const part of str.split(',')) {
    const stripped = part.replace(/^\s*(DNS:|IP Address:|URI:|email:)/i, '').trim();
    if (stripped) out.push(stripped);
  }
  return out;
}

/** Build CertInfo from a node:tls detailed certificate, collecting posture findings. */
function buildCertInfo(
  cert: tls.DetailedPeerCertificate,
  host: string,
  findings: string[],
): { info: CertInfo; chainDepth: number } {
  const now = Date.now();
  const validFrom = new Date(cert.valid_from);
  const validTo = new Date(cert.valid_to);
  const daysUntilExpiry = Math.floor((validTo.getTime() - now) / 86_400_000);

  const subjectCommonName = firstString(cert.subject?.CN, host);
  const issuerCommonName = firstString(cert.issuer?.CN ?? cert.issuer?.O, 'unknown');
  const issuerOrganization = cert.issuer?.O ? firstString(cert.issuer.O, '') : undefined;
  const subjectAltNames = parseSans(cert.subjectaltname);

  // Walk the issuer chain to measure depth.
  let chainDepth = 1;
  let current: tls.DetailedPeerCertificate | undefined = cert;
  const seen = new Set<string>();
  while (current?.issuerCertificate && current.issuerCertificate !== current) {
    const fp = current.issuerCertificate.fingerprint256;
    if (fp && seen.has(fp)) break;
    if (fp) seen.add(fp);
    chainDepth++;
    current = current.issuerCertificate;
    if (chainDepth > 20) break;
  }

  // Extended key usages — node:tls exposes ext_key_usage as an OID string array.
  const ekuRaw = (cert as { ext_key_usage?: string[] }).ext_key_usage ?? [];
  const extendedKeyUsages = ekuRaw.map(labelEku);

  // Posture findings.
  if (daysUntilExpiry < 0) {
    findings.push(`Certificate expired ${Math.abs(daysUntilExpiry)} day(s) ago.`);
  } else if (daysUntilExpiry < 14) {
    findings.push(`Certificate expires in ${daysUntilExpiry} day(s) — critical.`);
  } else if (daysUntilExpiry < 30) {
    findings.push(`Certificate expires in ${daysUntilExpiry} day(s) — renew soon.`);
  }
  const selfSigned =
    issuerCommonName === subjectCommonName && (chainDepth === 1 || cert.issuerCertificate === cert);
  if (selfSigned) findings.push('Certificate appears self-signed.');

  const info: CertInfo = {
    subjectCommonName,
    subjectAltNames,
    issuerCommonName,
    ...(issuerOrganization ? { issuerOrganization } : {}),
    validFrom: Number.isNaN(validFrom.getTime()) ? cert.valid_from : validFrom.toISOString(),
    validTo: Number.isNaN(validTo.getTime()) ? cert.valid_to : validTo.toISOString(),
    daysUntilExpiry,
    serialNumber: cert.serialNumber ?? '',
    fingerprintSha256: cert.fingerprint256 ?? '',
    extendedKeyUsages,
  };
  return { info, chainDepth };
}

/**
 * Perform one read-only TLS handshake and extract posture. Never rejects on cert validity.
 * `connectIp` is the SSRF-validated address to dial (pins the connection to a checked IP, closing
 * the rebinding window); when null the socket connects by `host`. `host` is always used as SNI and
 * for `checkServerIdentity`/reporting, so certificate validation reflects the hostname, not the IP.
 */
function inspectOne(
  host: string,
  connectIp: string | null,
  port: number,
  timeoutMs: number,
): Promise<TlsResult> {
  const checkedAt = new Date().toISOString();

  return new Promise((resolve) => {
    let settled = false;
    const settle = (result: TlsResult) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      resolve(result);
    };

    const timer = setTimeout(() => {
      settle({
        host,
        port,
        protocol: null,
        cipher: null,
        certificate: null,
        chainDepth: 0,
        validationAuthorized: false,
        validationError: null,
        findings: ['Connection timed out.'],
        checkedAt,
        error: `TLS handshake timed out after ${timeoutMs}ms.`,
      });
    }, timeoutMs);

    const socket = tls.connect(
      {
        host: connectIp ?? host,
        port,
        servername: host,
        rejectUnauthorized: false,
        checkServerIdentity: () => undefined,
        ALPNProtocols: ['h2', 'http/1.1'],
      },
      () => {
        const findings: string[] = [];
        const protocol = socket.getProtocol();
        const cipherInfo = socket.getCipher();
        const cipher = cipherInfo?.standardName ?? cipherInfo?.name ?? null;

        if (protocol === 'TLSv1' || protocol === 'TLSv1.1' || protocol === 'SSLv3') {
          findings.push(`Weak/deprecated protocol negotiated: ${protocol}.`);
        }

        const rawCert = socket.getPeerCertificate(true);
        let certificate: CertInfo | null = null;
        let chainDepth = 0;
        if (rawCert && Object.keys(rawCert).length > 0 && rawCert.subject) {
          const built = buildCertInfo(rawCert, host, findings);
          certificate = built.info;
          chainDepth = built.chainDepth;
        }

        const authorized = socket.authorized;
        const authError = socket.authorizationError;
        if (!authorized && authError) {
          findings.push(`Chain did not validate: ${String(authError)}.`);
        }

        settle({
          host,
          port,
          protocol: protocol ?? null,
          cipher,
          certificate,
          chainDepth,
          validationAuthorized: authorized,
          validationError: authError ? String(authError) : null,
          findings,
          checkedAt,
          error: null,
        });
      },
    );

    socket.on('error', (err) => {
      settle({
        host,
        port,
        protocol: null,
        cipher: null,
        certificate: null,
        chainDepth: 0,
        validationAuthorized: false,
        validationError: null,
        findings: [`Connection error: ${err.message}`],
        checkedAt,
        error: err.message,
      });
    });
  });
}

export class TlsService {
  /** Inspect TLS posture for multiple hosts. SSRF-guarded; per-host failures degrade, never throw. */
  async inspectHosts(
    hosts: string[],
    port = DEFAULT_PORT,
    timeoutMs = DEFAULT_TIMEOUT_MS,
  ): Promise<TlsResult[]> {
    const results = await Promise.allSettled(
      hosts.map(async (host) => {
        const connectIp = await resolveSafeHost(host);
        return inspectOne(host, connectIp, port, timeoutMs);
      }),
    );
    return results.map((r, i) =>
      r.status === 'fulfilled'
        ? r.value
        : {
            host: hosts[i] ?? 'unknown',
            port,
            protocol: null,
            cipher: null,
            certificate: null,
            chainDepth: 0,
            validationAuthorized: false,
            validationError: null,
            findings: [(r.reason as Error).message],
            checkedAt: new Date().toISOString(),
            error: (r.reason as Error).message,
          },
    );
  }

  /** Inspect a single host and return its SAN list (used as a CT fallback source). Empty on failure. */
  async getSans(
    host: string,
    port = DEFAULT_PORT,
    timeoutMs = DEFAULT_TIMEOUT_MS,
  ): Promise<string[]> {
    let connectIp: string | null;
    try {
      connectIp = await resolveSafeHost(host);
    } catch {
      return [];
    }
    const result = await inspectOne(host, connectIp, port, timeoutMs);
    return result.certificate?.subjectAltNames ?? [];
  }
}

// --- Init/accessor pattern ---

let _service: TlsService | undefined;

export function initTlsService(): void {
  _service = new TlsService();
}

export function getTlsService(): TlsService {
  if (!_service) throw new Error('TlsService not initialized — call initTlsService() in setup()');
  return _service;
}
