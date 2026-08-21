/**
 * @fileoverview attacksurface_inspect_tls — inspect TLS/SSL posture for one or more hosts via a real
 * read-only handshake. Reports negotiated protocol + cipher, the certificate chain, SANs, validity
 * window, days-to-expiry, issuer, and validation status. Invalid/expired/self-signed certs are
 * inspected and reported, never thrown on. Passive: one handshake per host, no data sent.
 * @module mcp-server/tools/definitions/inspect-tls.tool
 */

import { tool, z } from '@cyanheads/mcp-ts-core';
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { getTlsService } from '@/services/tls/tls-service.js';
import { isValidHost } from '@/utils/validation.js';

const CertInfoSchema = z
  .object({
    subjectCommonName: z.string().describe('Certificate subject common name.'),
    subjectAltNames: z.array(z.string()).describe('Subject Alternative Names (DNS/IP entries).'),
    issuerCommonName: z.string().describe('Issuer common name.'),
    issuerOrganization: z.string().optional().describe('Issuer organization, when present.'),
    validFrom: z.string().describe('Not-before validity bound (ISO 8601).'),
    validTo: z.string().describe('Not-after validity bound (ISO 8601).'),
    daysUntilExpiry: z.number().describe('Days until expiry; negative when already expired.'),
    serialNumber: z.string().describe('Certificate serial number (hex).'),
    fingerprintSha256: z.string().describe('SHA-256 fingerprint of the leaf certificate.'),
    extendedKeyUsages: z
      .array(z.string())
      .describe('Extended key usages, mapped from OID to a readable label where known.'),
  })
  .describe('A single certificate in the presented chain.');

const TlsResultSchema = z
  .object({
    host: z.string().describe('Host inspected.'),
    port: z.number().describe('Port inspected.'),
    protocol: z
      .string()
      .nullable()
      .describe('Negotiated TLS protocol, or null when the handshake failed.'),
    cipher: z.string().nullable().describe('Negotiated cipher suite, or null.'),
    certificate: CertInfoSchema.nullable().describe(
      'Leaf certificate, or null when none was presented.',
    ),
    chainDepth: z.number().describe('Depth of the presented certificate chain (1 = leaf only).'),
    validationAuthorized: z
      .boolean()
      .describe('Whether the chain validated against the system trust store.'),
    validationError: z
      .string()
      .nullable()
      .describe('Validation failure reason when not authorized, else null.'),
    findings: z
      .array(z.string())
      .describe('Posture findings (expiry windows, weak protocol, self-signed, etc.).'),
    checkedAt: z.string().describe('ISO 8601 timestamp of the inspection.'),
    handshakeError: z
      .string()
      .nullable()
      .describe('Connection/handshake error, or null on success.'),
  })
  .describe('TLS/SSL posture for one host:port.');

export const inspectTlsTool = tool('attacksurface_inspect_tls', {
  title: 'attacksurface_inspect_tls',
  description:
    'Inspect TLS/SSL posture for one or more hosts via a real read-only handshake: negotiated protocol and cipher, the full certificate chain, SANs, validity window, days-to-expiry, issuer, and validation status. Invalid, expired, and self-signed certificates are inspected and reported rather than failing — surfacing posture problems is the point. One handshake per host; no application data is sent. SSRF-guarded; per-host failures degrade to a per-host error.',
  annotations: { readOnlyHint: true, openWorldHint: true, idempotentHint: true },
  input: z.object({
    hosts: z
      .array(z.string().describe('Hostname or IP to inspect (e.g. "example.com").'))
      .min(1)
      .max(50)
      .describe('Hosts to inspect (1–50).'),
    port: z.number().int().min(1).max(65535).default(443).describe('TLS port to connect to.'),
    timeoutMs: z
      .number()
      .int()
      .min(1000)
      .max(30000)
      .default(8000)
      .describe('Per-host handshake timeout in milliseconds.'),
  }),
  output: z.object({
    results: z.array(TlsResultSchema).describe('Per-host TLS inspection results.'),
  }),
  enrichment: {
    notice: z.string().optional().describe('Guidance when every host failed to handshake.'),
  },
  errors: [
    {
      reason: 'invalid_host',
      code: JsonRpcErrorCode.ValidationError,
      when: 'A supplied host is not a syntactically valid hostname or IP.',
      recovery: 'Provide bare hostnames or IPs (no scheme/path), e.g. "secure.example.com".',
    },
  ],

  async handler(input, ctx) {
    for (const host of input.hosts) {
      if (!isValidHost(host)) {
        throw ctx.fail('invalid_host', `"${host}" is not a valid hostname or IP.`, {
          ...ctx.recoveryFor('invalid_host'),
        });
      }
    }

    const results = await getTlsService().inspectHosts(input.hosts, input.port, input.timeoutMs);

    if (results.every((r) => r.handshakeError !== null)) {
      ctx.enrich.notice(
        `No host completed a TLS handshake on port ${input.port}. The port may be closed or not running TLS.`,
      );
    }

    return { results };
  },

  format: (result) => {
    const lines: string[] = [];
    for (const r of result.results) {
      lines.push(`## ${r.host}:${r.port}`);
      lines.push(`**Error:** ${r.handshakeError ?? 'none'}`);
      lines.push(`**Protocol:** ${r.protocol ?? 'unknown'} | **Cipher:** ${r.cipher ?? 'unknown'}`);
      lines.push(
        `**Validation:** ${r.validationAuthorized ? 'trusted chain' : 'not trusted'} (${r.validationError ?? 'no error'}) | **Chain depth:** ${r.chainDepth}`,
      );
      const c = r.certificate;
      lines.push(`**Subject:** ${c?.subjectCommonName ?? 'none presented'}`);
      lines.push(
        `**Issuer:** ${c?.issuerCommonName ?? 'unknown'} (${c?.issuerOrganization ?? 'no org'})`,
      );
      lines.push(
        `**Valid:** ${c?.validFrom ?? 'unknown'} → ${c?.validTo ?? 'unknown'} (${c?.daysUntilExpiry ?? 'unknown'} days left)`,
      );
      lines.push(`**Serial:** ${c?.serialNumber ?? 'unknown'}`);
      lines.push(`**SHA-256:** ${c?.fingerprintSha256 ?? 'unknown'}`);
      lines.push(`**SANs:** ${c?.subjectAltNames.join(', ') || 'none'}`);
      lines.push(`**EKU:** ${c?.extendedKeyUsages.join(', ') || 'none'}`);
      lines.push(`**Findings:** ${r.findings.join(' ') || 'none'}`);
      lines.push(`_Checked at ${r.checkedAt}_`);
      lines.push('');
    }
    return [{ type: 'text', text: lines.join('\n') }];
  },
});
