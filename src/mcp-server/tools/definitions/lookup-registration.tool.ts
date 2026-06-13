/**
 * @fileoverview attacksurface_lookup_registration — registration and ownership lookup via RDAP
 * (structured JSON; WHOIS fallback for TLDs/registries without RDAP or when RDAP hangs). Accepts a
 * domain (registrar, status, lifecycle events, nameservers, DNSSEC) or an IP/CIDR (netblock,
 * allocation CIDRs, origin ASN, country). RDAP/WHOIS fields are frequently redacted or sparse —
 * absent fields are reported as unknown, never inferred. Passive: reads public registry records.
 * @module mcp-server/tools/definitions/lookup-registration.tool
 */

import { tool, z } from '@cyanheads/mcp-ts-core';
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { getRegistrationService } from '@/services/registration/registration-service.js';
import { isValidRegistrationTarget, normalizeDomain } from '@/utils/validation.js';

const EventSchema = z
  .object({
    action: z
      .string()
      .describe('Event action (e.g. "registration", "expiration", "last changed").'),
    date: z.string().describe('Event timestamp (ISO 8601 when from RDAP; raw when from WHOIS).'),
  })
  .describe('A registration lifecycle event.');

const DomainRegistrationSchema = z
  .object({
    kind: z.literal('domain').describe('Discriminator: domain registration record.'),
    target: z.string().describe('Domain queried.'),
    registrar: z.string().optional().describe('Registrar name, when disclosed.'),
    statuses: z.array(z.string()).describe('Registry/EPP status codes.'),
    events: z.array(EventSchema).describe('Registration lifecycle events.'),
    nameservers: z.array(z.string()).describe('Nameserver hostnames.'),
    dnssecSigned: z.boolean().optional().describe('Whether DNSSEC is signed, when reported.'),
  })
  .describe('Domain registration record (RDAP or WHOIS).');

const IpRegistrationSchema = z
  .object({
    kind: z.literal('ip').describe('Discriminator: IP/netblock registration record.'),
    target: z.string().describe('IP or CIDR queried.'),
    networkName: z.string().optional().describe('Network/handle name, when present.'),
    cidrs: z.array(z.string()).describe('Allocation CIDR(s) for the netblock.'),
    originAsns: z.array(z.number()).describe('Origin AS number(s), when present.'),
    country: z
      .string()
      .optional()
      .describe('Two-letter country code, when present (often null at the registry).'),
    statuses: z.array(z.string()).describe('Registry status codes.'),
    events: z.array(EventSchema).describe('Network lifecycle events.'),
  })
  .describe('IP/netblock registration record (RDAP or WHOIS).');

export const lookupRegistrationTool = tool('attacksurface_lookup_registration', {
  title: 'attacksurface_lookup_registration',
  description:
    'Look up registration and ownership via RDAP (structured JSON), with a WHOIS fallback for TLDs without RDAP or when RDAP is unresponsive. For a domain it returns registrar, status codes, creation/expiry/updated events, nameservers, and DNSSEC; for an IP or CIDR it returns the netblock name, allocation CIDRs, origin ASN, and country. Registry data is frequently redacted or sparse — absent fields are reported as unknown, never inferred. Use only on assets you own or are authorized to assess.',
  annotations: { readOnlyHint: true, openWorldHint: true },
  input: z.object({
    target: z
      .string()
      .describe(
        'A domain (e.g. "example.com"), an IP (e.g. "8.8.8.8"), or a CIDR (e.g. "8.8.8.0/24").',
      ),
    type: z
      .enum(['auto', 'domain', 'ip'])
      .default('auto')
      .describe('Force the target interpretation, or "auto" to detect domain vs IP/CIDR.'),
  }),
  output: z.object({
    source: z.enum(['rdap', 'whois']).describe('Which source answered the lookup.'),
    registration: z
      .discriminatedUnion('kind', [DomainRegistrationSchema, IpRegistrationSchema])
      .describe('The parsed registration record (domain or IP).'),
    rawWhois: z
      .string()
      .nullable()
      .describe('Raw WHOIS text when the WHOIS fallback answered, else null.'),
    notes: z.array(z.string()).describe('Notes such as RDAP-timeout-then-WHOIS-fallback.'),
  }),
  errors: [
    {
      reason: 'invalid_target',
      code: JsonRpcErrorCode.ValidationError,
      when: 'The target is not a valid domain, IP, or CIDR.',
      recovery: 'Provide a registrable domain, an IP address, or a CIDR like 192.0.2.0/24.',
    },
  ],

  async handler(input, ctx) {
    const normalized = input.type === 'ip' ? input.target.trim() : normalizeDomain(input.target);
    const target =
      input.type === 'domain' || input.type === 'auto' ? normalized : input.target.trim();

    if (!isValidRegistrationTarget(target)) {
      throw ctx.fail('invalid_target', `"${input.target}" is not a valid domain, IP, or CIDR.`, {
        ...ctx.recoveryFor('invalid_target'),
      });
    }

    return await getRegistrationService().lookup(target, input.type, ctx);
  },

  format: (result) => {
    const lines: string[] = [];
    const r = result.registration;
    lines.push(`## Registration: ${r.target} (${r.kind})`);
    lines.push(`**Source:** ${result.source}`);

    if (r.kind === 'domain') {
      lines.push(`**Registrar:** ${r.registrar ?? 'unknown'}`);
      lines.push(
        `**DNSSEC:** ${r.dnssecSigned === undefined ? 'unknown' : r.dnssecSigned ? 'signed' : 'unsigned'}`,
      );
      if (r.statuses.length > 0) lines.push(`**Status:** ${r.statuses.join(', ')}`);
      if (r.events.length > 0) {
        lines.push('**Events:**');
        for (const e of r.events) lines.push(`- ${e.action}: ${e.date}`);
      }
      if (r.nameservers.length > 0) lines.push(`**Nameservers:** ${r.nameservers.join(', ')}`);
    } else {
      lines.push(`**Network:** ${r.networkName ?? 'unknown'}`);
      lines.push(`**Country:** ${r.country ?? 'unknown'}`);
      if (r.cidrs.length > 0) lines.push(`**CIDRs:** ${r.cidrs.join(', ')}`);
      if (r.originAsns.length > 0)
        lines.push(`**Origin ASN:** ${r.originAsns.map((a) => `AS${a}`).join(', ')}`);
      if (r.statuses.length > 0) lines.push(`**Status:** ${r.statuses.join(', ')}`);
      if (r.events.length > 0) {
        lines.push('**Events:**');
        for (const e of r.events) lines.push(`- ${e.action}: ${e.date}`);
      }
    }

    if (result.notes.length > 0) {
      lines.push('**Notes:**');
      for (const n of result.notes) lines.push(`- ${n}`);
    }
    if (result.rawWhois) {
      const excerpt = result.rawWhois.split('\n').slice(0, 40).join('\n');
      lines.push('<details><summary>Raw WHOIS</summary>\n');
      lines.push('```');
      lines.push(excerpt);
      lines.push('```');
      lines.push('</details>');
    }
    return [{ type: 'text', text: lines.join('\n') }];
  },
});
