/**
 * @fileoverview attacksurface_enumerate_subdomains — passive subdomain discovery from Certificate
 * Transparency logs, with DNS resolution to mark which candidates are live. crt.sh is primary,
 * Certspotter the fallback, and the apex's own TLS SAN list a third always-available source. No DNS
 * brute-forcing: CT reads public logs only. Each candidate's liveness is checked by DNS resolution
 * (SSRF-guarded); unresolved names are included only when requested.
 * @module mcp-server/tools/definitions/enumerate-subdomains.tool
 */

import { tool, z } from '@cyanheads/mcp-ts-core';
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { getCtService } from '@/services/ct/ct-service.js';
import type { CtSource } from '@/services/ct/types.js';
import { getDnsService } from '@/services/dns/dns-service.js';
import { getTlsService } from '@/services/tls/tls-service.js';
import { isValidDomain, normalizeDomain } from '@/utils/validation.js';

const SourceEnum = z.enum(['crt.sh', 'certspotter', 'tls-san']);

const SubdomainSchema = z
  .object({
    name: z.string().describe('Discovered subdomain (wildcard prefix stripped).'),
    sources: z.array(SourceEnum).describe('CT source(s) that surfaced this name.'),
    resolved: z.boolean().describe('True when the name resolved to at least one A/AAAA address.'),
    addresses: z.array(z.string()).describe('Resolved IP addresses (empty when unresolved).'),
  })
  .describe('A discovered subdomain with provenance and liveness.');

const SourceStatusSchema = z
  .object({
    source: SourceEnum.describe('CT source.'),
    ok: z.boolean().describe('Whether the source answered successfully.'),
    count: z.number().describe('Distinct names this source contributed.'),
    sourceError: z.string().nullable().describe('Source error, or null on success.'),
  })
  .describe('Per-source outcome for the enumeration.');

const CONCURRENCY = 12;

/** Resolve liveness for names with a bounded concurrency pool. */
async function resolveLiveness(names: string[]): Promise<Map<string, string[]>> {
  const dns = getDnsService();
  const out = new Map<string, string[]>();
  let index = 0;
  const workers = Array.from({ length: Math.min(CONCURRENCY, names.length) }, async () => {
    while (index < names.length) {
      const i = index++;
      const name = names[i];
      if (!name) continue;
      try {
        out.set(name, await dns.resolveAddresses(name));
      } catch {
        out.set(name, []);
      }
    }
  });
  await Promise.all(workers);
  return out;
}

export const enumerateSubdomainsTool = tool('attacksurface_enumerate_subdomains', {
  title: 'attacksurface_enumerate_subdomains',
  description:
    "Discover subdomains passively from Certificate Transparency logs, then resolve each candidate via DNS to mark which are live. crt.sh is the primary source, Certspotter the fallback (crt.sh is frequently overloaded), and the apex domain's own TLS certificate SAN list a third always-available source. Every discovered name carries its source provenance. No DNS brute-forcing — this reads public logs, it does not probe the target's resolvers. Use only on domains you own or are authorized to assess.",
  annotations: { readOnlyHint: true, openWorldHint: true },
  input: z.object({
    domain: z.string().describe('Apex domain to enumerate (e.g. "example.com").'),
    sources: z
      .array(SourceEnum)
      .optional()
      .describe('CT sources to query. Omit for all of crt.sh, certspotter, tls-san.'),
    includeUnresolved: z
      .boolean()
      .default(true)
      .describe(
        'When true, include names that did not resolve. When false, return only live hosts.',
      ),
  }),
  output: z.object({
    domain: z.string().describe('Apex domain queried (normalized).'),
    subdomains: z
      .array(SubdomainSchema)
      .describe('Discovered subdomains with provenance and liveness.'),
    sourceStatuses: z
      .array(SourceStatusSchema)
      .describe('Per-source outcome (which answered, counts, errors).'),
  }),
  enrichment: {
    notice: z
      .string()
      .optional()
      .describe('Guidance when no source answered or nothing was found.'),
    totalCount: z
      .number()
      .optional()
      .describe('Total distinct names discovered before any liveness filter.'),
    liveCount: z.number().optional().describe('Count of names that resolved to an address.'),
  },
  errors: [
    {
      reason: 'invalid_domain',
      code: JsonRpcErrorCode.ValidationError,
      when: 'The supplied domain is not a syntactically valid registrable domain.',
      recovery: 'Provide a bare apex domain such as "example.com" (no scheme, path, or wildcard).',
    },
    {
      reason: 'all_sources_failed',
      code: JsonRpcErrorCode.ServiceUnavailable,
      when: 'Every requested CT source failed (e.g. crt.sh overloaded and Certspotter rate-limited).',
      retryable: true,
      recovery:
        'Retry shortly; crt.sh is often transiently down. A CERTSPOTTER_API_KEY raises the fallback limit.',
    },
  ],

  async handler(input, ctx) {
    const domain = normalizeDomain(input.domain);
    if (!isValidDomain(domain)) {
      throw ctx.fail('invalid_domain', `"${input.domain}" is not a valid domain.`, {
        ...ctx.recoveryFor('invalid_domain'),
      });
    }

    const sources: CtSource[] =
      input.sources && input.sources.length > 0
        ? input.sources
        : ['crt.sh', 'certspotter', 'tls-san'];

    // The TLS-SAN source needs the apex's certificate SANs — fetch opportunistically when requested.
    let sanNames: string[] = [];
    if (sources.includes('tls-san')) {
      sanNames = await getTlsService().getSans(domain);
    }

    const ct = await getCtService().enumerate(domain, sources, ctx, sanNames);

    // If every queried source failed (none ok), surface a retryable failure.
    if (ct.sourceStatuses.length > 0 && ct.sourceStatuses.every((s) => !s.ok)) {
      throw ctx.fail(
        'all_sources_failed',
        `All CT sources failed: ${ct.sourceStatuses.map((s) => `${s.source} (${s.sourceError})`).join('; ')}`,
        { ...ctx.recoveryFor('all_sources_failed') },
      );
    }

    const allNames = ct.names.map((n) => n.name);
    const liveness = await resolveLiveness(allNames);

    let subdomains = ct.names.map((n) => {
      const addresses = liveness.get(n.name) ?? [];
      return { name: n.name, sources: n.sources, resolved: addresses.length > 0, addresses };
    });

    const liveCount = subdomains.filter((s) => s.resolved).length;
    if (!input.includeUnresolved) {
      subdomains = subdomains.filter((s) => s.resolved);
    }

    ctx.enrich({ totalCount: allNames.length, liveCount });
    if (allNames.length === 0) {
      ctx.enrich.notice(
        `No subdomains found in CT logs for "${domain}". The domain may use only wildcard or pre-CT certificates, or the sources were unavailable.`,
      );
    }

    return { domain, subdomains, sourceStatuses: ct.sourceStatuses };
  },

  format: (result) => {
    const lines: string[] = [];
    lines.push(`## Subdomains for ${result.domain}`);
    lines.push('**Sources:**');
    for (const s of result.sourceStatuses) {
      lines.push(`- ${s.source}: ok=${s.ok}, count=${s.count}, error=${s.sourceError ?? 'none'}`);
    }
    lines.push(`\n**${result.subdomains.length} name(s):**`);
    for (const s of result.subdomains) {
      lines.push(
        `- **${s.name}** _(${s.sources.join(', ')})_ — resolved=${s.resolved} → ${s.addresses.join(', ') || 'none'}`,
      );
    }
    return [{ type: 'text', text: lines.join('\n') }];
  },
});
