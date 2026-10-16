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
import { getServerConfig } from '@/config/server-config.js';
import { getCtService } from '@/services/ct/ct-service.js';
import type { CtSource } from '@/services/ct/types.js';
import { getDnsService } from '@/services/dns/dns-service.js';
import { getTlsService } from '@/services/tls/tls-service.js';
import { discoveryPool } from '@/utils/discovery.js';
import { literalText } from '@/utils/literal-text.js';
import { NextCallSchema } from '@/utils/next-call.js';
import { RESPONSE_BYTE_TARGET, responseBytes } from '@/utils/response-budget.js';
import { isValidDomain, normalizeDomain } from '@/utils/validation.js';

const SourceEnum = z.enum(['crt.sh', 'certspotter', 'tls-san']);

const SubdomainSchema = z
  .object({
    name: z.string().describe('Discovered subdomain (wildcard prefix stripped).'),
    sources: z.array(SourceEnum).describe('CT source(s) that surfaced this name.'),
    resolved: z.boolean().describe('True when the name resolved to at least one A/AAAA address.'),
    addresses: z.array(z.string()).describe('Resolved IP addresses (empty when unresolved).'),
    addressError: z
      .string()
      .nullable()
      .describe('Address-family or blocked-target failure, or null.'),
  })
  .describe('A discovered subdomain with provenance and liveness.');

const SourceStatusSchema = z
  .object({
    source: SourceEnum.describe('CT source.'),
    ok: z.boolean().describe('Whether the source answered successfully.'),
    count: z.number().describe('Distinct names this source contributed.'),
    sourceError: z.string().nullable().describe('Source error, or null on success.'),
    complete: z.boolean().optional().describe('True when paged source coverage was exhausted.'),
    pagesFetched: z
      .number()
      .optional()
      .describe('Successfully read pages including an empty terminal page.'),
    incompleteReason: z
      .string()
      .nullable()
      .optional()
      .describe('Reason paged source coverage stopped, or null.'),
  })
  .describe('Per-source outcome for the enumeration.');

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
    offset: z
      .number()
      .int()
      .nonnegative()
      .default(0)
      .describe('Offset into current sorted CT candidates; data changes can shift offsets.'),
    limit: z
      .number()
      .int()
      .positive()
      .default(50)
      .describe(
        'Requested candidate count; effective limit is min(request, 50, ATTACKSURFACE_MAX_SUBDOMAINS).',
      ),
  }),
  output: z.object({
    offset: z.number().describe('Requested candidate offset.'),
    limit: z.number().describe('Effective candidate work limit.'),
    nextOffset: z
      .number()
      .nullable()
      .describe('Next consumed-candidate offset, or null when exhausted.'),
    discoveredCount: z.number().describe('Current discovered candidate total.'),
    examinedCount: z
      .number()
      .describe('Candidates resolved on this call, including undelivered suffix.'),
    returnedCount: z
      .number()
      .describe('Returned subdomain count after filtering and byte fitting.'),
    remainingCount: z.number().describe('Candidates remaining after the consumed prefix.'),
    oversize: z
      .boolean()
      .describe('One complete record or required metadata exceeds the byte target.'),
    pageInstructions: z.string().describe('Stateless offset and oversize guidance.'),
    truncated: z.boolean().describe('More candidates remain for another page.'),
    continuation: NextCallSchema.nullable().describe(
      'Next enumeration call preserving sources and filter.',
    ),
    domain: z.string().describe('Apex domain queried (normalized).'),
    subdomains: z
      .array(SubdomainSchema)
      .describe('Discovered subdomains with provenance and liveness.'),
    sourceStatuses: z
      .array(SourceStatusSchema)
      .describe('Per-source outcome (which answered, counts, errors).'),
    filteredAddressErrors: z
      .array(
        z
          .object({
            name: z.string().describe('Nonlive candidate excluded by includeUnresolved=false.'),
            addressError: z.string().describe('Operational address lookup failure.'),
          })
          .describe('A filtered candidate with failed address resolution.'),
      )
      .describe(
        'Operational failures for nonlive candidates filtered out of subdomains; empty when none were filtered.',
      ),
  }),
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
    let sanError: string | null = null;
    if (sources.includes('tls-san')) {
      try {
        sanNames = await getTlsService().getSans(domain, undefined, undefined, ctx.signal);
      } catch (err) {
        ctx.signal?.throwIfAborted();
        sanError = err instanceof Error ? err.message : String(err);
      }
    }

    const ct = await getCtService().enumerate(domain, sources, ctx, sanNames);
    if (sources.includes('tls-san') && !ct.sourceStatuses.some((s) => s.source === 'tls-san'))
      ct.sourceStatuses.push({
        source: 'tls-san',
        ok: sanError === null,
        count: 0,
        sourceError: sanError,
      });

    // If every queried source failed (none ok), surface a retryable failure.
    if (ct.sourceStatuses.length > 0 && ct.sourceStatuses.every((s) => !s.ok)) {
      throw ctx.fail(
        'all_sources_failed',
        `All CT sources failed: ${ct.sourceStatuses.map((s) => `${s.source} (${s.sourceError})`).join('; ')}`,
        { ...ctx.recoveryFor('all_sources_failed') },
      );
    }

    const sorted = [...ct.names].sort((a, b) => a.name.localeCompare(b.name));
    const discoveredCount = sorted.length;
    const limit = Math.min(input.limit, 50, getServerConfig().maxSubdomains);
    const selected = sorted.slice(input.offset, input.offset + limit);
    const liveness = await discoveryPool(
      selected.map((n) => n.name),
      (name) => getDnsService().resolveAddressStatus(name, undefined, ctx.signal),
      ctx.signal,
    );

    const records = selected.map((n) => {
      const result = liveness.get(n.name);
      const addresses = result?.value?.addresses ?? [];
      return {
        name: n.name,
        sources: n.sources,
        resolved: addresses.length > 0,
        addresses,
        addressError: result?.error ?? result?.value?.addressError ?? null,
      };
    });

    const build = (consumed: number, oversize = false) => {
      const prefix = records.slice(0, consumed);
      const subdomains = prefix.filter((s) => input.includeUnresolved || s.resolved);
      const nextOffset = input.offset + consumed < discoveredCount ? input.offset + consumed : null;
      return {
        domain,
        subdomains,
        sourceStatuses: ct.sourceStatuses,
        filteredAddressErrors: input.includeUnresolved
          ? []
          : prefix.flatMap((s) =>
              !s.resolved && s.addressError ? [{ name: s.name, addressError: s.addressError }] : [],
            ),
        offset: input.offset,
        limit,
        nextOffset,
        discoveredCount,
        examinedCount: selected.length,
        returnedCount: subdomains.length,
        remainingCount: Math.max(0, discoveredCount - input.offset - consumed),
        oversize,
        pageInstructions: `${discoveredCount === 0 ? `No subdomains found in CT logs for ${domain}. ` : ''}Continuation re-reads current CT data; changes can shift offsets. Examined but undelivered candidates are re-resolved.${oversize ? ' One complete oversized record or required source metadata exceeds the 24,000-byte target.' : ''}`,
        truncated: nextOffset !== null,
        continuation:
          nextOffset === null
            ? null
            : {
                toolName: 'attacksurface_enumerate_subdomains',
                reason: 'Read the next candidate prefix; current CT changes can shift offsets.',
                args: {
                  domain,
                  sources,
                  includeUnresolved: input.includeUnresolved,
                  offset: nextOffset,
                  limit,
                },
              },
      };
    };
    let consumed = 0;
    for (let count = 1; count <= records.length; count++) {
      const candidate = build(count);
      if (responseBytes(candidate, formatEnumeration(candidate)) > RESPONSE_BYTE_TARGET) {
        if (consumed === 0) consumed = count;
        break;
      }
      consumed = count;
    }
    let result = build(consumed);
    if (responseBytes(result, formatEnumeration(result)) > RESPONSE_BYTE_TARGET)
      result = build(consumed, true);
    return result;
  },
  format: formatEnumeration,
});

/** Render complete enumeration records, source status and continuation metadata. */
function formatEnumeration(result: {
  domain: string;
  subdomains: z.infer<typeof SubdomainSchema>[];
  sourceStatuses: z.infer<typeof SourceStatusSchema>[];
  filteredAddressErrors: Array<{ name: string; addressError: string }>;
  offset: number;
  limit: number;
  nextOffset: number | null;
  discoveredCount: number;
  examinedCount: number;
  returnedCount: number;
  remainingCount: number;
  oversize: boolean;
  pageInstructions: string;
  truncated: boolean;
  continuation: z.infer<typeof NextCallSchema> | null;
}): Array<{ type: 'text'; text: string }> {
  const lines: string[] = [];
  lines.push(`## Subdomains for ${result.domain}`);
  lines.push('**Sources:**');
  for (const s of result.sourceStatuses) {
    lines.push(
      `- ${s.source}: ok=${s.ok}, count=${s.count}, error=${literalText(s.sourceError ?? 'none')}`,
    );
    if (s.complete !== undefined)
      lines.push(
        `  - complete=${s.complete}, pagesFetched=${s.pagesFetched}, incompleteReason=${s.incompleteReason ?? 'none'}`,
      );
  }
  lines.push(`\n**${result.subdomains.length} name(s):**`);
  for (const s of result.subdomains) {
    lines.push(
      `- **${s.name}** _(${s.sources.join(', ')})_ — resolved=${s.resolved} → ${s.addresses.join(', ') || 'none'}; addressError=${literalText(s.addressError ?? 'none')}`,
    );
  }
  lines.push('**Filtered address failures:**');
  for (const failure of result.filteredAddressErrors)
    lines.push(`- ${literalText(failure.name)}: ${literalText(failure.addressError)}`);
  if (result.filteredAddressErrors.length === 0) lines.push('none');
  lines.push(
    `offset=${result.offset}; limit=${result.limit}; nextOffset=${result.nextOffset}; discoveredCount=${result.discoveredCount}; examinedCount=${result.examinedCount}; returnedCount=${result.returnedCount}; remainingCount=${result.remainingCount}; oversize=${result.oversize}`,
  );
  lines.push(
    `truncated=${result.truncated}; ${result.pageInstructions}`,
    `continuation=${literalText(JSON.stringify(result.continuation))}`,
  );
  return [{ type: 'text', text: lines.join('\n') }];
}
