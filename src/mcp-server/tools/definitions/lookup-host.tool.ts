/**
 * @fileoverview attacksurface_lookup_host — infrastructure intelligence for a single IP or a faceted
 * internet-wide search, powered by Shodan. Single-host lookup returns host records; faceted
 * search (mode: "search") may consume query credits. Requires SHODAN_API_KEY — degrades with a
 * typed `source_unavailable` error when unset, leaving the rest of the server fully functional.
 * Shodan data is as fresh as Shodan's last scan, never a live port state.
 * @module mcp-server/tools/definitions/lookup-host.tool
 */

import { isIP } from 'node:net';
import { tool, z } from '@cyanheads/mcp-ts-core';
import { JsonRpcErrorCode, McpError } from '@cyanheads/mcp-ts-core/errors';
import { getShodanService } from '@/services/shodan/shodan-service.js';
import { literalText } from '@/utils/literal-text.js';
import { NextCallSchema } from '@/utils/next-call.js';

const ServiceBannerSchema = z
  .object({
    port: z.number().describe('Open port observed by Shodan.'),
    transport: z.string().optional().describe('Transport (tcp/udp), when reported.'),
    product: z.string().optional().describe('Detected product/software, when reported.'),
    version: z.string().optional().describe('Software version, when reported.'),
    banner: z.string().optional().describe('Banner excerpt (truncated), when reported.'),
    observedAt: z.string().optional().describe("ISO 8601 timestamp of Shodan's last observation."),
  })
  .describe('A service/banner observed by Shodan on the host.');

const HostResultSchema = z.object({
  ip: z.string().describe('IP looked up.'),
  hostnames: z.array(z.string()).describe('Hostnames Shodan associates with the IP.'),
  ports: z.array(z.number()).describe('Open ports observed.'),
  services: z.array(ServiceBannerSchema).describe('Per-service banners.'),
  asn: z.string().optional().describe('Autonomous system number, when reported.'),
  org: z.string().optional().describe('ISP/organization, when reported.'),
  country: z.string().optional().describe('Two-letter country code, when reported.'),
  lastUpdate: z.string().optional().describe("ISO 8601 timestamp of Shodan's most recent scan."),
});

const SearchMatchSchema = z
  .object({
    ip: z.string().describe('IP of the match.'),
    port: z.number().describe('Port of the match.'),
    product: z.string().optional().describe('Detected product, when reported.'),
    org: z.string().optional().describe('Org/ISP, when reported.'),
    country: z.string().optional().describe('Country code, when reported.'),
  })
  .describe('A single host/port match in a faceted search.');

const FacetBucketSchema = z
  .object({
    value: z
      .string()
      .describe('The aggregated value (e.g. a country code, port number, or org name).'),
    count: z.number().describe('Number of Shodan results carrying this value.'),
  })
  .describe('A facet aggregation bucket (value and its count).');

const SearchResultSchema = z.object({
  total: z.number().describe('Total matches reported by Shodan.'),
  matches: z.array(SearchMatchSchema).describe('Returned matches from this page.'),
  page: z.number().describe('Requested search page.'),
  pageSize: z.literal(100).describe('Shodan search page size.'),
  hasMore: z.boolean().describe('Whether another page is available.'),
  nextPage: z.number().nullable().describe('Next search page, or null when exhausted.'),
  continuation: NextCallSchema.nullable().describe(
    'Opt-in next-page call, or null when exhausted.',
  ),
  facets: z
    .record(z.string(), z.array(FacetBucketSchema))
    .describe('Facet aggregations: facet name → value/count buckets.'),
});

export const lookupHostTool = tool('attacksurface_lookup_host', {
  title: 'attacksurface_lookup_host',
  description:
    'Get infrastructure intelligence for a single IP (open ports, service banners, software versions, hostnames, ASN, geo) via Shodan, or run a faceted internet-wide search (mode: "search") that may consume Shodan query credits. Requires SHODAN_API_KEY; without it this tool returns a typed source_unavailable error while the rest of the server keeps working. Shodan data reflects Shodan\'s last scan, not a live port state. Use only on assets you own or are authorized to assess.',
  annotations: { readOnlyHint: true, openWorldHint: true },
  input: z.object({
    target: z
      .string()
      .regex(/\S/, 'Target must contain a non-whitespace character.')
      .describe(
        'For mode "host": an IP address. For mode "search": a Shodan search query (e.g. "org:\\"Example Inc\\" port:443").',
      ),
    mode: z
      .enum(['host', 'search'])
      .default('host')
      .describe('"host" = single-IP lookup; "search" = faceted query (may consume query credits).'),
    facets: z
      .array(z.string())
      .optional()
      .describe('Facet fields for mode "search" (e.g. ["port", "org", "country"]).'),
    page: z
      .number()
      .int()
      .positive()
      .default(1)
      .describe(
        'Search page (100 matches per page); ignored in host mode. Each call fetches one page and may consume credits.',
      ),
  }),
  output: z.object({
    mode: z.enum(['host', 'search']).describe('The mode that was executed.'),
    host: HostResultSchema.optional().describe('Single-host result (present for mode "host").'),
    search: SearchResultSchema.optional().describe(
      'Faceted-search result (present for mode "search").',
    ),
  }),
  errors: [
    {
      reason: 'invalid_target',
      code: JsonRpcErrorCode.ValidationError,
      when: 'A host-mode target is not an IPv4 or IPv6 address.',
      recovery:
        'Provide a bare IPv4 or IPv6 address without brackets, a port, or a CIDR suffix; use mode "search" for Shodan queries.',
    },
    {
      reason: 'source_unavailable',
      code: JsonRpcErrorCode.ServiceUnavailable,
      when: 'SHODAN_API_KEY is not configured.',
      recovery:
        'Set SHODAN_API_KEY to enable host intelligence; the rest of the server works without it.',
    },
    {
      reason: 'no_data',
      code: JsonRpcErrorCode.NotFound,
      when: 'Shodan has no information for the target IP.',
      // An unscanned IP is an ordinary answer, not an incident — log it below the error level.
      severity: 'notice',
      recovery:
        'Shodan may not have scanned this host. Try map_domain or inspect_tls/probe_http for live posture.',
    },
  ],

  async handler(input, ctx) {
    if (input.mode === 'host' && !isIP(input.target)) {
      throw ctx.fail('invalid_target', `"${input.target}" is not a valid IPv4 or IPv6 address.`);
    }
    const shodan = getShodanService();
    if (!shodan.isConfigured()) {
      throw ctx.fail('source_unavailable', undefined, { ...ctx.recoveryFor('source_unavailable') });
    }

    if (input.mode === 'search') {
      const search = await shodan.search(input.target, input.facets ?? [], ctx, input.page);
      const hasMore = search.matches.length > 0 && input.page * 100 < search.total;
      const nextPage = hasMore ? input.page + 1 : null;
      const continuation =
        nextPage === null
          ? null
          : {
              toolName: 'attacksurface_lookup_host',
              reason: 'Fetch the next Shodan search page; this may consume query credits.',
              args: {
                target: input.target,
                mode: 'search',
                ...(input.facets ? { facets: input.facets } : {}),
                page: nextPage,
              },
            };
      return {
        mode: 'search' as const,
        search: {
          ...search,
          page: input.page,
          pageSize: 100 as const,
          hasMore,
          nextPage,
          continuation,
        },
      };
    }

    try {
      const host = await shodan.lookupHost(input.target, ctx);
      return { mode: 'host' as const, host };
    } catch (err) {
      if (err instanceof McpError && err.code === JsonRpcErrorCode.NotFound) {
        throw ctx.fail('no_data', `Shodan has no data for ${input.target}.`, {
          ...ctx.recoveryFor('no_data'),
        });
      }
      throw err;
    }
  },

  format: (result) => {
    const lines: string[] = [`## Shodan lookup (mode: ${result.mode})`];

    const h = result.host;
    if (h) {
      lines.push(`### Host: ${literalText(h.ip)}`);
      lines.push(
        `**Org:** ${literalText(h.org ?? 'unknown')} | **ASN:** ${literalText(h.asn ?? 'unknown')} | **Country:** ${literalText(h.country ?? 'unknown')}`,
      );
      lines.push(`**Hostnames:** ${h.hostnames.map(literalText).join(', ') || 'none'}`);
      lines.push(`**Last Shodan scan:** ${literalText(h.lastUpdate ?? 'unknown')}`);
      lines.push(`**Open ports:** ${h.ports.join(', ') || 'none reported'}`);
      lines.push('**Services:**');
      for (const s of h.services) {
        lines.push(
          `- port ${s.port} · ${literalText(s.transport ?? 'tcp')} · ${literalText(s.product ?? 'unknown')} ${s.version === undefined ? '' : literalText(s.version)} · seen ${literalText(s.observedAt ?? 'unknown')} · ${literalText(s.banner ?? 'no banner')}`,
        );
      }
    }

    const sr = result.search;
    if (sr) {
      lines.push(`### Search — ${sr.total} total match(es)`);
      lines.push(
        `Search page ${sr.page}; pageSize=${sr.pageSize}; hasMore=${sr.hasMore}; nextPage=${sr.nextPage ?? 'none'}; continuation=${literalText(JSON.stringify(sr.continuation))}`,
      );
      for (const m of sr.matches) {
        lines.push(
          `- ${literalText(`${m.ip}:${m.port}`)} — ${literalText(m.product ?? 'unknown product')} · ${literalText(m.org ?? 'unknown org')} · ${literalText(m.country ?? 'unknown country')}`,
        );
      }
      lines.push('**Facets:**');
      for (const [name, buckets] of Object.entries(sr.facets)) {
        lines.push(
          `- ${literalText(name)}: ${buckets.map((b) => `${literalText(b.value)} (${b.count})`).join(', ')}`,
        );
      }
    }
    return [{ type: 'text', text: lines.join('\n') }];
  },
});
