/**
 * @fileoverview attacksurface_lookup_host — infrastructure intelligence for a single IP or a faceted
 * internet-wide search, powered by Shodan. Single-host lookup uses the free host endpoint; faceted
 * search (mode: "search") consumes paid query credits. Requires SHODAN_API_KEY — degrades with a
 * typed `source_unavailable` error when unset, leaving the rest of the server fully functional.
 * Shodan data is as fresh as Shodan's last scan, never a live port state.
 * @module mcp-server/tools/definitions/lookup-host.tool
 */

import { tool, z } from '@cyanheads/mcp-ts-core';
import { JsonRpcErrorCode, McpError } from '@cyanheads/mcp-ts-core/errors';
import { getShodanService } from '@/services/shodan/shodan-service.js';

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
  matches: z.array(SearchMatchSchema).describe('Returned matches (first page).'),
  facets: z
    .record(z.string(), z.array(FacetBucketSchema))
    .describe('Facet aggregations: facet name → value/count buckets.'),
});

export const lookupHostTool = tool('attacksurface_lookup_host', {
  title: 'attacksurface_lookup_host',
  description:
    'Get infrastructure intelligence for a single IP (open ports, service banners, software versions, hostnames, ASN, geo) via Shodan\'s free host endpoint, or run a faceted internet-wide search (mode: "search") that consumes paid Shodan query credits. Requires SHODAN_API_KEY; without it this tool returns a typed source_unavailable error while the rest of the server keeps working. Shodan data reflects Shodan\'s last scan, not a live port state. Use only on assets you own or are authorized to assess.',
  annotations: { readOnlyHint: true, openWorldHint: true },
  input: z.object({
    target: z
      .string()
      .describe(
        'For mode "host": an IP address. For mode "search": a Shodan search query (e.g. "org:\\"Example Inc\\" port:443").',
      ),
    mode: z
      .enum(['host', 'search'])
      .default('host')
      .describe(
        '"host" = free single-IP lookup; "search" = faceted query (consumes paid credits).',
      ),
    facets: z
      .array(z.string())
      .optional()
      .describe('Facet fields for mode "search" (e.g. ["port", "org", "country"]).'),
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
      recovery:
        'Shodan may not have scanned this host. Try map_domain or inspect_tls/probe_http for live posture.',
    },
  ],

  async handler(input, ctx) {
    const shodan = getShodanService();
    if (!shodan.isConfigured()) {
      throw ctx.fail('source_unavailable', undefined, { ...ctx.recoveryFor('source_unavailable') });
    }

    if (input.mode === 'search') {
      const search = await shodan.search(input.target, input.facets ?? [], ctx);
      return { mode: 'search' as const, search };
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
      lines.push(`### Host: ${h.ip}`);
      lines.push(
        `**Org:** ${h.org ?? 'unknown'} | **ASN:** ${h.asn ?? 'unknown'} | **Country:** ${h.country ?? 'unknown'}`,
      );
      lines.push(`**Hostnames:** ${h.hostnames.join(', ') || 'none'}`);
      lines.push(`**Last Shodan scan:** ${h.lastUpdate ?? 'unknown'}`);
      lines.push(`**Open ports:** ${h.ports.join(', ') || 'none reported'}`);
      lines.push('**Services:**');
      for (const s of h.services) {
        lines.push(
          `- port ${s.port} · ${s.transport ?? 'tcp'} · ${s.product ?? 'unknown'} ${s.version ?? ''} · seen ${s.observedAt ?? 'unknown'} · ${s.banner ?? 'no banner'}`,
        );
      }
    }

    const sr = result.search;
    if (sr) {
      lines.push(`### Search — ${sr.total} total match(es)`);
      for (const m of sr.matches) {
        lines.push(
          `- ${m.ip}:${m.port} — ${m.product ?? 'unknown product'} · ${m.org ?? 'unknown org'} · ${m.country ?? 'unknown country'}`,
        );
      }
      lines.push('**Facets:**');
      for (const [name, buckets] of Object.entries(sr.facets)) {
        lines.push(`- ${name}: ${buckets.map((b) => `${b.value} (${b.count})`).join(', ')}`);
      }
    }
    return [{ type: 'text', text: lines.join('\n') }];
  },
});
