/**
 * @fileoverview attacksurface_resolve_dns — resolve and enumerate DNS records (A/AAAA/MX/NS/TXT/
 * CAA/CNAME) for one or more hosts across multiple public resolvers, with optional reverse PTR.
 * Per-resolver values surface propagation gaps. Passive: reads public DNS only.
 * @module mcp-server/tools/definitions/resolve-dns.tool
 */

import { tool, z } from '@cyanheads/mcp-ts-core';
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { getServerConfig, parseResolverList } from '@/config/server-config.js';
import { getDnsService } from '@/services/dns/dns-service.js';
import { ALL_RECORD_TYPES, type DnsRecordType } from '@/services/dns/types.js';
import { assertSafeResolverIp } from '@/utils/ssrf-guard.js';
import { isValidHost, isValidRegistrationTarget } from '@/utils/validation.js';

const RecordTypeEnum = z.enum(['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'CAA']);

const ResolverResultSchema = z
  .object({
    resolver: z.string().describe('Resolver IP that produced this result.'),
    latencyInMs: z.number().describe('Round-trip latency for this resolver in milliseconds.'),
    records: z
      .record(z.string(), z.array(z.string()))
      .describe(
        'Records keyed by type (A/AAAA/CNAME/MX/NS/TXT/CAA); types with no answer are omitted.',
      ),
    error: z
      .string()
      .nullable()
      .describe('Resolver-level error, or null when the query succeeded.'),
  })
  .describe("One resolver's answer for a host.");

const ReverseResultSchema = z
  .object({
    ip: z.string().describe('IP that was reverse-resolved.'),
    hostnames: z.array(z.string()).describe('PTR hostnames; empty when none exist.'),
    error: z.string().nullable().describe('Reverse-lookup error, or null on success.'),
  })
  .describe('A reverse-DNS (PTR) result for one IP.');

const HostResultSchema = z
  .object({
    host: z.string().describe('Host queried.'),
    resolved: z.boolean().describe('True when the host resolved to at least one A/AAAA address.'),
    records: z
      .record(z.string(), z.array(z.string()))
      .describe('Canonical records (from the first resolver that answered), keyed by type.'),
    resolverResults: z.array(ResolverResultSchema).describe('Per-resolver breakdown.'),
    propagationMismatches: z
      .array(RecordTypeEnum)
      .describe('Record types where resolvers disagreed (propagation gaps).'),
    reverse: z
      .array(ReverseResultSchema)
      .optional()
      .describe('Reverse-DNS (PTR) results for resolved IPs, when reverse was requested.'),
    error: z.string().nullable().describe('Host-level error (e.g. blocked target), or null.'),
  })
  .describe('Aggregate DNS result for one host across all queried resolvers.');

export const resolveDnsTool = tool('attacksurface_resolve_dns', {
  title: 'attacksurface_resolve_dns',
  description:
    'Resolve and enumerate DNS records (A, AAAA, CNAME, MX, NS, TXT, CAA) for one or more hosts across multiple public resolvers, with optional reverse DNS (PTR) for resolved IPs. Reports per-resolver values so propagation gaps and split-horizon DNS are visible. Each host is checked against an SSRF guard; one failing host degrades to a per-host error rather than failing the whole call.',
  annotations: { readOnlyHint: true, openWorldHint: true, idempotentHint: true },
  input: z.object({
    hosts: z
      .array(z.string().describe('Hostname to resolve (e.g. "example.com", "www.example.com").'))
      .min(1)
      .max(50)
      .describe('Hosts to resolve (1–50).'),
    recordTypes: z
      .array(RecordTypeEnum)
      .optional()
      .describe('Record types to query. Omit for all of A/AAAA/CNAME/MX/NS/TXT/CAA.'),
    resolvers: z
      .array(z.string().describe('Public resolver IP (e.g. "8.8.8.8").'))
      .optional()
      .describe(
        'Resolver IPs to query. Omit to use the server defaults (8.8.8.8, 1.1.1.1, 9.9.9.9). Private/loopback resolver IPs are rejected.',
      ),
    reverse: z
      .boolean()
      .default(false)
      .describe('When true, also perform reverse DNS (PTR) on resolved A/AAAA addresses.'),
  }),
  output: z.object({
    results: z.array(HostResultSchema).describe('Per-host DNS results.'),
    resolversUsed: z.array(z.string()).describe('Resolver IPs actually queried.'),
  }),
  enrichment: {
    notice: z.string().optional().describe('Guidance when no host resolved or all hosts errored.'),
  },
  errors: [
    {
      reason: 'invalid_host',
      code: JsonRpcErrorCode.ValidationError,
      when: 'A supplied host is not a syntactically valid hostname or IP.',
      recovery: 'Provide bare hostnames or IPs (no scheme/path), e.g. "api.example.com".',
    },
    {
      reason: 'invalid_resolver',
      code: JsonRpcErrorCode.ValidationError,
      when: 'A supplied resolver is not a valid IP address.',
      recovery: 'Pass resolver IPs such as 8.8.8.8 or 1.1.1.1, not hostnames.',
    },
    {
      reason: 'blocked_resolver',
      code: JsonRpcErrorCode.Forbidden,
      when: 'A supplied resolver IP is in a private, loopback, or link-local range.',
      recovery:
        'Use a public resolver such as 8.8.8.8 or 1.1.1.1. Private resolvers require ATTACKSURFACE_ALLOW_PRIVATE_TARGETS=true.',
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

    const config = getServerConfig();
    const resolvers =
      input.resolvers && input.resolvers.length > 0
        ? input.resolvers
        : parseResolverList(config.defaultResolvers);
    for (const ip of resolvers) {
      // Resolvers must be IPs (the service also SSRF-checks them); reject hostnames at the edge.
      if (!isValidRegistrationTarget(ip) || !/^[0-9a-f:.]+$/i.test(ip)) {
        throw ctx.fail('invalid_resolver', `"${ip}" is not a valid resolver IP.`, {
          ...ctx.recoveryFor('invalid_resolver'),
        });
      }
      // A syntactically-valid private/loopback resolver IP is refused for safety. Surface it as the
      // typed blocked_resolver reason rather than letting the service's plain throw auto-classify
      // to an opaque ServiceUnavailable the agent cannot branch on.
      try {
        assertSafeResolverIp(ip);
      } catch (err) {
        throw ctx.fail(
          'blocked_resolver',
          err instanceof Error ? err.message : `Resolver IP "${ip}" is not permitted.`,
          { ...ctx.recoveryFor('blocked_resolver') },
        );
      }
    }

    const types: DnsRecordType[] =
      input.recordTypes && input.recordTypes.length > 0 ? input.recordTypes : ALL_RECORD_TYPES;

    const results = await getDnsService().resolveHosts(
      input.hosts,
      types,
      resolvers,
      input.reverse,
    );

    const anyResolved = results.some((r) => r.resolved);
    if (!anyResolved) {
      ctx.enrich.notice(
        `No host resolved to an address across ${resolvers.length} resolver(s). Verify the hostnames, or the records may not exist.`,
      );
    }

    return { results, resolversUsed: resolvers };
  },

  format: (result) => {
    const lines: string[] = [];
    for (const r of result.results) {
      lines.push(`## ${r.host}`);
      lines.push(`**Resolved:** ${r.resolved ? 'yes' : 'no'}`);
      if (r.error) lines.push(`**Error:** ${r.error}`);
      const types = Object.keys(r.records) as DnsRecordType[];
      for (const t of types) {
        lines.push(`**${t}:** ${(r.records[t] ?? []).join(', ')}`);
      }
      if (r.propagationMismatches.length > 0) {
        lines.push(`**Propagation mismatch on:** ${r.propagationMismatches.join(', ')}`);
      }
      for (const rr of r.resolverResults) {
        const rendered = Object.entries(rr.records)
          .map(([t, vals]) => `${t}=[${vals.join(', ')}]`)
          .join(' ');
        lines.push(
          `- _${rr.resolver}_ — ${rendered || 'no records'}, ${rr.latencyInMs}ms (error: ${rr.error ?? 'none'})`,
        );
      }
      if (r.reverse && r.reverse.length > 0) {
        lines.push('**Reverse DNS:**');
        for (const rev of r.reverse) {
          lines.push(
            `- ${rev.ip} → ${rev.hostnames.length > 0 ? rev.hostnames.join(', ') : 'no PTR'}${rev.error ? ` (error: ${rev.error})` : ''}`,
          );
        }
      }
      lines.push('');
    }
    lines.push(`_Resolvers queried: ${result.resolversUsed.join(', ')}_`);
    return [{ type: 'text', text: lines.join('\n') }];
  },
});
