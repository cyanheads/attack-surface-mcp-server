/**
 * @fileoverview Shared bounded discovery work and explicit coverage for map, snapshot and enumeration.
 * @module utils/discovery
 */
import { z } from '@cyanheads/mcp-ts-core';
import { literalText } from './literal-text.js';
import { NextCallSchema } from './next-call.js';

/** DNS absence or a closed TLS port is ordinary absence of the optional SAN source. */
export function isTlsSourceAbsent(error: unknown): boolean {
  return (
    error instanceof Error &&
    'code' in error &&
    ['ENOTFOUND', 'ENODATA', 'ECONNREFUSED'].includes(String(error.code))
  );
}

/** DNS posture keeps the dedicated resolver tool's canonical and per-resolver semantics. */
export const DnsPostureSchema = z
  .object({
    host: z.string().describe('Host queried.'),
    resolved: z.boolean().describe('Whether canonical A/AAAA records resolve.'),
    records: z
      .record(z.string(), z.array(z.string()))
      .describe('Canonical records from the first configured resolver.'),
    resolverResults: z
      .array(
        z
          .object({
            resolver: z.string().describe('Resolver IP.'),
            latencyInMs: z.number().describe('Resolver latency in milliseconds.'),
            records: z.record(z.string(), z.array(z.string())).describe('This resolver’s records.'),
            queryError: z
              .string()
              .nullable()
              .describe('Operational error, or null for success/absence.'),
          })
          .describe('Per-resolver outcome.'),
      )
      .describe('All configured resolver outcomes.'),
    propagationMismatches: z
      .array(z.enum(['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'CAA']))
      .describe('Record types with different resolver answers.'),
    hostError: z.string().nullable().describe('Host or resolver failure, or null.'),
  })
  .describe('DNS posture for one examined live host.');

/** Work is bounded to ten simultaneous hosts; failures are values, cancellation is not. */
export async function discoveryPool<T>(
  items: string[],
  fn: (host: string) => Promise<T>,
  signal?: AbortSignal,
): Promise<Map<string, { value: T | null; error: string | null }>> {
  const out = new Map<string, { value: T | null; error: string | null }>();
  let i = 0;
  await Promise.all(
    Array.from({ length: Math.min(10, items.length) }, async () => {
      while (i < items.length) {
        signal?.throwIfAborted();
        const host = items[i++];
        if (!host) continue;
        try {
          out.set(host, { value: await fn(host), error: null });
        } catch (error) {
          signal?.throwIfAborted();
          out.set(host, {
            value: null,
            error: error instanceof Error ? error.message : String(error),
          });
        }
      }
    }),
  );
  signal?.throwIfAborted();
  return out;
}

/** Separate candidate resolution and detail coverage; exact omissions appear once. */
export const CoverageSchema = z
  .object({
    discovered: z.number().describe('Distinct candidates including the apex.'),
    examined: z.number().describe('Candidates whose liveness was examined.'),
    unexamined: z.array(z.string()).describe('Candidates omitted by the resolution cap.'),
    detailed: z
      .number()
      .describe('Live hosts with requested posture attempted; zero at quick depth.'),
    detailOmitted: z.array(z.string()).describe('Live hosts omitted by the snapshot detail cap.'),
    retrieval: z
      .array(NextCallSchema)
      .describe(
        'At most three executable examples; repeat over unexamined then detailOmitted names. DNS/TLS batches never exceed 50 hosts.',
      ),
  })
  .describe('Candidate and posture coverage, independent of CT completeness.');

/** Build exact executable follow-ups without repeating the whole omission set in each call. */
export function discoveryCoverage(
  candidates: string[],
  examined: string[],
  detailed: string[],
  detailOmitted: string[] = [],
): z.infer<typeof CoverageSchema> {
  const unexamined = candidates.slice(examined.length);
  const omitted = [...unexamined, ...detailOmitted];
  const retrieval: z.infer<typeof CoverageSchema>['retrieval'] = [];
  if (omitted.length > 0) {
    const hosts = omitted.slice(0, 50);
    retrieval.push(
      {
        toolName: 'attacksurface_resolve_dns',
        args: { hosts },
        reason:
          'Repeat with each successive batch of up to 50 names from unexamined followed by detailOmitted.',
      },
      {
        toolName: 'attacksurface_inspect_tls',
        args: { hosts },
        reason:
          'Repeat with each successive batch of up to 50 names from unexamined followed by detailOmitted.',
      },
      {
        toolName: 'attacksurface_probe_http',
        args: { url: `https://${omitted[0]}` },
        reason:
          'Repeat once per name from unexamined followed by detailOmitted, setting url to https:// plus that name.',
      },
    );
  }
  return {
    discovered: candidates.length,
    examined: examined.length,
    unexamined,
    detailed: detailed.length,
    detailOmitted,
    retrieval,
  };
}

/** Render every DNS posture field as literal evidence. */
export function renderDnsPosture(posture: z.infer<typeof DnsPostureSchema>): string {
  const records = (values: Record<string, string[]>) =>
    Object.entries(values)
      .map(([type, answers]) => `${literalText(type)}=[${answers.map(literalText).join(', ')}]`)
      .join(' ');
  return [
    `${literalText(posture.host)} resolved=${posture.resolved}; records: ${records(posture.records)}; hostError=${literalText(posture.hostError ?? 'none')}; propagationMismatches=${posture.propagationMismatches.join(', ') || 'none'}`,
    'resolverResults:',
    ...posture.resolverResults.map(
      (result) =>
        `${literalText(result.resolver)} latencyInMs=${result.latencyInMs}; records: ${records(result.records)}; queryError=${literalText(result.queryError ?? 'none')}`,
    ),
  ].join('\n');
}
