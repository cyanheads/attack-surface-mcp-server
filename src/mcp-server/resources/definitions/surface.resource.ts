/**
 * @fileoverview attacksurface://surface/{domain} — read-once snapshot of a domain's mapped surface
 * (subdomains + live hosts + per-host posture summary), equivalent to a standard-depth
 * attacksurface_map_domain call. A convenience for clients that support injectable context; the same
 * data is fully reachable via the map_domain tool, so tool-only clients lose nothing. Large maps
 * disclose a truncation count rather than returning unbounded host detail.
 * @module mcp-server/resources/definitions/surface.resource
 */

import { type Context, resource, z } from '@cyanheads/mcp-ts-core';
import { notFound, validationError } from '@cyanheads/mcp-ts-core/errors';
import { getServerConfig } from '@/config/server-config.js';
import { getCtService } from '@/services/ct/ct-service.js';
import { getDnsService } from '@/services/dns/dns-service.js';
import { getHttpService } from '@/services/http/http-service.js';
import { getTlsService } from '@/services/tls/tls-service.js';
import { isValidDomain, normalizeDomain } from '@/utils/validation.js';

const CONCURRENCY = 10;
/** Cap host detail in the resource view; the tool returns the full set. */
const HOST_DETAIL_CAP = 50;

interface HostSummary {
  addresses: string[];
  host: string;
  http: { finalStatus: number; securityFindings: string[]; technologies: string[] } | null;
  tls: {
    protocol: string | null;
    daysUntilExpiry: number | null;
    validationAuthorized: boolean;
    findings: string[];
  } | null;
}

/** Bounded-concurrency map. */
async function pool<T>(items: string[], fn: (item: string) => Promise<T>): Promise<Map<string, T>> {
  const out = new Map<string, T>();
  let i = 0;
  await Promise.all(
    Array.from({ length: Math.min(CONCURRENCY, items.length) }, async () => {
      while (i < items.length) {
        const idx = i++;
        const item = items[idx];
        if (!item) continue;
        try {
          out.set(item, await fn(item));
        } catch {
          // per-item failure → absent entry
        }
      }
    }),
  );
  return out;
}

export const surfaceResource = resource('attacksurface://surface/{domain}', {
  description:
    "Read-once snapshot of a domain's mapped external surface (subdomains, live hosts, and a per-host TLS/HTTP posture summary), equivalent to a standard-depth attacksurface_map_domain call. The same data is fully reachable via the map_domain tool. Assess only assets you own or are authorized to test.",
  name: 'domain-surface-snapshot',
  title: 'attacksurface://surface/{domain}',
  mimeType: 'application/json',
  params: z.object({
    domain: z.string().describe('Apex domain to snapshot (e.g. "example.com").'),
  }),

  async handler(params: { domain: string }, ctx: Context) {
    const domain = normalizeDomain(params.domain);
    if (!isValidDomain(domain)) {
      throw validationError(`"${params.domain}" is not a valid domain.`, { domain: params.domain });
    }

    const config = getServerConfig();
    const dns = getDnsService();
    const notes: string[] = [];

    const apexSans = await getTlsService()
      .getSans(domain)
      .catch(() => [] as string[]);
    const ct = await getCtService()
      .enumerate(domain, ['crt.sh', 'certspotter', 'tls-san'], ctx, apexSans)
      .catch(() => ({ domain, names: [], sourceStatuses: [] }));

    const candidates = [...new Set([domain, ...ct.names.map((n) => n.name)])].sort();
    const cap = Math.min(config.maxSubdomains, candidates.length);
    const capped = candidates.slice(0, cap);
    const liveness = await pool(capped, (h) => dns.resolveAddresses(h));
    const liveNames = capped.filter((h) => (liveness.get(h)?.length ?? 0) > 0);

    if (candidates.length === 1 && liveNames.length === 0) {
      throw notFound(
        `No surface found for "${domain}" — no subdomains and the apex did not resolve.`,
      );
    }

    const detailNames = liveNames.slice(0, HOST_DETAIL_CAP);
    const tlsResults = await getTlsService().inspectHosts(detailNames);
    const tlsByHost = new Map(tlsResults.map((r) => [r.host, r]));
    const httpResults = await pool(detailNames, (h) =>
      getHttpService().probe(`https://${h}`, undefined, 10000, ctx),
    );

    const hosts: HostSummary[] = detailNames.map((host) => {
      const tlsR = tlsByHost.get(host);
      const httpR = httpResults.get(host);
      return {
        host,
        addresses: liveness.get(host) ?? [],
        tls:
          tlsR && !tlsR.error
            ? {
                protocol: tlsR.protocol,
                daysUntilExpiry: tlsR.certificate?.daysUntilExpiry ?? null,
                validationAuthorized: tlsR.validationAuthorized,
                findings: tlsR.findings,
              }
            : null,
        http:
          httpR && !httpR.error
            ? {
                finalStatus: httpR.finalStatus,
                securityFindings: httpR.securityAudit.findings,
                technologies: httpR.technologies.map(
                  (t) => `${t.name}${t.version ? ` ${t.version}` : ''}`,
                ),
              }
            : null,
      };
    });

    const omitted = liveNames.length - detailNames.length;
    if (omitted > 0) {
      notes.push(
        `Host detail capped at ${HOST_DETAIL_CAP}; ${omitted} further live host(s) omitted (use map_domain for the full set).`,
      );
    }

    return {
      domain,
      subdomainCount: ct.names.length,
      liveHostCount: liveNames.length,
      hosts,
      notes,
    };
  },

  list: async () => ({
    resources: [
      {
        uri: 'attacksurface://surface/example.com',
        name: 'Domain surface snapshot (example)',
        mimeType: 'application/json',
      },
    ],
  }),
});
