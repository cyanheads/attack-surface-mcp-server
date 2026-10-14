/**
 * @fileoverview attacksurface://surface/{domain} — read-once snapshot of a domain's mapped surface
 * (subdomains + live hosts + per-host posture summary), equivalent to a standard-depth
 * attacksurface_map_domain call. A convenience for clients that support injectable context; the same
 * data is fully reachable via the map_domain tool, so tool-only clients lose nothing. Large maps
 * disclose a truncation count rather than returning unbounded host detail.
 * @module mcp-server/resources/definitions/surface.resource
 */

import { type Context, resource, z } from '@cyanheads/mcp-ts-core';
import { notFound, serviceUnavailable, validationError } from '@cyanheads/mcp-ts-core/errors';
import { getServerConfig, parseResolverList } from '@/config/server-config.js';
import { getCtService } from '@/services/ct/ct-service.js';
import { getDnsService } from '@/services/dns/dns-service.js';
import { ALL_RECORD_TYPES, type HostDnsResult } from '@/services/dns/types.js';
import { getHttpService } from '@/services/http/http-service.js';
import type { HttpProbeResult } from '@/services/http/types.js';
import { getTlsService } from '@/services/tls/tls-service.js';
import { discoveryCoverage, discoveryPool, isTlsSourceAbsent } from '@/utils/discovery.js';
import { isValidDomain, normalizeDomain } from '@/utils/validation.js';

/** Cap host detail in the resource view; the tool returns the full set. */
const HOST_DETAIL_CAP = 50;

interface HostSummary {
  addresses: string[];
  dns: HostDnsResult | null;
  errors: { addresses: string | null; dns: string | null; tls: string | null; http: string | null };
  host: string;
  http: {
    finalStatus: number;
    securityFindings: string[];
    technologies: string[];
    bodyInspection: HttpProbeResult['bodyInspection'];
  } | null;
  tls: {
    protocol: string | null;
    daysUntilExpiry: number | null;
    validationAuthorized: boolean;
    identityAuthorized: boolean | null;
    identityError: string | null;
    findings: string[];
  } | null;
}

export const surfaceResource = resource('attacksurface://surface/{domain}', {
  description:
    "Read-once snapshot of a domain's mapped external surface with DNS/TLS/HTTP posture for up to 50 examined live hosts. Candidate resolution reserves the apex before applying the server cap; coverage distinguishes unexamined candidates from omitted host detail and supplies executable follow-up calls. Assess only assets you own or are authorized to test.",
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
    let discoveryFailed = false;

    const apexSans = await getTlsService()
      .getSans(domain, undefined, undefined, ctx.signal)
      .catch((error) => {
        ctx.signal?.throwIfAborted();
        discoveryFailed = !isTlsSourceAbsent(error);
        notes.push(
          `TLS-SAN discovery failed: ${error instanceof Error ? error.message : String(error)}`,
        );
        return [] as string[];
      });
    const ct = await getCtService()
      .enumerate(domain, ['crt.sh', 'certspotter', 'tls-san'], ctx, apexSans)
      .catch((error) => {
        ctx.signal?.throwIfAborted();
        discoveryFailed = true;
        notes.push(
          `CT enumeration failed: ${error instanceof Error ? error.message : String(error)}`,
        );
        return { domain, names: [], sourceStatuses: [] };
      });

    for (const source of ct.sourceStatuses) {
      if (!source.ok) notes.push(`CT source ${source.source} failed: ${source.sourceError}`);
      else if (source.complete === false)
        notes.push(
          `CT source ${source.source} incomplete: ${source.incompleteReason}; pages=${source.pagesFetched}; error=${source.sourceError ?? 'none'}`,
        );
    }
    const candidates = [
      domain,
      ...[...new Set(ct.names.map((n) => n.name))].filter((name) => name !== domain).sort(),
    ];
    const cap = Math.min(config.maxSubdomains, candidates.length);
    const capped = candidates.slice(0, cap);
    const attempts = await discoveryPool(
      capped,
      (h) => dns.resolveAddressStatus(h, undefined, ctx.signal),
      ctx.signal,
    );
    const addressStatuses = capped.map((host) => ({
      host,
      addresses: attempts.get(host)?.value?.addresses ?? [],
      addressError: attempts.get(host)?.error ?? attempts.get(host)?.value?.addressError ?? null,
    }));
    const liveness = new Map(addressStatuses.map((r) => [r.host, r.addresses]));
    for (const r of addressStatuses)
      if (r.addressError) notes.push(`${r.host}: address lookup failed: ${r.addressError}`);
    const liveNames = capped.filter((h) => (liveness.get(h)?.length ?? 0) > 0);

    if (candidates.length === 1 && liveNames.length === 0) {
      if (
        ct.sourceStatuses.some((s) => !s.ok || s.complete === false) ||
        addressStatuses.some((r) => r.addressError) ||
        discoveryFailed
      )
        throw serviceUnavailable(`Discovery failed for "${domain}": ${notes.join('; ')}`, {
          reason: 'discovery_failed',
        });
      throw notFound(
        `No surface found for "${domain}" — no subdomains and the apex did not resolve.`,
      );
    }

    const detailNames = liveNames.slice(0, HOST_DETAIL_CAP);
    const [tlsAttempts, httpResults, dnsResults] = await Promise.all([
      discoveryPool(
        detailNames,
        async (h) => (await getTlsService().inspectHosts([h], undefined, undefined, ctx.signal))[0],
        ctx.signal,
      ),
      discoveryPool(
        detailNames,
        (h) => getHttpService().probe(`https://${h}`, undefined, 10000, ctx),
        ctx.signal,
      ),
      discoveryPool(
        detailNames,
        async (h) =>
          (
            await dns.resolveHosts(
              [h],
              ALL_RECORD_TYPES,
              parseResolverList(config.defaultResolvers),
              false,
              undefined,
              ctx.signal,
            )
          )[0],
        ctx.signal,
      ),
    ]);
    const tlsResults = [...tlsAttempts.values()].flatMap((r) => (r.value ? [r.value] : []));
    const tlsByHost = new Map(tlsResults.map((r) => [r.host, r]));

    const hosts: HostSummary[] = detailNames.map((host) => {
      const tlsR = tlsByHost.get(host);
      const httpR = httpResults.get(host)?.value;
      const dnsR = dnsResults.get(host);
      const errors = {
        addresses: addressStatuses.find((r) => r.host === host)?.addressError ?? null,
        dns: dnsR?.error ?? dnsR?.value?.hostError ?? null,
        tls: tlsAttempts.get(host)?.error ?? tlsR?.handshakeError ?? null,
        http: httpResults.get(host)?.error ?? httpR?.transportError ?? null,
      };
      for (const [leg, error] of Object.entries(errors))
        if (error) notes.push(`${host}: ${leg} failed: ${error}`);
      return {
        host,
        dns: dnsR?.value ?? null,
        errors,
        addresses: liveness.get(host) ?? [],
        tls:
          tlsR && !tlsR.handshakeError
            ? {
                protocol: tlsR.protocol,
                daysUntilExpiry: tlsR.certificate?.daysUntilExpiry ?? null,
                validationAuthorized: tlsR.validationAuthorized,
                identityAuthorized: tlsR.identityAuthorized,
                identityError: tlsR.identityError,
                findings: tlsR.findings,
              }
            : null,
        http:
          httpR && !httpR.transportError
            ? {
                finalStatus: httpR.finalStatus,
                bodyInspection: httpR.bodyInspection,
                securityFindings: httpR.securityAudit.findings,
                technologies: httpR.technologies.map(
                  (t) => `${t.name}${t.version ? ` ${t.version}` : ''}`,
                ),
              }
            : null,
      };
    });

    const omitted = liveNames.length - detailNames.length;
    if (candidates.length > capped.length)
      notes.push(
        `Candidate resolution capped at ${cap} of ${candidates.length}; inspect coverage.unexamined and coverage.retrieval.`,
      );
    if (omitted > 0) {
      notes.push(
        `Host detail capped at ${HOST_DETAIL_CAP}; ${omitted} further live host(s) omitted; inspect coverage.detailOmitted and coverage.retrieval.`,
      );
    }

    return {
      domain,
      subdomainCount: ct.names.length,
      liveHostCount: liveNames.length,
      hosts,
      notes,
      addressStatuses,
      coverage: discoveryCoverage(
        candidates,
        capped,
        detailNames,
        liveNames.slice(HOST_DETAIL_CAP),
      ),
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
