/**
 * @fileoverview attacksurface_map_domain — the flagship workflow. Maps a domain's external surface
 * end to end: CT-log subdomain discovery → DNS resolution of each candidate → (standard+) DNS
 * records, TLS posture, and HTTP headers/tech for live hosts → (when requested) RDAP/WHOIS
 * registration → (thorough + Shodan key) per-IP Shodan enrichment. All fan-out uses
 * Promise.allSettled so one failed source/host degrades to a note, never tanks the call. The
 * assessment block synthesizes only observable facts — never an exploitation path.
 *
 * Authorized, defensive use only: map only assets you own or are explicitly authorized to assess.
 * @module mcp-server/tools/definitions/map-domain.tool
 */

import type { Context } from '@cyanheads/mcp-ts-core';
import { tool, z } from '@cyanheads/mcp-ts-core';
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { getServerConfig } from '@/config/server-config.js';
import { getCtService } from '@/services/ct/ct-service.js';
import { getDnsService } from '@/services/dns/dns-service.js';
import { getHttpService } from '@/services/http/http-service.js';
import type { HttpProbeResult } from '@/services/http/types.js';
import { getRegistrationService } from '@/services/registration/registration-service.js';
import type { DomainRegistration, IpRegistration } from '@/services/registration/types.js';
import { getShodanService } from '@/services/shodan/shodan-service.js';
import type { ShodanHostResult } from '@/services/shodan/types.js';
import { getTlsService } from '@/services/tls/tls-service.js';
import type { TlsResult } from '@/services/tls/types.js';
import { isValidDomain, normalizeDomain } from '@/utils/validation.js';

const CONCURRENCY = 10;

const LiveHostSchema = z
  .object({
    host: z.string().describe('Subdomain hostname.'),
    addresses: z.array(z.string()).describe('Resolved IP addresses.'),
    tls: z
      .object({
        protocol: z.string().nullable().describe('Negotiated TLS protocol.'),
        cipher: z.string().nullable().describe('Negotiated cipher.'),
        issuer: z.string().nullable().describe('Certificate issuer common name.'),
        daysUntilExpiry: z.number().nullable().describe('Days until certificate expiry.'),
        validationAuthorized: z
          .boolean()
          .describe('Whether the chain validated against the trust store.'),
        findings: z.array(z.string()).describe('TLS posture findings.'),
      })
      .nullable()
      .describe(
        'TLS posture summary (standard+ depth), or null when not inspected/handshake failed.',
      ),
    http: z
      .object({
        finalStatus: z.number().describe('Final HTTP status after redirects.'),
        finalUrl: z.string().describe('Final URL after redirects.'),
        securityFindings: z.array(z.string()).describe('Security-header findings.'),
        technologies: z
          .array(
            z
              .object({
                name: z.string().describe('Technology name.'),
                category: z.string().describe('Detection category.'),
                version: z.string().optional().describe('Version when disclosed.'),
              })
              .describe('A detected technology (name/category/version).'),
          )
          .describe('Technology detections (name/category/version).'),
      })
      .nullable()
      .describe('HTTP posture summary (standard+ depth), or null when not probed/unreachable.'),
    shodan: z
      .object({
        ports: z.array(z.number()).describe("Open ports per Shodan's last scan."),
        lastUpdate: z.string().optional().describe('Shodan scan timestamp.'),
      })
      .nullable()
      .describe('Shodan enrichment (thorough depth + key), or null otherwise.'),
  })
  .describe('Posture summary for one live host.');

const RegistrationSummarySchema = z.object({
  source: z.enum(['rdap', 'whois']).describe('Source that answered.'),
  registrar: z.string().optional().describe('Registrar (domain lookups).'),
  statuses: z.array(z.string()).describe('Registry status codes.'),
  expiry: z.string().optional().describe('Expiration date when present.'),
  nameservers: z.array(z.string()).describe('Nameservers (domain lookups).'),
});

export const mapDomainTool = tool('attacksurface_map_domain', {
  title: 'attacksurface_map_domain',
  description:
    "Flagship workflow: map a domain's external attack surface end to end. Discovers subdomains from Certificate Transparency logs, resolves each to find live hosts, and (at standard+ depth) characterizes each live host's DNS records, TLS posture, and HTTP security headers and technology stack, plus optional RDAP/WHOIS registration. At thorough depth with a Shodan key it adds per-IP Shodan enrichment. Returns a structured surface map and a defensive assessment of observable facts (expiring certs, missing security headers, weak TLS) — never an exploitation plan. All work is passive (public records and the target's own published responses) and SSRF-guarded. Assess only assets you own or are explicitly authorized to test.",
  annotations: { readOnlyHint: true, openWorldHint: true },
  input: z.object({
    domain: z.string().describe('Apex domain to map (e.g. "example.com").'),
    depth: z
      .enum(['quick', 'standard', 'thorough'])
      .default('standard')
      .describe(
        '"quick" = subdomains + liveness only; "standard" = + DNS/TLS/HTTP posture; "thorough" = + Shodan enrichment (when keyed).',
      ),
    includeRegistration: z
      .boolean()
      .default(true)
      .describe(
        'When true (and depth is standard+), include RDAP/WHOIS registration for the apex.',
      ),
  }),
  output: z.object({
    domain: z.string().describe('Apex domain mapped (normalized).'),
    depth: z.enum(['quick', 'standard', 'thorough']).describe('Depth that was executed.'),
    subdomainCount: z.number().describe('Total distinct subdomains discovered.'),
    liveHostCount: z.number().describe('Count of subdomains that resolved to an address.'),
    liveHosts: z.array(LiveHostSchema).describe('Per-live-host posture.'),
    unresolvedSubdomains: z.array(z.string()).describe('Discovered names that did not resolve.'),
    registration: RegistrationSummarySchema.nullable().describe(
      'Apex registration summary, or null.',
    ),
    assessment: z
      .array(z.string())
      .describe('Observable posture findings synthesized across the surface.'),
    notes: z
      .array(z.string())
      .describe('Operational notes (skipped sources, degraded steps, Shodan absence).'),
  }),
  enrichment: {
    truncated: z.boolean().optional().describe('True when subdomain resolution was capped.'),
    shown: z.number().optional().describe('Number of subdomains resolved after the cap.'),
    cap: z.number().optional().describe('The ATTACKSURFACE_MAX_SUBDOMAINS cap applied.'),
    notice: z.string().optional().describe('Guidance when no subdomains or live hosts were found.'),
  },
  errors: [
    {
      reason: 'invalid_domain',
      code: JsonRpcErrorCode.ValidationError,
      when: 'The supplied domain is not a syntactically valid registrable domain.',
      recovery: 'Provide a bare apex domain such as "example.com" (no scheme, path, or wildcard).',
    },
    {
      reason: 'no_surface',
      code: JsonRpcErrorCode.NotFound,
      when: 'No subdomains were discovered and the apex did not resolve.',
      retryable: true,
      recovery:
        'Verify the domain. CT sources may be transiently down — retry, or use resolve_dns on the apex directly.',
    },
  ],

  async handler(input, ctx) {
    const domain = normalizeDomain(input.domain);
    if (!isValidDomain(domain)) {
      throw ctx.fail('invalid_domain', `"${input.domain}" is not a valid domain.`, {
        ...ctx.recoveryFor('invalid_domain'),
      });
    }

    const config = getServerConfig();
    const notes: string[] = [];
    const dns = getDnsService();

    // Step 1 — CT enumeration (always). TLS-SAN source needs the apex's SANs.
    const apexSans = await getTlsService()
      .getSans(domain)
      .catch(() => [] as string[]);
    const ct = await getCtService()
      .enumerate(domain, ['crt.sh', 'certspotter', 'tls-san'], ctx, apexSans)
      .catch((err) => {
        notes.push(`CT enumeration failed: ${err instanceof Error ? err.message : String(err)}`);
        return { domain, names: [], sourceStatuses: [] };
      });
    for (const s of ct.sourceStatuses) {
      if (!s.ok) notes.push(`CT source ${s.source} failed: ${s.sourceError}`);
    }

    // Always include the apex itself as a candidate.
    const candidateSet = new Set<string>([domain, ...ct.names.map((n) => n.name)]);

    // Step 2 — DNS resolution (always), capped.
    const cap = config.maxSubdomains;
    const allCandidates = [...candidateSet].sort();
    const capped = allCandidates.slice(0, cap);
    const wasTruncated = allCandidates.length > cap;
    if (wasTruncated) {
      notes.push(
        `Subdomain set capped at ${cap} of ${allCandidates.length} (ATTACKSURFACE_MAX_SUBDOMAINS).`,
      );
    }

    const liveness = await resolveWithPool(capped, (host) => dns.resolveAddresses(host));
    const liveNames = capped.filter((h) => (liveness.get(h)?.length ?? 0) > 0);
    const unresolved = capped.filter((h) => (liveness.get(h)?.length ?? 0) === 0);

    if (allCandidates.length === 1 && liveNames.length === 0) {
      // Only the apex was a candidate and it didn't resolve — no surface at all.
      throw ctx.fail('no_surface', `No subdomains discovered and "${domain}" did not resolve.`, {
        ...ctx.recoveryFor('no_surface'),
      });
    }

    // Assemble live-host records; posture filled in at standard+.
    const liveHosts = liveNames.map((host) => ({
      host,
      addresses: liveness.get(host) ?? [],
      tls: null as z.infer<typeof LiveHostSchema>['tls'],
      http: null as z.infer<typeof LiveHostSchema>['http'],
      shodan: null as z.infer<typeof LiveHostSchema>['shodan'],
    }));

    const assessment: string[] = [];
    let registration: z.infer<typeof RegistrationSummarySchema> | null = null;

    if (input.depth !== 'quick') {
      // Steps 3–5 — DNS records (apex), TLS + HTTP per live host (parallel, allSettled).
      await Promise.allSettled([enrichTls(liveHosts), enrichHttp(liveHosts, ctx)]);
      collectAssessment(liveHosts, assessment);

      // Step 6 — registration (apex) when requested.
      if (input.includeRegistration) {
        try {
          const reg = await getRegistrationService().lookup(domain, 'domain', ctx);
          registration = summarizeRegistration(reg.registration, reg.source);
          if (reg.notes.length > 0) notes.push(...reg.notes);
          assessExpiry(reg.registration, assessment);
        } catch (err) {
          notes.push(
            `Registration lookup failed: ${err instanceof Error ? err.message : String(err)}`,
          );
        }
      }
    }

    // Step 7 — Shodan enrichment (thorough + key), opportunistic.
    if (input.depth === 'thorough') {
      const shodan = getShodanService();
      if (shodan.isConfigured()) {
        await enrichShodan(liveHosts, ctx, notes);
      } else {
        notes.push('Shodan enrichment skipped: no API key (set SHODAN_API_KEY to enable).');
      }
    }

    if (wasTruncated) {
      ctx.enrich.truncated({ shown: capped.length, cap });
    }
    if (liveNames.length === 0) {
      ctx.enrich.notice(
        `Discovered ${ct.names.length} subdomain(s) for "${domain}" but none resolved to an address.`,
      );
    }

    return {
      domain,
      depth: input.depth,
      subdomainCount: ct.names.length,
      liveHostCount: liveNames.length,
      liveHosts,
      unresolvedSubdomains: unresolved,
      registration,
      assessment,
      notes,
    };
  },

  format: (result) => {
    const lines: string[] = [];
    lines.push(`# Attack surface: ${result.domain}`);
    lines.push(
      `**Depth:** ${result.depth} | **Subdomains:** ${result.subdomainCount} | **Live hosts:** ${result.liveHostCount}`,
    );

    if (result.registration) {
      const r = result.registration;
      lines.push('## Registration');
      lines.push(`- **Source:** ${r.source}`);
      if (r.registrar) lines.push(`- **Registrar:** ${r.registrar}`);
      if (r.expiry) lines.push(`- **Expiry:** ${r.expiry}`);
      if (r.statuses.length > 0) lines.push(`- **Status:** ${r.statuses.join(', ')}`);
      if (r.nameservers.length > 0) lines.push(`- **Nameservers:** ${r.nameservers.join(', ')}`);
    }

    if (result.assessment.length > 0) {
      lines.push('## Assessment (observable findings)');
      for (const a of result.assessment) lines.push(`- ${a}`);
    }

    lines.push('## Live hosts');
    for (const h of result.liveHosts) {
      lines.push(`### ${h.host}`);
      lines.push(`**Addresses:** ${h.addresses.join(', ')}`);
      if (h.tls) {
        lines.push(
          `**TLS:** ${h.tls.protocol ?? 'unknown'} / ${h.tls.cipher ?? 'unknown'} · issuer ${h.tls.issuer ?? 'unknown'} · ${h.tls.daysUntilExpiry ?? 'unknown'} days left · validationAuthorized=${h.tls.validationAuthorized}`,
        );
        if (h.tls.findings.length > 0) lines.push(`  - ${h.tls.findings.join(' ')}`);
      }
      if (h.http) {
        lines.push(`**HTTP:** ${h.http.finalStatus} → ${h.http.finalUrl}`);
        if (h.http.technologies.length > 0) {
          lines.push(
            `  - Tech: ${h.http.technologies.map((t) => `${t.name}${t.version ? ` ${t.version}` : ''} (${t.category})`).join(', ')}`,
          );
        }
        if (h.http.securityFindings.length > 0) {
          lines.push(`  - Security: ${h.http.securityFindings.join(' ')}`);
        }
      }
      if (h.shodan) {
        lines.push(
          `**Shodan ports:** ${h.shodan.ports.join(', ') || 'none'}${h.shodan.lastUpdate ? ` (scanned ${h.shodan.lastUpdate})` : ''}`,
        );
      }
    }

    if (result.unresolvedSubdomains.length > 0) {
      lines.push(`## Unresolved subdomains (${result.unresolvedSubdomains.length})`);
      lines.push(result.unresolvedSubdomains.join(', '));
    }

    if (result.notes.length > 0) {
      lines.push('## Notes');
      for (const n of result.notes) lines.push(`- ${n}`);
    }

    return [{ type: 'text', text: lines.join('\n') }];
  },
});

/** Bounded-concurrency map over hosts. */
async function resolveWithPool<T>(
  hosts: string[],
  fn: (host: string) => Promise<T>,
): Promise<Map<string, T>> {
  const out = new Map<string, T>();
  let index = 0;
  const workers = Array.from({ length: Math.min(CONCURRENCY, hosts.length) }, async () => {
    while (index < hosts.length) {
      const i = index++;
      const host = hosts[i];
      if (!host) continue;
      try {
        out.set(host, await fn(host));
      } catch {
        // Per-host failure is recorded as an empty/absent result by the caller.
      }
    }
  });
  await Promise.all(workers);
  return out;
}

type LiveHost = {
  host: string;
  addresses: string[];
  tls: z.infer<typeof LiveHostSchema>['tls'];
  http: z.infer<typeof LiveHostSchema>['http'];
  shodan: z.infer<typeof LiveHostSchema>['shodan'];
};

/** Inspect TLS for each live host and fold a summary into the record. */
async function enrichTls(hosts: LiveHost[]): Promise<void> {
  const results = await getTlsService().inspectHosts(hosts.map((h) => h.host));
  const byHost = new Map<string, TlsResult>(results.map((r) => [r.host, r]));
  for (const h of hosts) {
    const r = byHost.get(h.host);
    if (!r || r.handshakeError) continue;
    h.tls = {
      protocol: r.protocol,
      cipher: r.cipher,
      issuer: r.certificate?.issuerCommonName ?? null,
      daysUntilExpiry: r.certificate?.daysUntilExpiry ?? null,
      validationAuthorized: r.validationAuthorized,
      findings: r.findings,
    };
  }
}

/** Probe HTTPS for each live host and fold a summary into the record. */
async function enrichHttp(hosts: LiveHost[], ctx: Context): Promise<void> {
  const http = getHttpService();
  const results = await resolveWithPool(
    hosts.map((h) => h.host),
    (host) => http.probe(`https://${host}`, undefined, 10000, ctx),
  );
  for (const h of hosts) {
    const r: HttpProbeResult | undefined = results.get(h.host);
    if (!r || r.transportError) continue;
    h.http = {
      finalStatus: r.finalStatus,
      finalUrl: r.finalUrl,
      securityFindings: r.securityAudit.findings,
      technologies: r.technologies.map((t) => ({
        name: t.name,
        category: t.category,
        ...(t.version ? { version: t.version } : {}),
      })),
    };
  }
}

/** Enrich distinct IPs with Shodan host data, mapping back to hosts. */
async function enrichShodan(hosts: LiveHost[], ctx: Context, notes: string[]): Promise<void> {
  const shodan = getShodanService();
  const distinctIps = [...new Set(hosts.flatMap((h) => h.addresses))];
  const byIp = await resolveWithPool(distinctIps, (ip) => shodan.lookupHost(ip, ctx));
  let enriched = 0;
  for (const h of hosts) {
    const hit = h.addresses
      .map((ip) => byIp.get(ip))
      .find((r): r is ShodanHostResult => Boolean(r));
    if (hit) {
      h.shodan = { ports: hit.ports, ...(hit.lastUpdate ? { lastUpdate: hit.lastUpdate } : {}) };
      enriched++;
    }
  }
  if (enriched === 0 && distinctIps.length > 0) {
    notes.push('Shodan returned no data for any resolved IP (hosts may be unscanned).');
  }
}

/** Synthesize observable posture findings across live hosts (never an exploitation path). */
function collectAssessment(hosts: LiveHost[], assessment: string[]): void {
  for (const h of hosts) {
    if (h.tls?.findings) {
      for (const f of h.tls.findings) assessment.push(`${h.host}: ${f}`);
    }
    if (h.tls && !h.tls.validationAuthorized) {
      assessment.push(`${h.host}: TLS certificate chain did not validate against the trust store.`);
    }
    if (h.http?.securityFindings) {
      for (const f of h.http.securityFindings) assessment.push(`${h.host}: ${f}`);
    }
  }
}

/** Add a registration-expiry finding when the domain expires within 60 days. */
function assessExpiry(reg: DomainRegistration | IpRegistration, assessment: string[]): void {
  if (reg.kind !== 'domain') return;
  const expiryEvent = reg.events.find((e) => e.action === 'expiration');
  if (!expiryEvent) return;
  const expiry = new Date(expiryEvent.date);
  if (Number.isNaN(expiry.getTime())) return;
  const days = Math.floor((expiry.getTime() - Date.now()) / 86_400_000);
  if (days < 0) assessment.push(`Domain registration expired ${Math.abs(days)} day(s) ago.`);
  else if (days < 60) assessment.push(`Domain registration expires in ${days} day(s).`);
}

/** Summarize a registration record for the map's compact registration block. */
function summarizeRegistration(
  reg: DomainRegistration | IpRegistration,
  source: 'rdap' | 'whois',
): z.infer<typeof RegistrationSummarySchema> {
  if (reg.kind === 'domain') {
    const expiry = reg.events.find((e) => e.action === 'expiration')?.date;
    return {
      source,
      ...(reg.registrar ? { registrar: reg.registrar } : {}),
      statuses: reg.statuses,
      ...(expiry ? { expiry } : {}),
      nameservers: reg.nameservers,
    };
  }
  return { source, statuses: reg.statuses, nameservers: [] };
}
