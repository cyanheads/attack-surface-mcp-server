/**
 * @fileoverview Registration/ownership service — RDAP (structured JSON) with a WHOIS (port-43 text)
 * fallback. RDAP runs over the `rdap.org` bootstrap, which 302-redirects to the authoritative
 * registry; the client MUST follow redirects (verified: 8.8.8.8 → rdap.arin.net within ~1s). IP
 * lookups via rdap.org are reliable; domain lookups can hang, so each bootstrap or authoritative
 * hop — SSRF validation and request together — gets a strict 5s timeout before the lookup falls
 * back to WHOIS. Every RDAP field is treated as optional (sparse/redacted data is the norm —
 * `country` came back null for ARIN netblocks during design verification).
 * @module services/registration/registration-service
 */

import * as net from 'node:net';

const { isIP } = net;

import type { Context } from '@cyanheads/mcp-ts-core';
import { notFound, serviceUnavailable } from '@cyanheads/mcp-ts-core/errors';
import type { ServerConfig } from '@/config/server-config.js';
import { assertSafeUrl, resolveSafeHost } from '@/utils/ssrf-guard.js';
import { normalizeAllocation } from './allocations.js';
import type {
  DomainRegistration,
  IpRegistration,
  RegistrationEvent,
  RegistrationResult,
} from './types.js';

const RDAP_HOP_TIMEOUT_MS = 5000;
const WHOIS_DEADLINE_MS = 8000;
const WHOIS_IANA = 'whois.iana.org';
const WHOIS_PORT = 43;
/** RDAP bootstrap 302-redirects to the authoritative registry; a handful of hops covers referrals. */
const MAX_RDAP_REDIRECTS = 5;

/** RDAP JSON shape (only the fields we read; all optional). */
interface RdapResponse {
  arin_originas0_originautnums?: number[];
  cidr0_cidrs?: Array<{ v4prefix?: string; v6prefix?: string; length?: number }>;
  country?: string;
  endAddress?: string;
  entities?: Array<{ roles?: string[]; vcardArray?: unknown; handle?: string }>;
  events?: Array<{ eventAction?: string; eventDate?: string }>;
  handle?: string;
  ldhName?: string;
  name?: string;
  nameservers?: Array<{ ldhName?: string }>;
  secureDNS?: { delegationSigned?: boolean; zoneSigned?: boolean };
  startAddress?: string;
  status?: string[];
}

/** Determine whether a target is an IP/CIDR or a domain name. */
export function classifyTarget(target: string): 'ip' | 'domain' {
  const bare = target.split('/')[0] ?? target;
  return isIP(bare) !== 0 ? 'ip' : 'domain';
}

/** Map RDAP events into normalized {action, date} entries. */
function mapEvents(events: RdapResponse['events']): RegistrationEvent[] {
  if (!events) return [];
  const out: RegistrationEvent[] = [];
  for (const e of events) {
    if (e.eventAction && e.eventDate) out.push({ action: e.eventAction, date: e.eventDate });
  }
  return out;
}

/** Extract the registrar name from RDAP entities (role "registrar"). */
function extractRegistrar(entities: RdapResponse['entities']): string | undefined {
  if (!entities) return;
  for (const entity of entities) {
    if (!entity.roles?.includes('registrar')) continue;
    // vcardArray is ["vcard", [ ["version",{},"text","4.0"], ["fn",{},"text","Registrar Name"], ... ]]
    const vcard = entity.vcardArray;
    if (Array.isArray(vcard) && Array.isArray(vcard[1])) {
      for (const field of vcard[1] as unknown[]) {
        if (Array.isArray(field) && field[0] === 'fn' && typeof field[3] === 'string') {
          return field[3];
        }
      }
    }
    if (entity.handle) return entity.handle;
  }
  return;
}

/** Parse an RDAP domain response into a DomainRegistration. */
function parseDomainRdap(target: string, data: RdapResponse): DomainRegistration {
  const registrar = extractRegistrar(data.entities);
  return {
    kind: 'domain',
    target,
    ...(registrar ? { registrar } : {}),
    statuses: data.status ?? [],
    events: mapEvents(data.events),
    nameservers: (data.nameservers ?? [])
      .map((ns) => ns.ldhName)
      .filter((n): n is string => Boolean(n))
      .map((n) => n.toLowerCase()),
    ...(data.secureDNS?.delegationSigned !== undefined
      ? { dnssecSigned: data.secureDNS.delegationSigned }
      : {}),
  };
}

/** Parse an RDAP IP-network response into an IpRegistration. */
function parseIpRdap(target: string, data: RdapResponse): IpRegistration {
  const cidrs = (data.cidr0_cidrs ?? [])
    .map((c) => {
      const prefix = c.v4prefix ?? c.v6prefix;
      return prefix && c.length !== undefined ? `${prefix}/${c.length}` : prefix;
    })
    .filter((c): c is string => Boolean(c));

  return {
    kind: 'ip',
    target,
    ...(data.name ? { networkName: data.name } : data.handle ? { networkName: data.handle } : {}),
    cidrs,
    originAsns: data.arin_originas0_originautnums ?? [],
    ...(data.country ? { country: data.country } : {}),
    statuses: data.status ?? [],
    events: mapEvents(data.events),
  };
}

export class RegistrationService {
  constructor(private readonly config: ServerConfig) {}

  /** Look up registration for a domain or IP/CIDR. RDAP first; WHOIS fallback on hang/failure. */
  async lookup(
    target: string,
    type: 'auto' | 'domain' | 'ip',
    ctx: Context,
  ): Promise<RegistrationResult> {
    const kind = type === 'auto' ? classifyTarget(target) : type;
    const notes: string[] = [];

    try {
      const data = await this.fetchRdap(target, kind, ctx);
      const registration =
        kind === 'ip' ? parseIpRdap(target, data) : parseDomainRdap(target, data);
      return { source: 'rdap', registration, rawWhois: null, notes };
    } catch (err) {
      if (ctx.signal?.aborted) throw err;
      const msg = err instanceof Error ? err.message : String(err);
      notes.push(`RDAP lookup failed (${msg}); fell back to WHOIS.`);
    }

    // WHOIS fallback.
    const rawWhois = await this.fetchWhois(target.split('/')[0] ?? target, ctx);
    const registration =
      kind === 'ip' ? this.parseWhoisIp(target, rawWhois) : this.parseWhoisDomain(target, rawWhois);
    return { source: 'whois', registration, rawWhois, notes };
  }

  /**
   * Fetch RDAP via the rdap.org bootstrap, following its 302 to the authoritative registry. Each hop
   * gets a fresh strict timeout covering both SSRF validation and the request, while the redirect cap
   * bounds the full chain. Redirects are followed *manually* with `redirect: 'manual'` so every hop —
   * including registry-controlled `Location` targets — passes the SSRF guard before connecting; a
   * compromised or malicious bootstrap/registry cannot redirect the probe at an internal address.
   */
  private async fetchRdap(
    target: string,
    kind: 'ip' | 'domain',
    ctx: Context,
  ): Promise<RdapResponse> {
    const base = this.config.rdapBootstrapUrl.replace(/\/$/, '');
    const path = kind === 'ip' ? `ip/${target}` : `domain/${encodeURIComponent(target)}`;
    let url = `${base}/${path}`;

    for (let hop = 0; hop <= MAX_RDAP_REDIRECTS; hop++) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), RDAP_HOP_TIMEOUT_MS);
      const signal = ctx.signal
        ? AbortSignal.any([controller.signal, ctx.signal])
        : controller.signal;

      try {
        // SSRF guard on every hop target (also enforces http/https scheme).
        await assertSafeUrl(url, signal);

        const res = await fetch(url, {
          signal,
          redirect: 'manual',
          headers: {
            accept: 'application/rdap+json, application/json',
            'user-agent': this.config.httpUserAgent,
          },
        });

        const location = res.headers.get('location');
        if (res.status >= 300 && res.status < 400 && location) {
          if (hop === MAX_RDAP_REDIRECTS) {
            throw new Error(`RDAP exceeded ${MAX_RDAP_REDIRECTS} redirects.`);
          }
          await res.body?.cancel().catch(() => {});
          url = new URL(location, url).toString();
          continue;
        }

        if (res.status === 404) throw new Error('RDAP: target not found in any registry.');
        if (!res.ok) throw new Error(`RDAP returned HTTP ${res.status}`);
        return (await res.json()) as RdapResponse;
      } finally {
        clearTimeout(timer);
      }
    }
    // Unreachable — the loop returns or throws.
    throw new Error('RDAP: redirect handling fell through.');
  }

  /**
   * WHOIS fallback over port 43. Queries IANA first to discover the authoritative WHOIS server,
   * then queries it. Only the authoritative response may describe the target.
   */
  private async fetchWhois(target: string, ctx: Context): Promise<string> {
    let authoritative: string;
    try {
      const ianaText = await this.whoisQuery(WHOIS_IANA, target, ctx);
      const referral = /^(?:refer|whois):[ \t]*(\S+)/im.exec(ianaText)?.[1];
      if (!referral || referral.toLowerCase() === WHOIS_IANA) {
        throw new Error('IANA did not supply an authoritative WHOIS referral.');
      }
      authoritative = await this.whoisQuery(referral, target, ctx);
      if (!authoritative.trim()) throw new Error('Authoritative WHOIS returned an empty response.');
    } catch (cause) {
      ctx.signal?.throwIfAborted();
      throw serviceUnavailable(
        `WHOIS lookup unavailable: ${cause instanceof Error ? cause.message : String(cause)}`,
        { reason: 'source_unavailable' },
        { cause },
      );
    }
    if (
      /^[ \t]*(?:%[ \t]*)?(?:no match(?:\s|$)|not found\b|no entries found\b|no data found\b|no object found\b|no such domain\b)/im.test(
        authoritative,
      )
    ) {
      throw notFound(`No registration found for ${target}.`, { reason: 'no_match' });
    }
    const fields =
      classifyTarget(target) === 'ip'
        ? /^[ \t]*(?:NetName|netname|network:Network-Name|CIDR|inetnum|inet6num|route|route6|OriginAS|origin|Country|country|NetRange|netblock|network:IP-Network|network:ID|handle):[ \t]*\S/im
        : /^[ \t]*(?:Domain Name|domain|Registrar|registrar|Domain Status|status|Creation Date|created|Registered on|Registry Expiry Date|Expiry date|paid-till|Expiration Date|Updated Date|last-update|changed|Name Server|nserver|nameserver|DNSSEC|Registry Domain ID):[ \t]*\S/im;
    if (!fields.test(authoritative)) {
      throw serviceUnavailable('Authoritative WHOIS returned unrecognized registration text.', {
        reason: 'source_unavailable',
      });
    }
    return authoritative;
  }

  /**
   * Single WHOIS TCP query to one server. Resolves with the accumulated text. The server host is
   * SSRF-guarded and the connection pinned to a validated IP before connecting — the referral server
   * is parsed from IANA's response (registry-controlled), so a malicious referral (or a rebinding
   * DNS answer) cannot point the port-43 connection at an internal host.
   */
  private async whoisQuery(server: string, query: string, ctx: Context): Promise<string> {
    ctx.signal?.throwIfAborted();
    const connectHost = (await resolveSafeHost(server)) ?? server;
    ctx.signal?.throwIfAborted();
    return new Promise((resolve, reject) => {
      let data = '';
      let settled = false;
      const socket = net.createConnection(WHOIS_PORT, connectHost);

      const finish = (err?: Error) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        ctx.signal?.removeEventListener('abort', onAbort);
        socket.destroy();
        if (err) reject(err);
        else resolve(data);
      };

      const timer = setTimeout(
        () => finish(new Error(`WHOIS ${server} timed out`)),
        WHOIS_DEADLINE_MS,
      );

      const onAbort = () => finish(new Error('WHOIS query aborted'));
      if (ctx.signal) ctx.signal.addEventListener('abort', onAbort, { once: true });

      socket.setEncoding('utf8');
      socket.on('connect', () => socket.write(`${query}\r\n`));
      socket.on('data', (chunk) => {
        data += chunk;
      });
      socket.on('end', () => finish());
      socket.on('error', (err) => finish(err));
    });
  }

  /** Best-effort parse of WHOIS domain text into the structured shape. */
  private parseWhoisDomain(target: string, text: string): DomainRegistration {
    const statuses = [...text.matchAll(/^[ \t]*(?:Domain Status|status):[ \t]*(\S[^\r\n]*)$/gim)]
      .map((m) => (m[1] ?? '').trim().split(/\s+/)[0] ?? '')
      .filter(Boolean);
    const events: RegistrationEvent[] = [];
    const created = /^[ \t]*(?:Creation Date|created|Registered on):[ \t]*(\S[^\r\n]*)$/im
      .exec(text)?.[1]
      ?.trim();
    const expiry =
      /^[ \t]*(?:Registry Expiry Date|Expiry date|paid-till|Expiration Date):[ \t]*(\S[^\r\n]*)$/im
        .exec(text)?.[1]
        ?.trim();
    const updated = /^[ \t]*(?:Updated Date|last-update|changed):[ \t]*(\S[^\r\n]*)$/im
      .exec(text)?.[1]
      ?.trim();
    if (created) events.push({ action: 'registration', date: created });
    if (expiry) events.push({ action: 'expiration', date: expiry });
    if (updated) events.push({ action: 'last changed', date: updated });
    const registrar = /^[ \t]*(?:Registrar|registrar):[ \t]*(\S[^\r\n]*)$/im
      .exec(text)?.[1]
      ?.trim();
    const nameservers = [
      ...text.matchAll(/^[ \t]*(?:Name Server|nserver|nameserver):[ \t]*(\S+)/gim),
    ]
      .map((m) => (m[1] ?? '').toLowerCase())
      .filter(Boolean);
    const dnssec = /^[ \t]*DNSSEC:[ \t]*(\S[^\r\n]*)$/im.exec(text)?.[1]?.trim().toLowerCase();

    return {
      kind: 'domain',
      target,
      ...(registrar ? { registrar } : {}),
      statuses: [...new Set(statuses)],
      events,
      nameservers: [...new Set(nameservers)],
      ...(dnssec
        ? { dnssecSigned: dnssec.includes('signed') && !dnssec.includes('unsigned') }
        : {}),
    };
  }

  /** Best-effort parse of WHOIS IP text into the structured shape. */
  private parseWhoisIp(target: string, text: string): IpRegistration {
    const networkName = /^[ \t]*(?:NetName|netname|network:Network-Name):[ \t]*(\S[^\r\n]*)$/im
      .exec(text)?.[1]
      ?.trim();
    const cidrMatches = [
      ...text.matchAll(/^[ \t]*(?:CIDR|inetnum|inet6num|route|route6):[ \t]*(\S[^\r\n]*)$/gim),
    ].flatMap((m) => normalizeAllocation((m[1] ?? '').trim()));
    const asnMatches = [...text.matchAll(/^[ \t]*(?:OriginAS|origin):[ \t]*AS?(\d+)/gim)]
      .map((m) => Number.parseInt(m[1] ?? '', 10))
      .filter((n) => Number.isFinite(n));
    const country = /^[ \t]*(?:Country|country):[ \t]*([A-Za-z]{2})\b/im
      .exec(text)?.[1]
      ?.toUpperCase();

    return {
      kind: 'ip',
      target,
      ...(networkName ? { networkName } : {}),
      cidrs: [...new Set(cidrMatches)],
      originAsns: [...new Set(asnMatches)],
      ...(country ? { country } : {}),
      statuses: [],
      events: [],
    };
  }
}

// --- Init/accessor pattern ---

let _service: RegistrationService | undefined;

export function initRegistrationService(config: ServerConfig): void {
  _service = new RegistrationService(config);
}

export function getRegistrationService(): RegistrationService {
  if (!_service) {
    throw new Error(
      'RegistrationService not initialized — call initRegistrationService() in setup()',
    );
  }
  return _service;
}
