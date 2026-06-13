/**
 * @fileoverview Registration/ownership service — RDAP (structured JSON) with a WHOIS (port-43 text)
 * fallback. RDAP runs over the `rdap.org` bootstrap, which 302-redirects to the authoritative
 * registry; the client MUST follow redirects (verified: 8.8.8.8 → rdap.arin.net within ~1s). IP
 * lookups via rdap.org are reliable; domain lookups can hang, so a strict 5s per-request deadline
 * falls back to WHOIS rather than waiting. Every RDAP field is treated as optional (sparse/redacted
 * data is the norm — `country` came back null for ARIN netblocks during design verification).
 * @module services/registration/registration-service
 */

import * as net from 'node:net';

const { isIP } = net;

import type { Context } from '@cyanheads/mcp-ts-core';
import type { ServerConfig } from '@/config/server-config.js';
import { assertSafeUrl, resolveSafeHost } from '@/utils/ssrf-guard.js';
import type {
  DomainRegistration,
  IpRegistration,
  RegistrationEvent,
  RegistrationResult,
} from './types.js';

const RDAP_DEADLINE_MS = 5000;
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
   * Fetch RDAP via the rdap.org bootstrap, following its 302 to the authoritative registry under a
   * strict deadline. Redirects are followed *manually* with `redirect: 'manual'` so every hop —
   * including registry-controlled `Location` targets — passes the SSRF guard before connecting; a
   * compromised or malicious bootstrap/registry cannot redirect the probe at an internal address.
   */
  private async fetchRdap(
    target: string,
    kind: 'ip' | 'domain',
    ctx: Context,
  ): Promise<RdapResponse> {
    const base = this.config.rdapBootstrapUrl.replace(/\/$/, '');
    const path =
      kind === 'ip' ? `ip/${encodeURIComponent(target)}` : `domain/${encodeURIComponent(target)}`;
    let url = `${base}/${path}`;

    // One deadline across the whole redirect chain.
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), RDAP_DEADLINE_MS);
    const signal = ctx.signal
      ? AbortSignal.any([controller.signal, ctx.signal])
      : controller.signal;

    try {
      for (let hop = 0; hop <= MAX_RDAP_REDIRECTS; hop++) {
        // SSRF guard on every hop target (also enforces http/https scheme).
        await assertSafeUrl(url);

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
      }
      // Unreachable — the loop returns or throws.
      throw new Error('RDAP: redirect handling fell through.');
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * WHOIS fallback over port 43. Queries IANA first to discover the authoritative WHOIS server,
   * then queries it. Best-effort: a single referral hop, strict deadline. Returns the raw text.
   */
  private async fetchWhois(target: string, ctx: Context): Promise<string> {
    const ianaText = await this.whoisQuery(WHOIS_IANA, target, ctx);
    const referMatch = /^(?:refer|whois):\s*(\S+)/im.exec(ianaText);
    const referral = referMatch?.[1]?.trim();
    if (referral && referral !== WHOIS_IANA) {
      try {
        const authoritative = await this.whoisQuery(referral, target, ctx);
        if (authoritative.trim().length > 0) return authoritative;
      } catch {
        // Fall through to the IANA response.
      }
    }
    return ianaText;
  }

  /**
   * Single WHOIS TCP query to one server. Resolves with the accumulated text. The server host is
   * SSRF-guarded and the connection pinned to a validated IP before connecting — the referral server
   * is parsed from IANA's response (registry-controlled), so a malicious referral (or a rebinding
   * DNS answer) cannot point the port-43 connection at an internal host.
   */
  private async whoisQuery(server: string, query: string, ctx: Context): Promise<string> {
    const connectHost = (await resolveSafeHost(server)) ?? server;
    return new Promise((resolve, reject) => {
      let data = '';
      let settled = false;
      const socket = net.createConnection(WHOIS_PORT, connectHost);

      const finish = (err?: Error) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
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
    const statuses = [...text.matchAll(/^\s*(?:Domain Status|status):\s*(.+)$/gim)]
      .map((m) => (m[1] ?? '').trim().split(/\s+/)[0] ?? '')
      .filter(Boolean);
    const events: RegistrationEvent[] = [];
    const created = /^\s*(?:Creation Date|created|Registered on):\s*(.+)$/im
      .exec(text)?.[1]
      ?.trim();
    const expiry = /^\s*(?:Registry Expiry Date|Expiry date|paid-till|Expiration Date):\s*(.+)$/im
      .exec(text)?.[1]
      ?.trim();
    const updated = /^\s*(?:Updated Date|last-update|changed):\s*(.+)$/im.exec(text)?.[1]?.trim();
    if (created) events.push({ action: 'registration', date: created });
    if (expiry) events.push({ action: 'expiration', date: expiry });
    if (updated) events.push({ action: 'last changed', date: updated });
    const registrar = /^\s*(?:Registrar|registrar):\s*(.+)$/im.exec(text)?.[1]?.trim();
    const nameservers = [...text.matchAll(/^\s*(?:Name Server|nserver|nameserver):\s*(\S+)/gim)]
      .map((m) => (m[1] ?? '').toLowerCase())
      .filter(Boolean);
    const dnssec = /^\s*DNSSEC:\s*(.+)$/im.exec(text)?.[1]?.trim().toLowerCase();

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
    const networkName = /^\s*(?:NetName|netname|network:Network-Name):\s*(.+)$/im
      .exec(text)?.[1]
      ?.trim();
    const cidrMatches = [...text.matchAll(/^\s*(?:CIDR|inetnum|route):\s*(.+)$/gim)]
      .map((m) => (m[1] ?? '').trim())
      .filter(Boolean);
    const asnMatches = [...text.matchAll(/^\s*(?:OriginAS|origin):\s*AS?(\d+)/gim)]
      .map((m) => Number.parseInt(m[1] ?? '', 10))
      .filter((n) => Number.isFinite(n));
    const country = /^\s*(?:Country|country):\s*([A-Za-z]{2})\b/im.exec(text)?.[1]?.toUpperCase();

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
