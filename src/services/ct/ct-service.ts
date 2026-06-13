/**
 * @fileoverview Certificate Transparency service — passive subdomain discovery from issued certs.
 * crt.sh is primary (richest) but unreliable (frequent 502s); Certspotter is the fallback. Both
 * return arrays of records carrying a `dns_names` string array (verified shape). The TLS-SAN source
 * is a third, always-available fallback supplied by the caller (tls-service). Names are scoped to
 * the apex domain, wildcard-stripped, lower-cased, and deduplicated with source provenance.
 *
 * No DNS brute-forcing: CT enumeration only reads public logs, never touches the target.
 * @module services/ct/ct-service
 */

import type { Context } from '@cyanheads/mcp-ts-core';
import { withRetry } from '@cyanheads/mcp-ts-core/utils';
import type { ServerConfig } from '@/config/server-config.js';
import { toRequestContext } from '@/utils/request-context.js';
import type { CtEnumerationResult, CtSource, CtSourceStatus, DiscoveredName } from './types.js';

const CRTSH_TIMEOUT_MS = 20_000;
const CERTSPOTTER_TIMEOUT_MS = 15_000;

/** A CT log record as returned by crt.sh and Certspotter (only the field we read). */
interface CtRecord {
  dns_names?: string[];
}

/** Normalize a raw cert name: lower-case, strip wildcard prefix and trailing dot, trim. */
function normalizeName(raw: string): string {
  return raw.toLowerCase().trim().replace(/^\*\./, '').replace(/\.$/, '');
}

/** Keep names that are the apex itself or a subdomain of it. */
function inScope(name: string, domain: string): boolean {
  return name === domain || name.endsWith(`.${domain}`);
}

export class CtService {
  constructor(private readonly config: ServerConfig) {}

  /**
   * Enumerate subdomains from CT logs. Runs crt.sh and Certspotter independently; either failing
   * degrades to a per-source status rather than tanking the result. `extraSanNames` (from the
   * TLS-SAN fallback source) are merged in with `tls-san` provenance.
   */
  async enumerate(
    domain: string,
    sources: CtSource[],
    ctx: Context,
    extraSanNames: string[] = [],
  ): Promise<CtEnumerationResult> {
    const apex = normalizeName(domain);
    const byName = new Map<string, Set<CtSource>>();
    const sourceStatuses: CtSourceStatus[] = [];

    const record = (names: string[], source: CtSource): number => {
      let added = 0;
      for (const raw of names) {
        const name = normalizeName(raw);
        if (!name || !inScope(name, apex)) continue;
        const existing = byName.get(name);
        if (existing) {
          existing.add(source);
        } else {
          byName.set(name, new Set([source]));
          added++;
        }
      }
      return added;
    };

    // crt.sh
    if (sources.includes('crt.sh')) {
      try {
        const names = await this.fetchCrtSh(apex, ctx);
        const count = record(names, 'crt.sh');
        sourceStatuses.push({ source: 'crt.sh', ok: true, count, error: null });
      } catch (err) {
        sourceStatuses.push({
          source: 'crt.sh',
          ok: false,
          count: 0,
          error: err instanceof Error ? err.message : String(err),
        });
      }
    }

    // Certspotter
    if (sources.includes('certspotter')) {
      try {
        const names = await this.fetchCertspotter(apex, ctx);
        const count = record(names, 'certspotter');
        sourceStatuses.push({ source: 'certspotter', ok: true, count, error: null });
      } catch (err) {
        sourceStatuses.push({
          source: 'certspotter',
          ok: false,
          count: 0,
          error: err instanceof Error ? err.message : String(err),
        });
      }
    }

    // TLS-SAN (caller-supplied, always "ok" — it's already-resolved data)
    if (sources.includes('tls-san') && extraSanNames.length > 0) {
      const count = record(extraSanNames, 'tls-san');
      sourceStatuses.push({ source: 'tls-san', ok: true, count, error: null });
    }

    const names: DiscoveredName[] = [...byName.entries()]
      .map(([name, set]) => ({ name, sources: [...set].sort() }))
      .sort((a, b) => a.name.localeCompare(b.name));

    return { domain: apex, names, sourceStatuses };
  }

  /** Query crt.sh `/json?q=%.{domain}`. Returns the flattened `dns_names` from every record. */
  private async fetchCrtSh(domain: string, ctx: Context): Promise<string[]> {
    const url = `https://crt.sh/?q=${encodeURIComponent(`%.${domain}`)}&output=json`;
    return await withRetry(
      async () => {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), CRTSH_TIMEOUT_MS);
        const signal = ctx.signal
          ? AbortSignal.any([controller.signal, ctx.signal])
          : controller.signal;
        let res: Response;
        try {
          res = await fetch(url, {
            signal,
            headers: { accept: 'application/json', 'user-agent': this.config.httpUserAgent },
          });
        } finally {
          clearTimeout(timer);
        }
        if (!res.ok) {
          throw new Error(`crt.sh returned HTTP ${res.status}`);
        }
        const text = await res.text();
        // crt.sh occasionally returns an HTML error page with a 200 — detect and treat as transient.
        if (/^\s*<(?:!doctype\s+html|html[\s>])/i.test(text)) {
          throw new Error('crt.sh returned HTML instead of JSON (likely overloaded).');
        }
        const records = JSON.parse(text) as CtRecord[];
        return records.flatMap((r) => r.dns_names ?? []);
      },
      {
        operation: 'ctService.fetchCrtSh',
        context: toRequestContext(ctx, 'ctService.fetchCrtSh'),
        baseDelayMs: 1500,
        maxRetries: 2,
        signal: ctx.signal,
      },
    );
  }

  /**
   * Query Certspotter issuances API with `include_subdomains=true&expand=dns_names`. Uses the key
   * from config as a bearer token when present (raises rate limits), else the free tier.
   */
  private async fetchCertspotter(domain: string, ctx: Context): Promise<string[]> {
    const url =
      `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(domain)}` +
      `&include_subdomains=true&expand=dns_names`;
    const headers: Record<string, string> = {
      accept: 'application/json',
      'user-agent': this.config.httpUserAgent,
    };
    if (this.config.certspotterApiKey) {
      headers.authorization = `Bearer ${this.config.certspotterApiKey}`;
    }
    return await withRetry(
      async () => {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), CERTSPOTTER_TIMEOUT_MS);
        const signal = ctx.signal
          ? AbortSignal.any([controller.signal, ctx.signal])
          : controller.signal;
        let res: Response;
        try {
          res = await fetch(url, { signal, headers });
        } finally {
          clearTimeout(timer);
        }
        if (res.status === 429) {
          throw new Error('Certspotter rate limit hit (set CERTSPOTTER_API_KEY to raise it).');
        }
        if (!res.ok) {
          throw new Error(`Certspotter returned HTTP ${res.status}`);
        }
        const records = (await res.json()) as CtRecord[];
        return records.flatMap((r) => r.dns_names ?? []);
      },
      {
        operation: 'ctService.fetchCertspotter',
        context: toRequestContext(ctx, 'ctService.fetchCertspotter'),
        baseDelayMs: 2000,
        maxRetries: 2,
        signal: ctx.signal,
      },
    );
  }
}

// --- Init/accessor pattern ---

let _service: CtService | undefined;

export function initCtService(config: ServerConfig): void {
  _service = new CtService(config);
}

export function getCtService(): CtService {
  if (!_service) throw new Error('CtService not initialized — call initCtService() in setup()');
  return _service;
}
