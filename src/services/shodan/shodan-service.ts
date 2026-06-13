/**
 * @fileoverview Shodan service — optional-key host intelligence and faceted search. Single-host
 * lookups use the free `/shodan/host/{ip}` endpoint; faceted search uses `/shodan/host/search`
 * (consumes paid query credits). When `SHODAN_API_KEY` is absent the service reports
 * `isConfigured() === false` so the one calling tool can degrade with a typed `source_unavailable`
 * error while the rest of the server stays fully functional. Shodan data is as fresh as Shodan's
 * last scan — never presented as a live port state (this server never scans ports itself).
 * @module services/shodan/shodan-service
 */

import type { Context } from '@cyanheads/mcp-ts-core';
import { withRetry } from '@cyanheads/mcp-ts-core/utils';
import type { ServerConfig } from '@/config/server-config.js';
import { toRequestContext } from '@/utils/request-context.js';
import type {
  ShodanHostResult,
  ShodanSearchMatch,
  ShodanSearchResult,
  ShodanService as ShodanServiceBanner,
} from './types.js';

const BASE_URL = 'https://api.shodan.io';
const TIMEOUT_MS = 15_000;
const BANNER_LIMIT = 512;

/** Raw Shodan host response (subset). */
interface RawShodanHost {
  asn?: string;
  country_code?: string;
  data?: Array<{
    port?: number;
    transport?: string;
    product?: string;
    version?: string;
    data?: string;
    timestamp?: string;
  }>;
  hostnames?: string[];
  ip_str?: string;
  last_update?: string;
  org?: string;
  ports?: number[];
}

/** Raw Shodan search response (subset). */
interface RawShodanSearch {
  facets?: Record<string, Array<{ value?: string | number; count?: number }>>;
  matches?: Array<{
    ip_str?: string;
    port?: number;
    product?: string;
    org?: string;
    location?: { country_code?: string };
  }>;
  total?: number;
}

export class ShodanService {
  constructor(private readonly config: ServerConfig) {}

  /** True when a Shodan API key is configured. */
  isConfigured(): boolean {
    return Boolean(this.config.shodanApiKey);
  }

  /** Single-host lookup via the free host endpoint. Caller must check `isConfigured()` first. */
  async lookupHost(ip: string, ctx: Context): Promise<ShodanHostResult> {
    const key = this.requireKey();
    const url = `${BASE_URL}/shodan/host/${encodeURIComponent(ip)}?key=${encodeURIComponent(key)}`;
    const raw = await this.fetchJson<RawShodanHost>(url, ctx, 'shodanService.lookupHost');

    const services: ShodanServiceBanner[] = (raw.data ?? []).map((d) => ({
      port: d.port ?? 0,
      ...(d.transport ? { transport: d.transport } : {}),
      ...(d.product ? { product: d.product } : {}),
      ...(d.version ? { version: d.version } : {}),
      ...(d.data ? { banner: d.data.slice(0, BANNER_LIMIT) } : {}),
      ...(d.timestamp ? { observedAt: d.timestamp } : {}),
    }));

    return {
      ip: raw.ip_str ?? ip,
      hostnames: raw.hostnames ?? [],
      ports: (raw.ports ?? []).slice().sort((a, b) => a - b),
      services,
      ...(raw.asn ? { asn: raw.asn } : {}),
      ...(raw.org ? { org: raw.org } : {}),
      ...(raw.country_code ? { country: raw.country_code } : {}),
      ...(raw.last_update ? { lastUpdate: raw.last_update } : {}),
    };
  }

  /** Faceted internet-wide search (consumes paid query credits). */
  async search(query: string, facets: string[], ctx: Context): Promise<ShodanSearchResult> {
    const key = this.requireKey();
    const params = new URLSearchParams({ key, query });
    if (facets.length > 0) params.set('facets', facets.join(','));
    const url = `${BASE_URL}/shodan/host/search?${params.toString()}`;
    const raw = await this.fetchJson<RawShodanSearch>(url, ctx, 'shodanService.search');

    const matches: ShodanSearchMatch[] = (raw.matches ?? []).map((m) => ({
      ip: m.ip_str ?? '',
      port: m.port ?? 0,
      ...(m.product ? { product: m.product } : {}),
      ...(m.org ? { org: m.org } : {}),
      ...(m.location?.country_code ? { country: m.location.country_code } : {}),
    }));

    const facetOut: Record<string, Array<{ value: string; count: number }>> = {};
    for (const [name, buckets] of Object.entries(raw.facets ?? {})) {
      facetOut[name] = buckets.map((b) => ({ value: String(b.value ?? ''), count: b.count ?? 0 }));
    }

    return { total: raw.total ?? matches.length, matches, facets: facetOut };
  }

  private requireKey(): string {
    if (!this.config.shodanApiKey) {
      throw new Error('SHODAN_API_KEY is not configured.');
    }
    return this.config.shodanApiKey;
  }

  private async fetchJson<T>(url: string, ctx: Context, operation: string): Promise<T> {
    return await withRetry(
      async () => {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
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
        if (res.status === 401) throw new Error('Shodan rejected the API key (HTTP 401).');
        if (res.status === 404)
          throw new Error('Shodan has no information for this target (HTTP 404).');
        if (res.status === 429) throw new Error('Shodan rate limit / no query credits (HTTP 429).');
        if (!res.ok) throw new Error(`Shodan returned HTTP ${res.status}`);
        return (await res.json()) as T;
      },
      {
        operation,
        context: toRequestContext(ctx, operation),
        baseDelayMs: 1500,
        maxRetries: 2,
        signal: ctx.signal,
      },
    );
  }
}

// --- Init/accessor pattern ---

let _service: ShodanService | undefined;

export function initShodanService(config: ServerConfig): void {
  _service = new ShodanService(config);
}

export function getShodanService(): ShodanService {
  if (!_service) {
    throw new Error('ShodanService not initialized — call initShodanService() in setup()');
  }
  return _service;
}
