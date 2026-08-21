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
import { McpError, notFound } from '@cyanheads/mcp-ts-core/errors';
import { fetchWithTimeout, withRetry } from '@cyanheads/mcp-ts-core/utils';
import type { ServerConfig } from '@/config/server-config.js';
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
    // An unscanned IP (404) is a normal answer for host intelligence, not a failure.
    const raw = await this.fetchJson<RawShodanHost>(url, ctx, 'shodanService.lookupHost', [404]);

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

  private async fetchJson<T>(
    url: string,
    ctx: Context,
    operation: string,
    expectedStatuses: number[] = [],
  ): Promise<T> {
    return await withRetry(
      async () => {
        let res: Response;
        try {
          res = await fetchWithTimeout(url, TIMEOUT_MS, ctx, {
            headers: { accept: 'application/json', 'user-agent': this.config.httpUserAgent },
            expectedStatuses,
            signal: ctx.signal,
          });
        } catch (err) {
          throw translateUpstreamError(err);
        }
        return (await res.json()) as T;
      },
      {
        operation,
        context: ctx,
        baseDelayMs: 1500,
        maxRetries: 2,
        signal: ctx.signal,
      },
    );
  }
}

/** Extract the HTTP status from a `fetchWithTimeout` status-mapped error, else undefined. */
function upstreamStatus(err: unknown): number | undefined {
  if (err instanceof McpError && typeof err.data?.status === 'number') return err.data.status;
  return undefined;
}

/**
 * Re-label a status-mapped fetch error with Shodan's domain vocabulary; pass anything else
 * through unchanged. 429 keeps its code and `data.retryAfter` so retries honor Retry-After.
 */
function translateUpstreamError(err: unknown): unknown {
  switch (upstreamStatus(err)) {
    case 401:
      return new Error('Shodan rejected the API key (HTTP 401).', { cause: err });
    case 404:
      // An unscanned target is an expected outcome (the tool degrades to typed `no_data`),
      // so it logs at debug and fails fast instead of burning retries.
      return notFound('Shodan has no information for this target.');
    case 429:
      return err instanceof McpError
        ? new McpError(err.code, 'Shodan rate limit / no query credits (HTTP 429).', err.data)
        : err;
    default:
      return err;
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
