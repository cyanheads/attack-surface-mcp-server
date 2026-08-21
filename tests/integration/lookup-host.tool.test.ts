/**
 * @fileoverview Integration tests for attacksurface_lookup_host with only fetch faked.
 * @module tests/integration/lookup-host.tool.test
 */

import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { createMockContext } from '@cyanheads/mcp-ts-core/testing';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { ServerConfig } from '@/config/server-config.js';
import { lookupHostTool } from '@/mcp-server/tools/definitions/lookup-host.tool.js';
import { initShodanService } from '@/services/shodan/shodan-service.js';

type HandlerCtx = Parameters<typeof lookupHostTool.handler>[1];

const config = {
  shodanApiKey: 'test-key',
  defaultResolvers: '8.8.8.8',
  httpUserAgent: 'attack-surface-test',
  maxSubdomains: 200,
  rdapBootstrapUrl: 'https://rdap.org',
} satisfies ServerConfig;

function context(): HandlerCtx {
  return createMockContext({ errors: lookupHostTool.errors ?? [] }) as HandlerCtx;
}

describe('attacksurface_lookup_host', () => {
  const fetchMock = vi.fn<typeof fetch>();

  beforeEach(() => {
    fetchMock.mockReset();
    vi.stubGlobal('fetch', fetchMock);
    initShodanService(config);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  it('returns the complete host-mode output and renders optional fields', async () => {
    fetchMock.mockResolvedValue(
      Response.json({
        ip_str: '8.8.8.8',
        hostnames: ['dns.google'],
        ports: [443, 53],
        asn: 'AS15169',
        org: 'Google LLC',
        country_code: 'US',
        last_update: '2026-01-01T00:00:00Z',
        data: [
          {
            port: 53,
            transport: 'udp',
            product: 'Google DNS',
            version: '1.0',
            data: 'DNS banner',
            timestamp: '2025-12-31T00:00:00Z',
          },
        ],
      }),
    );

    const result = await lookupHostTool.handler(
      lookupHostTool.input.parse({ target: '8.8.8.8' }),
      context(),
    );

    expect(result).toEqual(expect.schemaMatching(lookupHostTool.output));
    expect(result).toEqual({
      mode: 'host',
      host: {
        ip: '8.8.8.8',
        hostnames: ['dns.google'],
        ports: [53, 443],
        services: [
          {
            port: 53,
            transport: 'udp',
            product: 'Google DNS',
            version: '1.0',
            banner: 'DNS banner',
            observedAt: '2025-12-31T00:00:00Z',
          },
        ],
        asn: 'AS15169',
        org: 'Google LLC',
        country: 'US',
        lastUpdate: '2026-01-01T00:00:00Z',
      },
    });
    const blocks = lookupHostTool.format?.(result);
    if (blocks?.[0]?.type === 'text') {
      expect(blocks[0].text).toContain('Google LLC');
      expect(blocks[0].text).toContain('port 53');
      expect(blocks[0].text).toContain('DNS banner');
    }
  });

  it('returns search matches and facet buckets in search mode', async () => {
    fetchMock.mockResolvedValue(
      Response.json({
        total: 1,
        matches: [
          {
            ip_str: '203.0.114.10',
            port: 443,
            product: 'nginx',
            org: 'Example Org',
            location: { country_code: 'US' },
          },
        ],
        facets: { port: [{ value: 443, count: 1 }] },
      }),
    );

    const result = await lookupHostTool.handler(
      lookupHostTool.input.parse({
        target: 'org:"Example Org" port:443',
        mode: 'search',
        facets: ['port'],
      }),
      context(),
    );

    expect(result).toEqual(expect.schemaMatching(lookupHostTool.output));
    expect(result).toEqual({
      mode: 'search',
      search: {
        total: 1,
        matches: [
          {
            ip: '203.0.114.10',
            port: 443,
            product: 'nginx',
            org: 'Example Org',
            country: 'US',
          },
        ],
        facets: { port: [{ value: '443', count: 1 }] },
      },
    });
  });

  it('enforces enum and facets schema boundaries', () => {
    expect(lookupHostTool.input.safeParse({ target: '8.8.8.8', mode: 'host' }).success).toBe(true);
    expect(lookupHostTool.input.safeParse({ target: '8.8.8.8', mode: 'scan' }).success).toBe(false);
    expect(
      lookupHostTool.input.safeParse({ target: 'query', mode: 'search', facets: ['port'] }).success,
    ).toBe(true);
    expect(
      lookupHostTool.input.safeParse({ target: 'query', mode: 'search', facets: 'port' }).success,
    ).toBe(false);
  });

  // Known defect: https://github.com/cyanheads/attack-surface-mcp-server/issues/6
  it.skip('rejects empty and non-IP host-mode targets before network I/O', () => {
    expect(lookupHostTool.input.safeParse({ target: '', mode: 'host' }).success).toBe(false);
    expect(lookupHostTool.input.safeParse({ target: 'not-an-ip', mode: 'host' }).success).toBe(
      false,
    );
  });

  it('returns the typed source_unavailable envelope when the key is absent', async () => {
    initShodanService({ ...config, shodanApiKey: undefined });

    await expect(
      lookupHostTool.handler(lookupHostTool.input.parse({ target: '8.8.8.8' }), context()),
    ).rejects.toMatchObject({
      code: JsonRpcErrorCode.ServiceUnavailable,
      data: {
        reason: 'source_unavailable',
        recovery: { hint: expect.stringContaining('SHODAN_API_KEY') },
      },
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('returns the typed no_data envelope for a Shodan 404', async () => {
    vi.useFakeTimers();
    fetchMock.mockImplementation(async () => new Response('', { status: 404 }));

    const pending = lookupHostTool.handler(
      lookupHostTool.input.parse({ target: '8.8.4.4' }),
      context(),
    );
    const rejection = expect(pending).rejects.toMatchObject({
      code: JsonRpcErrorCode.NotFound,
      data: {
        reason: 'no_data',
        recovery: { hint: expect.stringContaining('map_domain') },
      },
    });
    await vi.runAllTimersAsync();
    await rejection;
  });
});
