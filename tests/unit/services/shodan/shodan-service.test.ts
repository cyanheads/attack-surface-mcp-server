/**
 * @fileoverview Boundary and response-parser tests for Shodan with fetch faked.
 * @module tests/unit/services/shodan/shodan-service.test
 */

import { createMockContext } from '@cyanheads/mcp-ts-core/testing';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { ServerConfig } from '@/config/server-config.js';
import { ShodanService } from '@/services/shodan/shodan-service.js';

const config = {
  shodanApiKey: 'test-key',
  defaultResolvers: '8.8.8.8',
  httpUserAgent: 'attack-surface-test',
  maxSubdomains: 200,
  rdapBootstrapUrl: 'https://rdap.org',
} satisfies ServerConfig;

describe('ShodanService', () => {
  const fetchMock = vi.fn<typeof fetch>();

  beforeEach(() => {
    fetchMock.mockReset();
    vi.stubGlobal('fetch', fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  it('normalizes and sorts host intelligence while bounding banners', async () => {
    fetchMock.mockResolvedValue(
      Response.json({
        ip_str: '8.8.8.8',
        hostnames: ['dns.google'],
        ports: [853, 53, 443],
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
            data: 'x'.repeat(600),
            timestamp: '2025-12-31T00:00:00Z',
          },
        ],
      }),
    );

    const result = await new ShodanService(config).lookupHost('8.8.8.8', createMockContext());

    expect(result).toEqual({
      ip: '8.8.8.8',
      hostnames: ['dns.google'],
      ports: [53, 443, 853],
      services: [
        {
          port: 53,
          transport: 'udp',
          product: 'Google DNS',
          version: '1.0',
          banner: 'x'.repeat(512),
          observedAt: '2025-12-31T00:00:00Z',
        },
      ],
      asn: 'AS15169',
      org: 'Google LLC',
      country: 'US',
      lastUpdate: '2026-01-01T00:00:00Z',
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://api.shodan.io/shodan/host/8.8.8.8?key=test-key',
      expect.objectContaining({
        headers: { accept: 'application/json', 'user-agent': 'attack-surface-test' },
      }),
    );
  });

  it('preserves sparse host data without fabricating optional fields', async () => {
    fetchMock.mockResolvedValue(Response.json({ data: [{}] }));

    const result = await new ShodanService(config).lookupHost('9.9.9.9', createMockContext());

    expect(result).toEqual({
      ip: '9.9.9.9',
      hostnames: [],
      ports: [],
      services: [{ port: 0 }],
    });
    expect(result).not.toHaveProperty('country');
  });

  it('normalizes faceted search matches and numeric bucket values', async () => {
    fetchMock.mockResolvedValue(
      Response.json({
        total: 2,
        matches: [
          {
            ip_str: '203.0.114.10',
            port: 443,
            product: 'nginx',
            org: 'Example Org',
            location: { country_code: 'US' },
          },
          {},
        ],
        facets: {
          port: [{ value: 443, count: 10 }, {}],
        },
      }),
    );

    const result = await new ShodanService(config).search(
      'org:"Example Org"',
      ['port'],
      createMockContext(),
    );

    expect(result).toEqual({
      total: 2,
      matches: [
        {
          ip: '203.0.114.10',
          port: 443,
          product: 'nginx',
          org: 'Example Org',
          country: 'US',
        },
        { ip: '', port: 0 },
      ],
      facets: {
        port: [
          { value: '443', count: 10 },
          { value: '', count: 0 },
        ],
      },
    });
    expect(String(fetchMock.mock.calls[0]?.[0])).toContain('facets=port');
  });

  it('fails immediately when no API key is configured', async () => {
    const service = new ShodanService({ ...config, shodanApiKey: undefined });

    expect(service.isConfigured()).toBe(false);
    await expect(service.lookupHost('8.8.8.8', createMockContext())).rejects.toThrow(
      'SHODAN_API_KEY is not configured',
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });

  // 401/429 are re-labeled by the service; other statuses pass through the framework's
  // status-mapped error verbatim (`Fetch failed for <url>. Status: <code>`). A 500 maps to
  // ServiceUnavailable like the rest of the 5xx range, so it retries too.
  it.each([
    [401, 'rejected the API key'],
    [429, 'rate limit / no query credits'],
    [500, 'Fetch failed for https://api.shodan.io/shodan/host/8.8.8.8?…. Status: 500'],
    [503, 'Fetch failed for https://api.shodan.io/shodan/host/8.8.8.8?…. Status: 503'],
  ])('surfaces HTTP %i failures after bounded retries', async (status, message) => {
    vi.useFakeTimers();
    fetchMock.mockImplementation(async () => new Response('', { status }));

    const pending = new ShodanService(config).lookupHost('8.8.8.8', createMockContext());
    const rejection = expect(pending).rejects.toThrow(message);
    await vi.runAllTimersAsync();
    await rejection;
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  // An unscanned IP is an expected answer, not a failure — the service maps it to
  // notFound(), which withRetry treats as non-transient, so no retries are burned.
  it('fails fast on HTTP 404 without burning retries', async () => {
    vi.useFakeTimers();
    fetchMock.mockImplementation(async () => new Response('', { status: 404 }));

    const pending = new ShodanService(config).lookupHost('8.8.8.8', createMockContext());
    const rejection = expect(pending).rejects.toThrow('no information');
    await vi.runAllTimersAsync();
    await rejection;
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});
