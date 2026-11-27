/**
 * @fileoverview Integration tests for attacksurface_lookup_host with only fetch faked.
 * @module tests/integration/lookup-host.tool.test
 */

import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { createMockContext, runToolContract } from '@cyanheads/mcp-ts-core/testing';
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

  it('walks explicit search pages once per call and stops at empty or past-end pages', async () => {
    fetchMock.mockImplementation(async (url) => {
      const page = Number(new URL(String(url)).searchParams.get('page') ?? 1);
      return Response.json({
        total: 150,
        matches: Array.from({ length: page === 1 ? 100 : page === 2 ? 50 : 0 }, (_, i) => ({
          ip_str: `8.8.8.${i}`,
          port: 443,
        })),
      });
    });
    const first = await runToolContract(lookupHostTool, {
      target: 'org:owned',
      mode: 'search',
      facets: ['port'],
    });
    expect(first.structuredContent).toMatchObject({
      search: {
        page: 1,
        pageSize: 100,
        hasMore: true,
        nextPage: 2,
        continuation: {
          toolName: 'attacksurface_lookup_host',
          args: { target: 'org:owned', mode: 'search', facets: ['port'], page: 2 },
        },
      },
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    for (const page of [2, 3, 99]) {
      const result = await runToolContract(lookupHostTool, {
        target: 'org:owned',
        mode: 'search',
        page,
      });
      expect(result.structuredContent).toMatchObject({
        search: { page, hasMore: false, nextPage: null, continuation: null },
      });
      expect(JSON.stringify(result.content)).toContain(`page ${page}`);
      expect(new URL(String(fetchMock.mock.calls.at(-1)?.[0])).searchParams.get('page')).toBe(
        String(page),
      );
    }
    expect(fetchMock).toHaveBeenCalledTimes(4);
    for (const page of [0, -1, 1.5])
      expect(
        lookupHostTool.input.safeParse({ target: 'query', mode: 'search', page }).success,
      ).toBe(false);
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

  it('returns only the first 512 ASCII units by default and makes one host request', async () => {
    const excerpt = 'x'.repeat(512);
    fetchMock.mockResolvedValue(
      Response.json({ data: [{ port: 443, data: `${excerpt}TAIL-EVIDENCE` }] }),
    );
    const result = await runToolContract(lookupHostTool, { target: '192.0.2.1' });
    expect(result.structuredContent).toMatchObject({
      host: { services: [{ port: 443, banner: excerpt }] },
    });
    expect(JSON.stringify(result.content)).toContain(excerpt);
    expect(JSON.stringify(result.content)).not.toContain('TAIL-EVIDENCE');
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(new URL(String(fetchMock.mock.calls[0]?.[0])).pathname).toBe('/shodan/host/192.0.2.1');
  });

  it('marks clipped banners and follows up against the current observation losslessly', async () => {
    const target = '192.0.2.1';
    const boundary = 'x'.repeat(512);
    const prefix = ' '.repeat(511);
    const assertText = (blocks: Array<{ type: string }>, expected: string) => {
      expect(blocks).toContainEqual(
        expect.objectContaining({ type: 'text', text: expect.stringContaining(expected) }),
      );
    };
    fetchMock.mockResolvedValueOnce(
      Response.json({
        data: [
          { port: 80, data: boundary },
          {
            port: 443,
            transport: 'tcp',
            data: `${prefix}😀old`,
            timestamp: '2026-01-01T00:00:00Z',
          },
          { port: 53 },
        ],
      }),
    );
    const first = await runToolContract(lookupHostTool, { target });
    expect(first.structuredContent).toMatchObject({
      host: {
        ip: target,
        services: [
          { port: 80, banner: boundary },
          {
            port: 443,
            transport: 'tcp',
            banner: prefix,
            bannerTruncated: true,
            observedAt: '2026-01-01T00:00:00Z',
          },
          { port: 53 },
        ],
      },
    });
    const host = lookupHostTool.output.parse(first.structuredContent).host;
    expect(host?.services[0]).not.toHaveProperty('bannerTruncated');
    expect(host?.services[2]).not.toHaveProperty('banner');
    expect(host?.services[2]).not.toHaveProperty('bannerTruncated');
    expect(first.content).toHaveLength(1);
    assertText(first.content, 'bannerTruncated=true');
    const followUp = host?.fullBannerCall;
    expect(followUp).toMatchObject({
      toolName: 'attacksurface_lookup_host',
      args: { target, mode: 'host', bannerDetail: 'full' },
    });
    assertText(first.content, JSON.stringify(followUp));
    expect(fetchMock).toHaveBeenCalledTimes(1);

    const banner = `  ${'x'.repeat(513)}😀\r\n\r\`\`\`\`\` ~~~ *literal*\\\t\n\u0000  `;
    fetchMock.mockResolvedValueOnce(
      Response.json({
        data: [
          { port: 443, transport: 'tcp', data: banner, timestamp: '2026-01-02T00:00:00Z' },
          { port: 53, data: '' },
        ],
      }),
    );
    const full = await runToolContract(lookupHostTool, lookupHostTool.input.parse(followUp?.args));
    expect(full.structuredContent).toEqual({
      mode: 'host',
      host: {
        ip: target,
        hostnames: [],
        ports: [],
        services: [
          { port: 443, transport: 'tcp', banner, observedAt: '2026-01-02T00:00:00Z' },
          { port: 53, banner: '' },
        ],
      },
    });
    const textBlock = full.content[0];
    const text = textBlock?.type === 'text' ? textBlock.text : '';
    const encodedBanner = text.match(/(`{6})((?:".*"))\1/)?.[2];
    expect(encodedBanner).toBeDefined();
    expect(JSON.parse(encodedBanner ?? 'null')).toBe(banner);
    assertText(full.content, '2026-01-02T00:00:00Z');
    expect(text).not.toContain('bannerTruncated=true');
    expect(text).not.toContain('fullBannerCall');
    expect(fetchMock.mock.calls.map(([url]) => new URL(String(url)).pathname)).toEqual([
      '/shodan/host/192.0.2.1',
      '/shodan/host/192.0.2.1',
    ]);
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
        page: 1,
        pageSize: 100,
        hasMore: false,
        nextPage: null,
        continuation: null,
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

  it('omits the follow-up when banners are missing or already complete', async () => {
    const banner = 'x'.repeat(512);
    fetchMock.mockResolvedValue(
      Response.json({ data: [{ port: 443, data: banner }, { port: 53 }] }),
    );
    const result = await runToolContract(lookupHostTool, { target: '192.0.2.1' });
    expect(result.structuredContent).toEqual({
      mode: 'host',
      host: {
        ip: '192.0.2.1',
        hostnames: [],
        ports: [],
        services: [{ port: 443, banner }, { port: 53 }],
      },
    });
    expect(JSON.stringify(result.content)).not.toContain('fullBannerCall');
    expect(JSON.stringify(result.content)).not.toContain('bannerTruncated');
  });

  it('rejects an invalid banner selector before requesting Shodan', () => {
    const result = lookupHostTool.input.safeParse({ target: '192.0.2.1', bannerDetail: 'all' });
    expect(result.error?.issues).toContainEqual(
      expect.objectContaining({ path: ['bannerDetail'] }),
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each([
    '8.8.8.8',
    '2606:4700:4700::1111',
    '2606:4700:4700:0000:0000:0000:0000:1111',
    '::ffff:8.8.8.8',
  ])('preserves host lookup for %s on both output paths', async (target) => {
    fetchMock.mockImplementation(async () => Response.json({ ip_str: target }));
    const result = await runToolContract(lookupHostTool, { target });
    expect(result.isError).not.toBe(true);
    expect(result.structuredContent).toEqual({
      mode: 'host',
      host: { ip: target, hostnames: [], ports: [], services: [] },
    });
    expect(JSON.stringify(result.content)).toContain(target);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0]?.[0]).toContain(encodeURIComponent(target));
  });

  it('preserves search syntax verbatim and renders empty results', async () => {
    const target = '  org:"Example Org" port:443  ';
    fetchMock.mockResolvedValue(Response.json({ total: 0, matches: [], facets: {} }));
    const result = await runToolContract(lookupHostTool, {
      target,
      mode: 'search',
      bannerDetail: 'full',
    });
    expect(result.isError).not.toBe(true);
    expect(result.structuredContent).toEqual({
      mode: 'search',
      search: {
        total: 0,
        matches: [],
        facets: {},
        page: 1,
        pageSize: 100,
        hasMore: false,
        nextPage: null,
        continuation: null,
      },
    });
    expect(JSON.stringify(result.content)).toContain('0 total match(es)');
    expect(new URL(String(fetchMock.mock.calls[0]?.[0])).searchParams.get('query')).toBe(target);
    expect(new URL(String(fetchMock.mock.calls[0]?.[0])).searchParams.has('bannerDetail')).toBe(
      false,
    );
  });

  it.each(['', ' ', '\t\n'])(
    'rejects blank target %j at the schema in either mode',
    async (target) => {
      fetchMock.mockImplementation(async () => Response.json({}));
      for (const mode of ['host', 'search'] satisfies Array<'host' | 'search'>) {
        const result = await runToolContract(lookupHostTool, { target, mode });
        expect(result.isError).toBe(true);
        expect(result.structuredContent).toMatchObject({
          error: { code: JsonRpcErrorCode.InvalidParams },
        });
      }
      expect(fetchMock).not.toHaveBeenCalled();
    },
  );

  it.each([
    'not-an-ip',
    'example.com',
    'https://8.8.8.8',
    '8.8.8.0/24',
    '8.8.8.8:443',
    '[2606:4700:4700::1111]',
    '999.1.1.1',
    '1.2.3',
    '2001:::1',
  ])('rejects non-IP target %s with actionable errors and zero requests', async (target) => {
    fetchMock.mockImplementation(async () => Response.json({}));
    const result = await runToolContract(lookupHostTool, { target });
    expect(result.isError).toBe(true);
    expect(result.structuredContent).toMatchObject({
      error: {
        code: JsonRpcErrorCode.ValidationError,
        data: {
          reason: 'invalid_target',
          recovery: { hint: expect.stringContaining('IPv4 or IPv6') },
        },
      },
    });
    expect(JSON.stringify(result.content)).toContain('IPv4 or IPv6');
    expect(JSON.stringify(result.content)).toContain('invalid_target');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('returns the typed source_unavailable envelope when the key is absent', async () => {
    initShodanService({ ...config, shodanApiKey: undefined });

    const result = await runToolContract(lookupHostTool, {
      target: '192.0.2.1',
      bannerDetail: 'full',
    });
    expect(result.isError).toBe(true);
    expect(result.structuredContent).toMatchObject({
      error: {
        code: JsonRpcErrorCode.ServiceUnavailable,
        data: {
          reason: 'source_unavailable',
          recovery: { hint: expect.stringContaining('SHODAN_API_KEY') },
        },
      },
    });
    expect(JSON.stringify(result.content)).toContain('source_unavailable');
    expect(JSON.stringify(result.content)).toContain('SHODAN_API_KEY');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('returns the typed no_data envelope for a Shodan 404', async () => {
    vi.useFakeTimers();
    fetchMock.mockImplementation(async () => new Response('', { status: 404 }));

    const pending = runToolContract(lookupHostTool, { target: '192.0.2.1', bannerDetail: 'full' });
    await vi.runAllTimersAsync();
    const result = await pending;
    expect(result.isError).toBe(true);
    expect(result.structuredContent).toMatchObject({
      error: {
        code: JsonRpcErrorCode.NotFound,
        data: {
          reason: 'no_data',
          recovery: { hint: expect.stringContaining('map_domain') },
        },
      },
    });
    expect(JSON.stringify(result.content)).toContain('no_data');
    expect(JSON.stringify(result.content)).toContain('map_domain');
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});
