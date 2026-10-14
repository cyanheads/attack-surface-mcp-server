/**
 * @fileoverview Integration tests for attacksurface_enumerate_subdomains with HTTP/DNS faked.
 * @module tests/integration/enumerate-subdomains.tool.test
 */

import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { createMockContext, getEnrichment, runToolContract } from '@cyanheads/mcp-ts-core/testing';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const dnsBoundary = vi.hoisted(() => ({ lookup: vi.fn(), resolve: vi.fn() }));
vi.mock('node:dns/promises', () => ({
  lookup: dnsBoundary.lookup,
  Resolver: class FakeResolver {
    resolve4(host: string) {
      return dnsBoundary.resolve('A', host);
    }

    resolve6(host: string) {
      return dnsBoundary.resolve('AAAA', host);
    }
  },
}));

import { getServerConfig, resetServerConfig } from '@/config/server-config.js';
import { enumerateSubdomainsTool } from '@/mcp-server/tools/definitions/enumerate-subdomains.tool.js';
import { initCtService } from '@/services/ct/ct-service.js';
import { initDnsService } from '@/services/dns/dns-service.js';
import { initTlsService } from '@/services/tls/tls-service.js';

type HandlerCtx = Parameters<typeof enumerateSubdomainsTool.handler>[1];

function context(): HandlerCtx {
  return createMockContext({ errors: enumerateSubdomainsTool.errors ?? [] }) as HandlerCtx;
}

describe('attacksurface_enumerate_subdomains', () => {
  const fetchMock = vi.fn<typeof fetch>();

  beforeEach(() => {
    vi.unstubAllEnvs();
    resetServerConfig();
    fetchMock.mockReset();
    vi.stubGlobal('fetch', fetchMock);
    dnsBoundary.lookup.mockReset();
    dnsBoundary.resolve.mockReset();
    dnsBoundary.lookup.mockResolvedValue([{ address: '93.184.216.34', family: 4 }]);
    dnsBoundary.resolve.mockImplementation(async (type, host) => {
      if (type === 'A' && host === 'api.example.com') return ['93.184.216.34'];
      return [];
    });
    const config = getServerConfig();
    initCtService(config);
    initDnsService();
    initTlsService();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.unstubAllEnvs();
    vi.useRealTimers();
  });

  it('returns normalized provenance and liveness with complete structured/format output', async () => {
    fetchMock.mockResolvedValue(
      new Response(
        JSON.stringify([
          { name_value: '*.API.EXAMPLE.COM.\ndead.example.com\noutside.test' },
          { name_value: 'api.example.com' },
        ]),
        { status: 200 },
      ),
    );
    const ctx = context();

    const result = await enumerateSubdomainsTool.handler(
      enumerateSubdomainsTool.input.parse({
        domain: 'EXAMPLE.COM.',
        sources: ['crt.sh'],
        includeUnresolved: true,
      }),
      ctx,
    );

    expect(result).toEqual(expect.schemaMatching(enumerateSubdomainsTool.output));
    expect(result).toEqual({
      domain: 'example.com',
      filteredAddressErrors: [],
      subdomains: [
        {
          name: 'api.example.com',
          sources: ['crt.sh'],
          resolved: true,
          addresses: ['93.184.216.34'],
          addressError: null,
        },
        {
          name: 'dead.example.com',
          sources: ['crt.sh'],
          resolved: false,
          addresses: [],
          addressError: null,
        },
      ],
      sourceStatuses: [{ source: 'crt.sh', ok: true, count: 2, sourceError: null }],
    });
    expect(getEnrichment(ctx)).toEqual({ totalCount: 2, liveCount: 1 });
    const blocks = enumerateSubdomainsTool.format?.(result);
    if (blocks?.[0]?.type === 'text') {
      expect(blocks[0].text).toContain('api.example.com');
      expect(blocks[0].text).toContain('93.184.216.34');
      expect(blocks[0].text).toContain('dead.example.com');
      expect(blocks[0].text).toContain('crt.sh');
    }
  });

  it('filters unresolved names when requested', async () => {
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify([{ name_value: 'api.example.com\ndead.example.com' }]), {
        status: 200,
      }),
    );

    const result = await enumerateSubdomainsTool.handler(
      enumerateSubdomainsTool.input.parse({
        domain: 'example.com',
        sources: ['crt.sh'],
        includeUnresolved: false,
      }),
      context(),
    );

    expect(result.subdomains).toEqual([
      {
        name: 'api.example.com',
        sources: ['crt.sh'],
        resolved: true,
        addresses: ['93.184.216.34'],
        addressError: null,
      },
    ]);
  });

  it('carries partial CT coverage and mixed-family DNS failures on both MCP surfaces', async () => {
    fetchMock.mockImplementation(async () =>
      Response.json([{ dns_names: ['api.example.com'], id: '1' }]),
    );
    dnsBoundary.resolve.mockImplementation(async (type) => {
      if (type === 'A') return ['93.184.216.34'];
      throw Object.assign(new Error('IPv6 SERVFAIL'), { code: 'ESERVFAIL' });
    });
    const result = await runToolContract(enumerateSubdomainsTool, {
      domain: 'example.com',
      sources: ['certspotter'],
    });
    expect(result.structuredContent).toMatchObject({
      subdomains: [{ resolved: true, addressError: 'AAAA: IPv6 SERVFAIL' }],
      sourceStatuses: [
        { complete: false, pagesFetched: 2, incompleteReason: 'missing_or_repeated_cursor' },
      ],
    });
    expect(JSON.stringify(result.content)).toContain('IPv6 SERVFAIL');
    expect(JSON.stringify(result.content)).toContain('complete=false');
  });

  it('retains filtered operational failures while returning only live names', async () => {
    fetchMock.mockImplementation(async () =>
      Response.json([{ name_value: 'api.example.com\nbroken.example.com\ndead.example.com' }]),
    );
    dnsBoundary.resolve.mockImplementation(async (type, host) => {
      if (host === 'broken.example.com')
        throw Object.assign(new Error('SERVFAIL'), { code: 'ESERVFAIL' });
      if (type === 'A' && host === 'api.example.com') return ['93.184.216.34'];
      return [];
    });
    const result = await runToolContract(enumerateSubdomainsTool, {
      domain: 'example.com',
      sources: ['crt.sh'],
      includeUnresolved: false,
    });
    expect(result.structuredContent).toMatchObject({
      subdomains: [{ name: 'api.example.com' }],
      filteredAddressErrors: [
        { name: 'broken.example.com', addressError: 'A: SERVFAIL; AAAA: SERVFAIL' },
      ],
    });
    expect(result.structuredContent?.subdomains).toHaveLength(1);
    expect(JSON.stringify(result.content)).toContain('broken.example.com');
    expect(JSON.stringify(result.content)).toContain('A: SERVFAIL; AAAA: SERVFAIL');
    expect(JSON.stringify(result.content)).not.toContain('dead.example.com');
  });

  it('retains partial names after a later page failure instead of all_sources_failed', async () => {
    fetchMock.mockImplementation(async (input) =>
      String(input).includes('after=')
        ? new Response('', { status: 401 })
        : Response.json([{ id: '1', dns_names: ['api.example.com'] }]),
    );
    const result = await runToolContract(enumerateSubdomainsTool, {
      domain: 'example.com',
      sources: ['certspotter'],
    });
    expect(result.isError).not.toBe(true);
    expect(result.structuredContent).toMatchObject({
      subdomains: [{ name: 'api.example.com' }],
      sourceStatuses: [
        {
          ok: true,
          complete: false,
          pagesFetched: 1,
          incompleteReason: 'page_failed',
          sourceError: expect.any(String),
        },
      ],
    });
    expect(JSON.stringify(result.content)).toContain('page_failed');
    expect(JSON.stringify(result.content)).toContain('api.example.com');
  });

  it('enforces source enum boundaries and returns the typed invalid_domain envelope', async () => {
    expect(
      enumerateSubdomainsTool.input.safeParse({
        domain: 'example.com',
        sources: ['dns-bruteforce'],
      }).success,
    ).toBe(false);
    expect(
      enumerateSubdomainsTool.input.safeParse({ domain: 'example.com', includeUnresolved: 'yes' })
        .success,
    ).toBe(false);

    await expect(
      enumerateSubdomainsTool.handler(
        enumerateSubdomainsTool.input.parse({ domain: 'not a domain', sources: ['crt.sh'] }),
        context(),
      ),
    ).rejects.toMatchObject({
      code: JsonRpcErrorCode.ValidationError,
      data: {
        reason: 'invalid_domain',
        recovery: { hint: expect.stringContaining('bare apex domain') },
      },
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('returns the typed all_sources_failed envelope when every requested source fails', async () => {
    vi.useFakeTimers();
    fetchMock.mockImplementation(async () => new Response('', { status: 503 }));

    const pending = enumerateSubdomainsTool.handler(
      enumerateSubdomainsTool.input.parse({ domain: 'example.com', sources: ['crt.sh'] }),
      context(),
    );
    const rejection = expect(pending).rejects.toMatchObject({
      code: JsonRpcErrorCode.ServiceUnavailable,
      data: {
        reason: 'all_sources_failed',
        recovery: { hint: expect.stringContaining('Retry shortly') },
      },
    });
    await vi.runAllTimersAsync();
    await rejection;
  });

  it('enriches an empty successful CT response without throwing', async () => {
    fetchMock.mockResolvedValue(new Response('[]', { status: 200 }));
    const ctx = context();

    const result = await enumerateSubdomainsTool.handler(
      enumerateSubdomainsTool.input.parse({ domain: 'example.com', sources: ['crt.sh'] }),
      ctx,
    );

    expect(result.subdomains).toEqual([]);
    expect(getEnrichment(ctx)).toEqual({
      totalCount: 0,
      liveCount: 0,
      notice: expect.stringContaining('No subdomains found'),
    });
  });
});
