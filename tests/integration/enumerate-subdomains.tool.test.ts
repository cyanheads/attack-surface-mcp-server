/**
 * @fileoverview Integration tests for attacksurface_enumerate_subdomains with HTTP/DNS faked.
 * @module tests/integration/enumerate-subdomains.tool.test
 */

import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { createMockContext, getEnrichment } from '@cyanheads/mcp-ts-core/testing';
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
          { dns_names: ['*.API.EXAMPLE.COM.', 'dead.example.com', 'outside.test'] },
          { dns_names: ['api.example.com'] },
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
      subdomains: [
        {
          name: 'api.example.com',
          sources: ['crt.sh'],
          resolved: true,
          addresses: ['93.184.216.34'],
        },
        {
          name: 'dead.example.com',
          sources: ['crt.sh'],
          resolved: false,
          addresses: [],
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
      new Response(JSON.stringify([{ dns_names: ['api.example.com', 'dead.example.com'] }]), {
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
      },
    ]);
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
