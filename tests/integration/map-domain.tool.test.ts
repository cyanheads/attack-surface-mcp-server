/**
 * @fileoverview Integration tests for attacksurface_map_domain quick workflow with boundaries faked.
 * @module tests/integration/map-domain.tool.test
 */

import { EventEmitter } from 'node:events';
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { createMockContext, getEnrichment } from '@cyanheads/mcp-ts-core/testing';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const dnsBoundary = vi.hoisted(() => ({ resolve: vi.fn() }));
const tlsBoundary = vi.hoisted(() => ({ connect: vi.fn() }));

vi.mock('node:dns/promises', () => ({
  lookup: vi.fn(),
  Resolver: class FakeResolver {
    resolve4(host: string) {
      return dnsBoundary.resolve('A', host);
    }

    resolve6(host: string) {
      return dnsBoundary.resolve('AAAA', host);
    }
  },
}));
vi.mock('node:tls', () => ({ connect: tlsBoundary.connect }));

import { getServerConfig, resetServerConfig } from '@/config/server-config.js';
import { mapDomainTool } from '@/mcp-server/tools/definitions/map-domain.tool.js';
import { initCtService } from '@/services/ct/ct-service.js';
import { initDnsService } from '@/services/dns/dns-service.js';
import { initTlsService } from '@/services/tls/tls-service.js';

type HandlerCtx = Parameters<typeof mapDomainTool.handler>[1];

class ErrorTlsSocket extends EventEmitter {
  constructor() {
    super();
    queueMicrotask(() => this.emit('error', new Error('no apex TLS')));
  }

  destroy() {}
}

function context(): HandlerCtx {
  return createMockContext({ errors: mapDomainTool.errors ?? [] }) as HandlerCtx;
}

describe('attacksurface_map_domain', () => {
  const fetchMock = vi.fn<typeof fetch>();

  beforeEach(() => {
    vi.stubEnv('ATTACKSURFACE_ALLOW_PRIVATE_TARGETS', 'true');
    resetServerConfig();
    fetchMock.mockReset();
    vi.stubGlobal('fetch', fetchMock);
    dnsBoundary.resolve.mockReset();
    tlsBoundary.connect.mockReset();
    tlsBoundary.connect.mockImplementation(() => new ErrorTlsSocket());
    const config = getServerConfig();
    initCtService(config);
    initDnsService();
    initTlsService();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.unstubAllEnvs();
  });

  it('maps CT names and DNS liveness at quick depth with exact output and format shape', async () => {
    fetchMock.mockImplementation(async (input) => {
      if (String(input).startsWith('https://crt.sh/')) {
        return new Response(
          JSON.stringify([{ dns_names: ['api.example.com', 'dead.example.com'] }]),
          { status: 200 },
        );
      }
      return Response.json([{ dns_names: ['api.example.com'] }]);
    });
    dnsBoundary.resolve.mockImplementation(async (type, host) => {
      if (type !== 'A') return [];
      if (host === 'api.example.com') return ['93.184.216.34'];
      if (host === 'example.com') return ['93.184.216.35'];
      return [];
    });
    const ctx = context();

    const result = await mapDomainTool.handler(
      mapDomainTool.input.parse({
        domain: 'EXAMPLE.COM.',
        depth: 'quick',
        includeRegistration: false,
      }),
      ctx,
    );

    expect(result).toEqual(expect.schemaMatching(mapDomainTool.output));
    expect(result).toEqual({
      domain: 'example.com',
      depth: 'quick',
      subdomainCount: 2,
      liveHostCount: 2,
      liveHosts: [
        {
          host: 'api.example.com',
          addresses: ['93.184.216.34'],
          tls: null,
          http: null,
          shodan: null,
        },
        {
          host: 'example.com',
          addresses: ['93.184.216.35'],
          tls: null,
          http: null,
          shodan: null,
        },
      ],
      unresolvedSubdomains: ['dead.example.com'],
      registration: null,
      assessment: [],
      notes: [],
    });
    expect(getEnrichment(ctx)).toEqual({});
    const blocks = mapDomainTool.format?.(result);
    if (blocks?.[0]?.type === 'text') {
      expect(blocks[0].text).toContain('Attack surface: example.com');
      expect(blocks[0].text).toContain('api.example.com');
      expect(blocks[0].text).toContain('93.184.216.34');
      expect(blocks[0].text).toContain('dead.example.com');
    }
  });

  it('enforces depth/input boundaries and returns the typed invalid_domain envelope', async () => {
    expect(mapDomainTool.input.safeParse({ domain: 'example.com', depth: 'active' }).success).toBe(
      false,
    );
    expect(
      mapDomainTool.input.safeParse({ domain: 'example.com', includeRegistration: 'yes' }).success,
    ).toBe(false);

    await expect(
      mapDomainTool.handler(
        mapDomainTool.input.parse({ domain: 'not a domain', depth: 'quick' }),
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

  it('returns the typed no_surface envelope when CT is empty and the apex does not resolve', async () => {
    fetchMock.mockImplementation(async (input) =>
      String(input).startsWith('https://crt.sh/')
        ? new Response('[]', { status: 200 })
        : Response.json([]),
    );
    dnsBoundary.resolve.mockResolvedValue([]);

    await expect(
      mapDomainTool.handler(
        mapDomainTool.input.parse({ domain: 'empty.example.com', depth: 'quick' }),
        context(),
      ),
    ).rejects.toMatchObject({
      code: JsonRpcErrorCode.NotFound,
      data: {
        reason: 'no_surface',
        recovery: { hint: expect.stringContaining('resolve_dns') },
      },
    });
  });
});
