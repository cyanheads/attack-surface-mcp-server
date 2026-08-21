/**
 * @fileoverview Integration tests for attacksurface_resolve_dns with node:dns faked.
 * @module tests/integration/resolve-dns.tool.test
 */

import { createMockContext, getEnrichment } from '@cyanheads/mcp-ts-core/testing';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const dnsBoundary = vi.hoisted(() => ({ lookup: vi.fn(), query: vi.fn(), reverse: vi.fn() }));

vi.mock('node:dns/promises', () => ({
  lookup: dnsBoundary.lookup,
  Resolver: class FakeResolver {
    private server = '';

    setServers(servers: string[]) {
      this.server = servers[0] ?? '';
    }

    resolve4(host: string) {
      return dnsBoundary.query('A', host, this.server);
    }

    resolve6(host: string) {
      return dnsBoundary.query('AAAA', host, this.server);
    }

    resolveCname(host: string) {
      return dnsBoundary.query('CNAME', host, this.server);
    }

    resolveMx(host: string) {
      return dnsBoundary.query('MX', host, this.server);
    }

    resolveNs(host: string) {
      return dnsBoundary.query('NS', host, this.server);
    }

    resolveTxt(host: string) {
      return dnsBoundary.query('TXT', host, this.server);
    }

    resolveCaa(host: string) {
      return dnsBoundary.query('CAA', host, this.server);
    }

    reverse(ip: string) {
      return dnsBoundary.reverse(ip);
    }
  },
}));

import { resetServerConfig } from '@/config/server-config.js';
import { resolveDnsTool } from '@/mcp-server/tools/definitions/resolve-dns.tool.js';
import { initDnsService } from '@/services/dns/dns-service.js';

function dnsError(code: string): Error & { code: string } {
  return Object.assign(new Error(code), { code });
}

describe('attacksurface_resolve_dns', () => {
  beforeEach(() => {
    vi.unstubAllEnvs();
    resetServerConfig();
    initDnsService();
    dnsBoundary.lookup.mockReset();
    dnsBoundary.query.mockReset();
    dnsBoundary.reverse.mockReset();
    dnsBoundary.lookup.mockResolvedValue([{ address: '93.184.216.34', family: 4 }]);
    dnsBoundary.query.mockRejectedValue(dnsError('ENODATA'));
    dnsBoundary.reverse.mockResolvedValue(['ptr.example.com']);
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it('returns schema-valid records, resolver details, reverse PTRs, and complete format output', async () => {
    dnsBoundary.query.mockImplementation(async (type) => {
      if (type === 'A') return ['93.184.216.34'];
      if (type === 'AAAA') return [];
      if (type === 'MX') return [{ priority: 10, exchange: 'mail.example.com' }];
      throw dnsError('ENODATA');
    });
    const ctx = createMockContext();

    const result = await resolveDnsTool.handler(
      resolveDnsTool.input.parse({
        hosts: ['example.com'],
        recordTypes: ['A', 'AAAA', 'MX'],
        resolvers: ['8.8.8.8'],
        reverse: true,
      }),
      ctx,
    );

    expect(result).toEqual(expect.schemaMatching(resolveDnsTool.output));
    expect(result).toEqual({
      results: [
        {
          host: 'example.com',
          resolved: true,
          records: { A: ['93.184.216.34'], MX: ['10 mail.example.com'] },
          resolverResults: [
            {
              resolver: '8.8.8.8',
              latencyInMs: expect.any(Number),
              records: { A: ['93.184.216.34'], MX: ['10 mail.example.com'] },
              queryError: null,
            },
          ],
          propagationMismatches: [],
          reverse: [{ ip: '93.184.216.34', hostnames: ['ptr.example.com'], lookupError: null }],
          hostError: null,
        },
      ],
      resolversUsed: ['8.8.8.8'],
    });
    expect(getEnrichment(ctx)).toEqual({});
    const blocks = resolveDnsTool.format?.(result);
    if (blocks?.[0]?.type === 'text') {
      expect(blocks[0].text).toContain('A:** 93.184.216.34');
      expect(blocks[0].text).toContain('10 mail.example.com');
      expect(blocks[0].text).toContain('ptr.example.com');
      expect(blocks[0].text).toContain('8.8.8.8');
    }
  });

  it('enforces host-count and record-type schema boundaries', () => {
    expect(resolveDnsTool.input.safeParse({ hosts: [] }).success).toBe(false);
    expect(
      resolveDnsTool.input.safeParse({ hosts: Array.from({ length: 51 }, () => 'example.com') })
        .success,
    ).toBe(false);
    expect(resolveDnsTool.input.safeParse({ hosts: ['example.com'] }).success).toBe(true);
    expect(
      resolveDnsTool.input.safeParse({ hosts: ['example.com'], recordTypes: ['PTR'] }).success,
    ).toBe(false);
  });

  it('returns a shaped per-host SSRF error without failing other results', async () => {
    dnsBoundary.lookup.mockResolvedValue([{ address: '10.0.0.4', family: 4 }]);

    const result = await resolveDnsTool.handler(
      resolveDnsTool.input.parse({
        hosts: ['internal.example.com'],
        recordTypes: ['A'],
        resolvers: ['8.8.8.8'],
      }),
      createMockContext(),
    );

    expect(result).toEqual(expect.schemaMatching(resolveDnsTool.output));
    expect(result.results[0]).toMatchObject({
      host: 'internal.example.com',
      resolved: false,
      records: {},
      resolverResults: [],
      hostError: expect.stringMatching(/^SSRF_BLOCKED:/),
    });
  });

  it('enriches an all-unresolved result with guidance', async () => {
    const ctx = createMockContext();
    const result = await resolveDnsTool.handler(
      resolveDnsTool.input.parse({
        hosts: ['missing.example.com'],
        recordTypes: ['A'],
        resolvers: ['8.8.8.8'],
      }),
      ctx,
    );

    expect(result.results[0]?.resolved).toBe(false);
    expect(getEnrichment(ctx)).toEqual({
      notice: expect.stringContaining('No host resolved'),
    });
  });
});
