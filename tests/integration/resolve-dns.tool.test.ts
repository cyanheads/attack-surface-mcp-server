/**
 * @fileoverview Integration tests for attacksurface_resolve_dns with node:dns faked.
 * @module tests/integration/resolve-dns.tool.test
 */

import { createMockContext, getEnrichment, runToolContract } from '@cyanheads/mcp-ts-core/testing';
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

  it('retains operational failures in input order', async () => {
    dnsBoundary.query.mockRejectedValue(new Error('resolver unavailable'));
    const result = await runToolContract(resolveDnsTool, {
      hosts: ['first.example.com', 'second.example.com'],
      recordTypes: ['A'],
      resolvers: ['8.8.8.8'],
    });
    expect(result.structuredContent).toMatchObject({
      results: [
        { host: 'first.example.com', hostError: 'resolver unavailable' },
        { host: 'second.example.com', hostError: 'resolver unavailable' },
      ],
    });
    expect(JSON.stringify(result.content)).toContain('resolver unavailable');
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
      processedCount: 1,
      remainingHosts: [],
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
    expect(blocks).toEqual([{ type: 'text', text: expect.any(String) }]);
    expect(blocks?.[0]).toMatchObject({
      type: 'text',
      text: expect.stringContaining('`A`: `93.184.216.34`'),
    });
    expect(blocks?.[0]).toMatchObject({
      type: 'text',
      text: expect.stringContaining('`10 mail.example.com`'),
    });
    expect(blocks?.[0]).toMatchObject({
      type: 'text',
      text: expect.stringContaining('`ptr.example.com`'),
    });
    expect(blocks?.[0]).toMatchObject({ type: 'text', text: expect.stringContaining('`8.8.8.8`') });
  });

  it('enforces host-count and record-type schema boundaries', () => {
    expect(resolveDnsTool.input.safeParse({ hosts: [] }).success).toBe(false);
    expect(
      resolveDnsTool.input.safeParse({ hosts: Array.from({ length: 1001 }, () => 'example.com') })
        .success,
    ).toBe(false);
    expect(resolveDnsTool.input.safeParse({ hosts: ['example.com'] }).success).toBe(true);
    expect(
      resolveDnsTool.input.safeParse({ hosts: ['example.com'], recordTypes: ['PTR'] }).success,
    ).toBe(false);
  });

  it.each([1, 50, 51, 1000])(
    'bounds DNS work and retains the exact remainder for %i hosts',
    async (count) => {
      const hosts = Array.from({ length: count }, (_, i) => `h${i}.example.com`);
      const result = await runToolContract(resolveDnsTool, {
        hosts,
        recordTypes: ['A'],
        resolvers: ['8.8.8.8'],
      });
      expect(result.isError).not.toBe(true);
      expect(result.structuredContent).toMatchObject({
        processedCount: Math.min(count, 50),
        remainingHosts: hosts.slice(50),
      });
      expect(dnsBoundary.query).toHaveBeenCalledTimes(Math.min(count, 50));
      const output = resolveDnsTool.output.parse(result.structuredContent);
      expect(output.results.map((r) => r.host)).toEqual(hosts.slice(0, 50));
      const text = result.content
        .filter((b) => b.type === 'text')
        .map((b) => b.text)
        .join('\n');
      expect(text).toContain(
        `Processed ${Math.min(count, 50)} hosts; ${hosts.slice(50).length} remaining.`,
      );
      for (const host of hosts.slice(50)) expect(text).toContain(`\`${host}\``);
    },
  );

  it('validates malformed remainder before any DNS work', async () => {
    const result = await runToolContract(resolveDnsTool, {
      hosts: [...Array.from({ length: 50 }, () => 'example.com'), 'https://bad.example.com'],
    });
    expect(result.structuredContent).toMatchObject({ error: { data: { reason: 'invalid_host' } } });
    expect(dnsBoundary.query).not.toHaveBeenCalled();
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

  it('exposes resolver failure and retry guidance on both output paths', async () => {
    dnsBoundary.query.mockRejectedValue(
      Object.assign(new Error('upstream SERVFAIL'), { code: 'ESERVFAIL' }),
    );
    const result = await runToolContract(resolveDnsTool, {
      hosts: ['example.com'],
      recordTypes: ['A'],
      resolvers: ['8.8.8.8'],
    });
    expect(result.isError).not.toBe(true);
    expect(result.structuredContent).toMatchObject({
      results: [
        {
          resolved: false,
          hostError: 'upstream SERVFAIL',
          resolverResults: [{ queryError: 'upstream SERVFAIL' }],
        },
      ],
    });
    const text = JSON.stringify(result.content);
    expect(text).toContain('upstream SERVFAIL');
    expect(text).toContain('Retry');
    expect(text).not.toContain('records may not exist');
  });
});
