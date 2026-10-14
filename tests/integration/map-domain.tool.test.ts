/**
 * @fileoverview Integration tests for attacksurface_map_domain quick workflow with boundaries faked.
 * @module tests/integration/map-domain.tool.test
 */

import { EventEmitter } from 'node:events';
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { createMockContext, getEnrichment, runToolContract } from '@cyanheads/mcp-ts-core/testing';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const dnsBoundary = vi.hoisted(() => ({ resolve: vi.fn() }));
const tlsBoundary = vi.hoisted(() => ({ connect: vi.fn(), san: 'DNS:example.com' }));

vi.mock('node:dns/promises', () => ({
  lookup: vi.fn(),
  Resolver: class FakeResolver {
    private server = '';
    setServers(servers: string[]) {
      this.server = servers[0] ?? '';
    }
    resolveCname(host: string) {
      return dnsBoundary.resolve('CNAME', host);
    }
    resolveMx(host: string) {
      return dnsBoundary.resolve('MX', host);
    }
    resolveNs(host: string) {
      return dnsBoundary.resolve('NS', host);
    }
    resolveTxt(host: string) {
      return dnsBoundary.resolve('TXT', host);
    }
    resolveCaa(host: string) {
      return dnsBoundary.resolve('CAA', host);
    }
    resolve4(host: string) {
      return dnsBoundary.resolve('A', host, this.server);
    }

    resolve6(host: string) {
      return dnsBoundary.resolve('AAAA', host, this.server);
    }
  },
}));
vi.mock('node:tls', async (original) => ({
  ...(await original<typeof import('node:tls')>()),
  connect: tlsBoundary.connect,
}));

import { getServerConfig, resetServerConfig } from '@/config/server-config.js';
import { surfaceResource } from '@/mcp-server/resources/definitions/surface.resource.js';
import { mapDomainTool } from '@/mcp-server/tools/definitions/map-domain.tool.js';
import { initCtService } from '@/services/ct/ct-service.js';
import { initDnsService } from '@/services/dns/dns-service.js';
import { initHttpService } from '@/services/http/http-service.js';
import { initShodanService } from '@/services/shodan/shodan-service.js';
import { initTlsService } from '@/services/tls/tls-service.js';
import { discoveryCoverage } from '@/utils/discovery.js';

type HandlerCtx = Parameters<typeof mapDomainTool.handler>[1];

class ErrorTlsSocket extends EventEmitter {
  constructor() {
    super();
    queueMicrotask(() => this.emit('error', new Error('no apex TLS')));
  }

  destroy() {}
}

class CertificateSocket extends EventEmitter {
  authorized = true;
  authorizationError = undefined;

  constructor(
    private readonly validTo: string,
    callback: () => void,
  ) {
    super();
    queueMicrotask(callback);
  }

  destroy() {}
  getProtocol() {
    return 'TLSv1.3';
  }
  getCipher() {
    return { standardName: 'TLS_AES_128_GCM_SHA256' };
  }
  getPeerCertificate() {
    return {
      subject: { CN: 'example.com' },
      issuer: { CN: 'Example CA' },
      subjectaltname: tlsBoundary.san,
      valid_from: 'Jan 01 00:00:00 2026 GMT',
      valid_to: this.validTo,
      serialNumber: '01',
      fingerprint256: 'AA:BB',
    };
  }
}

function context(): HandlerCtx {
  return createMockContext({ errors: mapDomainTool.errors ?? [] }) as HandlerCtx;
}

describe('attacksurface_map_domain', () => {
  const fetchMock = vi.fn<typeof fetch>();

  it.each([600, 5000])(
    'keeps retrieval examples bounded for %i candidates with complete omission lists',
    (count) => {
      const names = Array.from({ length: count }, (_, i) => `host${i}.example.com`);
      const coverage = discoveryCoverage(names, names.slice(0, 200), []);
      expect(coverage.unexamined).toEqual(names.slice(200));
      expect(coverage.retrieval).toHaveLength(3);
      expect(coverage.retrieval[0]).toEqual({
        toolName: 'attacksurface_resolve_dns',
        args: { hosts: names.slice(200, 250) },
        reason: expect.stringContaining('successive batch'),
      });
      expect(coverage.retrieval[1]).toMatchObject({
        toolName: 'attacksurface_inspect_tls',
        args: { hosts: names.slice(200, 250) },
      });
      expect(coverage.retrieval[2]).toMatchObject({
        toolName: 'attacksurface_probe_http',
        args: { url: `https://${names[200]}` },
        reason: expect.stringContaining('once per name'),
      });
      expect(discoveryCoverage(names, names, []).retrieval).toEqual([]);
    },
  );

  beforeEach(() => {
    vi.stubEnv('ATTACKSURFACE_ALLOW_PRIVATE_TARGETS', 'true');
    resetServerConfig();
    fetchMock.mockReset();
    vi.stubGlobal('fetch', fetchMock);
    dnsBoundary.resolve.mockReset();
    tlsBoundary.connect.mockReset();
    tlsBoundary.san = 'DNS:example.com';
    tlsBoundary.connect.mockImplementation(() => new ErrorTlsSocket());
    const config = getServerConfig();
    initCtService(config);
    initDnsService();
    initTlsService();
    initHttpService('test-agent');
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
    vi.unstubAllEnvs();
  });

  it('keeps the apex at cap one with executable omission retrieval', async () => {
    vi.stubEnv('ATTACKSURFACE_MAX_SUBDOMAINS', '1');
    resetServerConfig();
    initCtService(getServerConfig());
    fetchMock.mockImplementation(async (input) =>
      new URL(String(input)).origin === 'https://crt.sh'
        ? Response.json([{ name_value: 'a.example.com\nb.example.com' }])
        : Response.json([]),
    );
    dnsBoundary.resolve.mockImplementation(async (type) => (type === 'A' ? ['93.184.216.34'] : []));
    const result = await runToolContract(mapDomainTool, { domain: 'example.com', depth: 'quick' });
    expect(result.structuredContent).toMatchObject({
      liveHosts: [{ host: 'example.com' }],
      coverage: { discovered: 3, examined: 1, unexamined: ['a.example.com', 'b.example.com'] },
    });
    expect(JSON.stringify(result.content)).toContain('attacksurface_resolve_dns');
  });

  it('returns standard DNS posture and attempted leg failures on both surfaces', async () => {
    fetchMock.mockImplementation(async (input) =>
      ['https://crt.sh', 'https://api.certspotter.com'].includes(new URL(String(input)).origin)
        ? Response.json([])
        : Promise.reject(new Error('HTTP reset')),
    );
    dnsBoundary.resolve.mockImplementation(async (type) => (type === 'A' ? ['93.184.216.34'] : []));
    const result = await runToolContract(mapDomainTool, {
      domain: 'example.com',
      includeRegistration: false,
    });
    expect(result.structuredContent).toMatchObject({
      liveHosts: [
        {
          dns: { records: { A: ['93.184.216.34'] } },
          errors: { tls: 'no apex TLS', http: expect.any(String) },
        },
      ],
    });
    expect(JSON.stringify(result.content)).toContain('resolverResults');
    expect(JSON.stringify(result.content)).toContain('HTTP reset');
  });

  it('separates snapshot candidate and fifty-host detail omissions with bounded retrieval', async () => {
    vi.stubEnv('ATTACKSURFACE_MAX_SUBDOMAINS', '52');
    resetServerConfig();
    initCtService(getServerConfig());
    fetchMock.mockImplementation(async (input) => {
      const url = new URL(String(input));
      if (url.origin === 'https://crt.sh')
        return Response.json([
          {
            name_value: Array.from(
              { length: 55 },
              (_, i) => `h${String(i).padStart(2, '0')}.example.com`,
            ).join('\n'),
          },
        ]);
      if (url.origin === 'https://api.certspotter.com') return Response.json([]);
      return new Response('');
    });
    dnsBoundary.resolve.mockImplementation(async (type) => (type === 'A' ? ['93.184.216.34'] : []));
    const result = await surfaceResource.handler({ domain: 'example.com' }, createMockContext());
    expect(result.coverage).toMatchObject({
      discovered: 56,
      examined: 52,
      detailed: 50,
      unexamined: ['h51.example.com', 'h52.example.com', 'h53.example.com', 'h54.example.com'],
      detailOmitted: ['h49.example.com', 'h50.example.com'],
    });
    expect(result.hosts[0]?.host).toBe('example.com');
    for (const call of result.coverage.retrieval) {
      if (call.toolName === 'attacksurface_probe_http')
        expect(Object.keys(call.args)).toEqual(['url']);
      else expect((call.args.hosts as string[]).length).toBeLessThanOrEqual(50);
    }
    expect(result.notes.some((n) => n.includes('Candidate resolution capped'))).toBe(true);
    expect(result.notes.some((n) => n.includes('Host detail capped'))).toBe(true);
  });

  it('distinguishes operational address failures from an absent surface', async () => {
    fetchMock.mockImplementation(async () => Response.json([]));
    dnsBoundary.resolve.mockRejectedValue(
      Object.assign(new Error('resolver SERVFAIL'), { code: 'ESERVFAIL' }),
    );
    const result = await runToolContract(mapDomainTool, { domain: 'example.com', depth: 'quick' });
    expect(result.structuredContent).toMatchObject({
      error: {
        data: { reason: 'discovery_failed', recovery: { hint: expect.stringContaining('retry') } },
      },
    });
    expect(JSON.stringify(result.content)).toContain('SERVFAIL');
    await expect(
      surfaceResource.handler({ domain: 'example.com' }, createMockContext()),
    ).rejects.toMatchObject({ code: JsonRpcErrorCode.ServiceUnavailable });
  });

  it('treats expected apex TLS DNS absence as no surface when CT and DNS establish absence', async () => {
    tlsBoundary.connect.mockImplementation(() => {
      const socket = new EventEmitter();
      Object.assign(socket, { destroy() {} });
      queueMicrotask(() =>
        socket.emit(
          'error',
          Object.assign(new Error('getaddrinfo ENOTFOUND absent.example.com'), {
            code: 'ENOTFOUND',
          }),
        ),
      );
      return socket;
    });
    fetchMock.mockImplementation(async () => Response.json([]));
    dnsBoundary.resolve.mockRejectedValue(
      Object.assign(new Error('absent'), { code: 'ENOTFOUND' }),
    );
    const result = await runToolContract(mapDomainTool, {
      domain: 'absent.example.com',
      depth: 'quick',
    });
    expect(result.structuredContent).toMatchObject({
      error: { code: JsonRpcErrorCode.NotFound, data: { reason: 'no_surface' } },
    });
    await expect(
      surfaceResource.handler({ domain: 'absent.example.com' }, createMockContext()),
    ).rejects.toMatchObject({ code: JsonRpcErrorCode.NotFound });
  });

  it.each([401, 404, 429])(
    'keeps Shodan HTTP %i distinct in map errors and notes',
    async (status) => {
      vi.useFakeTimers();
      vi.stubEnv('SHODAN_API_KEY', 'test-key');
      resetServerConfig();
      initShodanService(getServerConfig());
      dnsBoundary.resolve.mockImplementation(async (type) =>
        type === 'A' ? ['93.184.216.34'] : [],
      );
      fetchMock.mockImplementation(async (input) => {
        const origin = new URL(String(input)).origin;
        if (origin === 'https://api.shodan.io') return new Response('', { status });
        if (origin === 'https://crt.sh' || origin === 'https://api.certspotter.com')
          return Response.json([]);
        return new Response('');
      });
      const pending = runToolContract(mapDomainTool, {
        domain: 'example.com',
        depth: 'thorough',
        includeRegistration: false,
      });
      await vi.runAllTimersAsync();
      const result = await pending;
      const text = JSON.stringify(result.content);
      const expected =
        status === 401 ? 'rejected the API key' : status === 404 ? 'no information' : 'rate limit';
      expect(result.structuredContent).toMatchObject({
        liveHosts: [{ shodan: null, errors: { shodan: expect.stringContaining(expected) } }],
      });
      expect(text).toContain(expected);
      expect(text.includes('hosts may be unscanned')).toBe(status === 404);
    },
  );

  it('prices quick and standard DNS work and carries sparse records as literal evidence', async () => {
    fetchMock.mockImplementation(async (input) =>
      ['https://crt.sh', 'https://api.certspotter.com'].includes(new URL(String(input)).origin)
        ? Response.json([])
        : new Response(''),
    );
    const marker = '<section>*TXT* `x`</section>';
    dnsBoundary.resolve.mockImplementation(async (type, _host, resolver) => {
      if (type === 'A') return [resolver === '1.1.1.1' ? '93.184.216.35' : '93.184.216.34'];
      if (type === 'MX') return [{ priority: 10, exchange: 'mail.example.com' }];
      if (type === 'TXT') return [[marker]];
      if (type === 'CAA') return [{ critical: 0, issue: 'letsencrypt.org' }];
      if (type === 'NS') return ['ns.example.com'];
      if (type === 'AAAA' && resolver === '8.8.8.8')
        throw Object.assign(new Error('IPv6 SERVFAIL'), { code: 'ESERVFAIL' });
      return [];
    });
    await runToolContract(mapDomainTool, {
      domain: 'example.com',
      depth: 'quick',
      includeRegistration: false,
    });
    expect(dnsBoundary.resolve).toHaveBeenCalledTimes(2);
    dnsBoundary.resolve.mockClear();
    const standard = await runToolContract(mapDomainTool, {
      domain: 'example.com',
      includeRegistration: false,
    });
    expect(dnsBoundary.resolve).toHaveBeenCalledTimes(23);
    expect(standard.structuredContent).toMatchObject({
      liveHosts: [
        {
          dns: {
            records: {
              A: ['93.184.216.34'],
              TXT: [marker],
              MX: ['10 mail.example.com'],
              NS: ['ns.example.com'],
              CAA: ['0 issue "letsencrypt.org"'],
            },
            propagationMismatches: ['A'],
            hostError: 'IPv6 SERVFAIL',
            resolverResults: [
              { resolver: '8.8.8.8', queryError: 'IPv6 SERVFAIL' },
              { resolver: '1.1.1.1', queryError: null },
              { resolver: '9.9.9.9', queryError: null },
            ],
          },
        },
      ],
    });
    expect(JSON.stringify(standard.content)).toContain(marker);
    expect(
      standard.content
        .filter((block) => block.type === 'text')
        .map((block) => block.text)
        .join('\n'),
    ).toContain(`\`\`${marker}\`\``);
  });

  it('bounds standard DNS fanout beyond the first ten hosts', async () => {
    let active = 0;
    let peak = 0;
    dnsBoundary.resolve.mockImplementation(async (type) => {
      peak = Math.max(peak, ++active);
      await Promise.resolve();
      active--;
      return type === 'A' ? ['93.184.216.34'] : [];
    });
    fetchMock.mockImplementation(async (input) => {
      const origin = new URL(String(input)).origin;
      if (origin === 'https://crt.sh')
        return Response.json([
          { name_value: Array.from({ length: 11 }, (_, i) => `h${i}.example.com`).join('\n') },
        ]);
      if (origin === 'https://api.certspotter.com') return Response.json([]);
      return new Response('');
    });
    const result = await runToolContract(mapDomainTool, {
      domain: 'example.com',
      includeRegistration: false,
    });
    expect(result.structuredContent).toMatchObject({
      liveHostCount: 12,
      coverage: { detailed: 12 },
    });
    expect(dnsBoundary.resolve).toHaveBeenCalledTimes(276);
    expect(peak).toBe(210);
    expect(active).toBe(0);
  });

  it('maps CT names and DNS liveness at quick depth with exact output and format shape', async () => {
    fetchMock.mockImplementation(async (input) => {
      if (String(input).startsWith('https://crt.sh/')) {
        return new Response(JSON.stringify([{ name_value: 'api.example.com\ndead.example.com' }]), {
          status: 200,
        });
      }
      if (String(input).includes('after=')) return Response.json([]);
      return Response.json([{ id: '1', dns_names: ['api.example.com'] }]);
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
    expect(result).toMatchObject({
      domain: 'example.com',
      depth: 'quick',
      subdomainCount: 2,
      liveHostCount: 2,
      liveHosts: [
        {
          host: 'example.com',
          addresses: ['93.184.216.35'],
          tls: null,
          http: null,
          shodan: null,
        },
        {
          host: 'api.example.com',
          addresses: ['93.184.216.34'],
          tls: null,
          http: null,
          shodan: null,
        },
      ],
      unresolvedSubdomains: ['dead.example.com'],
      registration: null,
      assessment: [],
      notes: ['TLS-SAN discovery failed: no apex TLS'],
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

  it.each(['Jan 01 00:00:00 2030 GMT', 'Bad time value'])(
    'preserves TLS expiry %s in mapped and resource summaries',
    async (validTo) => {
      tlsBoundary.connect.mockImplementation(
        (_options, callback) => new CertificateSocket(validTo, callback),
      );
      dnsBoundary.resolve.mockImplementation(async (type) =>
        type === 'A' ? ['93.184.216.34'] : [],
      );
      fetchMock.mockImplementation(async (input) => {
        const origin = new URL(String(input)).origin;
        if (origin === 'https://crt.sh' || origin === 'https://api.certspotter.com')
          return Response.json([]);
        return new Response('', { headers: { server: 'cloudflare' } });
      });
      const result = await runToolContract(mapDomainTool, {
        domain: 'example.com',
        depth: 'standard',
        includeRegistration: false,
      });
      const daysUntilExpiry = validTo === 'Bad time value' ? null : expect.any(Number);
      expect(result.isError).not.toBe(true);
      expect(result.structuredContent).toMatchObject({
        liveHosts: [
          {
            tls: { daysUntilExpiry },
            http: { technologies: [{ name: 'Cloudflare', category: 'cdn' }] },
          },
        ],
      });
      expect(JSON.stringify(result.content)).toContain('Cloudflare (cdn)');
      const resource = await surfaceResource.handler(
        { domain: 'example.com' },
        createMockContext(),
      );
      expect(resource).toMatchObject({ hosts: [{ tls: { daysUntilExpiry } }] });
      expect(JSON.parse(JSON.stringify(resource))).toEqual(resource);
      if (validTo === 'Bad time value') {
        expect(JSON.stringify(result.content)).toContain('unknown days left');
        expect(JSON.stringify(result.content)).toContain('expiry is unknown');
        expect(JSON.stringify(resource)).toContain('expiry is unknown');
      }
    },
  );

  it('returns the typed no_surface envelope when CT is empty and the apex does not resolve', async () => {
    tlsBoundary.san = '';
    tlsBoundary.connect.mockImplementation(
      (_options, callback) => new CertificateSocket('Jan 01 00:00:00 2030 GMT', callback),
    );
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

  it('carries identity status and mismatch findings through mapped and resource summaries', async () => {
    tlsBoundary.san = 'DNS:other.example.com';
    tlsBoundary.connect.mockImplementation(
      (_options, callback) => new CertificateSocket('Jan 01 00:00:00 2030 GMT', callback),
    );
    dnsBoundary.resolve.mockImplementation(async (type, host) =>
      type === 'A' && host === 'example.com' ? ['93.184.216.34'] : [],
    );
    fetchMock.mockImplementation(async (input) => {
      const origin = new URL(String(input)).origin;
      if (origin === 'https://crt.sh' || origin === 'https://api.certspotter.com')
        return Response.json([]);
      return new Response('');
    });
    const result = await runToolContract(mapDomainTool, {
      domain: 'example.com',
      includeRegistration: false,
    });
    expect(result.isError).not.toBe(true);
    expect(result.structuredContent).toMatchObject({
      liveHosts: [
        {
          tls: {
            validationAuthorized: true,
            identityAuthorized: false,
            identityError: expect.any(String),
          },
        },
      ],
      assessment: expect.arrayContaining([
        expect.stringContaining('Certificate identity did not match'),
      ]),
    });
    expect(JSON.stringify(result.content)).toContain('identityAuthorized=false');
    expect(JSON.stringify(result.content)).toContain('Certificate identity did not match');
    const resource = await surfaceResource.handler({ domain: 'example.com' }, createMockContext());
    expect(resource).toMatchObject({
      hosts: [
        {
          tls: {
            identityAuthorized: false,
            identityError: expect.any(String),
            findings: expect.arrayContaining([
              expect.stringContaining('Certificate identity did not match'),
            ]),
          },
        },
      ],
    });
  });

  it.each(['limited', 'failed'])(
    'carries %s body inspection through map and resource summaries',
    async (status) => {
      dnsBoundary.resolve.mockImplementation(async (type) =>
        type === 'A' ? ['93.184.216.34'] : [],
      );
      fetchMock.mockImplementation(async (input) => {
        const origin = new URL(String(input)).origin;
        if (origin === 'https://crt.sh' || origin === 'https://api.certspotter.com')
          return Response.json([]);
        const body =
          status === 'failed'
            ? new ReadableStream({
                start(controller) {
                  controller.error(new Error('body interrupted'));
                },
              })
            : 'x'.repeat(64_000);
        return new Response(body, { headers: { server: 'Caddy' } });
      });
      const result = await runToolContract(mapDomainTool, {
        domain: 'example.com',
        includeRegistration: false,
      });
      expect(result.isError).not.toBe(true);
      expect(result.structuredContent).toMatchObject({
        liveHosts: [{ http: { bodyInspection: { status }, technologies: [{ name: 'Caddy' }] } }],
      });
      expect(JSON.stringify(result.content)).toContain(`Body inspection: ${status}`);
      const resource = await surfaceResource.handler(
        { domain: 'example.com' },
        createMockContext(),
      );
      expect(resource).toMatchObject({ hosts: [{ http: { bodyInspection: { status } } }] });
    },
  );

  it.each(['map', 'resource'])(
    'propagates cancellation past %s aggregation catches',
    async (surface) => {
      vi.useFakeTimers();
      dnsBoundary.resolve.mockImplementation(async (type) =>
        type === 'A' ? ['93.184.216.34'] : [],
      );
      let bodyStarted!: () => void;
      const ready = new Promise<void>((resolve) => {
        bodyStarted = resolve;
      });
      fetchMock.mockImplementation(async (input) => {
        const origin = new URL(String(input)).origin;
        if (origin === 'https://crt.sh' || origin === 'https://api.certspotter.com')
          return Response.json([]);
        bodyStarted();
        return new Response(new ReadableStream());
      });
      const controller = new AbortController();
      if (surface === 'map') {
        const pending = runToolContract(
          mapDomainTool,
          { domain: 'example.com', includeRegistration: false },
          { context: { signal: controller.signal } },
        );
        await ready;
        await vi.advanceTimersByTimeAsync(0);
        controller.abort();
        const result = await pending;
        expect(result.structuredContent).toMatchObject({
          error: { code: JsonRpcErrorCode.RequestCancelled },
        });
        expect(JSON.stringify(result.content)).toMatch(/cancel|abort/i);
      } else {
        const pending = surfaceResource.handler(
          { domain: 'example.com' },
          createMockContext({ signal: controller.signal }),
        );
        const rejected = expect(pending).rejects.toMatchObject({ name: 'AbortError' });
        await ready;
        await vi.advanceTimersByTimeAsync(0);
        controller.abort();
        await rejected;
      }
      expect(vi.getTimerCount()).toBe(0);
    },
  );

  it('propagates ineffective header findings into mapped assessment and resource posture', async () => {
    dnsBoundary.resolve.mockImplementation(async (type) => (type === 'A' ? ['93.184.216.34'] : []));
    fetchMock.mockImplementation(async (input) => {
      const origin = new URL(String(input)).origin;
      if (origin === 'https://crt.sh' || origin === 'https://api.certspotter.com')
        return Response.json([]);
      return new Response('', {
        headers: {
          'x-frame-options': 'invalid',
          'x-content-type-options': 'invalid',
          'strict-transport-security': 'max-age=0',
        },
      });
    });
    const result = await runToolContract(mapDomainTool, {
      domain: 'example.com',
      includeRegistration: false,
    });
    expect(result.isError).not.toBe(true);
    expect(result.structuredContent).toMatchObject({
      assessment: expect.arrayContaining([
        expect.stringContaining('No clickjacking'),
        expect.stringContaining('HSTS does not contain'),
      ]),
    });
    expect(JSON.stringify(result.content)).toContain('No clickjacking');
    const resource = await surfaceResource.handler({ domain: 'example.com' }, createMockContext());
    expect(resource).toMatchObject({
      hosts: [
        {
          http: {
            securityFindings: expect.arrayContaining([
              expect.stringContaining('No clickjacking'),
              expect.stringContaining('HSTS does not contain'),
            ]),
          },
        },
      ],
    });
  });
});
