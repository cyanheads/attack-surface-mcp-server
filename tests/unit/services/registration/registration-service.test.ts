/**
 * @fileoverview Boundary and parser tests for RDAP/WHOIS registration lookup.
 * @module services/registration/registration-service.test
 */

import { EventEmitter } from 'node:events';
import { createMockContext } from '@cyanheads/mcp-ts-core/testing';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { ServerConfig } from '@/config/server-config.js';

interface WhoisScenario {
  chunks?: string[];
  error?: Error;
  mode: 'success' | 'error' | 'timeout';
}

const netBoundary = vi.hoisted(() => ({
  createConnection: vi.fn(),
  scenarios: [] as WhoisScenario[],
}));
const ssrfBoundary = vi.hoisted(() => ({
  assertSafeUrl: vi.fn<(rawUrl: string, signal?: AbortSignal) => Promise<void>>(),
}));

vi.mock('node:net', async () => {
  const actual = await vi.importActual<typeof import('node:net')>('node:net');
  return { ...actual, createConnection: netBoundary.createConnection };
});

vi.mock('@/utils/ssrf-guard.js', async () => {
  const actual =
    await vi.importActual<typeof import('@/utils/ssrf-guard.js')>('@/utils/ssrf-guard.js');
  return { ...actual, assertSafeUrl: ssrfBoundary.assertSafeUrl };
});

import {
  classifyTarget,
  RegistrationService,
} from '@/services/registration/registration-service.js';

const config = {
  defaultResolvers: '8.8.8.8',
  httpUserAgent: 'attack-surface-test',
  maxSubdomains: 200,
  rdapBootstrapUrl: 'https://rdap.example.test/',
} satisfies ServerConfig;

class FakeWhoisSocket extends EventEmitter {
  constructor(private readonly scenario: WhoisScenario) {
    super();
    if (scenario.mode !== 'timeout') {
      queueMicrotask(() => {
        if (scenario.mode === 'error') {
          this.emit('error', scenario.error ?? new Error('WHOIS failed'));
          return;
        }
        this.emit('connect');
      });
    }
  }

  destroy() {}

  setEncoding() {}

  write() {
    for (const chunk of this.scenario.chunks ?? []) this.emit('data', chunk);
    this.emit('end');
  }
}

function delayedResponse(
  response: Response,
  delayMs: number,
  signal: AbortSignal | null | undefined,
): Promise<Response> {
  return new Promise((resolve, reject) => {
    const onAbort = () => {
      clearTimeout(timer);
      reject(new DOMException('The operation was aborted.', 'AbortError'));
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve(response);
    }, delayMs);

    if (signal?.aborted) onAbort();
    else signal?.addEventListener('abort', onAbort, { once: true });
  });
}

describe('classifyTarget', () => {
  it('classifies IPv4 and IPv6 literals as ip', () => {
    expect(classifyTarget('8.8.8.8')).toBe('ip');
    expect(classifyTarget('2001:4860:4860::8888')).toBe('ip');
  });

  it('classifies CIDRs as ip', () => {
    expect(classifyTarget('8.8.8.0/24')).toBe('ip');
    expect(classifyTarget('2001:db8::/32')).toBe('ip');
  });

  it('classifies domains as domain', () => {
    expect(classifyTarget('example.com')).toBe('domain');
  });
});

describe('RegistrationService', () => {
  const fetchMock = vi.fn<typeof fetch>();

  beforeEach(() => {
    vi.useRealTimers();
    vi.stubEnv('ATTACKSURFACE_ALLOW_PRIVATE_TARGETS', 'true');
    fetchMock.mockReset();
    vi.stubGlobal('fetch', fetchMock);
    ssrfBoundary.assertSafeUrl.mockReset();
    ssrfBoundary.assertSafeUrl.mockResolvedValue();
    netBoundary.createConnection.mockReset();
    netBoundary.scenarios.length = 0;
    netBoundary.createConnection.mockImplementation(() => {
      const scenario = netBoundary.scenarios.shift();
      if (!scenario) throw new Error('Missing fake WHOIS scenario');
      return new FakeWhoisSocket(scenario);
    });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.unstubAllEnvs();
    vi.useRealTimers();
  });

  it('parses a complete domain RDAP response without inventing missing fields', async () => {
    fetchMock.mockResolvedValue(
      Response.json({
        status: ['active', 'client transfer prohibited'],
        events: [
          { eventAction: 'registration', eventDate: '1995-08-14T04:00:00Z' },
          { eventAction: 'incomplete' },
        ],
        nameservers: [{ ldhName: 'NS1.EXAMPLE.COM' }, {}, { ldhName: 'NS2.EXAMPLE.COM' }],
        secureDNS: { delegationSigned: false },
        entities: [
          {
            roles: ['registrar'],
            vcardArray: [
              'vcard',
              [
                ['version', {}, 'text', '4.0'],
                ['fn', {}, 'text', 'Example Registrar LLC'],
              ],
            ],
          },
        ],
      }),
    );

    await expect(
      new RegistrationService(config).lookup('example.com', 'domain', createMockContext()),
    ).resolves.toEqual({
      source: 'rdap',
      registration: {
        kind: 'domain',
        target: 'example.com',
        registrar: 'Example Registrar LLC',
        statuses: ['active', 'client transfer prohibited'],
        events: [{ action: 'registration', date: '1995-08-14T04:00:00Z' }],
        nameservers: ['ns1.example.com', 'ns2.example.com'],
        dnssecSigned: false,
      },
      rawWhois: null,
      notes: [],
    });
  });

  it('parses sparse IP RDAP data and preserves absent fields as absent', async () => {
    fetchMock.mockResolvedValue(
      Response.json({
        handle: 'NET-93-184-216-0-1',
        cidr0_cidrs: [
          { v4prefix: '93.184.216.0', length: 24 },
          { v6prefix: '2001:db8::', length: 32 },
          {},
        ],
        arin_originas0_originautnums: [15133],
        country: null,
      }),
    );

    const result = await new RegistrationService(config).lookup(
      '93.184.216.34',
      'auto',
      createMockContext(),
    );

    expect(result).toEqual({
      source: 'rdap',
      registration: {
        kind: 'ip',
        target: '93.184.216.34',
        networkName: 'NET-93-184-216-0-1',
        cidrs: ['93.184.216.0/24', '2001:db8::/32'],
        originAsns: [15133],
        statuses: [],
        events: [],
      },
      rawWhois: null,
      notes: [],
    });
    expect(result.registration).not.toHaveProperty('country');
  });

  it('follows relative RDAP redirects manually before parsing', async () => {
    fetchMock
      .mockResolvedValueOnce(
        new Response(null, { status: 302, headers: { location: '/authoritative/example.com' } }),
      )
      .mockResolvedValueOnce(Response.json({ status: ['active'] }));

    const result = await new RegistrationService(config).lookup(
      'example.com',
      'domain',
      createMockContext(),
    );

    expect(result.source).toBe('rdap');
    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      'https://rdap.example.test/authoritative/example.com',
      expect.objectContaining({ redirect: 'manual' }),
    );
  });

  it('gives an authoritative RDAP redirect target a fresh timeout', async () => {
    vi.useFakeTimers();
    fetchMock
      .mockImplementationOnce((_input, init) =>
        delayedResponse(
          new Response(null, {
            status: 302,
            headers: { location: '/authoritative/example.com' },
          }),
          4_000,
          init?.signal,
        ),
      )
      .mockImplementationOnce((_input, init) =>
        delayedResponse(Response.json({ status: ['active'] }), 2_000, init?.signal),
      );
    netBoundary.scenarios.push({
      mode: 'success',
      chunks: ['Registrar: WHOIS fallback\n'],
    });

    const pending = new RegistrationService(config).lookup(
      'example.com',
      'domain',
      createMockContext(),
    );
    await vi.advanceTimersByTimeAsync(6_000);

    await expect(pending).resolves.toMatchObject({ source: 'rdap' });
  });

  it('bounds an unresponsive RDAP hop before falling back to WHOIS', async () => {
    vi.useFakeTimers();
    fetchMock.mockImplementation((_input, init) =>
      delayedResponse(Response.json({}), 60_000, init?.signal),
    );
    netBoundary.scenarios.push({
      mode: 'success',
      chunks: ['Registrar: WHOIS fallback\n'],
    });

    const pending = new RegistrationService(config).lookup(
      'example.com',
      'domain',
      createMockContext(),
    );
    await vi.advanceTimersByTimeAsync(5_000);

    await expect(pending).resolves.toMatchObject({
      source: 'whois',
      notes: [expect.stringContaining('fell back to WHOIS')],
    });
  });

  it('includes SSRF validation in the per-hop RDAP timeout', async () => {
    vi.useFakeTimers();
    ssrfBoundary.assertSafeUrl.mockImplementation((_url, signal) =>
      delayedResponse(Response.json({}), 6_000, signal).then(() => undefined),
    );
    fetchMock.mockResolvedValue(Response.json({ status: ['active'] }));
    netBoundary.scenarios.push({
      mode: 'success',
      chunks: ['Registrar: WHOIS fallback\n'],
    });

    const pending = new RegistrationService(config).lookup(
      'example.com',
      'domain',
      createMockContext(),
    );
    await vi.advanceTimersByTimeAsync(6_000);

    await expect(pending).resolves.toMatchObject({ source: 'whois' });
    expect(fetchMock).not.toHaveBeenCalled();
    expect(ssrfBoundary.assertSafeUrl).toHaveBeenCalledWith(
      'https://rdap.example.test/domain/example.com',
      expect.any(AbortSignal),
    );
  });

  it('propagates caller cancellation without starting WHOIS', async () => {
    const controller = new AbortController();
    let rdapSignal: AbortSignal | null | undefined;
    fetchMock.mockImplementation((_input, init) => {
      rdapSignal = init?.signal;
      return delayedResponse(Response.json({}), 60_000, init?.signal);
    });
    const pending = new RegistrationService(config).lookup(
      'example.com',
      'domain',
      createMockContext({ signal: controller.signal }),
    );
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledOnce());
    controller.abort();

    await expect(pending).rejects.toMatchObject({ name: 'AbortError' });
    expect(rdapSignal?.aborted).toBe(true);
    expect(netBoundary.createConnection).not.toHaveBeenCalled();
  });

  it('falls back to authoritative WHOIS and parses domain fields', async () => {
    fetchMock.mockRejectedValue(new Error('RDAP offline'));
    netBoundary.scenarios.push(
      { mode: 'success', chunks: ['refer: whois.registry.test\n'] },
      {
        mode: 'success',
        chunks: [
          'Registrar: Example Registrar\n',
          'Domain Status: clientTransferProhibited https://icann.org/epp\n',
          'Creation Date: 1995-08-14T04:00:00Z\n',
          'Registry Expiry Date: 2030-08-13T04:00:00Z\n',
          'Updated Date: 2025-01-01T00:00:00Z\n',
          'Name Server: NS1.EXAMPLE.COM\nName Server: NS1.EXAMPLE.COM\n',
          'DNSSEC: unsigned\n',
        ],
      },
    );

    const result = await new RegistrationService(config).lookup(
      'example.com',
      'domain',
      createMockContext(),
    );

    expect(result).toEqual({
      source: 'whois',
      registration: {
        kind: 'domain',
        target: 'example.com',
        registrar: 'Example Registrar',
        statuses: ['clientTransferProhibited'],
        events: [
          { action: 'registration', date: '1995-08-14T04:00:00Z' },
          { action: 'expiration', date: '2030-08-13T04:00:00Z' },
          { action: 'last changed', date: '2025-01-01T00:00:00Z' },
        ],
        nameservers: ['ns1.example.com'],
        dnssecSigned: false,
      },
      rawWhois: expect.stringContaining('Example Registrar'),
      notes: ['RDAP lookup failed (RDAP offline); fell back to WHOIS.'],
    });
    expect(netBoundary.createConnection).toHaveBeenNthCalledWith(1, 43, 'whois.iana.org');
    expect(netBoundary.createConnection).toHaveBeenNthCalledWith(2, 43, 'whois.registry.test');
  });

  it('parses IP WHOIS fields and tolerates truncated text', async () => {
    fetchMock.mockRejectedValue(new Error('RDAP unavailable'));
    netBoundary.scenarios.push({
      mode: 'success',
      chunks: [
        'NetName: EXAMPLE-NET\nCIDR: 8.8.8.0/24\nroute: 8.8.8.0/24\n',
        'OriginAS: AS15169\norigin: 15169\nCountry: us\ntruncated-tail-without-colon',
      ],
    });

    const result = await new RegistrationService(config).lookup(
      '8.8.8.8',
      'ip',
      createMockContext(),
    );

    expect(result.registration).toEqual({
      kind: 'ip',
      target: '8.8.8.8',
      networkName: 'EXAMPLE-NET',
      cidrs: ['8.8.8.0/24'],
      originAsns: [15169],
      country: 'US',
      statuses: [],
      events: [],
    });
  });

  it('does not let whitespace-only IP WHOIS fields consume later CRLF records', async () => {
    fetchMock.mockRejectedValue(new Error('RDAP unavailable'));
    netBoundary.scenarios.push({
      mode: 'success',
      chunks: [
        'NetName: \t \r\nNetName: EXAMPLE-NET\r\n',
        'CIDR: \t \r\nCIDR: 192.0.2.0/24\r\n',
        'OriginAS: \t \r\nOriginAS: AS1\r\n',
        'Country: \t \r\nCountry: AA\r\n',
      ],
    });

    const result = await new RegistrationService(config).lookup(
      '192.0.2.1',
      'ip',
      createMockContext(),
    );

    expect(result.registration).toEqual({
      kind: 'ip',
      target: '192.0.2.1',
      networkName: 'EXAMPLE-NET',
      cidrs: ['192.0.2.0/24'],
      originAsns: [1],
      country: 'AA',
      statuses: [],
      events: [],
    });
  });

  it('does not let whitespace-only domain WHOIS fields consume later CRLF records', async () => {
    fetchMock.mockRejectedValue(new Error('RDAP unavailable'));
    netBoundary.scenarios.push({
      mode: 'success',
      chunks: [
        'Registrar: \t \r\nRegistrar: Example Registrar\r\n',
        'Domain Status: \t \r\nDomain Status: active\r\n',
        'Creation Date: \t \r\nCreation Date: 1995-08-14T04:00:00Z\r\n',
        'Registry Expiry Date: \t \r\nRegistry Expiry Date: 2030-08-13T04:00:00Z\r\n',
        'Updated Date: \t \r\nUpdated Date: 2025-01-01T00:00:00Z\r\n',
        'Name Server: \t \r\nName Server: NS1.EXAMPLE.COM\r\n',
        'DNSSEC: \t \r\nDNSSEC: signedDelegation\r\n',
      ],
    });

    const result = await new RegistrationService(config).lookup(
      'example.com',
      'domain',
      createMockContext(),
    );

    expect(result.registration).toEqual({
      kind: 'domain',
      target: 'example.com',
      registrar: 'Example Registrar',
      statuses: ['active'],
      events: [
        { action: 'registration', date: '1995-08-14T04:00:00Z' },
        { action: 'expiration', date: '2030-08-13T04:00:00Z' },
        { action: 'last changed', date: '2025-01-01T00:00:00Z' },
      ],
      nameservers: ['ns1.example.com'],
      dnssecSigned: true,
    });
  });

  it('times out a WHOIS fallback that never answers', async () => {
    vi.useFakeTimers();
    fetchMock.mockRejectedValue(new Error('RDAP unavailable'));
    netBoundary.scenarios.push({ mode: 'timeout' });

    const pending = new RegistrationService(config).lookup(
      'example.com',
      'domain',
      createMockContext(),
    );
    const rejection = expect(pending).rejects.toThrow('WHOIS whois.iana.org timed out');
    await vi.advanceTimersByTimeAsync(8_000);

    await rejection;
  });
});
