/**
 * @fileoverview Integration tests for attacksurface_lookup_registration with RDAP/WHOIS faked.
 * @module tests/integration/lookup-registration.tool.test
 */

import { EventEmitter } from 'node:events';
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { createMockContext } from '@cyanheads/mcp-ts-core/testing';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { ServerConfig } from '@/config/server-config.js';

const netBoundary = vi.hoisted(() => ({
  createConnection: vi.fn(),
  responses: [] as Array<string | Error>,
}));

vi.mock('node:net', async () => {
  const actual = await vi.importActual<typeof import('node:net')>('node:net');
  return { ...actual, createConnection: netBoundary.createConnection };
});

import { lookupRegistrationTool } from '@/mcp-server/tools/definitions/lookup-registration.tool.js';
import { initRegistrationService } from '@/services/registration/registration-service.js';

type HandlerCtx = Parameters<typeof lookupRegistrationTool.handler>[1];

const config = {
  defaultResolvers: '8.8.8.8',
  httpUserAgent: 'attack-surface-test',
  maxSubdomains: 200,
  rdapBootstrapUrl: 'https://rdap.example.test',
} satisfies ServerConfig;

class FakeWhoisSocket extends EventEmitter {
  constructor(private readonly response: string | Error) {
    super();
    queueMicrotask(() => {
      if (response instanceof Error) this.emit('error', response);
      else this.emit('connect');
    });
  }

  destroy() {}

  setEncoding() {}

  write() {
    if (typeof this.response === 'string') {
      this.emit('data', this.response);
      this.emit('end');
    }
  }
}

function context(): HandlerCtx {
  return createMockContext({ errors: lookupRegistrationTool.errors ?? [] }) as HandlerCtx;
}

describe('attacksurface_lookup_registration', () => {
  const fetchMock = vi.fn<typeof fetch>();

  beforeEach(() => {
    vi.stubEnv('ATTACKSURFACE_ALLOW_PRIVATE_TARGETS', 'true');
    fetchMock.mockReset();
    vi.stubGlobal('fetch', fetchMock);
    netBoundary.responses.length = 0;
    netBoundary.createConnection.mockReset();
    netBoundary.createConnection.mockImplementation(() => {
      const response = netBoundary.responses.shift();
      if (!response) throw new Error('Missing fake WHOIS response');
      return new FakeWhoisSocket(response);
    });
    initRegistrationService(config);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.unstubAllEnvs();
  });

  it('normalizes a domain and returns schema-valid sparse RDAP output', async () => {
    fetchMock.mockResolvedValue(
      Response.json({
        status: ['active'],
        events: [{ eventAction: 'registration', eventDate: '1995-08-14T04:00:00Z' }],
        nameservers: [{ ldhName: 'NS1.EXAMPLE.COM' }],
        entities: [{ roles: ['registrar'], handle: 'REGISTRAR-HANDLE' }],
      }),
    );

    const result = await lookupRegistrationTool.handler(
      lookupRegistrationTool.input.parse({ target: 'HTTPS://EXAMPLE.COM/path' }),
      context(),
    );

    expect(result).toEqual(expect.schemaMatching(lookupRegistrationTool.output));
    expect(result).toEqual({
      source: 'rdap',
      registration: {
        kind: 'domain',
        target: 'example.com',
        registrar: 'REGISTRAR-HANDLE',
        statuses: ['active'],
        events: [{ action: 'registration', date: '1995-08-14T04:00:00Z' }],
        nameservers: ['ns1.example.com'],
      },
      rawWhois: null,
      notes: [],
    });
    const blocks = lookupRegistrationTool.format?.(result);
    if (blocks?.[0]?.type === 'text') {
      expect(blocks[0].text).toContain('REGISTRAR-HANDLE');
      expect(blocks[0].text).toContain('DNSSEC:** unknown');
      expect(blocks[0].text).toContain('ns1.example.com');
    }
  });

  it('returns IP registration output for auto-detected IPv4 CIDR input', async () => {
    fetchMock.mockResolvedValue(
      Response.json({
        name: 'EXAMPLE-NET',
        cidr0_cidrs: [{ v4prefix: '8.8.8.0', length: 24 }],
        arin_originas0_originautnums: [15169],
        country: 'US',
      }),
    );

    const result = await lookupRegistrationTool.handler(
      lookupRegistrationTool.input.parse({ target: '8.8.8.0/24' }),
      context(),
    );

    expect(result).toEqual(expect.schemaMatching(lookupRegistrationTool.output));
    expect(result.registration).toEqual({
      kind: 'ip',
      target: '8.8.8.0/24',
      networkName: 'EXAMPLE-NET',
      cidrs: ['8.8.8.0/24'],
      originAsns: [15169],
      country: 'US',
      statuses: [],
      events: [],
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://rdap.example.test/ip/8.8.8.0%2F24',
      expect.objectContaining({ redirect: 'manual' }),
    );
    const blocks = lookupRegistrationTool.format?.(result);
    expect(blocks?.[0]).toMatchObject({
      type: 'text',
      text: expect.stringContaining('Registration: 8.8.8.0/24 (ip)'),
    });
  });

  it('preserves an auto-detected IPv6 CIDR through RDAP and output', async () => {
    fetchMock.mockResolvedValue(
      Response.json({
        name: 'EXAMPLE-V6-NET',
        cidr0_cidrs: [{ v6prefix: '2001:db8::', length: 32 }],
      }),
    );

    const result = await lookupRegistrationTool.handler(
      lookupRegistrationTool.input.parse({ target: '2001:db8::/32' }),
      context(),
    );

    expect(result).toEqual(expect.schemaMatching(lookupRegistrationTool.output));
    expect(result.registration).toMatchObject({
      kind: 'ip',
      target: '2001:db8::/32',
      cidrs: ['2001:db8::/32'],
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://rdap.example.test/ip/2001%3Adb8%3A%3A%2F32',
      expect.objectContaining({ redirect: 'manual' }),
    );
    const blocks = lookupRegistrationTool.format?.(result);
    expect(blocks?.[0]).toMatchObject({
      type: 'text',
      text: expect.stringContaining('Registration: 2001:db8::/32 (ip)'),
    });
  });

  it('retains explicit IP normalization behavior', async () => {
    fetchMock.mockResolvedValue(Response.json({ name: 'EXAMPLE-NET' }));

    const result = await lookupRegistrationTool.handler(
      lookupRegistrationTool.input.parse({ target: ' 8.8.8.8 ', type: 'ip' }),
      context(),
    );

    expect(result.registration).toMatchObject({ kind: 'ip', target: '8.8.8.8' });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://rdap.example.test/ip/8.8.8.8',
      expect.objectContaining({ redirect: 'manual' }),
    );
  });

  it('enforces type enum boundaries and returns the typed invalid_target envelope', async () => {
    expect(
      lookupRegistrationTool.input.safeParse({ target: 'example.com', type: 'network' }).success,
    ).toBe(false);

    await expect(
      lookupRegistrationTool.handler(
        lookupRegistrationTool.input.parse({ target: 'not a target' }),
        context(),
      ),
    ).rejects.toMatchObject({
      code: JsonRpcErrorCode.ValidationError,
      data: {
        reason: 'invalid_target',
        recovery: { hint: expect.stringContaining('CIDR') },
      },
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('falls back to WHOIS and returns raw text plus parsed fields', async () => {
    fetchMock.mockRejectedValue(new Error('RDAP offline'));
    netBoundary.responses.push(
      'refer: whois.registry.test\n',
      'Registrar: Example Registrar\nName Server: NS1.EXAMPLE.COM\nDNSSEC: signedDelegation\n',
    );

    const result = await lookupRegistrationTool.handler(
      lookupRegistrationTool.input.parse({ target: 'example.com' }),
      context(),
    );

    expect(result).toEqual(expect.schemaMatching(lookupRegistrationTool.output));
    expect(result).toMatchObject({
      source: 'whois',
      registration: {
        kind: 'domain',
        registrar: 'Example Registrar',
        nameservers: ['ns1.example.com'],
        dnssecSigned: true,
      },
      rawWhois: expect.stringContaining('Example Registrar'),
      notes: [expect.stringContaining('fell back to WHOIS')],
    });
  });

  it('propagates a WHOIS transport failure after RDAP fails', async () => {
    fetchMock.mockRejectedValue(new Error('RDAP offline'));
    netBoundary.responses.push(new Error('WHOIS refused'));

    await expect(
      lookupRegistrationTool.handler(
        lookupRegistrationTool.input.parse({ target: 'example.com' }),
        context(),
      ),
    ).rejects.toThrow('WHOIS refused');
  });
});
