/**
 * @fileoverview Integration tests for attacksurface_inspect_tls with node:tls faked.
 * @module tests/integration/inspect-tls.tool.test
 */

import { EventEmitter } from 'node:events';
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { createMockContext, getEnrichment, runToolContract } from '@cyanheads/mcp-ts-core/testing';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

interface Scenario {
  error?: Error;
  mode: 'success' | 'error';
  validTo?: string;
}

const tlsBoundary = vi.hoisted(() => ({ connect: vi.fn(), scenarios: [] as Scenario[] }));
vi.mock('node:tls', () => ({ connect: tlsBoundary.connect }));

import { inspectTlsTool } from '@/mcp-server/tools/definitions/inspect-tls.tool.js';
import { initTlsService } from '@/services/tls/tls-service.js';

type HandlerCtx = Parameters<typeof inspectTlsTool.handler>[1];

class FakeSocket extends EventEmitter {
  authorized = true;
  authorizationError: string | undefined;

  constructor(
    private readonly scenario: Scenario,
    callback: () => void,
  ) {
    super();
    if (scenario.mode === 'success') queueMicrotask(callback);
    else queueMicrotask(() => this.emit('error', scenario.error ?? new Error('TLS failed')));
  }

  destroy() {}

  getCipher() {
    return { standardName: 'TLS_AES_128_GCM_SHA256' };
  }

  getPeerCertificate() {
    return {
      subject: { CN: 'secure.example.com' },
      issuer: { CN: 'Example CA', O: 'Example PKI' },
      subjectaltname: 'DNS:secure.example.com, DNS:www.example.com',
      valid_from: 'Jan 01 00:00:00 2026 GMT',
      valid_to: this.scenario.validTo ?? 'Jan 01 00:00:00 2027 GMT',
      serialNumber: '01AB',
      fingerprint256: 'AA:BB:CC',
      ext_key_usage: ['1.3.6.1.5.5.7.3.1'],
    };
  }

  getProtocol() {
    return 'TLSv1.3';
  }
}

function context(): HandlerCtx {
  return createMockContext({ errors: inspectTlsTool.errors ?? [] }) as HandlerCtx;
}

describe('attacksurface_inspect_tls', () => {
  beforeEach(() => {
    vi.stubEnv('ATTACKSURFACE_ALLOW_PRIVATE_TARGETS', 'true');
    initTlsService();
    tlsBoundary.scenarios.length = 0;
    tlsBoundary.connect.mockReset();
    tlsBoundary.connect.mockImplementation((_options, callback) => {
      const scenario = tlsBoundary.scenarios.shift();
      if (!scenario) throw new Error('Missing fake TLS scenario');
      return new FakeSocket(scenario, callback);
    });
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    vi.useRealTimers();
  });

  it('returns schema-valid certificate posture and complete format output', async () => {
    tlsBoundary.scenarios.push({ mode: 'success' });

    const result = await inspectTlsTool.handler(
      inspectTlsTool.input.parse({ hosts: ['secure.example.com'], port: 443, timeoutMs: 1_000 }),
      context(),
    );

    expect(result).toEqual(expect.schemaMatching(inspectTlsTool.output));
    expect(result.results[0]).toMatchObject({
      host: 'secure.example.com',
      port: 443,
      protocol: 'TLSv1.3',
      cipher: 'TLS_AES_128_GCM_SHA256',
      certificate: {
        subjectCommonName: 'secure.example.com',
        subjectAltNames: ['secure.example.com', 'www.example.com'],
        issuerCommonName: 'Example CA',
        issuerOrganization: 'Example PKI',
        serialNumber: '01AB',
        fingerprintSha256: 'AA:BB:CC',
        extendedKeyUsages: ['serverAuth (1.3.6.1.5.5.7.3.1)'],
      },
      validationAuthorized: true,
      validationError: null,
      handshakeError: null,
    });
    const blocks = inspectTlsTool.format?.(result);
    if (blocks?.[0]?.type === 'text') {
      expect(blocks[0].text).toContain('secure.example.com:443');
      expect(blocks[0].text).toContain('TLSv1.3');
      expect(blocks[0].text).toContain('AA:BB:CC');
      expect(blocks[0].text).toContain('www.example.com');
    }
  });

  it('enforces host-count, port, and timeout schema boundaries', () => {
    expect(inspectTlsTool.input.safeParse({ hosts: [] }).success).toBe(false);
    expect(
      inspectTlsTool.input.safeParse({ hosts: Array.from({ length: 51 }, () => 'example.com') })
        .success,
    ).toBe(false);
    expect(inspectTlsTool.input.safeParse({ hosts: ['example.com'], port: 0 }).success).toBe(false);
    expect(inspectTlsTool.input.safeParse({ hosts: ['example.com'], port: 65_536 }).success).toBe(
      false,
    );
    expect(inspectTlsTool.input.safeParse({ hosts: ['example.com'], timeoutMs: 999 }).success).toBe(
      false,
    );
    expect(
      inspectTlsTool.input.safeParse({ hosts: ['example.com'], timeoutMs: 30_001 }).success,
    ).toBe(false);
    expect(
      inspectTlsTool.input.safeParse({ hosts: ['example.com'], port: 1, timeoutMs: 1_000 }).success,
    ).toBe(true);
    expect(
      inspectTlsTool.input.safeParse({ hosts: ['example.com'], port: 65_535, timeoutMs: 30_000 })
        .success,
    ).toBe(true);
  });

  it.each(['1.1.1.1', '2606:4700:4700::1111', 'secure.example.com'])(
    'preserves certificate output for %s with SNI only for hostnames',
    async (host) => {
      tlsBoundary.scenarios.push({ mode: 'success' });
      const result = await runToolContract(inspectTlsTool, { hosts: [host] });
      expect(result.isError).not.toBe(true);
      expect(result.structuredContent).toMatchObject({
        results: [{ host, handshakeError: null, certificate: { fingerprintSha256: 'AA:BB:CC' } }],
      });
      const text = JSON.stringify(result.content);
      expect(text).toContain(`${host}:443`);
      expect(text).toContain('AA:BB:CC');
      expect(text).toContain('www.example.com');
      if (host === 'secure.example.com') {
        expect(tlsBoundary.connect.mock.calls[0]?.[0]).toHaveProperty('servername', host);
      } else {
        expect(tlsBoundary.connect.mock.calls[0]?.[0]).not.toHaveProperty('servername');
      }
    },
  );

  it('preserves good and constructor-failure hosts on both output paths without a leftover timer', async () => {
    vi.useFakeTimers();
    tlsBoundary.connect.mockImplementationOnce(() => {
      throw new Error('socket construction failed');
    });
    tlsBoundary.scenarios.push({ mode: 'success' });
    const result = await runToolContract(inspectTlsTool, {
      hosts: ['broken.example.com', 'secure.example.com'],
      timeoutMs: 1_000,
    });
    expect(result.isError).not.toBe(true);
    expect(result.structuredContent).toMatchObject({
      results: [
        {
          host: 'broken.example.com',
          certificate: null,
          handshakeError: 'socket construction failed',
        },
        {
          host: 'secure.example.com',
          certificate: { fingerprintSha256: 'AA:BB:CC' },
          handshakeError: null,
        },
      ],
    });
    const text = JSON.stringify(result.content);
    expect(text).toContain('broken.example.com');
    expect(text).toContain('socket construction failed');
    expect(text).toContain('secure.example.com');
    expect(text).toContain('AA:BB:CC');
    expect(text).not.toContain('No host completed');
    expect.soft(vi.getTimerCount()).toBe(0);
    await vi.advanceTimersByTimeAsync(1_500);
    expect(vi.getTimerCount()).toBe(0);
  });

  it('keeps multi-host certificate results and unknown expiry on both output paths', async () => {
    tlsBoundary.scenarios.push({ mode: 'success', validTo: 'Bad time value' }, { mode: 'success' });
    const result = await runToolContract(inspectTlsTool, {
      hosts: ['malformed.example.com', 'secure.example.com'],
    });
    expect(result.isError).not.toBe(true);
    expect(result.structuredContent).toMatchObject({
      results: [
        {
          host: 'malformed.example.com',
          handshakeError: null,
          certificate: {
            validTo: 'Bad time value',
            daysUntilExpiry: null,
            subjectAltNames: ['secure.example.com', 'www.example.com'],
          },
          findings: ['Certificate not-after date could not be parsed; expiry is unknown.'],
        },
        {
          host: 'secure.example.com',
          handshakeError: null,
          certificate: { daysUntilExpiry: expect.any(Number) },
        },
      ],
    });
    const text = JSON.stringify(result.content);
    expect(text).toContain('unknown days left');
    expect(text).toContain('Bad time value');
    expect(text).toContain('expiry is unknown');
    expect(text).toContain('www.example.com');
    expect(text).not.toContain('NaN');
    expect(text).not.toContain('No host completed');
  });

  it('returns the typed invalid_host error before attempting a handshake', async () => {
    await expect(
      inspectTlsTool.handler(
        inspectTlsTool.input.parse({ hosts: ['https://example.com/path'] }),
        context(),
      ),
    ).rejects.toMatchObject({
      code: JsonRpcErrorCode.ValidationError,
      data: {
        reason: 'invalid_host',
        recovery: { hint: expect.stringContaining('bare hostnames') },
      },
    });
    expect(tlsBoundary.connect).not.toHaveBeenCalled();
  });

  it('returns shaped per-host errors and all-failed enrichment', async () => {
    tlsBoundary.scenarios.push({ mode: 'error', error: new Error('ECONNREFUSED') });
    const ctx = context();

    const result = await inspectTlsTool.handler(
      inspectTlsTool.input.parse({ hosts: ['closed.example.com'] }),
      ctx,
    );

    expect(result).toEqual(expect.schemaMatching(inspectTlsTool.output));
    expect(result.results[0]).toMatchObject({
      host: 'closed.example.com',
      protocol: null,
      certificate: null,
      findings: ['Connection error: ECONNREFUSED'],
      handshakeError: 'ECONNREFUSED',
    });
    expect(getEnrichment(ctx)).toEqual({
      notice: expect.stringContaining('No host completed a TLS handshake'),
    });
  });
});
