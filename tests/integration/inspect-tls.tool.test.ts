/**
 * @fileoverview Integration tests for attacksurface_inspect_tls with node:tls faked.
 * @module tests/integration/inspect-tls.tool.test
 */

import { EventEmitter } from 'node:events';
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { createMockContext, getEnrichment } from '@cyanheads/mcp-ts-core/testing';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

interface Scenario {
  error?: Error;
  mode: 'success' | 'error';
}

const tlsBoundary = vi.hoisted(() => ({ connect: vi.fn(), scenarios: [] as Scenario[] }));
vi.mock('node:tls', () => ({ connect: tlsBoundary.connect }));

import { inspectTlsTool } from '@/mcp-server/tools/definitions/inspect-tls.tool.js';
import { initTlsService } from '@/services/tls/tls-service.js';

type HandlerCtx = Parameters<typeof inspectTlsTool.handler>[1];

class FakeSocket extends EventEmitter {
  authorized = true;
  authorizationError: string | undefined;

  constructor(scenario: Scenario, callback: () => void) {
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
      valid_to: 'Jan 01 00:00:00 2027 GMT',
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
