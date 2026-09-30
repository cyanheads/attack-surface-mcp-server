/**
 * @fileoverview Boundary tests for TLS inspection with node:tls and DNS fully faked.
 * @module services/tls/tls-service.test
 */

import { EventEmitter } from 'node:events';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

interface TlsScenario {
  authorizationError?: Error | string;
  authorized?: boolean;
  certificate?: Record<string, unknown>;
  cipher?: { name?: string; standardName?: string };
  error?: Error;
  mode: 'success' | 'error' | 'timeout';
  protocol?: string | null;
}

const tlsBoundary = vi.hoisted(() => ({
  connect: vi.fn(),
  scenarios: [] as TlsScenario[],
}));
const dnsBoundary = vi.hoisted(() => ({ lookup: vi.fn() }));

vi.mock('node:tls', () => ({ connect: tlsBoundary.connect }));
vi.mock('node:dns/promises', () => ({ lookup: dnsBoundary.lookup }));

import { inspectTlsTool } from '@/mcp-server/tools/definitions/inspect-tls.tool.js';
import { TlsService } from '@/services/tls/tls-service.js';

class FakeTlsSocket extends EventEmitter {
  authorized: boolean;
  authorizationError: Error | string | undefined;

  constructor(
    private readonly scenario: TlsScenario,
    onSecureConnect: () => void,
  ) {
    super();
    this.authorized = scenario.authorized ?? true;
    this.authorizationError = scenario.authorizationError;
    if (scenario.mode === 'success') queueMicrotask(onSecureConnect);
    if (scenario.mode === 'error') {
      queueMicrotask(() => this.emit('error', scenario.error ?? new Error('TLS failed')));
    }
  }

  destroy() {}

  getCipher() {
    return this.scenario.cipher ?? {};
  }

  getPeerCertificate() {
    return this.scenario.certificate ?? {};
  }

  getProtocol() {
    return this.scenario.protocol ?? null;
  }
}

function certificate(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const root: Record<string, unknown> = {
    subject: { CN: 'Example Root CA' },
    issuer: { CN: 'Example Root CA' },
    fingerprint256: 'ROOT:FP',
  };
  root.issuerCertificate = root;
  return {
    subject: { CN: 'secure.example.com' },
    issuer: { CN: 'Example Intermediate CA', O: ['Example PKI'] },
    subjectaltname: 'DNS:secure.example.com, DNS:www.example.com, IP Address:93.184.216.34',
    valid_from: 'Dec 01 00:00:00 2025 GMT',
    valid_to: 'Jan 21 00:00:00 2026 GMT',
    serialNumber: '01AB',
    fingerprint256: 'AA:BB:CC',
    ext_key_usage: ['1.3.6.1.5.5.7.3.1', '1.2.3.4'],
    issuerCertificate: root,
    ...overrides,
  };
}

describe('TlsService', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-01-01T00:00:00.000Z'));
    vi.stubEnv('ATTACKSURFACE_ALLOW_PRIVATE_TARGETS', 'true');
    tlsBoundary.scenarios.length = 0;
    tlsBoundary.connect.mockReset();
    dnsBoundary.lookup.mockReset();
    dnsBoundary.lookup.mockResolvedValue([{ address: '93.184.216.34', family: 4 }]);
    tlsBoundary.connect.mockImplementation((_options, callback) => {
      const scenario = tlsBoundary.scenarios.shift();
      if (!scenario) throw new Error('Missing fake TLS scenario');
      return new FakeTlsSocket(scenario, callback);
    });
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllEnvs();
  });

  it('parses certificate, chain, SAN, EKU, cipher, and validation posture', async () => {
    tlsBoundary.scenarios.push({
      mode: 'success',
      protocol: 'TLSv1.3',
      cipher: { standardName: 'TLS_AES_256_GCM_SHA384', name: 'fallback' },
      certificate: certificate(),
      authorized: false,
      authorizationError: 'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
    });

    const pending = new TlsService().inspectHosts(['secure.example.com'], 8443, 2_000);
    await vi.runAllTicks();
    const [result] = await pending;

    expect(result).toEqual({
      host: 'secure.example.com',
      port: 8443,
      protocol: 'TLSv1.3',
      cipher: 'TLS_AES_256_GCM_SHA384',
      certificate: {
        subjectCommonName: 'secure.example.com',
        subjectAltNames: ['secure.example.com', 'www.example.com', '93.184.216.34'],
        issuerCommonName: 'Example Intermediate CA',
        issuerOrganization: 'Example PKI',
        validFrom: '2025-12-01T00:00:00.000Z',
        validTo: '2026-01-21T00:00:00.000Z',
        daysUntilExpiry: 20,
        serialNumber: '01AB',
        fingerprintSha256: 'AA:BB:CC',
        extendedKeyUsages: ['serverAuth (1.3.6.1.5.5.7.3.1)', '1.2.3.4'],
      },
      chainDepth: 2,
      validationAuthorized: false,
      validationError: 'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
      findings: [
        'Certificate expires in 20 day(s) — renew soon.',
        'Chain did not validate: UNABLE_TO_VERIFY_LEAF_SIGNATURE.',
      ],
      checkedAt: '2026-01-01T00:00:00.000Z',
      handshakeError: null,
    });
    expect(tlsBoundary.connect).toHaveBeenCalledWith(
      expect.objectContaining({
        host: 'secure.example.com',
        port: 8443,
        servername: 'secure.example.com',
        rejectUnauthorized: false,
      }),
      expect.any(Function),
    );
  });

  it('preserves malformed certificate dates as unknown instead of returning NaN', async () => {
    tlsBoundary.scenarios.push({
      mode: 'success',
      protocol: 'TLSv1.2',
      certificate: certificate({ valid_from: 'bad-not-before', valid_to: 'bad-not-after' }),
    });

    const pending = new TlsService().inspectHosts(['malformed.example.com']);
    await vi.runAllTicks();
    const [result] = await pending;

    expect(result?.certificate).toMatchObject({
      validFrom: 'bad-not-before',
      validTo: 'bad-not-after',
      daysUntilExpiry: null,
    });
    expect(result?.findings).toContain('Certificate not-before date could not be parsed.');
    expect(result?.findings).toContain(
      'Certificate not-after date could not be parsed; expiry is unknown.',
    );
    expect(result?.handshakeError).toBeNull();
    expect({ results: [result] }).toEqual(expect.schemaMatching(inspectTlsTool.output));
  });

  it.each(['1.1.1.1', '2606:4700:4700::1111', '::ffff:1.1.1.1'])(
    'omits SNI for literal IP %s while inspecting its certificate',
    async (host) => {
      tlsBoundary.scenarios.push({ mode: 'success', certificate: certificate() });
      const [result] = await new TlsService().inspectHosts([host]);
      expect(result).toMatchObject({
        host,
        handshakeError: null,
        certificate: { serialNumber: '01AB' },
      });
      expect(tlsBoundary.connect.mock.calls[0]?.[0]).toMatchObject({ host });
      expect(tlsBoundary.connect.mock.calls[0]?.[0]).not.toHaveProperty('servername');
      expect(vi.getTimerCount()).toBe(0);
    },
  );

  it('leaves no timeout when socket construction throws synchronously', async () => {
    tlsBoundary.connect.mockImplementation(() => {
      throw new Error('socket construction failed');
    });
    const [result] = await new TlsService().inspectHosts(['secure.example.com'], 443, 1_000);
    expect(result).toMatchObject({
      host: 'secure.example.com',
      certificate: null,
      handshakeError: 'socket construction failed',
    });
    expect.soft(vi.getTimerCount()).toBe(0);
    await vi.advanceTimersByTimeAsync(1_500);
    expect(vi.getTimerCount()).toBe(0);
  });

  it.each([
    ['bad-not-before', 'Jan 21 00:00:00 2026 GMT', 20],
    ['Dec 01 00:00:00 2025 GMT', 'bad-not-after', null],
    ['bad-not-before', 'bad-not-after', null],
  ])('parses validity bounds independently: %s / %s', async (validFrom, validTo, expectedDays) => {
    vi.stubEnv('ATTACKSURFACE_ALLOW_PRIVATE_TARGETS', 'false');
    dnsBoundary.lookup.mockResolvedValue([
      { address: '2606:4700:4700::1111', family: 6 },
      { address: '93.184.216.34', family: 4 },
    ]);
    tlsBoundary.scenarios.push({
      mode: 'success',
      certificate: certificate({ valid_from: validFrom, valid_to: validTo }),
    });
    const [result] = await new TlsService().inspectHosts(['secure.example.com']);
    expect(result?.certificate?.daysUntilExpiry).toBe(expectedDays);
    expect(result?.handshakeError).toBeNull();
    expect({ results: [result] }).toEqual(expect.schemaMatching(inspectTlsTool.output));
    expect(JSON.parse(JSON.stringify(result))).toEqual(result);
    expect(result?.certificate?.subjectAltNames).toContain('www.example.com');
    expect(tlsBoundary.connect).toHaveBeenCalledWith(
      expect.objectContaining({ host: '93.184.216.34', servername: 'secure.example.com' }),
      expect.any(Function),
    );
    if (expectedDays === null) {
      expect(result?.certificate?.validTo).toBe(validTo);
      expect(result?.findings.some((finding) => /expired|expires in/.test(finding))).toBe(false);
    }
    if (validFrom === 'bad-not-before') {
      expect(result?.certificate?.validFrom).toBe(validFrom);
      expect(result?.findings).toContain('Certificate not-before date could not be parsed.');
    }
  });

  it('keeps SAN fallback usable when expiry is malformed', async () => {
    tlsBoundary.scenarios.push({
      mode: 'success',
      certificate: certificate({ valid_to: 'Bad time value' }),
    });
    await expect(new TlsService().getSans('secure.example.com')).resolves.toEqual([
      'secure.example.com',
      'www.example.com',
      '93.184.216.34',
    ]);
  });

  it('reports expired self-signed certificates and deprecated protocols', async () => {
    const leaf = certificate({
      subject: { CN: 'legacy.example.com' },
      issuer: { CN: 'legacy.example.com' },
      valid_to: 'Dec 25 00:00:00 2025 GMT',
    });
    leaf.issuerCertificate = leaf;
    tlsBoundary.scenarios.push({
      mode: 'success',
      protocol: 'TLSv1',
      cipher: { name: 'AES128-SHA' },
      certificate: leaf,
    });

    const pending = new TlsService().inspectHosts(['legacy.example.com']);
    await vi.runAllTicks();
    const [result] = await pending;

    expect(result).toMatchObject({ protocol: 'TLSv1', cipher: 'AES128-SHA', chainDepth: 1 });
    expect(result?.findings).toEqual([
      'Weak/deprecated protocol negotiated: TLSv1.',
      'Certificate expired 7 day(s) ago.',
      'Certificate appears self-signed.',
    ]);
  });

  it('returns shaped per-host results for connection errors and timeouts', async () => {
    tlsBoundary.scenarios.push(
      { mode: 'error', error: new Error('ECONNREFUSED') },
      { mode: 'timeout' },
    );

    const pending = new TlsService().inspectHosts(
      ['closed.example.com', 'slow.example.com'],
      443,
      1_000,
    );
    await vi.runAllTicks();
    await vi.advanceTimersByTimeAsync(1_000);
    const results = await pending;

    expect(results[0]).toMatchObject({
      host: 'closed.example.com',
      protocol: null,
      certificate: null,
      findings: ['Connection error: ECONNREFUSED'],
      handshakeError: 'ECONNREFUSED',
    });
    expect(results[1]).toMatchObject({
      host: 'slow.example.com',
      findings: ['Connection timed out.'],
      handshakeError: 'TLS handshake timed out after 1000ms.',
    });
  });

  it('returns no SANs when the SSRF guard rejects the host', async () => {
    vi.stubEnv('ATTACKSURFACE_ALLOW_PRIVATE_TARGETS', 'false');
    dnsBoundary.lookup.mockResolvedValue([{ address: '10.0.0.4', family: 4 }]);

    await expect(new TlsService().getSans('internal.example.com')).resolves.toEqual([]);
    expect(tlsBoundary.connect).not.toHaveBeenCalled();
  });
});
