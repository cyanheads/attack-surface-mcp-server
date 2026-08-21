/**
 * @fileoverview Property tests for certificate field and SAN parsing at the TLS boundary.
 * @module tests/fuzz/tls-service.fuzz.test
 */

import { EventEmitter } from 'node:events';
import fc from 'fast-check';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const tlsBoundary = vi.hoisted(() => ({
  connect: vi.fn(),
  certificate: {} as Record<string, unknown>,
}));
const dnsBoundary = vi.hoisted(() => ({ lookup: vi.fn() }));

vi.mock('node:tls', () => ({ connect: tlsBoundary.connect }));
vi.mock('node:dns/promises', () => ({ lookup: dnsBoundary.lookup }));

import { TlsService } from '@/services/tls/tls-service.js';

class FakeTlsSocket extends EventEmitter {
  authorized = true;
  authorizationError = undefined;

  constructor(onSecureConnect: () => void) {
    super();
    queueMicrotask(onSecureConnect);
  }

  destroy() {}

  getCipher() {
    return { standardName: 'TLS_AES_128_GCM_SHA256' };
  }

  getPeerCertificate() {
    return tlsBoundary.certificate;
  }

  getProtocol() {
    return 'TLSv1.3';
  }
}

const label = fc
  .array(fc.constantFrom(...'abcdefghijklmnopqrstuvwxyz0123456789-'), {
    minLength: 1,
    maxLength: 30,
  })
  .map((characters) => characters.join(''));
const sanName = fc.tuple(label, label).map(([left, right]) => `${left}.${right}.example`);
const oid = fc
  .array(fc.integer({ min: 0, max: 99 }), { minLength: 2, maxLength: 8 })
  .map((parts) => parts.join('.'));

describe('TlsService fuzz', () => {
  beforeEach(() => {
    vi.stubEnv('ATTACKSURFACE_ALLOW_PRIVATE_TARGETS', 'true');
    dnsBoundary.lookup.mockReset();
    dnsBoundary.lookup.mockResolvedValue([{ address: '93.184.216.34', family: 4 }]);
    tlsBoundary.connect.mockReset();
    tlsBoundary.connect.mockImplementation((_options, callback) => new FakeTlsSocket(callback));
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it('parses arbitrary SAN arrays, subject forms, and EKU OIDs into a stable certificate shape', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.record({
          sans: fc.array(sanName, { maxLength: 30 }),
          subjectAsArray: fc.boolean(),
          commonName: sanName,
          organization: fc.array(label, { minLength: 1, maxLength: 3 }),
          usages: fc.array(oid, { maxLength: 12 }),
          sanAsArray: fc.boolean(),
        }),
        async ({ sans, subjectAsArray, commonName, organization, usages, sanAsArray }) => {
          const root: Record<string, unknown> = {
            subject: { CN: 'Fuzz Root' },
            issuer: { CN: 'Fuzz Root' },
            fingerprint256: 'ROOT',
          };
          root.issuerCertificate = root;
          const sanText = sans.map((name) => `DNS:${name}`).join(', ');
          tlsBoundary.certificate = {
            subject: { CN: subjectAsArray ? [commonName, 'ignored.example'] : commonName },
            issuer: { CN: 'Fuzz Issuer', O: organization },
            subjectaltname: sanAsArray ? [sanText] : sanText,
            valid_from: 'Jan 01 00:00:00 2026 GMT',
            valid_to: 'Jan 01 00:00:00 2030 GMT',
            serialNumber: 'FUZZ',
            fingerprint256: 'AA:BB',
            ext_key_usage: usages,
            issuerCertificate: root,
          };

          const [result] = await new TlsService().inspectHosts(['tls.example']);

          expect(result).toMatchObject({
            host: 'tls.example',
            protocol: 'TLSv1.3',
            cipher: 'TLS_AES_128_GCM_SHA256',
            chainDepth: 2,
            validationAuthorized: true,
            handshakeError: null,
          });
          expect(result?.certificate).toMatchObject({
            subjectCommonName: commonName,
            subjectAltNames: sans,
            issuerCommonName: 'Fuzz Issuer',
            issuerOrganization: organization[0],
            extendedKeyUsages: usages.map((value) =>
              value === '1.3.6.1.5.5.7.3.1' ? `serverAuth (${value})` : value,
            ),
          });
        },
      ),
      { numRuns: 75 },
    );
  });
});
