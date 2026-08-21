/**
 * @fileoverview Property tests for normalization of every supported DNS response shape.
 * @module tests/fuzz/dns-service.fuzz.test
 */

import fc from 'fast-check';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

interface DnsScenario {
  A: string[];
  AAAA: string[];
  CAA: Array<{ critical: number; issue?: string; issuewild?: string; iodef?: string }>;
  CNAME: string[];
  MX: Array<{ exchange: string; priority: number }>;
  NS: string[];
  TXT: string[][];
}

const dnsBoundary = vi.hoisted(() => ({
  lookup: vi.fn(),
  scenario: undefined as DnsScenario | undefined,
}));

vi.mock('node:dns/promises', () => ({
  lookup: dnsBoundary.lookup,
  Resolver: class FakeResolver {
    setServers() {}

    resolve4() {
      return Promise.resolve([...(dnsBoundary.scenario?.A ?? [])]);
    }

    resolve6() {
      return Promise.resolve([...(dnsBoundary.scenario?.AAAA ?? [])]);
    }

    resolveCaa() {
      return Promise.resolve((dnsBoundary.scenario?.CAA ?? []).map((record) => ({ ...record })));
    }

    resolveCname() {
      return Promise.resolve([...(dnsBoundary.scenario?.CNAME ?? [])]);
    }

    resolveMx() {
      return Promise.resolve((dnsBoundary.scenario?.MX ?? []).map((record) => ({ ...record })));
    }

    resolveNs() {
      return Promise.resolve([...(dnsBoundary.scenario?.NS ?? [])]);
    }

    resolveTxt() {
      return Promise.resolve((dnsBoundary.scenario?.TXT ?? []).map((record) => [...record]));
    }

    reverse() {
      return Promise.resolve([]);
    }
  },
}));

import { DnsService } from '@/services/dns/dns-service.js';
import { ALL_RECORD_TYPES } from '@/services/dns/types.js';

const label = fc
  .array(fc.constantFrom(...'abcdefghijklmnopqrstuvwxyz0123456789-'), {
    minLength: 1,
    maxLength: 30,
  })
  .map((characters) => characters.join(''));
const hostname = fc.tuple(label, label).map(([left, right]) => `${left}.${right}.example`);
const ipv4 = fc
  .tuple(
    fc.integer({ min: 1, max: 223 }),
    fc.integer({ min: 0, max: 255 }),
    fc.integer({ min: 0, max: 255 }),
    fc.integer({ min: 1, max: 254 }),
  )
  .map((parts) => parts.join('.'));

describe('DnsService fuzz', () => {
  beforeEach(() => {
    vi.stubEnv('ATTACKSURFACE_ALLOW_PRIVATE_TARGETS', 'true');
    dnsBoundary.lookup.mockReset();
    dnsBoundary.lookup.mockResolvedValue([{ address: '93.184.216.34', family: 4 }]);
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it('normalizes arbitrary valid record sets from all supported resolver methods', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.record({
          A: fc.array(ipv4, { maxLength: 10 }),
          AAAA: fc.array(
            fc.integer({ min: 1, max: 65_535 }).map((n) => `2001:db8::${n.toString(16)}`),
            {
              maxLength: 10,
            },
          ),
          CNAME: fc.array(hostname, { maxLength: 10 }),
          NS: fc.array(hostname, { maxLength: 10 }),
          MX: fc.array(
            fc.record({
              priority: fc.integer({ min: 0, max: 65_535 }),
              exchange: fc.option(hostname, { nil: '' }),
            }),
            { maxLength: 10 },
          ),
          TXT: fc.array(fc.array(label, { maxLength: 5 }), { maxLength: 10 }),
          CAA: fc.array(
            fc.oneof(
              fc.record({ critical: fc.integer({ min: 0, max: 255 }), issue: label }),
              fc.record({ critical: fc.integer({ min: 0, max: 255 }), issuewild: label }),
              fc.record({ critical: fc.integer({ min: 0, max: 255 }), iodef: label }),
            ),
            { maxLength: 10 },
          ),
        }),
        async (scenario) => {
          dnsBoundary.scenario = scenario;
          const [result] = await new DnsService().resolveHosts(
            ['records.example.com'],
            ALL_RECORD_TYPES,
            ['8.8.8.8'],
            false,
          );

          expect(result).toMatchObject({
            host: 'records.example.com',
            resolverResults: [expect.objectContaining({ resolver: '8.8.8.8', queryError: null })],
            propagationMismatches: [],
            hostError: null,
          });
          for (const values of Object.values(result?.records ?? {})) {
            expect(values).toEqual([...values].sort());
          }
          expect(result?.resolved).toBe(scenario.A.length > 0 || scenario.AAAA.length > 0);
        },
      ),
      { numRuns: 75 },
    );
  });
});
