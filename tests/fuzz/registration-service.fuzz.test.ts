/**
 * @fileoverview Property tests for RDAP JSON and truncated WHOIS text parsing.
 * @module tests/fuzz/registration-service.fuzz.test
 */

import { EventEmitter } from 'node:events';
import { createMockContext } from '@cyanheads/mcp-ts-core/testing';
import fc from 'fast-check';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { ServerConfig } from '@/config/server-config.js';

const netBoundary = vi.hoisted(() => ({ createConnection: vi.fn(), response: '' }));

vi.mock('node:net', async () => {
  const actual = await vi.importActual<typeof import('node:net')>('node:net');
  return { ...actual, createConnection: netBoundary.createConnection };
});

import { RegistrationService } from '@/services/registration/registration-service.js';

const config = {
  defaultResolvers: '8.8.8.8',
  httpUserAgent: 'attack-surface-fuzz',
  maxSubdomains: 200,
  rdapBootstrapUrl: 'https://rdap.example.test',
} satisfies ServerConfig;

class FakeWhoisSocket extends EventEmitter {
  constructor() {
    super();
    queueMicrotask(() => this.emit('connect'));
  }

  destroy() {}

  setEncoding() {}

  write() {
    this.emit('data', netBoundary.response);
    this.emit('end');
  }
}

const lineValue = fc
  .array(fc.integer({ min: 33, max: 126 }), { minLength: 1, maxLength: 80 })
  .map((characters) => String.fromCharCode(...characters).replaceAll(':', '-'));

describe('RegistrationService fuzz', () => {
  const fetchMock = vi.fn<typeof fetch>();

  beforeEach(() => {
    fetchMock.mockReset();
    vi.stubGlobal('fetch', fetchMock);
    vi.stubEnv('ATTACKSURFACE_ALLOW_PRIVATE_TARGETS', 'true');
    netBoundary.createConnection.mockReset();
    netBoundary.createConnection.mockImplementation(() => new FakeWhoisSocket());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.unstubAllEnvs();
  });

  it('maps arbitrary sparse-but-well-typed RDAP domain fields without inventing values', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.record({
          statuses: fc.array(lineValue, { maxLength: 10 }),
          events: fc.array(fc.record({ eventAction: lineValue, eventDate: lineValue }), {
            maxLength: 10,
          }),
          nameservers: fc.array(lineValue, { maxLength: 10 }),
          registrar: lineValue,
        }),
        async ({ statuses, events, nameservers, registrar }) => {
          fetchMock.mockResolvedValue(
            Response.json({
              status: statuses,
              events,
              nameservers: nameservers.map((ldhName) => ({ ldhName })),
              entities: [{ roles: ['registrar'], handle: registrar }],
            }),
          );

          const result = await new RegistrationService(config).lookup(
            'example.com',
            'domain',
            createMockContext(),
          );

          expect(result.source).toBe('rdap');
          expect(result.registration).toEqual({
            kind: 'domain',
            target: 'example.com',
            ...(registrar ? { registrar } : {}),
            statuses,
            events: events
              .filter(({ eventAction, eventDate }) => eventAction && eventDate)
              .map(({ eventAction, eventDate }) => ({ action: eventAction, date: eventDate })),
            nameservers: nameservers.filter(Boolean).map((name) => name.toLowerCase()),
          });
        },
      ),
      { numRuns: 75 },
    );
  });

  it('parses arbitrary WHOIS values and ignores a truncated tail', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.record({
          netName: lineValue,
          cidr: lineValue,
          asn: fc.integer({ min: 1, max: 4_294_967_295 }),
          country: fc
            .tuple(
              fc.constantFrom(...'ABCDEFGHIJKLMNOPQRSTUVWXYZ'),
              fc.constantFrom(...'ABCDEFGHIJKLMNOPQRSTUVWXYZ'),
            )
            .map(([a, b]) => `${a}${b}`),
          truncated: lineValue,
        }),
        async ({ netName, cidr, asn, country, truncated }) => {
          fetchMock.mockRejectedValue(new Error('RDAP unavailable'));
          netBoundary.response = [
            `NetName: ${netName}`,
            `CIDR: ${cidr}`,
            `OriginAS: AS${asn}`,
            `Country: ${country}`,
            truncated,
          ].join('\n');

          const result = await new RegistrationService(config).lookup(
            '8.8.8.8',
            'ip',
            createMockContext(),
          );

          expect(result.source).toBe('whois');
          expect(result.registration).toEqual({
            kind: 'ip',
            target: '8.8.8.8',
            ...(netName ? { networkName: netName } : {}),
            cidrs: cidr ? [cidr] : [],
            originAsns: [asn],
            country,
            statuses: [],
            events: [],
          });
          expect(result.rawWhois).toBe(netBoundary.response);
        },
      ),
      { numRuns: 75 },
    );
  });

  // https://github.com/cyanheads/attack-surface-mcp-server/issues/8
  it('does not consume the next WHOIS record when a field value is empty', async () => {
    fetchMock.mockRejectedValue(new Error('RDAP unavailable'));
    netBoundary.response = 'NetName:\nCIDR:\nOriginAS: AS1\nCountry: AA';

    const result = await new RegistrationService(config).lookup(
      '8.8.8.8',
      'ip',
      createMockContext(),
    );

    expect(result.registration).toEqual({
      kind: 'ip',
      target: '8.8.8.8',
      cidrs: [],
      originAsns: [1],
      country: 'AA',
      statuses: [],
      events: [],
    });
  });
});
