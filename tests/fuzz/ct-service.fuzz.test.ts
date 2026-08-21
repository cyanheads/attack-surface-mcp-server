/**
 * @fileoverview Property tests for untrusted Certificate Transparency JSON payloads.
 * @module tests/fuzz/ct-service.fuzz.test
 */

import { createMockContext } from '@cyanheads/mcp-ts-core/testing';
import fc from 'fast-check';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { ServerConfig } from '@/config/server-config.js';
import { CtService } from '@/services/ct/ct-service.js';

const config = {
  defaultResolvers: '8.8.8.8',
  httpUserAgent: 'attack-surface-fuzz',
  maxSubdomains: 200,
  rdapBootstrapUrl: 'https://rdap.example.test',
} satisfies ServerConfig;

const label = fc
  .array(fc.constantFrom(...'abcdefghijklmnopqrstuvwxyz0123456789-'), {
    minLength: 1,
    maxLength: 30,
  })
  .map((characters) => characters.join(''));

describe('CtService fuzz', () => {
  const fetchMock = vi.fn<typeof fetch>();

  beforeEach(() => {
    fetchMock.mockReset();
    vi.stubGlobal('fetch', fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  it('normalizes arbitrary in-scope CT name arrays without leaking out-of-scope names', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.array(
          fc.record({
            dns_names: fc.array(
              fc
                .tuple(fc.boolean(), label, fc.boolean())
                .map(
                  ([wildcard, subdomain, trailingDot]) =>
                    `${wildcard ? '*.' : ''}${subdomain}.example.com${trailingDot ? '.' : ''}`,
                ),
              { maxLength: 20 },
            ),
          }),
          { maxLength: 20 },
        ),
        async (records) => {
          fetchMock.mockImplementation(async () => Response.json(records));

          const result = await new CtService(config).enumerate(
            'EXAMPLE.COM.',
            ['crt.sh'],
            createMockContext(),
          );

          expect(result.domain).toBe('example.com');
          expect(result.sourceStatuses).toEqual([
            { source: 'crt.sh', ok: true, count: result.names.length, sourceError: null },
          ]);
          expect(result.names).toEqual(
            [...result.names].sort((a, b) => a.name.localeCompare(b.name)),
          );
          expect(new Set(result.names.map(({ name }) => name)).size).toBe(result.names.length);
          for (const discovered of result.names) {
            expect(discovered.name).toMatch(/^[a-z0-9-]+\.example\.com$/);
            expect(discovered.sources).toEqual(['crt.sh']);
          }
        },
      ),
      { numRuns: 75 },
    );
  });

  it('degrades non-array JSON payloads to a source error', async () => {
    vi.useFakeTimers();
    await fc.assert(
      fc.asyncProperty(
        fc.oneof(
          fc.integer(),
          fc.string(),
          fc.boolean(),
          fc.dictionary(fc.string(), fc.jsonValue()),
        ),
        async (payload) => {
          fetchMock.mockImplementation(async () => Response.json(payload));
          const pending = new CtService(config).enumerate(
            'example.com',
            ['crt.sh'],
            createMockContext(),
          );
          await vi.runAllTimersAsync();
          const result = await pending;

          expect(result.names).toEqual([]);
          expect(result.sourceStatuses).toEqual([
            expect.objectContaining({ source: 'crt.sh', ok: false, count: 0 }),
          ]);
        },
      ),
      { numRuns: 25 },
    );
  });
});
