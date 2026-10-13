/**
 * @fileoverview Property tests for untrusted HTTP headers and body prefixes.
 * @module tests/fuzz/http-service.fuzz.test
 */

import { createMockContext } from '@cyanheads/mcp-ts-core/testing';
import fc from 'fast-check';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { HttpService } from '@/services/http/http-service.js';

const headerValue = fc
  .array(fc.integer({ min: 32, max: 126 }), { maxLength: 100 })
  .map((characters) => String.fromCharCode(...characters));

describe('HttpService fuzz', () => {
  const fetchMock = vi.fn<typeof fetch>();

  beforeEach(() => {
    fetchMock.mockReset();
    vi.stubGlobal('fetch', fetchMock);
    vi.stubEnv('ATTACKSURFACE_ALLOW_PRIVATE_TARGETS', 'true');
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.unstubAllEnvs();
  });

  it('parses arbitrary printable posture headers and body text into a stable result shape', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.record({
          body: fc.string({ maxLength: 2_000 }),
          server: headerValue,
          poweredBy: headerValue,
          hsts: headerValue,
          csp: headerValue,
          xfo: headerValue,
          nosniff: headerValue,
          cookieName: fc
            .array(fc.constantFrom(...'abcdefghijklmnopqrstuvwxyz'), {
              minLength: 1,
              maxLength: 20,
            })
            .map((characters) => characters.join('')),
          cookieValue: headerValue,
        }),
        async ({ body, server, poweredBy, cookieName, cookieValue, hsts, csp, xfo, nosniff }) => {
          const headers = new Headers({
            server,
            'x-powered-by': poweredBy,
            'strict-transport-security': hsts,
            'content-security-policy': csp,
            'x-frame-options': xfo,
            'x-content-type-options': nosniff,
          });
          headers.append('set-cookie', `${cookieName}=${cookieValue}; Secure; SameSite=Strict`);
          fetchMock.mockResolvedValue(new Response(body, { status: 200, headers }));

          const result = await new HttpService('fuzz-agent').probe(
            'https://example.com',
            undefined,
            1_000,
            createMockContext(),
          );

          expect(result).toMatchObject({
            url: 'https://example.com',
            finalUrl: 'https://example.com',
            finalStatus: 200,
            transportError: null,
            bodyInspection: { status: 'complete', error: null },
          });
          expect(result.headers.server).toBe(server.trim());
          expect(result.headers['x-powered-by']).toBe(poweredBy.trim());
          expect(result.securityAudit.cookies[0]).toMatchObject({
            name: cookieName,
            secure: true,
            sameSite: 'Strict',
          });
          expect(result.technologies.every((item) => item.evidence.length > 0)).toBe(true);
        },
      ),
      { numRuns: 75 },
    );
  });

  it('keeps header parsing CPU growth bounded across increasing caller-controlled values', async () => {
    const cases = [
      (size: number) => ({
        'strict-transport-security': `max-age=1; extension="${'a;'.repeat(size / 2)}"`,
      }),
      (size: number) => ({ 'content-security-policy': `frame-ancestors ${'a'.repeat(size)}?` }),
      (size: number) => ({
        'set-cookie': `session=x; ${'Securely;'.repeat(Math.ceil(size / 9))} SameSite=unexpected`,
      }),
    ];
    const service = new HttpService('test');
    for (const makeHeaders of cases) {
      const cpu: number[] = [];
      for (const size of [1_250, 5_000, 20_000, 80_000]) {
        const headers = makeHeaders(size);
        for (let warm = 0; warm < 3; warm++) {
          fetchMock.mockResolvedValue(new Response(null, { headers }));
          await service.probe('https://example.com', undefined, 1_000, createMockContext());
        }
        const start = process.threadCpuUsage();
        for (let run = 0; run < 10; run++) {
          fetchMock.mockResolvedValue(new Response(null, { headers }));
          const result = await service.probe(
            'https://example.com',
            undefined,
            1_000,
            createMockContext(),
          );
          expect(result.transportError).toBeNull();
        }
        const elapsed = process.threadCpuUsage(start);
        cpu.push(elapsed.user + elapsed.system);
      }
      expect(cpu[3]).toBeLessThan((cpu[0] ?? 0) * 256);
      expect(cpu[3]).toBeLessThan(500_000);
    }
  });
});
