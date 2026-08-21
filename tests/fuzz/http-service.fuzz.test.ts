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
          cookieName: fc
            .array(fc.constantFrom(...'abcdefghijklmnopqrstuvwxyz'), {
              minLength: 1,
              maxLength: 20,
            })
            .map((characters) => characters.join('')),
          cookieValue: headerValue,
        }),
        async ({ body, server, poweredBy, cookieName, cookieValue }) => {
          const headers = new Headers({ server, 'x-powered-by': poweredBy });
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
});
