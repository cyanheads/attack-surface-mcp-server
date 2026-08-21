/**
 * @fileoverview Boundary tests for passive HTTP probing with fetch fully faked.
 * @module services/http/http-service.test
 */

import { createMockContext } from '@cyanheads/mcp-ts-core/testing';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { HttpService } from '@/services/http/http-service.js';

describe('HttpService', () => {
  const fetchMock = vi.fn<typeof fetch>();

  beforeEach(() => {
    fetchMock.mockReset();
    vi.stubGlobal('fetch', fetchMock);
    vi.stubEnv('ATTACKSURFACE_ALLOW_PRIVATE_TARGETS', 'true');
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.unstubAllEnvs();
    vi.useRealTimers();
  });

  it('follows relative redirects and returns the complete audited output shape', async () => {
    const headers = new Headers({
      'access-control-allow-origin': 'https://attack-surface-probe.example',
      'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
      'permissions-policy': 'camera=()',
      'referrer-policy': 'strict-origin-when-cross-origin',
      server: 'nginx/1.25.4',
      'strict-transport-security': 'max-age=31536000',
      'x-content-type-options': 'nosniff',
    });
    headers.append('set-cookie', 'session=abc; Secure; HttpOnly; SameSite=Lax');
    headers.append('set-cookie', 'prefs=dark');
    fetchMock
      .mockResolvedValueOnce(new Response(null, { status: 302, headers: { location: '/landing' } }))
      .mockResolvedValueOnce(
        new Response('<html><script id="__NEXT_DATA__"></script></html>', {
          status: 200,
          headers,
        }),
      );

    const result = await new HttpService('default-agent').probe(
      'https://example.com/start',
      ' custom-agent ',
      5_000,
      createMockContext(),
    );

    expect(result).toEqual({
      url: 'https://example.com/start',
      finalUrl: 'https://example.com/landing',
      finalStatus: 200,
      redirectChain: [{ url: 'https://example.com/start', status: 302, location: '/landing' }],
      headers: expect.objectContaining({
        server: 'nginx/1.25.4',
        'strict-transport-security': 'max-age=31536000',
      }),
      securityAudit: {
        hsts: 'max-age=31536000',
        csp: "default-src 'self'; frame-ancestors 'none'",
        xFrameOptions: null,
        xContentTypeOptions: 'nosniff',
        referrerPolicy: 'strict-origin-when-cross-origin',
        permissionsPolicy: 'camera=()',
        cookies: [
          { name: 'session', secure: true, httpOnly: true, sameSite: 'Lax' },
          { name: 'prefs', secure: false, httpOnly: false, sameSite: null },
        ],
        corsAllowOrigin: 'https://attack-surface-probe.example',
        corsReflectsOrigin: true,
        findings: [
          'CORS reflects an arbitrary request Origin — combined with credentials this is exploitable.',
          'Cookie "prefs" is missing the Secure flag.',
          'Cookie "prefs" is missing the HttpOnly flag.',
          'Cookie "prefs" has no SameSite attribute.',
        ],
      },
      technologies: [
        {
          name: 'nginx',
          category: 'server',
          version: '1.25.4',
          evidence: 'server: nginx/1.25.4',
        },
        {
          name: 'Next.js',
          category: 'framework',
          evidence: 'body marker: __NEXT_DATA__',
        },
      ],
      checkedAt: expect.stringMatching(/^\d{4}-\d{2}-\d{2}T/),
      transportError: null,
    });
    expect(fetchMock).toHaveBeenNthCalledWith(
      1,
      'https://example.com/start',
      expect.objectContaining({
        method: 'GET',
        redirect: 'manual',
        headers: expect.objectContaining({ 'user-agent': 'custom-agent' }),
      }),
    );
    expect(fetchMock).toHaveBeenNthCalledWith(2, 'https://example.com/landing', expect.any(Object));
  });

  it('returns a deterministic error envelope for a transport failure', async () => {
    fetchMock.mockRejectedValue(new Error('socket reset'));

    const result = await new HttpService('default-agent').probe(
      'https://example.com',
      undefined,
      1_000,
      createMockContext(),
    );

    expect(result).toMatchObject({
      url: 'https://example.com',
      finalUrl: 'https://example.com',
      finalStatus: 0,
      redirectChain: [],
      headers: {},
      technologies: [],
      transportError: 'socket reset',
      securityAudit: {
        hsts: null,
        csp: null,
        xFrameOptions: null,
        xContentTypeOptions: null,
        referrerPolicy: null,
        permissionsPolicy: null,
        cookies: [],
        corsAllowOrigin: null,
        corsReflectsOrigin: false,
        findings: [
          'Content-Security-Policy is not set.',
          'No clickjacking protection (X-Frame-Options or CSP frame-ancestors).',
          'X-Content-Type-Options: nosniff is not set.',
        ],
      },
    });
  });

  it('aborts a fetch at the configured deadline and reports the timeout', async () => {
    vi.useFakeTimers();
    fetchMock.mockImplementation(
      async (_input, init) =>
        await new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener(
            'abort',
            () => reject(new DOMException('The operation was aborted', 'AbortError')),
            { once: true },
          );
        }),
    );

    const pending = new HttpService('default-agent').probe(
      'https://slow.example.com',
      undefined,
      1_000,
      createMockContext(),
    );
    await vi.advanceTimersByTimeAsync(1_000);

    await expect(pending).resolves.toMatchObject({
      finalStatus: 0,
      transportError: 'The operation was aborted',
    });
  });

  // Known defect: https://github.com/cyanheads/attack-surface-mcp-server/issues/4
  it.skip('stops with an error after the maximum redirect chain', async () => {
    fetchMock.mockImplementation(
      async () => new Response(null, { status: 302, headers: { location: '/again' } }),
    );

    const result = await new HttpService('default-agent').probe(
      'https://loop.example.com',
      undefined,
      1_000,
      createMockContext(),
    );

    expect(result).toMatchObject({
      finalStatus: 0,
      error: 'Exceeded 10 redirects without a final response.',
    });
    expect(result.redirectChain).toHaveLength(10);
    expect(fetchMock).toHaveBeenCalledTimes(11);
  });

  it('fingerprints only the bounded body prefix', async () => {
    fetchMock.mockResolvedValue(
      new Response(`${'x'.repeat(64_000)}__NEXT_DATA__`, {
        status: 200,
        headers: { server: 'Caddy' },
      }),
    );

    const result = await new HttpService('default-agent').probe(
      'https://large.example.com',
      undefined,
      1_000,
      createMockContext(),
    );

    expect(result.technologies).toEqual([
      { name: 'Caddy', category: 'server', evidence: 'server: Caddy' },
    ]);
  });
});
