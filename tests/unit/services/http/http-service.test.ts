/**
 * @fileoverview Boundary tests for passive HTTP probing with fetch fully faked.
 * @module services/http/http-service.test
 */

import { createMockContext } from '@cyanheads/mcp-ts-core/testing';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const dnsBoundary = vi.hoisted(() => ({ lookup: vi.fn() }));
vi.mock('node:dns/promises', () => ({ lookup: dnsBoundary.lookup }));

import { HttpService } from '@/services/http/http-service.js';

describe('HttpService', () => {
  const fetchMock = vi.fn<typeof fetch>();

  beforeEach(() => {
    fetchMock.mockReset();
    dnsBoundary.lookup.mockReset();
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
      bodyInspection: { status: 'complete', error: null },
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

  it('stops with an error after the maximum redirect chain', async () => {
    const cancel = vi.fn();
    fetchMock.mockImplementation(
      async () =>
        new Response(
          new ReadableStream({
            start(controller) {
              controller.enqueue(new Uint8Array(64_000));
            },
            cancel,
          }),
          { status: 302, headers: { location: '/again' } },
        ),
    );

    const result = await new HttpService('default-agent').probe(
      'https://loop.example.com',
      undefined,
      1_000,
      createMockContext(),
    );

    expect(result).toMatchObject({
      finalStatus: 0,
      transportError: 'Exceeded 10 redirects without a final response.',
    });
    expect(result.redirectChain).toHaveLength(10);
    expect(fetchMock).toHaveBeenCalledTimes(11);
    expect(cancel).toHaveBeenCalledTimes(11);
  });

  it.each([200, 404, 304])('accepts a final %i after ten redirects', async (status) => {
    for (let hop = 0; hop < 10; hop++) {
      fetchMock.mockResolvedValueOnce(
        new Response(null, { status: 302, headers: { location: `/hop-${hop}` } }),
      );
    }
    fetchMock.mockResolvedValueOnce(new Response(null, { status }));
    const result = await new HttpService('test').probe(
      'https://example.com',
      undefined,
      1_000,
      createMockContext(),
    );
    expect(result).toMatchObject({ finalStatus: status, transportError: null });
    expect(result.redirectChain).toHaveLength(10);
    expect(fetchMock).toHaveBeenCalledTimes(11);
  });

  it('rejects a private redirect target before fetching it', async () => {
    vi.stubEnv('ATTACKSURFACE_ALLOW_PRIVATE_TARGETS', 'false');
    fetchMock.mockResolvedValueOnce(
      new Response(null, { status: 302, headers: { location: 'http://127.0.0.1/private' } }),
    );
    const result = await new HttpService('test').probe(
      'https://93.184.216.34',
      undefined,
      1_000,
      createMockContext(),
    );
    expect(result).toMatchObject({
      finalStatus: 0,
      transportError: expect.stringContaining('SSRF_BLOCKED'),
    });
    expect(result.redirectChain).toHaveLength(1);
    expect(fetchMock).toHaveBeenCalledTimes(1);
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

  it('characterizes an empty body as usable final headers without body detections', async () => {
    fetchMock.mockResolvedValue(new Response(null, { headers: { server: 'Caddy' } }));
    const result = await new HttpService('test').probe(
      'https://example.com',
      undefined,
      1_000,
      createMockContext(),
    );
    expect(result).toMatchObject({
      finalStatus: 200,
      transportError: null,
      technologies: [{ name: 'Caddy', evidence: 'server: Caddy' }],
    });
  });

  it('bounds DNS validation before sending any request', async () => {
    vi.useFakeTimers();
    vi.stubEnv('ATTACKSURFACE_ALLOW_PRIVATE_TARGETS', 'false');
    let finishDns!: (addresses: { address: string; family: number }[]) => void;
    dnsBoundary.lookup.mockImplementation(
      () =>
        new Promise((resolve) => {
          finishDns = resolve;
        }),
    );
    fetchMock.mockResolvedValue(new Response(null));
    let settled = false;
    const pending = new HttpService('test')
      .probe('https://example.com', undefined, 1_000, createMockContext())
      .then((result) => {
        settled = true;
        return result;
      });
    try {
      await vi.advanceTimersByTimeAsync(1_000);
      expect(settled).toBe(true);
      expect(fetchMock).not.toHaveBeenCalled();
      expect(await pending).toMatchObject({
        finalStatus: 0,
        bodyInspection: { status: 'not_read', error: null },
        transportError: expect.any(String),
      });
    } finally {
      finishDns([{ address: '8.8.8.8', family: 4 }]);
      await pending;
    }
  });

  it('shares one deadline across successive redirects', async () => {
    vi.useFakeTimers();
    fetchMock.mockImplementation(
      async (_url, init) =>
        new Promise((resolve, reject) => {
          const timer = setTimeout(
            () => resolve(new Response(null, { status: 302, headers: { location: '/next' } })),
            400,
          );
          init?.signal?.addEventListener(
            'abort',
            () => {
              clearTimeout(timer);
              reject(init.signal?.reason);
            },
            { once: true },
          );
        }),
    );
    let settled = false;
    const pending = new HttpService('test')
      .probe('https://example.com', undefined, 1_000, createMockContext())
      .then((result) => {
        settled = true;
        return result;
      });
    await vi.advanceTimersByTimeAsync(1_000);
    expect.soft(settled).toBe(true);
    await vi.runAllTimersAsync();
    expect(await pending).toMatchObject({
      finalStatus: 0,
      transportError: 'The operation was aborted',
      bodyInspection: { status: 'not_read', error: null },
      redirectChain: [
        { url: 'https://example.com', status: 302, location: '/next' },
        { url: 'https://example.com/next', status: 302, location: '/next' },
      ],
    });
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it.each(['deadline', 'caller'])(
    'settles a stalled body on %s even when cleanup does not resolve',
    async (cause) => {
      vi.useFakeTimers();
      const cancel = vi.fn(() => new Promise<void>(() => {}));
      fetchMock.mockResolvedValue(
        new Response(new ReadableStream({ cancel }), { headers: { server: 'nginx' } }),
      );
      const controller = new AbortController();
      let settled = false;
      const pending = new HttpService('test')
        .probe(
          'https://example.com',
          undefined,
          1_000,
          createMockContext({ signal: controller.signal }),
        )
        .then(
          (result) => {
            settled = true;
            return result;
          },
          (err: unknown) => {
            settled = true;
            return err;
          },
        );
      await vi.advanceTimersByTimeAsync(0);
      if (cause === 'caller') controller.abort(new Error('caller stopped'));
      await vi.advanceTimersByTimeAsync(1_000);
      expect(settled).toBe(true);
      const result = await pending;
      if (cause === 'caller') expect(result).toBe(controller.signal.reason);
      else
        expect(result).toMatchObject({
          finalStatus: 200,
          transportError: null,
          headers: { server: 'nginx' },
          bodyInspection: { status: 'failed', error: expect.any(String) },
          technologies: [{ name: 'nginx' }],
        });
      expect(vi.getTimerCount()).toBe(0);
    },
  );

  it('discloses body errors without losing final headers or header fingerprints', async () => {
    fetchMock.mockResolvedValue(
      new Response(
        new ReadableStream({
          start(controller) {
            controller.error(new Error('body interrupted'));
          },
        }),
        { status: 404, headers: { server: 'Caddy' } },
      ),
    );
    const result = await new HttpService('test').probe(
      'https://example.com',
      undefined,
      1_000,
      createMockContext(),
    );
    expect(result).toMatchObject({
      finalStatus: 404,
      transportError: null,
      bodyInspection: { status: 'failed', error: 'body interrupted' },
      technologies: [{ name: 'Caddy' }],
    });
  });

  it.each([0, 63_999, 64_000, 64_001])(
    'discloses observed body completion at %i bytes',
    async (bytes) => {
      fetchMock.mockResolvedValue(new Response('x'.repeat(bytes)));
      const result = await new HttpService('test').probe(
        'https://example.com',
        undefined,
        1_000,
        createMockContext(),
      );
      expect(result).toMatchObject({
        bodyInspection: { status: bytes < 64_000 ? 'complete' : 'limited', error: null },
      });
    },
  );

  it('characterizes supported security-header and assigned cookie-flag controls', async () => {
    fetchMock.mockResolvedValue(
      new Response('', {
        headers: {
          'strict-transport-security': 'max-age=31536000',
          'x-frame-options': 'SAMEORIGIN',
          'x-content-type-options': 'nosniff',
          'content-security-policy': "frame-ancestors 'none'",
          'set-cookie': 'session=x; Secure=value; HttpOnly=value; SameSite=Lax',
        },
      }),
    );
    const result = await new HttpService('test').probe(
      'https://example.com',
      undefined,
      1_000,
      createMockContext(),
    );
    expect(result.securityAudit.findings).toEqual([]);
    expect(result.securityAudit.cookies).toEqual([
      { name: 'session', secure: true, httpOnly: true, sameSite: 'Lax' },
    ]);
  });

  it('rejects prefix cookie attributes and reports SameSite None without Secure', async () => {
    fetchMock.mockResolvedValue(
      new Response('', {
        headers: { 'set-cookie': 'session=x; Securely; HttpOnlyish; SameSite=None' },
      }),
    );
    const result = await new HttpService('test').probe(
      'https://example.com',
      undefined,
      1_000,
      createMockContext(),
    );
    expect(result.securityAudit.cookies).toEqual([
      { name: 'session', secure: false, httpOnly: false, sameSite: 'None' },
    ]);
    expect(result.securityAudit.findings).toContain(
      'Cookie "session" uses SameSite=None without Secure; modern browsers reject it.',
    );
  });

  it.each([
    ['SameSite=Strict; SameSite=lAx', 'Lax', false],
    ['SameSite=Lax; SameSite=unexpected', 'unexpected', true],
    ['SameSite=Lax; SameSite=', '', true],
    ['SameSite=Lax; SameSite=__proto__', '__proto__', true],
    ['SameSite=Lax; SameSite=toString', 'toString', true],
  ])('uses last SameSite attribute: %s', async (attributes, sameSite, invalid) => {
    fetchMock.mockResolvedValue(
      new Response('', { headers: { 'set-cookie': `session=x; Secure; HttpOnly; ${attributes}` } }),
    );
    const result = await new HttpService('test').probe(
      'https://example.com',
      undefined,
      1_000,
      createMockContext(),
    );
    expect(result.securityAudit.cookies[0]?.sameSite).toBe(sameSite);
    expect(
      result.securityAudit.findings.some((finding) => finding.includes('invalid SameSite')),
    ).toBe(invalid);
  });

  it.each([
    ['DENY', true],
    [' sameorigin ', true],
    ['DENY, DENY', true],
    ['DENY, SAMEORIGIN', false],
    ['ALLOW-FROM https://example.com', false],
    ['invalid', false],
  ])('audits X-Frame-Options token %s', async (value, effective) => {
    fetchMock.mockResolvedValue(new Response('', { headers: { 'x-frame-options': value } }));
    const result = await new HttpService('test').probe(
      'https://example.com',
      undefined,
      1_000,
      createMockContext(),
    );
    expect(
      result.securityAudit.findings.some((finding) => finding.startsWith('No clickjacking')),
    ).toBe(!effective);
    expect(result.securityAudit.xFrameOptions).toBe(value.trim());
  });

  it.each([
    ['nosniff, invalid', true],
    ['invalid, nosniff', false],
    [' NoSnIfF ', true],
    ['invalid', false],
  ])('audits first nosniff token %s', async (value, effective) => {
    fetchMock.mockResolvedValue(new Response('', { headers: { 'x-content-type-options': value } }));
    const result = await new HttpService('test').probe(
      'https://example.com',
      undefined,
      1_000,
      createMockContext(),
    );
    expect(result.securityAudit.findings.some((finding) => finding.includes('nosniff'))).toBe(
      !effective,
    );
  });

  it.each([
    ["default-src 'self'; report-uri /frame-ancestors", false],
    ["FRAME-ANCESTORS 'self'", true],
    ['frame-ancestors', true],
    ['frame-ancestors *', false],
    ["frame-ancestors *; frame-ancestors 'none'", false],
    ["frame-ancestors 'none'; frame-ancestors *", true],
    ["frame-ancestors *, frame-ancestors 'none'", true],
    ['frame-ancestors unexpected???', false],
  ])('audits first frame-ancestors directive within each policy: %s', async (value, effective) => {
    fetchMock.mockResolvedValue(
      new Response('', { headers: { 'content-security-policy': value } }),
    );
    const result = await new HttpService('test').probe(
      'https://example.com',
      undefined,
      1_000,
      createMockContext(),
    );
    expect(
      result.securityAudit.findings.some((finding) => finding.startsWith('No clickjacking')),
    ).toBe(!effective);
    expect(result.securityAudit.csp).toBe(value);
  });

  it('does not credit report-only framing restrictions as enforced', async () => {
    fetchMock.mockResolvedValue(
      new Response('', {
        headers: { 'content-security-policy-report-only': "frame-ancestors 'none'" },
      }),
    );
    const result = await new HttpService('test').probe(
      'https://example.com',
      undefined,
      1_000,
      createMockContext(),
    );
    expect(
      result.securityAudit.findings.some((finding) => finding.startsWith('No clickjacking')),
    ).toBe(true);
  });

  it.each([
    ['max-age=1', true],
    [' MAX-AGE = "12" ; includeSubDomains', true],
    ['max-age=0001; extension="a;b"', true],
    ['max-age=0', false],
    ['max-age=-1', false],
    ['max-age=abc', false],
    ['max-age="12', false],
    ['max-age=1; max-age=2', false],
    ['max-age=1; includeSubDomains; includesubdomains', false],
    ['max-age=1; invalid=()', false],
  ])('requires valid positive HSTS without duplicate directives: %s', async (value, effective) => {
    fetchMock.mockResolvedValue(
      new Response('', { headers: { 'strict-transport-security': value } }),
    );
    const result = await new HttpService('test').probe(
      'https://example.com',
      undefined,
      1_000,
      createMockContext(),
    );
    expect(result.securityAudit.findings.some((finding) => finding.startsWith('HSTS'))).toBe(
      !effective,
    );
    expect(result.securityAudit.hsts).toBe(value.trim());
  });
});
