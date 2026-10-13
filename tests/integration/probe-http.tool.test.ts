/**
 * @fileoverview Integration tests for attacksurface_probe_http with only fetch faked.
 * @module tests/integration/probe-http.tool.test
 */

import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { createMockContext, getEnrichment, runToolContract } from '@cyanheads/mcp-ts-core/testing';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { probeHttpTool } from '@/mcp-server/tools/definitions/probe-http.tool.js';
import { initHttpService } from '@/services/http/http-service.js';

type HandlerCtx = Parameters<typeof probeHttpTool.handler>[1];

function context(): HandlerCtx {
  return createMockContext({ errors: probeHttpTool.errors ?? [] }) as HandlerCtx;
}

describe('attacksurface_probe_http', () => {
  const fetchMock = vi.fn<typeof fetch>();

  beforeEach(() => {
    vi.stubEnv('ATTACKSURFACE_ALLOW_PRIVATE_TARGETS', 'true');
    fetchMock.mockReset();
    vi.stubGlobal('fetch', fetchMock);
    initHttpService('default-test-agent');
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
    vi.unstubAllEnvs();
  });

  it('returns schema-valid posture and format output for a successful probe', async () => {
    fetchMock.mockResolvedValue(
      new Response('<meta name="generator" content="WordPress 6.8">', {
        status: 200,
        headers: {
          'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
          server: 'nginx/1.25.4',
          'strict-transport-security': 'max-age=31536000',
          'x-content-type-options': 'nosniff',
        },
      }),
    );

    const input = probeHttpTool.input.parse({
      url: 'https://example.com',
      userAgent: 'integration-agent',
      timeoutMs: 1_000,
    });
    const result = await probeHttpTool.handler(input, context());

    expect(result).toEqual(expect.schemaMatching(probeHttpTool.output));
    expect(result).toMatchObject({
      url: 'https://example.com',
      finalUrl: 'https://example.com',
      finalStatus: 200,
      transportError: null,
      technologies: [
        expect.objectContaining({ name: 'nginx', version: '1.25.4', category: 'server' }),
        expect.objectContaining({ name: 'WordPress', version: '6.8', category: 'cms' }),
      ],
    });
    const blocks = probeHttpTool.format?.(result);
    expect(blocks?.[0]).toMatchObject({ type: 'text' });
    if (blocks?.[0]?.type === 'text') {
      expect(blocks[0].text).toContain('Final status:** 200');
      expect(blocks[0].text).toContain('nginx');
      expect(blocks[0].text).toContain('Response headers');
    }
  });

  it('enforces URL and timeout schema boundaries', () => {
    expect(probeHttpTool.input.safeParse({ url: '', timeoutMs: 1_000 }).success).toBe(false);
    expect(
      probeHttpTool.input.safeParse({ url: 'https://example.com', timeoutMs: 999 }).success,
    ).toBe(false);
    expect(
      probeHttpTool.input.safeParse({ url: 'https://example.com', timeoutMs: 30_001 }).success,
    ).toBe(false);
    expect(
      probeHttpTool.input.safeParse({ url: 'https://example.com', timeoutMs: 1_000.5 }).success,
    ).toBe(false);
    expect(
      probeHttpTool.input.safeParse({ url: 'https://example.com', timeoutMs: 1_000 }).success,
    ).toBe(true);
    expect(
      probeHttpTool.input.safeParse({ url: 'https://example.com', timeoutMs: 30_000 }).success,
    ).toBe(true);
  });

  it.each([
    ['cloudflare', 'Cloudflare', 'cdn'],
    ['awselb/2.0', 'AWS ELB', 'other'],
  ])('reports %s evidence accurately on both output paths', async (server, name, category) => {
    fetchMock.mockResolvedValue(new Response('', { headers: { server } }));
    const result = await runToolContract(probeHttpTool, { url: 'https://example.com' });
    expect(result.isError).not.toBe(true);
    expect(result.structuredContent).toMatchObject({
      technologies: [{ name, category, evidence: `server: ${server}` }],
    });
    const text = JSON.stringify(result.content);
    expect(text).toContain(`**${name}**  _(${category})_`);
    expect(text).toContain(`server: ${server}`);
    expect(text).not.toContain('_(waf)_');
    expect(text).not.toContain('_(server)_');
  });

  it('returns the typed blocked_target error envelope for a forbidden scheme', async () => {
    const input = probeHttpTool.input.parse({ url: 'file:///etc/passwd' });

    await expect(probeHttpTool.handler(input, context())).rejects.toMatchObject({
      code: JsonRpcErrorCode.Forbidden,
      data: {
        reason: 'blocked_target',
        recovery: { hint: expect.stringContaining('public http(s) URLs') },
      },
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('returns a shaped transport error and enriches it with recovery guidance', async () => {
    fetchMock.mockRejectedValue(new Error('ECONNRESET'));
    const ctx = context();
    const result = await probeHttpTool.handler(
      probeHttpTool.input.parse({ url: 'https://example.com' }),
      ctx,
    );

    expect(result).toEqual(expect.schemaMatching(probeHttpTool.output));
    expect(result).toMatchObject({ finalStatus: 0, headers: {}, transportError: 'ECONNRESET' });
    expect(getEnrichment(ctx)).toEqual({
      notice: 'Could not complete the probe of https://example.com: ECONNRESET',
    });
  });

  it('discloses redirect exhaustion on both output paths', async () => {
    fetchMock.mockImplementation(
      async () => new Response(null, { status: 302, headers: { location: '/again' } }),
    );
    const result = await runToolContract(probeHttpTool, { url: 'https://example.com' });
    expect(result.isError).not.toBe(true);
    expect(result.structuredContent).toMatchObject({
      finalStatus: 0,
      transportError: 'Exceeded 10 redirects without a final response.',
      redirectChain: expect.arrayContaining([
        { url: 'https://example.com', status: 302, location: '/again' },
      ]),
    });
    expect(JSON.stringify(result.content)).toContain(
      'Exceeded 10 redirects without a final response.',
    );
    expect(JSON.stringify(result.content)).toContain('Could not complete the probe');
  });

  it.each(['complete', 'limited', 'failed'])(
    'exposes %s body inspection on both surfaces',
    async (status) => {
      const body =
        status === 'failed'
          ? new ReadableStream({
              start(controller) {
                controller.error(new Error('body interrupted'));
              },
            })
          : 'x'.repeat(status === 'limited' ? 64_000 : 0);
      fetchMock.mockResolvedValue(new Response(body, { headers: { server: 'Caddy' } }));
      const result = await runToolContract(probeHttpTool, { url: 'https://example.com' });
      expect(result.isError).not.toBe(true);
      expect(result.structuredContent).toMatchObject({
        finalStatus: 200,
        transportError: null,
        bodyInspection: { status, error: status === 'failed' ? 'body interrupted' : null },
        technologies: [{ name: 'Caddy' }],
      });
      expect(JSON.stringify(result.content)).toContain(`Body inspection:** ${status}`);
      if (status === 'failed') expect(JSON.stringify(result.content)).toContain('body interrupted');
    },
  );

  it('propagates caller cancellation during body inspection through both error surfaces', async () => {
    vi.useFakeTimers();
    fetchMock.mockResolvedValue(new Response(new ReadableStream()));
    const controller = new AbortController();
    const pending = runToolContract(
      probeHttpTool,
      { url: 'https://example.com' },
      { context: { signal: controller.signal } },
    );
    await vi.advanceTimersByTimeAsync(0);
    controller.abort();
    const result = await pending;
    expect(result.isError).toBe(true);
    expect(result.structuredContent).toMatchObject({
      error: { code: JsonRpcErrorCode.RequestCancelled },
    });
    expect(JSON.stringify(result.content)).toMatch(/cancel|abort/i);
    expect(vi.getTimerCount()).toBe(0);
  });

  it('reports ineffective security values with retained evidence on both surfaces', async () => {
    const headers = {
      'x-frame-options': 'invalid',
      'x-content-type-options': 'invalid',
      'strict-transport-security': 'max-age=0',
      'content-security-policy': "default-src 'self'; report-uri /frame-ancestors",
      'set-cookie': 'session=x; Securely; HttpOnlyish; SameSite=None',
    };
    fetchMock.mockResolvedValue(new Response('', { headers }));
    const result = await runToolContract(probeHttpTool, { url: 'https://example.com' });
    expect(result.isError).not.toBe(true);
    expect(result.structuredContent).toMatchObject({
      headers,
      securityAudit: {
        cookies: [{ secure: false, httpOnly: false, sameSite: 'None' }],
        findings: expect.arrayContaining([
          expect.stringContaining('HSTS does not contain'),
          expect.stringContaining('No clickjacking'),
          expect.stringContaining('nosniff'),
          expect.stringContaining('SameSite=None without Secure'),
        ]),
      },
    });
    const text = JSON.stringify(result.content);
    expect(text).toContain('Secure=false, HttpOnly=false, SameSite=None');
    expect(text).toContain('max-age=0');
    expect(text).toContain('No clickjacking');
    expect(text).toContain('SameSite=None without Secure');
  });
});
