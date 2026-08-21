/**
 * @fileoverview Integration tests for attacksurface_probe_http with only fetch faked.
 * @module tests/integration/probe-http.tool.test
 */

import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { createMockContext, getEnrichment } from '@cyanheads/mcp-ts-core/testing';
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
});
