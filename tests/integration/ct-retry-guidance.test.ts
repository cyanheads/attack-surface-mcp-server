/**
 * @fileoverview Certspotter retry guidance on both MCP response surfaces.
 * @module tests/integration/ct-retry-guidance
 */
import { runToolContract } from '@cyanheads/mcp-ts-core/testing';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { getServerConfig, resetServerConfig } from '@/config/server-config.js';
import { enumerateSubdomainsTool } from '@/mcp-server/tools/definitions/enumerate-subdomains.tool.js';
import { initCtService } from '@/services/ct/ct-service.js';

beforeEach(() => {
  vi.useFakeTimers();
  resetServerConfig();
  initCtService(getServerConfig());
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

it('carries an upstream wait into all-sources-failed recovery', async () => {
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => new Response('', { status: 429, headers: { 'retry-after': '20' } })),
  );
  const pending = runToolContract(enumerateSubdomainsTool, {
    domain: 'example.com',
    sources: ['certspotter'],
  });
  await vi.advanceTimersByTimeAsync(0);
  const result = await pending;
  expect(result.isError).toBe(true);
  expect(result.structuredContent).toMatchObject({
    error: {
      data: {
        reason: 'all_sources_failed',
        recovery: { hint: expect.stringContaining('20000 ms') },
      },
    },
  });
  expect(JSON.stringify(result.content)).toContain('20000 ms');
});

it('retains a later-page retry window on both result surfaces', async () => {
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: string | URL | Request) =>
      String(input).includes('after=')
        ? new Response('', { status: 429, headers: { 'retry-after': '20' } })
        : Response.json([{ id: '1', dns_names: [] }]),
    ),
  );
  const pending = runToolContract(enumerateSubdomainsTool, {
    domain: 'example.com',
    sources: ['certspotter'],
  });
  await vi.advanceTimersByTimeAsync(0);
  const result = await pending;
  expect(result.isError).not.toBe(true);
  expect(result.structuredContent).toMatchObject({
    sourceStatuses: [{ pagesFetched: 1, retryAfterMs: 20_000, incompleteReason: 'page_failed' }],
  });
  expect(JSON.stringify(result.content)).toContain('retryAfterMs=20000');
});
