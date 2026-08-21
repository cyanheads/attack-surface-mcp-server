/**
 * @fileoverview Boundary tests for Certificate Transparency enumeration with HTTP faked.
 * @module services/ct/ct-service.test
 */

import { createMockContext } from '@cyanheads/mcp-ts-core/testing';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { ServerConfig } from '@/config/server-config.js';
import { CtService } from '@/services/ct/ct-service.js';

const config = {
  certspotterApiKey: 'certspotter-key',
  defaultResolvers: '8.8.8.8',
  httpUserAgent: 'attack-surface-test',
  maxSubdomains: 200,
  rdapBootstrapUrl: 'https://rdap.org',
} satisfies ServerConfig;

describe('CtService', () => {
  const fetchMock = vi.fn<typeof fetch>();

  beforeEach(() => {
    fetchMock.mockReset();
    vi.stubGlobal('fetch', fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  it('normalizes, scopes, deduplicates, and attributes names from every source', async () => {
    fetchMock.mockImplementation(async (input) => {
      const url = String(input);
      if (url.startsWith('https://crt.sh/')) {
        return new Response(
          JSON.stringify([
            { dns_names: ['*.WWW.Example.COM.', 'api.example.com', 'outside.test'] },
            { dns_names: ['api.example.com'] },
            {},
          ]),
          { status: 200 },
        );
      }
      expect(url).toContain('api.certspotter.com');
      return Response.json([
        { dns_names: ['API.EXAMPLE.COM', 'mail.example.com'] },
        { dns_names: [] },
      ]);
    });

    const result = await new CtService(config).enumerate(
      'EXAMPLE.COM.',
      ['crt.sh', 'certspotter', 'tls-san'],
      createMockContext(),
      ['*.tls.example.com', 'www.example.com', 'not-example.com'],
    );

    expect(result).toEqual({
      domain: 'example.com',
      names: [
        { name: 'api.example.com', sources: ['certspotter', 'crt.sh'] },
        { name: 'mail.example.com', sources: ['certspotter'] },
        { name: 'tls.example.com', sources: ['tls-san'] },
        { name: 'www.example.com', sources: ['crt.sh', 'tls-san'] },
      ],
      sourceStatuses: [
        { source: 'crt.sh', ok: true, count: 2, sourceError: null },
        { source: 'certspotter', ok: true, count: 1, sourceError: null },
        { source: 'tls-san', ok: true, count: 1, sourceError: null },
      ],
    });
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(fetchMock.mock.calls[1]?.[1]).toMatchObject({
      headers: expect.objectContaining({ authorization: 'Bearer certspotter-key' }),
    });
  });

  it('reports malformed upstream payloads as a source failure instead of throwing', async () => {
    vi.useFakeTimers();
    fetchMock.mockImplementation(async () => new Response('{"not":"an array"}', { status: 200 }));

    const pending = new CtService(config).enumerate('example.com', ['crt.sh'], createMockContext());
    await vi.runAllTimersAsync();
    const result = await pending;

    expect(result.names).toEqual([]);
    expect(result.sourceStatuses).toHaveLength(1);
    expect(result.sourceStatuses[0]).toMatchObject({ source: 'crt.sh', ok: false, count: 0 });
    expect(result.sourceStatuses[0]?.sourceError).toMatch(/flatMap|array/i);
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it('treats crt.sh HTML and Certspotter rate limits as independent source failures', async () => {
    vi.useFakeTimers();
    fetchMock.mockImplementation(async (input) =>
      String(input).startsWith('https://crt.sh/')
        ? new Response('<!doctype html><title>overloaded</title>', { status: 200 })
        : new Response('', { status: 429 }),
    );

    const pending = new CtService(config).enumerate(
      'example.com',
      ['crt.sh', 'certspotter'],
      createMockContext(),
    );
    await vi.runAllTimersAsync();
    const result = await pending;

    expect(result.sourceStatuses).toEqual([
      expect.objectContaining({
        source: 'crt.sh',
        ok: false,
        sourceError: expect.stringMatching(/HTML/),
      }),
      expect.objectContaining({
        source: 'certspotter',
        ok: false,
        sourceError: expect.stringMatching(/rate limit/i),
      }),
    ]);
  });
});
