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

  it('reads crt.sh newline names rather than Certspotter fields', async () => {
    fetchMock.mockResolvedValue(
      Response.json([{ name_value: 'api.example.com\n*.WWW.EXAMPLE.COM.\nother.test' }, {}]),
    );
    const result = await new CtService(config).enumerate(
      'example.com',
      ['crt.sh'],
      createMockContext(),
    );
    expect(result.names.map((n) => n.name)).toEqual(['api.example.com', 'www.example.com']);
  });

  it('exhausts successive Certspotter pages', async () => {
    fetchMock.mockImplementation(async (input) =>
      String(input).includes('after=2')
        ? Response.json([])
        : String(input).includes('after=1')
          ? Response.json([{ id: '2', dns_names: ['mail.example.com'] }])
          : Response.json([{ id: '1', dns_names: ['api.example.com'] }]),
    );
    const result = await new CtService(config).enumerate(
      'example.com',
      ['certspotter'],
      createMockContext(),
    );
    expect(result.names.map((n) => n.name)).toEqual(['api.example.com', 'mail.example.com']);
    expect(result.sourceStatuses[0]).toMatchObject({ complete: true, pagesFetched: 3 });
  });

  it.each(['missing', 'loop', 'failure', 'cap'])(
    'retains prior Certspotter pages when traversal ends at %s',
    async (mode) => {
      fetchMock.mockImplementation(async (input) => {
        const url = new URL(String(input));
        const cursor = url.searchParams.get('after');
        if (cursor && mode === 'failure') return new Response('', { status: 401 });
        return Response.json([
          {
            ...(mode === 'missing'
              ? {}
              : { id: mode === 'cap' ? String(Number(cursor ?? 0) + 1) : '1' }),
            dns_names: [`${cursor ? 'mail' : 'api'}.example.com`],
          },
        ]);
      });
      const result = await new CtService(config).enumerate(
        'example.com',
        ['certspotter'],
        createMockContext(),
      );
      expect(result.names.map((n) => n.name)).toContain('api.example.com');
      expect(result.sourceStatuses[0]).toMatchObject({
        ok: true,
        complete: false,
        incompleteReason:
          mode === 'cap'
            ? 'page_cap'
            : mode === 'failure'
              ? 'page_failed'
              : 'missing_or_repeated_cursor',
      });
      expect(fetchMock.mock.calls.length).toBeLessThanOrEqual(5);
      if (mode === 'failure') expect(result.sourceStatuses[0]?.sourceError).toBeTruthy();
    },
  );

  it.each([null, { name_value: 4 }, { name_value: ['api.example.com'] }])(
    'discloses malformed crt.sh records %j',
    async (record) => {
      vi.useFakeTimers();
      fetchMock.mockImplementation(async () => Response.json([record]));
      const pending = new CtService(config).enumerate(
        'example.com',
        ['crt.sh'],
        createMockContext(),
      );
      await vi.runAllTimersAsync();
      expect((await pending).sourceStatuses[0]).toMatchObject({
        ok: false,
        count: 0,
        sourceError: expect.any(String),
      });
    },
  );

  it('preserves cancellation during a Certspotter body read', async () => {
    vi.useFakeTimers();
    const controller = new AbortController();
    const reading = Promise.withResolvers<void>();
    const json = Response.prototype.json;
    const jsonSpy = vi.spyOn(Response.prototype, 'json').mockImplementation(function (
      this: Response,
    ) {
      reading.resolve();
      return json.call(this);
    });
    fetchMock.mockImplementation(async () => new Response(new ReadableStream()));
    const pending = new CtService(config).enumerate(
      'example.com',
      ['certspotter'],
      createMockContext({ signal: controller.signal }),
    );
    const rejection = expect(pending).rejects.toMatchObject({ name: 'AbortError' });
    let settled = false;
    void pending.then(
      () => {
        settled = true;
      },
      () => {
        settled = true;
      },
    );
    await reading.promise;
    controller.abort();
    await vi.advanceTimersByTimeAsync(0);
    expect(settled).toBe(true);
    await rejection;
    expect(fetchMock).toHaveBeenCalledTimes(1);
    jsonSpy.mockRestore();
  });

  it.each(['body', 'retry'])(
    'uses one fifteen-second Certspotter deadline across later-page %s work',
    async (mode) => {
      vi.useFakeTimers();
      const timeoutSpy = vi.spyOn(AbortSignal, 'timeout').mockImplementation((ms) => {
        const controller = new AbortController();
        setTimeout(
          () => controller.abort(new DOMException('deadline exceeded', 'TimeoutError')),
          ms,
        );
        return controller.signal;
      });
      fetchMock.mockImplementation(async (input) => {
        if (!String(input).includes('after='))
          return Response.json([{ id: '1', dns_names: ['api.example.com'] }]);
        return mode === 'body'
          ? new Response(new ReadableStream())
          : new Response('', { status: 429, headers: { 'retry-after': '20' } });
      });
      try {
        const pending = new CtService(config).enumerate(
          'example.com',
          ['certspotter'],
          createMockContext(),
        );
        await vi.advanceTimersByTimeAsync(15_000);
        const result = await pending;
        expect(result.names).toEqual([{ name: 'api.example.com', sources: ['certspotter'] }]);
        expect(result.sourceStatuses[0]).toMatchObject({
          ok: true,
          complete: false,
          pagesFetched: 1,
          incompleteReason: 'deadline',
        });
        expect(fetchMock).toHaveBeenCalledTimes(2);
      } finally {
        timeoutSpy.mockRestore();
      }
    },
  );

  it('accepts sparse Certspotter records but discloses malformed present names', async () => {
    fetchMock.mockImplementation(async (input) =>
      String(input).includes('after=') ? Response.json([]) : Response.json([{ id: '1' }]),
    );
    const sparse = await new CtService(config).enumerate(
      'example.com',
      ['certspotter'],
      createMockContext(),
    );
    expect(sparse.names).toEqual([]);
    expect(sparse.sourceStatuses[0]).toMatchObject({
      complete: true,
      pagesFetched: 2,
      sourceError: null,
    });
    vi.useFakeTimers();
    fetchMock.mockImplementation(async () =>
      Response.json([{ id: '1', dns_names: ['api.example.com', 4] }]),
    );
    const pending = new CtService(config).enumerate(
      'example.com',
      ['certspotter'],
      createMockContext(),
    );
    await vi.runAllTimersAsync();
    expect((await pending).sourceStatuses[0]).toMatchObject({
      ok: false,
      sourceError: expect.stringContaining('string array'),
    });
  });

  it('normalizes, scopes, deduplicates, and attributes names from every source', async () => {
    fetchMock.mockImplementation(async (input) => {
      const url = String(input);
      if (url.startsWith('https://crt.sh/')) {
        return new Response(
          JSON.stringify([
            { name_value: '*.WWW.Example.COM.\napi.example.com\noutside.test' },
            { name_value: 'api.example.com' },
            {},
          ]),
          { status: 200 },
        );
      }
      expect(url).toContain('api.certspotter.com');
      if (url.includes('after=')) return Response.json([]);
      return Response.json([
        { id: '1', dns_names: ['API.EXAMPLE.COM', 'mail.example.com'] },
        { id: '2', dns_names: [] },
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
        {
          source: 'certspotter',
          ok: true,
          count: 1,
          sourceError: null,
          complete: true,
          pagesFetched: 2,
          incompleteReason: null,
        },
        { source: 'tls-san', ok: true, count: 1, sourceError: null },
      ],
    });
    expect(fetchMock).toHaveBeenCalledTimes(3);
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
