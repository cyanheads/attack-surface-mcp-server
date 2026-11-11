/**
 * @fileoverview Certspotter retry deadlines and upstream retry guidance at the HTTP boundary.
 * @module tests/unit/services/ct/retry-budget.test
 */
import { createMockContext } from '@cyanheads/mcp-ts-core/testing';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { CtService } from '@/services/ct/ct-service.js';

const config = {
  defaultResolvers: '8.8.8.8',
  httpUserAgent: 'attack-surface-test',
  maxSubdomains: 200,
  rdapBootstrapUrl: 'https://rdap.org',
};
const fetchMock = vi.fn<typeof fetch>();

beforeEach(() => {
  vi.useFakeTimers();
  fetchMock.mockReset();
  vi.stubGlobal('fetch', fetchMock);
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

it.each([false, true])(
  'preserves an unaffordable retry window after prior page=%s',
  async (later) => {
    fetchMock.mockImplementation(async (input) =>
      later && !String(input).includes('after=')
        ? Response.json([{ id: '1', dns_names: ['api.example.com'] }])
        : new Response('', { status: 429, headers: { 'retry-after': '20' } }),
    );
    const pending = new CtService(config).enumerate(
      'example.com',
      ['certspotter'],
      createMockContext(),
    );
    let settled = false;
    const observed = pending.then((value) => {
      settled = true;
      return value;
    });
    await vi.advanceTimersByTimeAsync(0);
    expect(settled).toBe(true);
    const result = await observed;
    expect(result.sourceStatuses[0]).toMatchObject({
      ok: later,
      pagesFetched: later ? 1 : 0,
      incompleteReason: 'page_failed',
      retryAfterMs: 20_000,
      sourceError: expect.stringContaining('Retry after 20000 ms.'),
    });
    expect(result.names).toEqual(
      later ? [{ name: 'api.example.com', sources: ['certspotter'] }] : [],
    );
    expect(fetchMock).toHaveBeenCalledTimes(later ? 2 : 1);
  },
);

it('allows a fitting retry and completes the page walk', async () => {
  fetchMock.mockResolvedValueOnce(
    new Response('', { status: 429, headers: { 'retry-after': '1' } }),
  );
  fetchMock.mockResolvedValueOnce(Response.json([]));
  const pending = new CtService(config).enumerate(
    'example.com',
    ['certspotter'],
    createMockContext(),
  );
  await vi.advanceTimersByTimeAsync(1_000);
  expect((await pending).sourceStatuses[0]).toMatchObject({
    complete: true,
    pagesFetched: 1,
    sourceError: null,
  });
  expect(fetchMock).toHaveBeenCalledTimes(2);
});

it('preserves caller cancellation during a retry wait', async () => {
  const caller = new AbortController();
  const reason = new Error('caller cancelled');
  fetchMock.mockResolvedValue(new Response('', { status: 429, headers: { 'retry-after': '1' } }));
  const pending = new CtService(config).enumerate(
    'example.com',
    ['certspotter'],
    createMockContext({ signal: caller.signal }),
  );
  const rejection = expect(pending).rejects.toBe(reason);
  await vi.advanceTimersByTimeAsync(0);
  caller.abort(reason);
  await rejection;
  expect(fetchMock).toHaveBeenCalledTimes(1);
});

it('uses the remaining source budget on a later page', async () => {
  fetchMock.mockImplementation(async (input) => {
    if (String(input).includes('after='))
      return new Response('', { status: 429, headers: { 'retry-after': '10' } });
    await new Promise((resolve) => setTimeout(resolve, 10_000));
    return Response.json([{ id: '1', dns_names: ['api.example.com'] }]);
  });
  let settled = false;
  const pending = new CtService(config)
    .enumerate('example.com', ['certspotter'], createMockContext())
    .then((value) => {
      settled = true;
      return value;
    });
  await vi.advanceTimersByTimeAsync(10_000);
  expect(settled).toBe(true);
  expect((await pending).sourceStatuses[0]).toMatchObject({
    pagesFetched: 1,
    incompleteReason: 'page_failed',
    retryAfterMs: 10_000,
  });
  expect(fetchMock).toHaveBeenCalledTimes(2);
});

it('preserves an HTTP-date retry window', async () => {
  vi.setSystemTime(new Date('2026-11-11T12:00:00Z'));
  fetchMock.mockResolvedValue(
    new Response('', { status: 429, headers: { 'retry-after': 'Wed, 11 Nov 2026 12:00:20 GMT' } }),
  );
  const pending = new CtService(config).enumerate(
    'example.com',
    ['certspotter'],
    createMockContext(),
  );
  await vi.advanceTimersByTimeAsync(0);
  expect((await pending).sourceStatuses[0]).toMatchObject({
    retryAfterMs: 20_000,
    sourceError: expect.stringContaining('Retry after 20000 ms.'),
  });
});

it.each([undefined, 'later'])('does not invent a retry window for %s', async (retryAfter) => {
  fetchMock.mockImplementation(
    async () =>
      new Response('', {
        status: 429,
        headers: retryAfter === undefined ? {} : { 'retry-after': retryAfter },
      }),
  );
  const pending = new CtService(config).enumerate(
    'example.com',
    ['certspotter'],
    createMockContext(),
  );
  await vi.runAllTimersAsync();
  const status = (await pending).sourceStatuses[0];
  expect(status?.sourceError).toContain('rate limit');
  expect(status?.sourceError).not.toContain('Retry after');
  expect(status).not.toHaveProperty('retryAfterMs');
  expect(fetchMock).toHaveBeenCalledTimes(3);
});
