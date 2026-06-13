/**
 * @fileoverview Tests for attacksurface_resolve_dns input-validation contracts. These assert the
 * typed error contracts that fire at the edge before any network I/O — invalid hosts, malformed
 * resolver IPs, and (the SSRF-relevant case) syntactically-valid but private/loopback resolver IPs,
 * which must surface as the typed `blocked_resolver` reason rather than an opaque auto-classified
 * error the agent cannot branch on.
 * @module mcp-server/tools/definitions/resolve-dns.tool.test
 */

import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { createMockContext } from '@cyanheads/mcp-ts-core/testing';
import { describe, expect, it } from 'vitest';
import { resolveDnsTool } from './resolve-dns.tool.js';

type HandlerCtx = Parameters<typeof resolveDnsTool.handler>[1];

/** Mock context wired with the tool's own contract so `ctx.fail` is typed against its reasons. */
const ctx = () => createMockContext({ errors: resolveDnsTool.errors ?? [] }) as HandlerCtx;

const run = (input: unknown) => resolveDnsTool.handler(resolveDnsTool.input.parse(input), ctx());

describe('attacksurface_resolve_dns input contracts', () => {
  it('rejects a syntactically invalid host with the invalid_host reason', async () => {
    await expect(run({ hosts: ['not a host!!'] })).rejects.toMatchObject({
      code: JsonRpcErrorCode.ValidationError,
      data: { reason: 'invalid_host' },
    });
  });

  it('rejects a resolver hostname (non-IP) with the invalid_resolver reason', async () => {
    await expect(run({ hosts: ['example.com'], resolvers: ['dns.google'] })).rejects.toMatchObject({
      code: JsonRpcErrorCode.ValidationError,
      data: { reason: 'invalid_resolver' },
    });
  });

  it('rejects a private resolver IP with the typed blocked_resolver reason (not opaque)', async () => {
    // 10.0.0.1 is a valid IP literal, so it passes the syntactic invalid_resolver gate and reaches
    // the SSRF guard. The rejection must be the typed Forbidden/blocked_resolver contract, with a
    // populated data.reason, so the agent can distinguish "private resolver" from a server fault.
    await expect(run({ hosts: ['example.com'], resolvers: ['10.0.0.1'] })).rejects.toMatchObject({
      code: JsonRpcErrorCode.Forbidden,
      data: { reason: 'blocked_resolver' },
    });
  });

  it('rejects the cloud-metadata resolver IP as blocked_resolver', async () => {
    await expect(
      run({ hosts: ['example.com'], resolvers: ['169.254.169.254'] }),
    ).rejects.toMatchObject({
      code: JsonRpcErrorCode.Forbidden,
      data: { reason: 'blocked_resolver' },
    });
  });
});
