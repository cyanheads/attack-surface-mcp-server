/**
 * @fileoverview Derive a framework `RequestContext` from the unified handler `Context` for utilities
 * that require it (`withRetry`'s `context` option). Carries request/trace IDs through for correlated
 * retry logging.
 * @module utils/request-context
 */

import type { Context } from '@cyanheads/mcp-ts-core';
import { type RequestContext, requestContextService } from '@cyanheads/mcp-ts-core/utils';

/** Build a correlated `RequestContext` from the handler `ctx` for a named operation. */
export function toRequestContext(ctx: Context, operation: string): RequestContext {
  return requestContextService.createRequestContext({
    operation,
    parentContext: { requestId: ctx.requestId, ...(ctx.traceId ? { traceId: ctx.traceId } : {}) },
  });
}
