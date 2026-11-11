/**
 * @fileoverview Explicit DNS resolver operations with caller cancellation.
 * @module services/dns/configured-resolver
 */
import { Resolver } from 'node:dns/promises';

/** Redacted DNS failure during validation, with a code for callers that classify absence. */
export class DnsValidationError extends Error {
  readonly code: string;

  constructor(message: string, code: string) {
    super(message);
    this.code = code;
  }
}

/** Run queries on one validated resolver IP and cancel its outstanding queries on abort. */
export async function withConfiguredResolver<T>(
  ip: string,
  options: { timeout: number; tries: number },
  signal: AbortSignal | undefined,
  query: (resolver: Resolver) => Promise<T>,
): Promise<T> {
  signal?.throwIfAborted();
  const resolver = new Resolver(options);
  resolver.setServers([ip]);
  const cancel = () => resolver.cancel();
  signal?.addEventListener('abort', cancel, { once: true });
  try {
    return await query(resolver);
  } finally {
    signal?.removeEventListener('abort', cancel);
    signal?.throwIfAborted();
  }
}

/** DNS errors use a stable code independent of the upstream's message text. */
export function dnsErrorCode(error: unknown): string | undefined {
  return error instanceof Error && 'code' in error && typeof error.code === 'string'
    ? error.code
    : undefined;
}

/** ENOTFOUND and ENODATA represent ordinary DNS absence. */
export function isDnsAbsent(error: unknown): boolean {
  const code = dnsErrorCode(error);
  return code === 'ENOTFOUND' || code === 'ENODATA';
}
