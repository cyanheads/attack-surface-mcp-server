/**
 * @fileoverview Complete two-surface response sizing for bounded pages.
 * @module utils/response-budget
 */
export const RESPONSE_BYTE_TARGET = 24_000;

/** Count JSON keys, escaping and every content block. */
export function responseBytes(value: unknown, content: unknown): number {
  return Buffer.byteLength(JSON.stringify({ structuredContent: value, content }));
}
