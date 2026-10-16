/**
 * @fileoverview Local executable follow-up contract shared by discovery and guidance.
 * @module utils/next-call
 */
import { z } from '@cyanheads/mcp-ts-core';

/** A supported local tool call with its purpose and executable arguments. */
export const NextCallSchema = z
  .object({
    toolName: z.string().describe('Registered local tool to call next.'),
    reason: z.string().describe('Why this follow-up advances the defensive review.'),
    args: z.record(z.string(), z.unknown()).describe('Pre-filled executable tool arguments.'),
  })
  .describe('A local follow-up tool call.');
