/**
 * @fileoverview Fuzz test for attacksurface_recon_guidance — the one fully-offline tool, so fuzzing
 * exercises the synthesis logic against adversarial input without live network calls. Asserts no
 * crashes, no leaks, no prototype pollution.
 * @module mcp-server/tools/definitions/recon-guidance.fuzz.test
 */

import { fuzzTool } from '@cyanheads/mcp-ts-core/testing/fuzz';
import { describe, expect, it } from 'vitest';
import { reconGuidanceTool } from './recon-guidance.tool.js';

describe('attacksurface_recon_guidance fuzz', () => {
  it('survives adversarial input', async () => {
    const report = await fuzzTool(reconGuidanceTool, { numRuns: 60, numAdversarial: 40 });
    expect(report.crashes).toHaveLength(0);
    expect(report.leaks).toHaveLength(0);
    expect(report.prototypePollution).toBe(false);
  });
});
