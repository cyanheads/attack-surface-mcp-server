/**
 * @fileoverview Tests for attacksurface_recon_guidance — offline synthesis over passed-in findings.
 * @module mcp-server/tools/definitions/recon-guidance.tool.test
 */

import { createMockContext } from '@cyanheads/mcp-ts-core/testing';
import { describe, expect, it } from 'vitest';
import { reconGuidanceTool } from './recon-guidance.tool.js';

const run = (input: unknown) =>
  reconGuidanceTool.handler(reconGuidanceTool.input.parse(input), createMockContext());

describe('attacksurface_recon_guidance', () => {
  it('flags an expired certificate as high priority', async () => {
    const result = await run({
      findings: { hosts: [{ host: 'old.example.com', certDaysUntilExpiry: -3 }] },
    });
    const high = result.priorities.find((p) => p.severity === 'high');
    expect(high?.finding).toContain('old.example.com');
    expect(high?.finding).toMatch(/expired/i);
  });

  it('retains product/version advisory review without external executable calls', async () => {
    const result = await run({
      findings: {
        hosts: [{ host: 'app.example.com', technologies: [{ name: 'nginx', version: '1.18.0' }] }],
      },
    });
    expect(
      result.priorities.some(
        (p) => p.finding.includes('nginx 1.18.0') && p.action.includes('advisories'),
      ),
    ).toBe(true);
    expect(result.nextToolSuggestions.map((s) => [s.toolName, s.args])).toEqual([
      ['attacksurface_probe_http', { url: 'https://app.example.com' }],
    ]);
  });

  it('treats versionless software as an info-level identify-first item, not a CVE lookup', async () => {
    const result = await run({
      findings: { hosts: [{ host: 'x.example.com', technologies: [{ name: 'Apache' }] }] },
    });
    expect(result.nextToolSuggestions.map((s) => [s.toolName, s.args])).toEqual([
      ['attacksurface_probe_http', { url: 'https://x.example.com' }],
    ]);
    expect(result.priorities.some((p) => p.severity === 'info' && /Apache/.test(p.finding))).toBe(
      true,
    );
  });

  it('suggests re-inspecting a resolved host with no TLS posture yet', async () => {
    const result = await run({
      findings: { hosts: [{ host: 'bare.example.com', addresses: ['93.184.216.34'] }] },
    });
    expect(result.nextToolSuggestions.some((s) => s.toolName === 'attacksurface_inspect_tls')).toBe(
      true,
    );
  });

  it('returns an info baseline when there are no high-signal findings', async () => {
    const result = await run({ findings: { hosts: [] } });
    expect(result.priorities).toHaveLength(1);
    expect(result.priorities[0]?.severity).toBe('info');
    expect(result.plan).toContain('Defensive review');
  });

  it('produces format() output that mentions priorities and suggested calls', async () => {
    const input = reconGuidanceTool.input.parse({
      findings: {
        domain: 'example.com',
        hosts: [{ host: 'app.example.com', technologies: [{ name: 'nginx', version: '1.18.0' }] }],
      },
    });
    const result = await reconGuidanceTool.handler(input, createMockContext());
    const text = reconGuidanceTool.format?.(result as never)?.[0];
    expect(text?.type).toBe('text');
    if (text?.type === 'text') {
      expect(text.text).toContain('nginx 1.18.0');
      expect(text.text).toContain('advisories');
    }
  });
});
