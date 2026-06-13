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

  it('suggests a cross-server CVE lookup for versioned software', async () => {
    const result = await run({
      findings: {
        hosts: [{ host: 'app.example.com', technologies: [{ name: 'nginx', version: '1.18.0' }] }],
      },
    });
    const nvd = result.nextToolSuggestions.find((s) => s.server === 'nist-nvd-mcp-server');
    expect(nvd).toBeDefined();
    expect(nvd?.arguments).toMatchObject({ keyword: 'nginx 1.18.0' });
    expect(result.nextToolSuggestions.some((s) => s.server === 'osv-advisory-mcp-server')).toBe(
      true,
    );
  });

  it('treats versionless software as an info-level identify-first item, not a CVE lookup', async () => {
    const result = await run({
      findings: { hosts: [{ host: 'x.example.com', technologies: [{ name: 'Apache' }] }] },
    });
    expect(result.nextToolSuggestions.some((s) => s.server === 'nist-nvd-mcp-server')).toBe(false);
    expect(result.priorities.some((p) => p.severity === 'info' && /Apache/.test(p.finding))).toBe(
      true,
    );
  });

  it('suggests re-inspecting a resolved host with no TLS posture yet', async () => {
    const result = await run({
      findings: { hosts: [{ host: 'bare.example.com', addresses: ['93.184.216.34'] }] },
    });
    expect(
      result.nextToolSuggestions.some((s) => s.tool === 'attacksurface_inspect_tls' && !s.server),
    ).toBe(true);
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
      expect(text.text).toContain('nist-nvd-mcp-server');
      expect(text.text).toContain('Priorities');
    }
  });
});
