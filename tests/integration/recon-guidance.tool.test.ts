/**
 * @fileoverview Contract tests for the offline attacksurface_recon_guidance tool.
 * @module tests/integration/recon-guidance.tool.test
 */

import { createMockContext, type MockContextLogger } from '@cyanheads/mcp-ts-core/testing';
import { describe, expect, it } from 'vitest';
import { reconGuidanceTool } from '@/mcp-server/tools/definitions/recon-guidance.tool.js';

describe('attacksurface_recon_guidance contract', () => {
  it('returns schema-valid priorities, follow-up calls, logs, and complete format output', async () => {
    const ctx = createMockContext();
    const result = await reconGuidanceTool.handler(
      reconGuidanceTool.input.parse({
        topic: 'posture',
        findings: {
          domain: 'example.com',
          registrationExpiryDays: 10,
          hosts: [
            {
              host: 'legacy.example.com',
              addresses: ['93.184.216.34'],
              tlsProtocol: 'TLSv1.1',
              certDaysUntilExpiry: 7,
              certValidationAuthorized: false,
              missingSecurityHeaders: ['HSTS', 'CSP'],
              technologies: [{ name: 'nginx', version: '1.18.0' }],
              openPorts: [80, 443],
            },
          ],
        },
      }),
      ctx,
    );

    expect(result).toEqual(expect.schemaMatching(reconGuidanceTool.output));
    expect(result.priorities).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          severity: 'high',
          finding: expect.stringContaining('expires in 10'),
        }),
        expect.objectContaining({ severity: 'high', finding: expect.stringContaining('TLSv1.1') }),
        expect.objectContaining({
          severity: 'medium',
          finding: expect.stringContaining('HSTS, CSP'),
        }),
      ]),
    );
    expect(result.nextToolSuggestions).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          server: 'nist-nvd-mcp-server',
          tool: 'nvd_audit_cpe',
          arguments: { keyword: 'nginx 1.18.0' },
        }),
        expect.objectContaining({
          server: 'osv-advisory-mcp-server',
          tool: 'osv_query_package',
          arguments: { name: 'nginx', version: '1.18.0' },
        }),
      ]),
    );
    const log = ctx.log as MockContextLogger;
    expect(log.calls).toContainEqual(
      expect.objectContaining({ level: 'info', msg: 'Recon guidance synthesized' }),
    );
    const blocks = reconGuidanceTool.format?.(result);
    if (blocks?.[0]?.type === 'text') {
      expect(blocks[0].text).toContain('Defensive review — example.com');
      expect(blocks[0].text).toContain('nist-nvd-mcp-server');
      expect(blocks[0].text).toContain('keyword="nginx 1.18.0"');
    }
  });

  it('rejects malformed findings and topic values at the Zod boundary', () => {
    expect(reconGuidanceTool.input.safeParse({}).success).toBe(false);
    expect(reconGuidanceTool.input.safeParse({ findings: { hosts: 'not-an-array' } }).success).toBe(
      false,
    );
    expect(
      reconGuidanceTool.input.safeParse({ findings: { hosts: [] }, topic: 'exploit' }).success,
    ).toBe(false);
    expect(
      reconGuidanceTool.input.safeParse({
        findings: { hosts: [{ host: 'example.com', openPorts: ['443'] }] },
      }).success,
    ).toBe(false);
  });

  it('returns an explicit informational baseline for sparse valid findings', async () => {
    const result = await reconGuidanceTool.handler(
      reconGuidanceTool.input.parse({ findings: { hosts: [] }, topic: 'coverage' }),
      createMockContext(),
    );

    expect(result).toEqual(expect.schemaMatching(reconGuidanceTool.output));
    expect(result.priorities).toEqual([
      {
        severity: 'info',
        finding: 'No high-signal posture issues in the supplied findings.',
        action:
          'Broaden coverage: run map_domain at standard depth, or inspect any hosts not yet probed.',
      },
    ]);
    expect(result.nextToolSuggestions).toEqual([]);
    expect(result.plan).toContain('Focused on filling gaps in surface coverage.');
  });
});
