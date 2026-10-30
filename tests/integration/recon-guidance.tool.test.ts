/**
 * @fileoverview Contract tests for the offline attacksurface_recon_guidance tool.
 * @module tests/integration/recon-guidance.tool.test
 */

import { createMockContext, type MockContextLogger } from '@cyanheads/mcp-ts-core/testing';
import { describe, expect, it } from 'vitest';
import { reconGuidanceTool } from '@/mcp-server/tools/definitions/recon-guidance.tool.js';

describe('attacksurface_recon_guidance contract', () => {
  it('keeps domain text raw in structured output and encodes only the text twin', async () => {
    const result = await reconGuidanceTool.handler(
      reconGuidanceTool.input.parse({ findings: { domain: '<b>*domain*</b>', hosts: [] } }),
      createMockContext(),
    );
    expect(result.plan).toBe(
      'Defensive review — <b>*domain*</b>. Topic: triage; 1 of 1 priorities and 0 of 0 local calls on this page. Assess only assets you own or are authorized to assess.',
    );
    expect(reconGuidanceTool.format?.(result)?.[0]).toMatchObject({
      text: expect.stringContaining('\\<b>\\*domain\\*\\</b>'),
    });
  });

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
          finding: expect.stringContaining('expires in 7'),
        }),
        expect.objectContaining({ severity: 'high', finding: expect.stringContaining('TLSv1.1') }),
        expect.objectContaining({
          severity: 'medium',
          finding: expect.stringContaining('HSTS, CSP'),
        }),
      ]),
    );
    expect(result.nextToolSuggestions).toEqual([]);
    const log = ctx.log as MockContextLogger;
    expect(log.calls).toContainEqual(
      expect.objectContaining({ level: 'info', msg: 'Recon guidance synthesized' }),
    );
    const blocks = reconGuidanceTool.format?.(result);
    expect(blocks).toEqual([{ type: 'text', text: expect.any(String) }]);
    expect(blocks?.[0]).toMatchObject({
      text: expect.stringContaining('Defensive review — example.com'),
    });
    expect(blocks?.[0]).toMatchObject({ text: expect.stringContaining('TLSv1.1') });
    expect(result.priorities.some((p) => p.finding.includes('nginx'))).toBe(false);
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
        finding: 'Assessment coverage is unknown from the supplied findings.',
        action: 'Gather authorized DNS, TLS and HTTP evidence before drawing posture conclusions.',
      },
    ]);
    expect(result.nextToolSuggestions).toEqual([]);
    expect(result.plan).toContain('Topic: coverage');
  });
});
