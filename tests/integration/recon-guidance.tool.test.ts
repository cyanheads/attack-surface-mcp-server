/**
 * @fileoverview Contract tests for the offline attacksurface_recon_guidance tool.
 * @module tests/integration/recon-guidance.tool.test
 */

import { z } from '@cyanheads/mcp-ts-core';
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import {
  createMockContext,
  type MockContextLogger,
  runToolContract,
} from '@cyanheads/mcp-ts-core/testing';
import { describe, expect, it } from 'vitest';
import {
  FindingHostSchema,
  reconGuidanceTool,
} from '@/mcp-server/tools/definitions/recon-guidance.tool.js';

describe('attacksurface_recon_guidance contract', () => {
  it.each(['', ' \t '])('rejects blank host (%j) on both response surfaces', async (host) => {
    const result = await runToolContract(reconGuidanceTool, {
      findings: {
        hosts: [{ host: 'other.example.com' }, { host, missingSecurityHeaders: [] }],
      },
    });
    const path = 'findings.hosts.1.host';
    const message = 'Provide a nonblank host identifier.';
    expect(result.isError).toBe(true);
    expect(result.structuredContent).toMatchObject({
      error: { code: JsonRpcErrorCode.InvalidParams, message: expect.stringContaining(path) },
    });
    expect(JSON.stringify(result.structuredContent)).toContain(message);
    expect(JSON.stringify(result.content)).toContain(path);
    expect(JSON.stringify(result.content)).toContain(message);
  });

  it('advertises nonblank hosts and optional TLS strings', () => {
    const schema = z.toJSONSchema(FindingHostSchema);
    expect(schema).toMatchObject({
      properties: { host: { pattern: '\\S' }, tlsProtocol: { type: 'string' } },
      required: ['host'],
    });
    expect(schema.properties?.tlsProtocol).not.toHaveProperty('pattern');
  });

  it.each(['posture', 'triage'] as const)(
    'keeps certificate expiry with a blank TLS protocol in %s',
    async (topic) => {
      const finding = 'example.test: TLS certificate expired 3 day(s) ago.';
      const result = await runToolContract(reconGuidanceTool, {
        topic,
        findings: { hosts: [{ host: 'example.test', tlsProtocol: '', certDaysUntilExpiry: -3 }] },
      });
      expect(result.isError).not.toBe(true);
      expect(result.structuredContent).toMatchObject({
        priorities: expect.arrayContaining([
          { severity: 'high', finding, action: 'Renew now; automate certificate renewal.' },
        ]),
      });
      const text = JSON.stringify(result.content);
      expect(text).toContain(finding);
      expect(text.includes('TLS posture is unknown.')).toBe(topic === 'triage');
    },
  );

  it.each(['', ' \t '])('treats protocol %j alone as unknown', async (tlsProtocol) => {
    const finding = 'Assessment coverage is unknown from the supplied findings.';
    const result = await runToolContract(reconGuidanceTool, {
      topic: 'posture',
      findings: { hosts: [{ host: 'example.test', tlsProtocol }] },
    });
    expect(result.isError).not.toBe(true);
    expect(result.structuredContent).toMatchObject({ priorities: [{ finding }] });
    expect(JSON.stringify(result.content)).toContain(finding);
  });

  it.each(['TLSv1.4', ' TLSv1.1 '])('keeps protocol %j as supplied', async (tlsProtocol) => {
    const finding = 'No selected findings require action based on the supplied evidence.';
    const result = await runToolContract(reconGuidanceTool, {
      topic: 'posture',
      findings: { hosts: [{ host: 'example.test', tlsProtocol }] },
    });
    expect(result.isError).not.toBe(true);
    expect(result.structuredContent).toMatchObject({ priorities: [{ finding }] });
    expect(JSON.stringify(result.content)).toContain(finding);
  });

  it.each(['triage', 'coverage'] as const)(
    'reports an omitted protocol as unknown in %s',
    async (topic) => {
      const finding = 'example.com: TLS posture is unknown.';
      const result = await runToolContract(reconGuidanceTool, {
        topic,
        findings: {
          hosts: [{ host: 'example.com', addresses: ['192.0.2.1'], missingSecurityHeaders: [] }],
        },
      });
      expect(result.isError).not.toBe(true);
      expect(result.structuredContent).toMatchObject({
        priorities: [{ finding }],
        nextToolSuggestions: [
          { toolName: 'attacksurface_inspect_tls', args: { hosts: ['example.com'], port: 443 } },
        ],
      });
      expect(JSON.stringify(result.content)).toContain(finding);
    },
  );
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
