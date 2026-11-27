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

  it.each(['triage', 'coverage'] as const)(
    'reviews only confirmed in-zone aliases in %s',
    async (topic) => {
      const owner = 'Legacy.Dept.Example.Test.';
      const target = 'Archive.Provider.Test.';
      const absent = (host: string) => ({ host, addresses: [], addressError: null });
      const cnameRecords = [
        { owner, target },
        { owner: owner.toLowerCase(), target: target.toLowerCase() },
        ...['missing', 'timeout', 'conflict', 'live', 'ambiguous'].map((name) => ({
          owner: `${name}.example.test`,
          target,
        })),
        { owner: 'ambiguous.example.test', target: 'second.provider.test' },
        { owner: 'suffix.notexample.test', target },
      ];
      const result = await runToolContract(reconGuidanceTool, {
        topic,
        findings: {
          hosts: [],
          dnsReview: {
            zone: 'EXAMPLE.TEST.',
            cnameRecords,
            addressStatuses: [
              absent('legacy.dept.example.test'),
              { ...absent('timeout.example.test'), addressError: 'ETIMEOUT' },
              absent('conflict.example.test'),
              { ...absent('CONFLICT.EXAMPLE.TEST.'), addressError: 'ESERVFAIL' },
              { ...absent('live.example.test'), addresses: ['192.0.2.1'] },
              absent('ambiguous.example.test'),
              absent('suffix.notexample.test'),
              absent('child.missing.example.test'),
            ],
          },
        },
      });
      const finding = `${owner}: exported CNAME points to ${target}; supplied address status shows no A or AAAA answers.`;
      const action = 'Review whether this DNS record should be retained.';
      expect(result.structuredContent).toMatchObject({
        priorities: [{ severity: 'low', finding, action }],
        priorityTotal: 1,
        nextToolSuggestions: [],
        suggestionTotal: 0,
      });
      expect(result.content[0]).toMatchObject({
        text: expect.stringContaining(`\`${finding}\` → \`${action}\``),
      });
    },
  );

  it('pages DNS review through the shared priority offsets and leaves an exhausted page empty', async () => {
    const names = ['example.test', ...Array.from({ length: 51 }, (_, i) => `h${i}.example.test`)];
    const findings = {
      hosts: [],
      dnsReview: {
        zone: 'example.test',
        cnameRecords: names.map((owner) => ({ owner, target: 'archive.provider.test' })),
        addressStatuses: names.map((host) => ({ host, addresses: [], addressError: null })),
      },
    };
    const first = await runToolContract(reconGuidanceTool, { findings, limit: 100 });
    expect(first.structuredContent).toMatchObject({
      limit: 50,
      priorityTotal: 52,
      priorityReturnedCount: 50,
      nextPriorityOffset: 50,
      nextSuggestionOffset: null,
      truncated: true,
    });
    expect(first.content[0]).toMatchObject({
      text: expect.stringContaining('nextPriorityOffset=50'),
    });
    const second = await runToolContract(reconGuidanceTool, { findings, priorityOffset: 50 });
    expect(second.structuredContent).toMatchObject({
      priorities: [
        { finding: expect.stringContaining('h49.example.test') },
        { finding: expect.stringContaining('h50.example.test') },
      ],
      priorityTotal: 52,
      nextPriorityOffset: null,
      truncated: false,
    });
    expect(second.content[0]).toMatchObject({
      text: expect.stringContaining('h50.example.test'),
    });
    const beyond = await runToolContract(reconGuidanceTool, { findings, priorityOffset: 53 });
    expect(beyond.structuredContent).toMatchObject({
      priorities: [],
      priorityTotal: 52,
      priorityReturnedCount: 0,
      nextToolSuggestions: [],
    });
    expect(beyond.content[0]).toMatchObject({
      text: expect.stringContaining('priorityReturnedCount=0'),
    });
  });

  it.each(['triage', 'posture'] as const)(
    'keeps the empty review baseline in %s',
    async (topic) => {
      const result = await runToolContract(reconGuidanceTool, {
        topic,
        findings: {
          hosts: [],
          dnsReview: {
            zone: 'example.test',
            cnameRecords: [{ owner: 'example.test', target: 'archive.provider.test' }],
            addressStatuses:
              topic === 'posture'
                ? [{ host: 'example.test', addresses: [], addressError: null }]
                : [],
          },
        },
      });
      const finding = 'Assessment coverage is unknown from the supplied findings.';
      expect(result.structuredContent).toMatchObject({
        priorities: [{ finding }],
        nextToolSuggestions: [],
      });
      expect(result.content[0]).toMatchObject({ text: expect.stringContaining(finding) });
    },
  );

  it.each(['https://example.test', 'example.test/path', '*.example.test', '192.0.2.1'])(
    'rejects invalid zone %s on both error surfaces',
    async (zone) => {
      const result = await runToolContract(reconGuidanceTool, {
        findings: { hosts: [], dnsReview: { zone, cnameRecords: [], addressStatuses: [] } },
      });
      expect(result.isError).toBe(true);
      expect(result.structuredContent).toMatchObject({
        error: { data: { reason: 'invalid_arguments', recovery: { hint: expect.any(String) } } },
      });
      expect(result.content[0]).toMatchObject({
        text: expect.stringContaining('findings.dnsReview.zone'),
      });
      expect(result.content[0]).toMatchObject({
        text: expect.stringContaining('invalid_arguments'),
      });
    },
  );
});
