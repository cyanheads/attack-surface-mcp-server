/**
 * @fileoverview Topic selection, executable suggestions and stateless guidance paging.
 * @module tests/integration/bounded-guidance
 */
import { runToolContract } from '@cyanheads/mcp-ts-core/testing';
import { describe, expect, it } from 'vitest';
import { inspectTlsTool } from '@/mcp-server/tools/definitions/inspect-tls.tool.js';
import { probeHttpTool } from '@/mcp-server/tools/definitions/probe-http.tool.js';
import { reconGuidanceTool } from '@/mcp-server/tools/definitions/recon-guidance.tool.js';

describe('bounded guidance', () => {
  it('distinguishes healthy supplied posture from absent assessment evidence', async () => {
    const healthy = await runToolContract(reconGuidanceTool, {
      topic: 'posture',
      findings: {
        hosts: [
          {
            host: 'example.com',
            tlsProtocol: 'TLSv1.3',
            certDaysUntilExpiry: 90,
            certValidationAuthorized: true,
            missingSecurityHeaders: [],
          },
        ],
      },
    });
    expect(reconGuidanceTool.output.parse(healthy.structuredContent).priorities).toEqual([
      expect.objectContaining({
        finding: 'No selected findings require action based on the supplied evidence.',
      }),
    ]);
    const empty = await runToolContract(reconGuidanceTool, {
      topic: 'posture',
      findings: { hosts: [] },
    });
    expect(reconGuidanceTool.output.parse(empty.structuredContent).priorities).toEqual([
      expect.objectContaining({
        finding: 'Assessment coverage is unknown from the supplied findings.',
      }),
    ]);
  });
  it.each(['example.com', '2606:4700:4700::1111', '8.8.8.8', 'not a hostname'])(
    'emits only schema-valid local calls for %s',
    async (host) => {
      const result = await runToolContract(reconGuidanceTool, {
        findings: { hosts: [{ host, addresses: ['8.8.8.8'], openPorts: [22, 3389, 8443] }] },
      });
      const output = reconGuidanceTool.output.parse(result.structuredContent);
      expect(output.nextToolSuggestions.map(({ toolName, args }) => ({ toolName, args }))).toEqual(
        host === 'not a hostname'
          ? []
          : [
              { toolName: inspectTlsTool.name, args: { hosts: [host], port: 443 } },
              {
                toolName: probeHttpTool.name,
                args: { url: `https://${host.includes(':') ? `[${host}]` : host}` },
              },
              { toolName: inspectTlsTool.name, args: { hosts: [host], port: 8443 } },
            ],
      );
      for (const call of output.nextToolSuggestions) {
        const def = [inspectTlsTool, probeHttpTool].find((t) => t.name === call.toolName);
        expect(def?.input.safeParse(call.args).success).toBe(true);
        expect(JSON.stringify(result.content)).toContain(call.toolName);
      }
    },
  );

  it('retains literal finding evidence and renders each detailed action once in severity order', async () => {
    const host = '<section>*host*</section>';
    const result = await runToolContract(reconGuidanceTool, {
      findings: {
        hosts: [
          {
            host,
            certDaysUntilExpiry: 0,
            technologies: [{ name: 'prod`uct', version: '1.0' }],
            missingSecurityHeaders: ['CSP'],
          },
        ],
      },
    });
    const output = reconGuidanceTool.output.parse(result.structuredContent);
    const text = result.content
      .filter((b) => b.type === 'text')
      .map((b) => b.text)
      .join('\n');
    const severity = { high: 0, medium: 1, low: 2, info: 3 };
    expect(output.priorities.map((p) => severity[p.severity])).toEqual(
      output.priorities.map((p) => severity[p.severity]).toSorted((a, b) => a - b),
    );
    for (const priority of output.priorities) {
      expect(text.split(priority.finding)).toHaveLength(2);
      expect(text.split(priority.action)).toHaveLength(2);
    }
    expect(output.plan).not.toContain(host);
    expect(text).toContain('`<section>*host*</section>: TLS');
  });

  it.each([{ limit: 0 }, { priorityOffset: -1 }, { suggestionOffset: 1.5 }])(
    'rejects invalid page controls %j',
    async (controls) => {
      const result = await runToolContract(reconGuidanceTool, {
        findings: { hosts: [] },
        ...controls,
      });
      expect(result.isError).toBe(true);
      expect(JSON.stringify(result.content)).toContain('invalid_arguments');
    },
  );
  it('selects topics before paging and keeps advisory details as priorities', async () => {
    const findings = {
      domain: 'example.com',
      registrationExpiryDays: 0,
      hosts: [
        {
          host: 'example.com',
          addresses: ['8.8.8.8'],
          certDaysUntilExpiry: 0,
          missingSecurityHeaders: ['CSP'],
          technologies: [{ name: 'nginx', version: '1.2' }],
          openPorts: [22, 3389, 8443],
        },
      ],
    };
    const results = [];
    for (const topic of ['triage', 'posture', 'coverage'] satisfies Array<
      'triage' | 'posture' | 'coverage'
    >) {
      const result = await runToolContract(reconGuidanceTool, { findings, topic });
      expect(result.isError).not.toBe(true);
      const output = reconGuidanceTool.output.parse(result.structuredContent);
      for (const call of output.nextToolSuggestions) {
        expect(call).toHaveProperty('toolName');
        expect(call).not.toHaveProperty('tool');
        const def = [inspectTlsTool, probeHttpTool].find((t) => t.name === call.toolName);
        expect(def).toBeDefined();
        expect(def?.input.safeParse(call.args).success).toBe(true);
      }
      results.push(output);
    }
    expect(JSON.stringify(results[0]?.priorities)).toContain('nginx');
    expect(JSON.stringify(results[0]?.priorities)).toContain('1.2');
    expect(JSON.stringify(results[0]?.priorities)).toContain('registration');
    expect(JSON.stringify(results[1]?.priorities)).not.toContain('registration');
    expect(JSON.stringify(results[1]?.priorities)).not.toContain('SSH');
    expect(JSON.stringify(results[2]?.priorities)).toContain('SSH');
    expect(JSON.stringify(results[2]?.priorities)).toContain('RDP');
    expect(JSON.stringify(results[2]?.priorities)).not.toContain('Renew now');
  });

  it('walks independent pages without resetting exhausted collections and measures complete serialized surfaces', async () => {
    const findings = {
      hosts: Array.from({ length: 80 }, (_, i) => ({
        host: `h${i}.example.com`,
        addresses: ['8.8.8.8'],
        certDaysUntilExpiry: 7,
        technologies: [{ name: `product${i}${'\\"'.repeat((i % 5) * 70)}`, version: '1' }],
      })),
    };
    let priorityOffset = 0,
      suggestionOffset = 0;
    const priorities: string[] = [];
    const suggestions: string[] = [];
    let exhausted = false;
    for (let page = 0; page < 30; page++) {
      const result = await runToolContract(reconGuidanceTool, {
        findings,
        priorityOffset,
        suggestionOffset,
        limit: 100,
      });
      const output = reconGuidanceTool.output.parse(result.structuredContent);
      expect(output).toHaveProperty('limit', 50);
      expect(
        Buffer.byteLength(
          JSON.stringify({ structuredContent: result.structuredContent, content: result.content }),
        ),
      ).toBeLessThanOrEqual(24000);
      expect(output.priorityTotal).toBe(320);
      expect(output.suggestionTotal).toBe(160);
      expect(output.priorityReturnedCount).toBe(output.priorities.length);
      expect(output.suggestionReturnedCount).toBe(output.nextToolSuggestions.length);
      priorities.push(...output.priorities.map((p) => p.finding));
      suggestions.push(
        ...output.nextToolSuggestions.map((s) => JSON.stringify([s.toolName, s.args])),
      );
      const p = output.nextPriorityOffset;
      const s = output.nextSuggestionOffset;
      expect(p).toBe(
        priorityOffset + output.priorities.length < 320
          ? priorityOffset + output.priorities.length
          : null,
      );
      expect(s).toBe(
        suggestionOffset + output.nextToolSuggestions.length < 160
          ? suggestionOffset + output.nextToolSuggestions.length
          : null,
      );
      if (p === null && s === null) {
        exhausted = true;
        break;
      }
      expect(output.priorities.length + output.nextToolSuggestions.length).toBeGreaterThan(0);
      priorityOffset = p ?? output.priorityTotal;
      suggestionOffset = s ?? output.suggestionTotal;
    }
    expect(exhausted).toBe(true);
    expect(priorities).toHaveLength(320);
    expect(new Set(priorities).size).toBe(320);
    expect(new Set(priorities)).toEqual(
      new Set(
        findings.hosts.flatMap((host) => [
          `${host.host}: TLS certificate expires in 7 day(s).`,
          `${host.host}: ${host.technologies[0]?.name} 1 detected.`,
          `${host.host}: TLS posture is unknown.`,
          `${host.host}: HTTP header inspection coverage is unknown.`,
        ]),
      ),
    );
    expect(suggestions).toHaveLength(160);
    expect(new Set(suggestions)).toEqual(
      new Set(
        findings.hosts.flatMap(({ host }) => [
          JSON.stringify([inspectTlsTool.name, { hosts: [host], port: 443 }]),
          JSON.stringify([probeHttpTool.name, { url: `https://${host}` }]),
        ]),
      ),
    );
    const end = await runToolContract(reconGuidanceTool, {
      findings,
      priorityOffset: 99999,
      suggestionOffset: 99999,
    });
    expect(end.structuredContent).toMatchObject({
      priorities: [],
      nextToolSuggestions: [],
      nextPriorityOffset: null,
      nextSuggestionOffset: null,
    });
  });

  it('returns one complete oversized priority and an explicit advancing exception', async () => {
    const literal = 'x'.repeat(30000);
    const result = await runToolContract(reconGuidanceTool, {
      findings: {
        hosts: [{ host: 'example.com', technologies: [{ name: literal, version: '1' }] }],
      },
    });
    expect(JSON.stringify(result.structuredContent)).toContain(literal);
    expect(JSON.stringify(result.content)).toContain(literal);
    expect(result.structuredContent).toMatchObject({ oversize: true });
    expect(JSON.stringify(result.content)).toContain('oversized');
  });
});
