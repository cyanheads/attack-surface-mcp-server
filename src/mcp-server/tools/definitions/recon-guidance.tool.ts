/**
 * @fileoverview attacksurface_recon_guidance — instruction tool. Given the findings gathered so far
 * (passed in from prior tool calls), returns a prioritized DEFENSIVE review plan as markdown plus
 * pre-filled follow-up tool calls: which hosts to inspect next, which expiring certs to flag, which
 * software versions warrant a CVE lookup against an external NVD/OSV server. Read-only, no external
 * calls — pure synthesis over the supplied state. Output is a remediation/visibility plan, never an
 * exploitation playbook. Assess only assets you own or are explicitly authorized to test.
 * @module mcp-server/tools/definitions/recon-guidance.tool
 */

import { tool, z } from '@cyanheads/mcp-ts-core';

const FindingHostSchema = z
  .object({
    host: z.string().describe('Hostname this finding pertains to.'),
    addresses: z.array(z.string()).optional().describe('Resolved IPs, when known.'),
    tlsProtocol: z.string().optional().describe('Negotiated TLS protocol, when known.'),
    certDaysUntilExpiry: z
      .number()
      .optional()
      .describe('Days until certificate expiry, when known.'),
    certValidationAuthorized: z.boolean().optional().describe('Whether the cert chain validated.'),
    missingSecurityHeaders: z
      .array(z.string())
      .optional()
      .describe('Security headers reported missing/weak.'),
    technologies: z
      .array(
        z
          .object({
            name: z.string().describe('Technology name.'),
            version: z.string().optional().describe('Version when known.'),
          })
          .describe('A detected technology and its version.'),
      )
      .optional()
      .describe('Detected technologies with versions (drives CVE-lookup suggestions).'),
    openPorts: z
      .array(z.number())
      .optional()
      .describe('Open ports (e.g. from Shodan), when known.'),
  })
  .describe('Per-host findings gathered from prior tool calls.');

const NextCallSchema = z
  .object({
    tool: z.string().describe('Tool to call next (this server or a sibling server).'),
    server: z.string().optional().describe('Owning server when the tool is on another MCP server.'),
    arguments: z
      .record(z.string(), z.unknown())
      .describe('Pre-filled arguments for the suggested call.'),
    rationale: z.string().describe('Why this follow-up advances the defensive review.'),
  })
  .describe('A pre-filled follow-up tool call suggestion.');

export const reconGuidanceTool = tool('attacksurface_recon_guidance', {
  title: 'attacksurface_recon_guidance',
  description:
    'Synthesize findings gathered so far into a prioritized defensive review plan plus pre-filled follow-up tool calls. Given live hosts, TLS/cert state, missing security headers, detected software versions, and open ports, returns markdown guidance (what to remediate first, which certs are expiring, which versions warrant a CVE check) and concrete next calls — including chaining detected software to an external NVD or OSV vulnerability server. Read-only and offline: reasons only over the state passed in, makes no external calls, and never produces an exploitation plan. For assets you own or are authorized to assess.',
  annotations: { readOnlyHint: true, openWorldHint: false },
  input: z.object({
    findings: z
      .object({
        domain: z.string().optional().describe('Apex domain under review, when known.'),
        hosts: z
          .array(FindingHostSchema)
          .describe('Per-host findings gathered from prior tool calls.'),
        registrationExpiryDays: z
          .number()
          .optional()
          .describe('Days until domain registration expiry, when known.'),
      })
      .describe('Findings gathered so far from prior attack-surface tool calls.'),
    topic: z
      .enum(['triage', 'posture', 'coverage'])
      .default('triage')
      .describe(
        '"triage" = prioritize what to fix first; "posture" = TLS/header hardening; "coverage" = gaps to fill next.',
      ),
  }),
  output: z.object({
    plan: z.string().describe('Prioritized defensive review plan as markdown.'),
    priorities: z
      .array(
        z
          .object({
            severity: z
              .enum(['high', 'medium', 'low', 'info'])
              .describe('Relative priority of the item.'),
            finding: z.string().describe('What was observed.'),
            action: z.string().describe('Recommended defensive action.'),
          })
          .describe('A single prioritized finding and its recommended action.'),
      )
      .describe('Structured priority items behind the plan.'),
    nextToolSuggestions: z.array(NextCallSchema).describe('Pre-filled follow-up tool calls.'),
  }),

  handler(input, ctx) {
    const { findings, topic } = input;
    const priorities: Array<{
      severity: 'high' | 'medium' | 'low' | 'info';
      finding: string;
      action: string;
    }> = [];
    const nextToolSuggestions: z.infer<typeof NextCallSchema>[] = [];

    // Registration expiry.
    if (findings.registrationExpiryDays !== undefined) {
      if (findings.registrationExpiryDays < 0) {
        priorities.push({
          severity: 'high',
          finding: `Domain registration expired ${Math.abs(findings.registrationExpiryDays)} day(s) ago.`,
          action: 'Renew the domain registration immediately to prevent takeover.',
        });
      } else if (findings.registrationExpiryDays < 30) {
        priorities.push({
          severity: 'high',
          finding: `Domain registration expires in ${findings.registrationExpiryDays} day(s).`,
          action: 'Renew the registration and enable auto-renew + registrar lock.',
        });
      }
    }

    for (const h of findings.hosts) {
      // Cert expiry.
      if (h.certDaysUntilExpiry !== undefined) {
        if (h.certDaysUntilExpiry < 0) {
          priorities.push({
            severity: 'high',
            finding: `${h.host}: TLS certificate expired ${Math.abs(h.certDaysUntilExpiry)} day(s) ago.`,
            action: 'Reissue and deploy a valid certificate; clients are seeing errors now.',
          });
        } else if (h.certDaysUntilExpiry < 14) {
          priorities.push({
            severity: 'high',
            finding: `${h.host}: TLS certificate expires in ${h.certDaysUntilExpiry} day(s).`,
            action: 'Renew now; automate renewal (ACME) to avoid recurrence.',
          });
        } else if (h.certDaysUntilExpiry < 30) {
          priorities.push({
            severity: 'medium',
            finding: `${h.host}: TLS certificate expires in ${h.certDaysUntilExpiry} day(s).`,
            action: 'Schedule renewal; verify automation is in place.',
          });
        }
      }

      // Cert validation.
      if (h.certValidationAuthorized === false) {
        priorities.push({
          severity: 'high',
          finding: `${h.host}: TLS chain did not validate (self-signed, expired, or wrong host).`,
          action: 'Install a publicly-trusted certificate with the correct SANs and full chain.',
        });
      }

      // Weak TLS.
      if (h.tlsProtocol && /TLSv1(\.1)?$|SSLv3/.test(h.tlsProtocol)) {
        priorities.push({
          severity: 'high',
          finding: `${h.host}: negotiated deprecated protocol ${h.tlsProtocol}.`,
          action: 'Disable TLS 1.0/1.1 and SSLv3; require TLS 1.2+ (prefer 1.3).',
        });
      }

      // Missing headers.
      if (h.missingSecurityHeaders && h.missingSecurityHeaders.length > 0) {
        priorities.push({
          severity: 'medium',
          finding: `${h.host}: missing/weak security headers — ${h.missingSecurityHeaders.join(', ')}.`,
          action: 'Add the missing headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options).',
        });
      }

      // Software → CVE lookup chaining (cross-server).
      for (const tech of h.technologies ?? []) {
        if (tech.version) {
          nextToolSuggestions.push({
            tool: 'nvd_audit_cpe',
            server: 'nist-nvd-mcp-server',
            arguments: { keyword: `${tech.name} ${tech.version}` },
            rationale: `${h.host} discloses ${tech.name} ${tech.version}; check for known CVEs against that version.`,
          });
          nextToolSuggestions.push({
            tool: 'osv_query_package',
            server: 'osv-advisory-mcp-server',
            arguments: { name: tech.name, version: tech.version },
            rationale: `Cross-check ${tech.name} ${tech.version} against the OSV advisory database.`,
          });
        } else {
          priorities.push({
            severity: 'info',
            finding: `${h.host}: ${tech.name} detected without a version.`,
            action:
              'Identify the exact version (banner/changelog) before a CVE lookup is meaningful.',
          });
        }
      }

      // Re-inspect suggestions for hosts lacking posture data.
      if (h.tlsProtocol === undefined && h.addresses && h.addresses.length > 0) {
        nextToolSuggestions.push({
          tool: 'attacksurface_inspect_tls',
          arguments: { hosts: [h.host] },
          rationale: `${h.host} resolved but has no TLS posture yet; inspect its certificate and protocol.`,
        });
      }
    }

    if (priorities.length === 0) {
      priorities.push({
        severity: 'info',
        finding: 'No high-signal posture issues in the supplied findings.',
        action:
          'Broaden coverage: run map_domain at standard depth, or inspect any hosts not yet probed.',
      });
    }

    const plan = renderPlan(findings.domain, topic, priorities, nextToolSuggestions);
    ctx.log.info('Recon guidance synthesized', {
      hostCount: findings.hosts.length,
      priorityCount: priorities.length,
      suggestionCount: nextToolSuggestions.length,
    });

    return { plan, priorities, nextToolSuggestions };
  },

  format: (result) => {
    const lines: string[] = [result.plan, '', '## Priorities'];
    for (const p of result.priorities) {
      lines.push(`- **[${p.severity}]** ${p.finding} → ${p.action}`);
    }
    lines.push('## Suggested next calls');
    if (result.nextToolSuggestions.length === 0) lines.push('- (none)');
    for (const s of result.nextToolSuggestions) {
      const where = s.server ? `${s.server} → ${s.tool}` : s.tool;
      lines.push(`- **${where}** — ${s.rationale}`);
      const args = Object.entries(s.arguments)
        .map(([k, v]) => `${k}=${JSON.stringify(v)}`)
        .join(', ');
      lines.push(`  - arguments: ${args}`);
    }
    return [{ type: 'text', text: lines.join('\n') }];
  },
});

/** Render the markdown plan from the structured priorities. */
function renderPlan(
  domain: string | undefined,
  topic: 'triage' | 'posture' | 'coverage',
  priorities: Array<{ severity: string; finding: string; action: string }>,
  suggestions: z.infer<typeof NextCallSchema>[],
): string {
  const heading = domain ? `Defensive review — ${domain}` : 'Defensive review';
  const topicLine = {
    triage: 'Prioritized by remediation urgency.',
    posture: 'Focused on TLS and HTTP hardening.',
    coverage: 'Focused on filling gaps in surface coverage.',
  }[topic];

  const order = { high: 0, medium: 1, low: 2, info: 3 } as const;
  const sorted = [...priorities].sort(
    (a, b) =>
      (order[a.severity as keyof typeof order] ?? 9) -
      (order[b.severity as keyof typeof order] ?? 9),
  );

  const lines: string[] = [`# ${heading}`, `_${topicLine}_`, ''];
  for (const p of sorted) {
    lines.push(`- **[${p.severity.toUpperCase()}]** ${p.finding}`);
    lines.push(`  - → ${p.action}`);
  }
  if (suggestions.length > 0) {
    lines.push('', `${suggestions.length} pre-filled follow-up call(s) are attached below.`);
  }
  return lines.join('\n');
}
