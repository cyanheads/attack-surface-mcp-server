/**
 * @fileoverview Offline defensive guidance with local calls, topic selection and bounded pages.
 * @module mcp-server/tools/definitions/recon-guidance.tool
 */
import { isIP } from 'node:net';
import { tool, z } from '@cyanheads/mcp-ts-core';
import { escapeMarkdownInline } from '@cyanheads/mcp-ts-core/utils';
import { literalText } from '@/utils/literal-text.js';
import { NextCallSchema } from '@/utils/next-call.js';
import { RESPONSE_BYTE_TARGET, responseBytes } from '@/utils/response-budget.js';
import { isValidHost } from '@/utils/validation.js';

/** Findings accepted by guidance and generated directly from map service evidence. */
export const FindingHostSchema = z
  .object({
    host: z.string().describe('Hostname this finding pertains to.'),
    addresses: z.array(z.string()).optional().describe('Resolved IPs, when known.'),
    tlsProtocol: z.string().optional().describe('Negotiated TLS protocol, when known.'),
    certDaysUntilExpiry: z
      .number()
      .optional()
      .describe('Days until certificate expiry, when known.'),
    certValidationAuthorized: z
      .boolean()
      .optional()
      .describe('Whether the certificate chain validated.'),
    missingSecurityHeaders: z
      .array(z.string())
      .optional()
      .describe('Audited missing security headers.'),
    technologies: z
      .array(
        z
          .object({
            name: z.string().describe('Technology name.'),
            version: z.string().optional().describe('Version when known.'),
          })
          .describe('Detected technology and optional version.'),
      )
      .optional()
      .describe('Detected products and versions for advisory review.'),
    openPorts: z
      .array(z.number())
      .optional()
      .describe('Previously observed ports; never proof of vulnerability.'),
  })
  .describe('Per-host findings from prior tool calls.');

const PrioritySchema = z
  .object({
    severity: z
      .enum(['high', 'medium', 'low', 'info'])
      .describe('Relative defensive review priority.'),
    finding: z.string().describe('Observed evidence or unknown coverage.'),
    action: z.string().describe('Recommended defensive action.'),
  })
  .describe('A prioritized finding.');

const OutputSchema = z.object({
  plan: z
    .string()
    .describe(
      'Concise topic and coverage summary; detailed findings and actions are in priorities.',
    ),
  priorities: z.array(PrioritySchema).describe('Returned priority page.'),
  nextToolSuggestions: z.array(NextCallSchema).describe('Returned local follow-up call page.'),
  topic: z
    .enum(['triage', 'posture', 'coverage'])
    .describe('Selected topic; retain on continuation.'),
  limit: z.number().describe('Effective per-collection limit, at most 50.'),
  priorityOffset: z.number().describe('Requested priority offset.'),
  suggestionOffset: z.number().describe('Requested suggestion offset.'),
  nextPriorityOffset: z.number().nullable().describe('Next priority offset, null when exhausted.'),
  nextSuggestionOffset: z
    .number()
    .nullable()
    .describe('Next suggestion offset, null when exhausted.'),
  priorityTotal: z.number().describe('Selected priorities before paging.'),
  suggestionTotal: z.number().describe('Selected suggestions before paging.'),
  priorityReturnedCount: z.number().describe('Priorities returned on this page.'),
  suggestionReturnedCount: z.number().describe('Suggestions returned on this page.'),
  oversize: z
    .boolean()
    .describe('A complete single record or required metadata exceeds the byte target.'),
  pageInstructions: z.string().describe('Continuation instructions and byte-target exceptions.'),
  truncated: z.boolean().describe('Selected priorities or suggestions remain for another page.'),
});
type Output = z.infer<typeof OutputSchema>;
type Priority = z.infer<typeof PrioritySchema>;

export const reconGuidanceTool = tool('attacksurface_recon_guidance', {
  title: 'attacksurface_recon_guidance',
  description:
    'Synthesize supplied findings into an offline defensive review plan and executable local follow-up calls. triage orders all findings by urgency; posture selects TLS/header hardening; coverage selects inspection/version gaps and observed-service review. Versioned products retain host/product/version advisory-check instructions without external executable calls. Stateless pages target 24,000 serialized bytes across both response surfaces, except one complete oversized record. Makes no external calls or active scans. For assets you own or are authorized to assess.',
  annotations: { readOnlyHint: true, openWorldHint: false },
  input: z.object({
    findings: z
      .object({
        domain: z.string().optional().describe('Apex domain under review.'),
        hosts: z.array(FindingHostSchema).describe('Findings gathered from prior calls.'),
        registrationExpiryDays: z
          .number()
          .optional()
          .describe('Days until domain registration expiry, when known.'),
      })
      .describe('Original findings; resubmit unchanged for stateless continuation.'),
    topic: z
      .enum(['triage', 'posture', 'coverage'])
      .default('triage')
      .describe(
        'triage: all findings; posture: TLS/headers; coverage: inspection/version evidence and observed ports.',
      ),
    limit: z
      .number()
      .int()
      .positive()
      .default(50)
      .describe('Requested records per collection; clamped to 50.'),
    priorityOffset: z
      .number()
      .int()
      .nonnegative()
      .default(0)
      .describe('Priority offset; use its total to keep an exhausted collection exhausted.'),
    suggestionOffset: z
      .number()
      .int()
      .nonnegative()
      .default(0)
      .describe('Suggestion offset; use its total to keep an exhausted collection exhausted.'),
  }),
  output: OutputSchema,
  handler(input, ctx) {
    const priorities: Priority[] = [];
    const suggestions: z.infer<typeof NextCallSchema>[] = [];
    const posture = input.topic !== 'coverage',
      coverage = input.topic !== 'posture';
    const add = (severity: Priority['severity'], finding: string, action: string) =>
      priorities.push({ severity, finding, action });
    const expiry = input.findings.registrationExpiryDays;
    if (input.topic === 'triage' && expiry !== undefined && expiry < 30)
      add(
        'high',
        expiry < 0
          ? `Domain registration expired ${Math.abs(expiry)} day(s) ago.`
          : `Domain registration expires in ${expiry} day(s).`,
        'Renew the domain registration and enable auto-renew and registrar lock.',
      );
    for (const h of input.findings.hosts) {
      if (posture) {
        const days = h.certDaysUntilExpiry;
        if (days !== undefined && days < 30)
          add(
            days < 14 ? 'high' : 'medium',
            days < 0
              ? `${h.host}: TLS certificate expired ${Math.abs(days)} day(s) ago.`
              : `${h.host}: TLS certificate expires in ${days} day(s).`,
            days < 14
              ? 'Renew now; automate certificate renewal.'
              : 'Schedule renewal and verify automation.',
          );
        if (h.certValidationAuthorized === false)
          add(
            'high',
            `${h.host}: TLS chain did not validate.`,
            'Review chain trust and deploy the correct certificate and full chain.',
          );
        if (h.tlsProtocol && ['TLSv1', 'TLSv1.0', 'TLSv1.1', 'SSLv3'].includes(h.tlsProtocol))
          add(
            'high',
            `${h.host}: negotiated deprecated protocol ${h.tlsProtocol}.`,
            'Disable deprecated protocols; require TLS 1.2 or later.',
          );
        if (h.missingSecurityHeaders?.length)
          add(
            'medium',
            `${h.host}: missing/weak security headers — ${h.missingSecurityHeaders.join(', ')}.`,
            'Add the missing security headers and verify their policy values.',
          );
      }
      if (coverage) {
        for (const tech of h.technologies ?? [])
          add(
            'info',
            tech.version
              ? `${h.host}: ${tech.name} ${tech.version} detected.`
              : `${h.host}: ${tech.name} detected without a version.`,
            tech.version
              ? `Check ${tech.name} ${tech.version} on ${h.host} against authoritative vendor advisories and CVE records; confirm applicability before remediation.`
              : 'Identify the exact product version before checking advisories.',
          );
        if (h.tlsProtocol === undefined) {
          add(
            'info',
            `${h.host}: TLS posture is unknown.`,
            'Inspect a known TLS service to establish certificate and protocol evidence.',
          );
          if (isValidHost(h.host) && h.addresses?.length)
            suggestions.push({
              toolName: 'attacksurface_inspect_tls',
              args: { hosts: [h.host], port: 443 },
              reason: `${h.host} resolved but has no TLS posture; inspect its known HTTPS service.`,
            });
        }
        if (h.missingSecurityHeaders === undefined) {
          add(
            'info',
            `${h.host}: HTTP header inspection coverage is unknown.`,
            'Read the authorized HTTP service to collect header and technology evidence.',
          );
          if (isValidHost(h.host))
            suggestions.push({
              toolName: 'attacksurface_probe_http',
              args: { url: `https://${isIP(h.host) === 6 ? `[${h.host}]` : h.host}` },
              reason: `${h.host} has no HTTP header evidence; inspect its published HTTPS surface.`,
            });
        }
        for (const port of h.openPorts ?? []) {
          const service = port === 22 ? 'SSH' : port === 3389 ? 'RDP' : 'service';
          add(
            'info',
            `${h.host}: observed ${service} port ${port}.`,
            'Review inventory, intended exposure and access controls; an observed port is not evidence of a vulnerability.',
          );
          if (isValidHost(h.host) && port === 8443)
            suggestions.push({
              toolName: 'attacksurface_inspect_tls',
              args: { hosts: [h.host], port },
              reason: `Review the observed TLS service on ${h.host}:${port}; no port scanning is performed.`,
            });
        }
      }
    }
    if (!priorities.length) {
      const hasEvidence =
        (input.topic === 'triage' && expiry !== undefined) ||
        input.findings.hosts.some(
          (host) =>
            host.tlsProtocol !== undefined ||
            host.certDaysUntilExpiry !== undefined ||
            host.certValidationAuthorized !== undefined ||
            host.missingSecurityHeaders !== undefined,
        );
      add(
        'info',
        hasEvidence
          ? 'No selected findings require action based on the supplied evidence.'
          : 'Assessment coverage is unknown from the supplied findings.',
        hasEvidence
          ? 'Retain the supplied evidence and review any inspection gaps before drawing broader conclusions.'
          : 'Gather authorized DNS, TLS and HTTP evidence before drawing posture conclusions.',
      );
    }
    const order = { high: 0, medium: 1, low: 2, info: 3 };
    priorities.sort((a, b) => order[a.severity] - order[b.severity]);
    const limit = Math.min(input.limit, 50);
    const selectedP = priorities.slice(input.priorityOffset, input.priorityOffset + limit);
    const selectedS = suggestions.slice(input.suggestionOffset, input.suggestionOffset + limit);
    const build = (p: number, s: number, oversize = false): Output => ({
      plan: `Defensive review${input.findings.domain ? ` — ${input.findings.domain}` : ''}. Topic: ${input.topic}; ${p} of ${priorities.length} priorities and ${s} of ${suggestions.length} local calls on this page. Assess only assets you own or are authorized to assess.`,
      priorities: selectedP.slice(0, p),
      nextToolSuggestions: selectedS.slice(0, s),
      topic: input.topic,
      limit,
      priorityOffset: input.priorityOffset,
      suggestionOffset: input.suggestionOffset,
      nextPriorityOffset:
        input.priorityOffset + p < priorities.length ? input.priorityOffset + p : null,
      nextSuggestionOffset:
        input.suggestionOffset + s < suggestions.length ? input.suggestionOffset + s : null,
      priorityTotal: priorities.length,
      suggestionTotal: suggestions.length,
      priorityReturnedCount: p,
      suggestionReturnedCount: s,
      oversize,
      pageInstructions: `Continue with the original findings and topic, using each next offset; when null, use that collection's total to keep it exhausted.${oversize ? ' One complete oversized record or required metadata exceeds the 24,000-byte target.' : ''}`,
      truncated:
        input.priorityOffset + p < priorities.length ||
        input.suggestionOffset + s < suggestions.length,
    });
    let p = 0,
      s = 0;
    while (p < selectedP.length || s < selectedS.length) {
      const nextP = p < selectedP.length ? p + 1 : p;
      const nextS = nextP === p && s < selectedS.length ? s + 1 : s;
      const candidate = build(nextP, nextS);
      if (responseBytes(candidate, formatGuidance(candidate)) > RESPONSE_BYTE_TARGET) {
        if (p + s === 0) {
          p = nextP;
          s = nextS;
        }
        break;
      }
      p = nextP;
      s = nextS;
    }
    let result = build(p, s);
    if (responseBytes(result, formatGuidance(result)) > RESPONSE_BYTE_TARGET)
      result = build(p, s, true);
    ctx.log.info('Recon guidance synthesized', {
      hostCount: input.findings.hosts.length,
      priorityCount: priorities.length,
      suggestionCount: suggestions.length,
    });
    return result;
  },
  format: formatGuidance,
});

/** Complete text twin used for actual output and byte fitting. */
function formatGuidance(result: Output): Array<{ type: 'text'; text: string }> {
  return [
    {
      type: 'text',
      text: [
        escapeMarkdownInline(result.plan),
        '## Priorities',
        ...result.priorities.map(
          (p) => `- **[${p.severity}]** ${literalText(p.finding)} → ${literalText(p.action)}`,
        ),
        '## Suggested next calls',
        ...result.nextToolSuggestions.map(
          (s) =>
            `${literalText(s.toolName)} — ${literalText(s.reason)}; args=${literalText(JSON.stringify(s.args))}`,
        ),
        `topic=${result.topic}; limit=${result.limit}; priorityOffset=${result.priorityOffset}; suggestionOffset=${result.suggestionOffset}; nextPriorityOffset=${result.nextPriorityOffset}; nextSuggestionOffset=${result.nextSuggestionOffset}; priorityTotal=${result.priorityTotal}; suggestionTotal=${result.suggestionTotal}; priorityReturnedCount=${result.priorityReturnedCount}; suggestionReturnedCount=${result.suggestionReturnedCount}; oversize=${result.oversize}`,
        `truncated=${result.truncated}; ${result.pageInstructions}`,
      ].join('\n'),
    },
  ];
}
