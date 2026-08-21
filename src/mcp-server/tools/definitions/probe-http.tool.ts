/**
 * @fileoverview attacksurface_probe_http — passive HTTP(S) probe of a single URL: one GET, following
 * redirects. Returns status, the redirect chain, response headers, a security-header audit
 * (HSTS/CSP/X-Frame-Options/cookie flags/CORS reflection), and an evidence-bound technology
 * fingerprint. One request per host — no path traversal, no parameter injection, no multi-method
 * probing. The URL is checked against an SSRF guard on every redirect hop.
 * @module mcp-server/tools/definitions/probe-http.tool
 */

import { tool, z } from '@cyanheads/mcp-ts-core';
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { getHttpService } from '@/services/http/http-service.js';

const RedirectHopSchema = z
  .object({
    url: z.string().describe('URL requested at this hop.'),
    status: z.number().describe('HTTP status returned at this hop.'),
    location: z.string().optional().describe('Location header that drove the next hop.'),
  })
  .describe('One hop in the redirect chain.');

const CookieAuditSchema = z
  .object({
    name: z.string().describe('Cookie name.'),
    secure: z.boolean().describe('Whether the Secure flag is set.'),
    httpOnly: z.boolean().describe('Whether the HttpOnly flag is set.'),
    sameSite: z.string().nullable().describe('SameSite attribute value, or null when absent.'),
  })
  .describe('Security-flag audit for one Set-Cookie header.');

const SecurityAuditSchema = z.object({
  hsts: z.string().nullable().describe('Strict-Transport-Security value, or null when absent.'),
  csp: z.string().nullable().describe('Content-Security-Policy value, or null when absent.'),
  xFrameOptions: z.string().nullable().describe('X-Frame-Options value, or null when absent.'),
  xContentTypeOptions: z.string().nullable().describe('X-Content-Type-Options value, or null.'),
  referrerPolicy: z.string().nullable().describe('Referrer-Policy value, or null when absent.'),
  permissionsPolicy: z
    .string()
    .nullable()
    .describe('Permissions-Policy value, or null when absent.'),
  cookies: z.array(CookieAuditSchema).describe('Per-cookie security-flag audit.'),
  corsAllowOrigin: z.string().nullable().describe('Access-Control-Allow-Origin value, or null.'),
  corsReflectsOrigin: z
    .boolean()
    .describe('True when the server reflected an arbitrary request Origin into ACAO.'),
  findings: z.array(z.string()).describe('Human-readable findings for missing or weak headers.'),
});

const TechDetectionSchema = z
  .object({
    name: z.string().describe('Detected technology or product name.'),
    category: z
      .enum(['server', 'framework', 'cdn', 'waf', 'cms', 'language', 'analytics', 'other'])
      .describe('Detection category.'),
    version: z.string().optional().describe('Version string when disclosed by the evidence.'),
    evidence: z
      .string()
      .describe('The concrete evidence (header or body marker) that triggered the detection.'),
  })
  .describe('A technology detection with its triggering evidence.');

export const probeHttpTool = tool('attacksurface_probe_http', {
  title: 'attacksurface_probe_http',
  description:
    'Passively probe a single URL with one HTTP(S) GET, following redirects. Returns the final status, the full redirect chain, response headers, a security-header audit (HSTS, CSP, X-Frame-Options, cookie Secure/HttpOnly/SameSite flags, and CORS origin-reflection), and an evidence-bound technology fingerprint (server, framework, CDN, WAF, CMS) drawn from headers and lightweight body markers. Strictly one request per host — no path traversal, parameter injection, or multi-method probing. Each redirect hop is validated against an SSRF guard. Use only on assets you own or are authorized to assess.',
  annotations: { readOnlyHint: true, openWorldHint: true },
  input: z.object({
    url: z
      .string()
      .min(1)
      .describe(
        'Absolute http:// or https:// URL to probe (e.g. "https://example.com"). Must be an http(s) URL; other schemes and private/loopback targets are rejected.',
      ),
    userAgent: z
      .string()
      .optional()
      .describe('Override the User-Agent header. Omit to use the server default.'),
    timeoutMs: z
      .number()
      .int()
      .min(1000)
      .max(30000)
      .default(10000)
      .describe('Per-request timeout in milliseconds.'),
  }),
  output: z.object({
    url: z.string().describe('The initial request URL.'),
    finalUrl: z.string().describe('Final URL after following redirects.'),
    finalStatus: z.number().describe('Final HTTP status code (0 when the probe errored).'),
    redirectChain: z
      .array(RedirectHopSchema)
      .describe('Redirect chain leading to the final response.'),
    headers: z
      .record(z.string(), z.string())
      .describe('Final-response headers (lower-cased keys).'),
    securityAudit: SecurityAuditSchema.describe('Security-header audit.'),
    technologies: z.array(TechDetectionSchema).describe('Technology detections with evidence.'),
    checkedAt: z.string().describe('ISO 8601 timestamp of the probe.'),
    transportError: z.string().nullable().describe('Transport error, or null on success.'),
  }),
  enrichment: {
    notice: z.string().optional().describe('Guidance when the probe could not reach the target.'),
  },
  errors: [
    {
      reason: 'blocked_target',
      code: JsonRpcErrorCode.Forbidden,
      when: 'The URL resolves to a private/loopback/metadata address, or uses a non-http(s) scheme.',
      recovery:
        'Probe only public http(s) URLs. Internal targets require ATTACKSURFACE_ALLOW_PRIVATE_TARGETS=true.',
    },
  ],

  async handler(input, ctx) {
    const result = await getHttpService().probe(input.url, input.userAgent, input.timeoutMs, ctx);

    // The service surfaces SSRF rejections via its transportError field with an SSRF_BLOCKED
    // prefix; promote that to the typed contract so the agent gets an actionable reason.
    if (result.transportError?.startsWith('SSRF_BLOCKED')) {
      throw ctx.fail('blocked_target', result.transportError, {
        ...ctx.recoveryFor('blocked_target'),
      });
    }

    if (result.transportError) {
      ctx.enrich.notice(`Could not complete the probe of ${input.url}: ${result.transportError}`);
    }

    return result;
  },

  format: (result) => {
    const lines: string[] = [];
    lines.push(`## ${result.url}`);
    lines.push(`**Error:** ${result.transportError ?? 'none'}`);
    lines.push(`**Final status:** ${result.finalStatus} | **Final URL:** ${result.finalUrl}`);
    lines.push('**Redirect chain:**');
    if (result.redirectChain.length === 0) lines.push('- (none)');
    for (const hop of result.redirectChain) {
      lines.push(`- ${hop.status} ${hop.url} → ${hop.location ?? '(no location)'}`);
    }

    const a = result.securityAudit;
    lines.push('### Security headers');
    lines.push(`- **HSTS:** ${a.hsts ?? 'absent'}`);
    lines.push(`- **CSP:** ${a.csp ?? 'absent'}`);
    lines.push(`- **X-Frame-Options:** ${a.xFrameOptions ?? 'absent'}`);
    lines.push(`- **X-Content-Type-Options:** ${a.xContentTypeOptions ?? 'absent'}`);
    lines.push(`- **Referrer-Policy:** ${a.referrerPolicy ?? 'absent'}`);
    lines.push(`- **Permissions-Policy:** ${a.permissionsPolicy ?? 'absent'}`);
    lines.push(
      `- **CORS Allow-Origin:** ${a.corsAllowOrigin ?? 'absent'} (reflects arbitrary origin: ${a.corsReflectsOrigin})`,
    );
    lines.push('- **Cookies:**');
    if (a.cookies.length === 0) lines.push('  - (none)');
    for (const c of a.cookies) {
      lines.push(
        `  - ${c.name}: Secure=${c.secure}, HttpOnly=${c.httpOnly}, SameSite=${c.sameSite ?? 'none'}`,
      );
    }
    lines.push('**Findings:**');
    if (a.findings.length === 0) lines.push('- (none)');
    for (const f of a.findings) lines.push(`- ${f}`);

    lines.push('### Technology fingerprint');
    if (result.technologies.length === 0) lines.push('- (none detected)');
    for (const t of result.technologies) {
      lines.push(`- **${t.name}** ${t.version ?? ''} _(${t.category})_ — ${t.evidence}`);
    }

    const headerKeys = Object.keys(result.headers);
    lines.push(`### Response headers (${headerKeys.length})`);
    for (const k of headerKeys) lines.push(`- ${k}: ${result.headers[k]}`);

    lines.push(`_Checked at ${result.checkedAt}_`);
    return [{ type: 'text', text: lines.join('\n') }];
  },
});
