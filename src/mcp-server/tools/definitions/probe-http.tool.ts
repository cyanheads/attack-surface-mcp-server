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
import { literalText } from '@/utils/literal-text.js';

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
    sameSite: z
      .string()
      .nullable()
      .describe(
        'Canonical Strict/Lax/None, raw invalid value (including empty), or null when absent.',
      ),
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
  corsAllowCredentials: z
    .string()
    .nullable()
    .describe(
      'Observed Access-Control-Allow-Credentials value, or null when absent or unobserved.',
    ),
  corsAllowOrigin: z.string().nullable().describe('Access-Control-Allow-Origin value, or null.'),
  corsReflectsOrigin: z
    .boolean()
    .describe('True when the final Access-Control-Allow-Origin matched the probe origin.'),
  findings: z
    .array(z.string())
    .describe('Findings based on the final response scheme and headers.'),
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

/** Validate the record in place so Zod preserves every own header name, including __proto__. */
const ResponseHeadersSchema = z
  .unknown()
  .refine((value): value is Record<string, string> => {
    if (typeof value !== 'object' || value === null) return false;
    const prototype: unknown = Object.getPrototypeOf(value);
    return (
      (prototype === null || prototype === Object.prototype) &&
      Object.values(value).every((header) => typeof header === 'string')
    );
  })
  .meta({
    type: 'object',
    propertyNames: { type: 'string' },
    additionalProperties: { type: 'string' },
  })
  .describe('Final-response headers (lower-cased keys).');

export const probeHttpTool = tool('attacksurface_probe_http', {
  title: 'attacksurface_probe_http',
  description:
    'Passively probe a single URL with HTTP(S) GET requests, following redirects. Returns the final status, the full redirect chain, response headers, a security-header audit (HSTS, CSP, X-Frame-Options, cookie Secure/HttpOnly/SameSite flags, and CORS origin-reflection), and an evidence-bound technology fingerprint (server, framework, CDN, WAF, CMS) drawn from headers and lightweight body markers. Each redirect hop is validated against an SSRF guard. Use only on assets you own or are authorized to assess.',
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
      .describe(
        'Total probe timeout in milliseconds, including DNS, redirects, and body inspection.',
      ),
  }),
  output: z.object({
    url: z.string().describe('The initial request URL.'),
    finalUrl: z.string().describe('Final URL after following redirects.'),
    finalStatus: z.number().describe('Final HTTP status code (0 when the probe errored).'),
    redirectChain: z
      .array(RedirectHopSchema)
      .describe('Followed redirects, capped at ten; another redirect produces a transport error.'),
    headers: ResponseHeadersSchema,
    securityAudit: SecurityAuditSchema.describe(
      'Final-response audit. Without a final response, header values are null, cookies and findings are empty, and reflection is false.',
    ),
    technologies: z.array(TechDetectionSchema).describe('Technology detections with evidence.'),
    checkedAt: z.string().describe('ISO 8601 timestamp of the probe.'),
    bodyInspection: z
      .object({
        status: z
          .enum(['complete', 'limited', 'failed', 'not_read'])
          .describe('Observed EOF, prefix cap reached, body failure, or no final response.'),
        error: z.string().nullable().describe('Body inspection failure reason, or null.'),
      })
      .describe('Body inspection completeness; limited does not imply EOF.'),
    transportError: z
      .string()
      .nullable()
      .describe('Transport error, including redirect exhaustion, or null on success.'),
  }),
  enrichment: {
    notice: z.string().optional().describe('Guidance when the probe could not reach the target.'),
  },
  errors: [
    {
      reason: 'invalid_url',
      code: JsonRpcErrorCode.ValidationError,
      when: 'The supplied value cannot be parsed as an absolute URL.',
      recovery: 'Provide an absolute HTTP(S) URL, such as https://example.com.',
    },
    {
      reason: 'blocked_target',
      code: JsonRpcErrorCode.Forbidden,
      when: 'The URL resolves to a private/loopback/metadata address, or uses a non-http(s) scheme.',
      recovery:
        'Probe only public http(s) URLs. Internal targets require ATTACKSURFACE_ALLOW_PRIVATE_TARGETS=true.',
    },
  ],

  async handler(input, ctx) {
    if (!URL.canParse(input.url)) {
      throw ctx.fail('invalid_url', 'The supplied value is not an absolute URL.');
    }
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
    lines.push(`## ${literalText(result.url)}`);
    lines.push(`**Error:** ${literalText(result.transportError ?? 'none')}`);
    lines.push(
      `**Final status:** ${result.finalStatus} | **Final URL:** ${literalText(result.finalUrl)}`,
    );
    lines.push(
      `**Body inspection:** ${result.bodyInspection.status} (${literalText(result.bodyInspection.error ?? 'no error')})`,
    );
    lines.push('**Redirect chain:**');
    if (result.redirectChain.length === 0) lines.push('- (none)');
    for (const hop of result.redirectChain) {
      lines.push(
        `- ${hop.status} ${literalText(hop.url)} → ${literalText(hop.location ?? '(no location)')}`,
      );
    }

    const a = result.securityAudit;
    const observed = result.transportError === null;
    const missingHeader = observed ? 'absent' : 'not observed';
    lines.push('### Security headers');
    lines.push(`- **HSTS:** ${literalText(a.hsts ?? missingHeader)}`);
    lines.push(`- **CSP:** ${literalText(a.csp ?? missingHeader)}`);
    lines.push(`- **X-Frame-Options:** ${literalText(a.xFrameOptions ?? missingHeader)}`);
    lines.push(
      `- **X-Content-Type-Options:** ${literalText(a.xContentTypeOptions ?? missingHeader)}`,
    );
    lines.push(`- **Referrer-Policy:** ${literalText(a.referrerPolicy ?? missingHeader)}`);
    lines.push(`- **Permissions-Policy:** ${literalText(a.permissionsPolicy ?? missingHeader)}`);
    lines.push(
      `- **CORS Allow-Origin:** ${literalText(a.corsAllowOrigin ?? missingHeader)} (reflects probe origin: ${observed ? a.corsReflectsOrigin : 'not observed'})`,
    );
    lines.push(
      `- **CORS Allow-Credentials:** ${literalText(a.corsAllowCredentials ?? missingHeader)}`,
    );
    lines.push('- **Cookies:**');
    if (a.cookies.length === 0) lines.push(observed ? '  - (none)' : '  - (not observed)');
    for (const c of a.cookies) {
      lines.push(
        `  - ${literalText(c.name)}: Secure=${c.secure}, HttpOnly=${c.httpOnly}, SameSite=${literalText(c.sameSite ?? 'none')}`,
      );
    }
    lines.push('**Findings:**');
    if (a.findings.length === 0) lines.push(observed ? '- (none)' : '- (not observed)');
    for (const f of a.findings) lines.push(`- ${literalText(f)}`);

    lines.push('### Technology fingerprint');
    if (result.technologies.length === 0)
      lines.push(observed ? '- (none detected)' : '- (not observed)');
    for (const t of result.technologies) {
      lines.push(
        `- ${literalText(t.name)} ${t.version === undefined ? '' : literalText(t.version)} _(${t.category})_ — ${literalText(t.evidence)}`,
      );
    }

    const headerLines: string[] = [];
    for (const name in result.headers) {
      if (Object.hasOwn(result.headers, name)) {
        const value = result.headers[name];
        if (value !== undefined) headerLines.push(`- ${literalText(name)}: ${literalText(value)}`);
      }
    }
    lines.push(`### Response headers (${headerLines.length})`);
    if (!observed) lines.push('- (not observed)');
    for (const line of headerLines) lines.push(line);

    lines.push(`Checked at ${literalText(result.checkedAt)}`);
    return [{ type: 'text', text: lines.join('\n') }];
  },
});
