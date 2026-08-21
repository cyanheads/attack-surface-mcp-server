/**
 * @fileoverview HTTP probe service — a single passive GET per URL, following redirects manually so
 * the full chain and any status (including non-2xx) are captured as posture data, not errors. Audits
 * security headers (HSTS/CSP/X-Frame-Options/cookie flags/CORS reflection) and runs an
 * evidence-bound tech fingerprint. One request per host: no path traversal, no parameter injection,
 * no multi-method probing. Every hop is SSRF-guarded via `assertSafeUrl`.
 * @module services/http/http-service
 */

import type { Context } from '@cyanheads/mcp-ts-core';
import { assertSafeUrl } from '@/utils/ssrf-guard.js';
import { fingerprint } from './fingerprint.js';
import type { CookieAudit, HttpProbeResult, RedirectHop, SecurityHeaderAudit } from './types.js';

const MAX_REDIRECTS = 10;
const BODY_PREFIX_BYTES = 64_000;
/** A throwaway origin used to test whether the server reflects an arbitrary Origin into CORS. */
const CORS_PROBE_ORIGIN = 'https://attack-surface-probe.example';

/** Flatten Headers into a lower-cased record (multi-value headers joined with ", "). */
function headersToRecord(headers: Headers): Record<string, string> {
  const out: Record<string, string> = {};
  headers.forEach((value, key) => {
    out[key.toLowerCase()] = value;
  });
  return out;
}

/** Collect all Set-Cookie values (Headers.getSetCookie preserves individual cookies). */
function auditCookies(headers: Headers): CookieAudit[] {
  const raw = typeof headers.getSetCookie === 'function' ? headers.getSetCookie() : [];
  return raw.map((cookie) => {
    const firstPair = cookie.split(';')[0] ?? '';
    const name = firstPair.split('=')[0]?.trim() ?? '';
    const sameSiteMatch = /;\s*samesite=([^;]+)/i.exec(cookie);
    return {
      name,
      secure: /;\s*secure/i.test(cookie),
      httpOnly: /;\s*httponly/i.test(cookie),
      sameSite: sameSiteMatch?.[1]?.trim() ?? null,
    };
  });
}

/** Build the security-header audit from the final response. */
function auditSecurity(
  headers: Record<string, string>,
  cookies: CookieAudit[],
  isHttps: boolean,
  corsReflectsOrigin: boolean,
): SecurityHeaderAudit {
  const findings: string[] = [];
  const hsts = headers['strict-transport-security'] ?? null;
  const csp = headers['content-security-policy'] ?? null;
  const xFrameOptions = headers['x-frame-options'] ?? null;
  const xContentTypeOptions = headers['x-content-type-options'] ?? null;
  const referrerPolicy = headers['referrer-policy'] ?? null;
  const permissionsPolicy = headers['permissions-policy'] ?? null;
  const corsAllowOrigin = headers['access-control-allow-origin'] ?? null;

  if (isHttps && !hsts) findings.push('HSTS (Strict-Transport-Security) is not set.');
  if (!csp) findings.push('Content-Security-Policy is not set.');
  if (!xFrameOptions && !(csp && /frame-ancestors/i.test(csp))) {
    findings.push('No clickjacking protection (X-Frame-Options or CSP frame-ancestors).');
  }
  if (!xContentTypeOptions) findings.push('X-Content-Type-Options: nosniff is not set.');
  if (corsAllowOrigin === '*') {
    findings.push('CORS allows any origin (Access-Control-Allow-Origin: *).');
  }
  if (corsReflectsOrigin) {
    findings.push(
      'CORS reflects an arbitrary request Origin — combined with credentials this is exploitable.',
    );
  }
  for (const c of cookies) {
    if (!c.secure && isHttps) findings.push(`Cookie "${c.name}" is missing the Secure flag.`);
    if (!c.httpOnly) findings.push(`Cookie "${c.name}" is missing the HttpOnly flag.`);
    if (!c.sameSite) findings.push(`Cookie "${c.name}" has no SameSite attribute.`);
  }

  return {
    hsts,
    csp,
    xFrameOptions,
    xContentTypeOptions,
    referrerPolicy,
    permissionsPolicy,
    cookies,
    corsAllowOrigin,
    corsReflectsOrigin,
    findings,
  };
}

export class HttpService {
  constructor(private readonly defaultUserAgent: string) {}

  /**
   * Probe a single URL with one passive GET, following redirects manually. The chain and any status
   * are captured; non-2xx responses are posture data, not errors. SSRF-guarded per hop.
   */
  async probe(
    rawUrl: string,
    userAgent: string | undefined,
    timeoutMs: number,
    ctx: Context,
  ): Promise<HttpProbeResult> {
    const checkedAt = new Date().toISOString();
    const ua = userAgent?.trim() || this.defaultUserAgent;
    const redirectChain: RedirectHop[] = [];

    let currentUrl = rawUrl;
    let finalResponse: Response | undefined;

    try {
      for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
        // SSRF guard on every hop target (also validates http/https scheme).
        await assertSafeUrl(currentUrl);

        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), timeoutMs);
        const composite = ctx.signal
          ? AbortSignal.any([controller.signal, ctx.signal])
          : controller.signal;

        let response: Response;
        try {
          response = await fetch(currentUrl, {
            method: 'GET',
            redirect: 'manual',
            signal: composite,
            headers: {
              'user-agent': ua,
              accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
              origin: CORS_PROBE_ORIGIN,
            },
          });
        } finally {
          clearTimeout(timer);
        }

        const status = response.status;
        const location = response.headers.get('location');
        const isRedirect = status >= 300 && status < 400 && location;

        if (isRedirect && hop < MAX_REDIRECTS) {
          redirectChain.push({ url: currentUrl, status, location });
          // Resolve relative redirects against the current URL.
          currentUrl = new URL(location, currentUrl).toString();
          // Drain the body so the socket can be reused/closed.
          await response.body?.cancel().catch(() => {});
          continue;
        }

        finalResponse = response;
        break;
      }
    } catch (err) {
      return {
        url: rawUrl,
        finalUrl: currentUrl,
        finalStatus: 0,
        redirectChain,
        headers: {},
        securityAudit: auditSecurity({}, [], false, false),
        technologies: [],
        checkedAt,
        transportError: err instanceof Error ? err.message : String(err),
      };
    }

    if (!finalResponse) {
      return {
        url: rawUrl,
        finalUrl: currentUrl,
        finalStatus: 0,
        redirectChain,
        headers: {},
        securityAudit: auditSecurity({}, [], false, false),
        technologies: [],
        checkedAt,
        transportError: `Exceeded ${MAX_REDIRECTS} redirects without a final response.`,
      };
    }

    const headers = headersToRecord(finalResponse.headers);
    const cookies = auditCookies(finalResponse.headers);
    const isHttps = new URL(currentUrl).protocol === 'https:';
    const corsReflectsOrigin = headers['access-control-allow-origin'] === CORS_PROBE_ORIGIN;
    const securityAudit = auditSecurity(headers, cookies, isHttps, corsReflectsOrigin);

    // Read a bounded body prefix for body-marker fingerprinting.
    let bodyPrefix = '';
    try {
      const buf = await this.readBounded(finalResponse, BODY_PREFIX_BYTES);
      bodyPrefix = buf;
    } catch {
      // Body read failures don't invalidate header-level findings.
    }

    const technologies = fingerprint(headers, bodyPrefix);

    ctx.log.debug('HTTP probe complete', {
      url: rawUrl,
      finalStatus: finalResponse.status,
      redirects: redirectChain.length,
      techCount: technologies.length,
    });

    return {
      url: rawUrl,
      finalUrl: currentUrl,
      finalStatus: finalResponse.status,
      redirectChain,
      headers,
      securityAudit,
      technologies,
      checkedAt,
      transportError: null,
    };
  }

  /** Read up to `maxBytes` of the response body as UTF-8, then abort the stream. */
  private async readBounded(response: Response, maxBytes: number): Promise<string> {
    if (!response.body) return '';
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    try {
      while (total < maxBytes) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value) {
          chunks.push(value);
          total += value.byteLength;
        }
      }
    } finally {
      await reader.cancel().catch(() => {});
    }
    const merged = new Uint8Array(total);
    let offset = 0;
    for (const c of chunks) {
      merged.set(c.subarray(0, Math.min(c.byteLength, maxBytes - offset)), offset);
      offset += c.byteLength;
      if (offset >= maxBytes) break;
    }
    return new TextDecoder('utf-8', { fatal: false }).decode(merged.subarray(0, maxBytes));
  }
}

// --- Init/accessor pattern ---

let _service: HttpService | undefined;

export function initHttpService(userAgent: string): void {
  _service = new HttpService(userAgent);
}

export function getHttpService(): HttpService {
  if (!_service) throw new Error('HttpService not initialized — call initHttpService() in setup()');
  return _service;
}
