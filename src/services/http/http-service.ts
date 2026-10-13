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

/** Race a pending I/O operation against the probe budget, removing the listener on settlement. */
async function withinBudget<T>(operation: Promise<T>, signal: AbortSignal): Promise<T> {
  let abort!: () => void;
  try {
    return await Promise.race([
      operation,
      new Promise<never>((_resolve, reject) => {
        abort = () => reject(signal.reason);
        signal.addEventListener('abort', abort, { once: true });
        if (signal.aborted) abort();
      }),
    ]);
  } finally {
    signal.removeEventListener('abort', abort);
  }
}

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
    const [firstPair = '', ...attributes] = cookie.split(';');
    const name = firstPair.split('=')[0]?.trim() ?? '';
    let secure = false;
    let httpOnly = false;
    let sameSite: string | null = null;
    for (const attribute of attributes) {
      const equals = attribute.indexOf('=');
      const key = (equals < 0 ? attribute : attribute.slice(0, equals)).trim().toLowerCase();
      const value = equals < 0 ? '' : attribute.slice(equals + 1).trim();
      if (key === 'secure') secure = true;
      if (key === 'httponly') httpOnly = true;
      if (key === 'samesite') {
        const key = value.toLowerCase();
        const recognized =
          key === 'strict' ? 'Strict' : key === 'lax' ? 'Lax' : key === 'none' ? 'None' : undefined;
        sameSite = recognized ?? value;
      }
    }
    return {
      name,
      secure,
      httpOnly,
      sameSite,
    };
  });
}

/** Parse the selected HSTS semantics; unknown directives must still have valid HTTP syntax. */
function effectiveHsts(raw: string): boolean {
  const directives: string[] = [];
  let start = 0;
  let quoted = false;
  let escaped = false;
  for (let i = 0; i < raw.length; i++) {
    const char = raw[i];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (quoted && char === '\\') {
      escaped = true;
      continue;
    }
    if (char === '"') quoted = !quoted;
    if (!quoted && char === ';') {
      directives.push(raw.slice(start, i));
      start = i + 1;
    }
  }
  if (quoted || escaped) return false;
  directives.push(raw.slice(start));
  const names = new Set<string>();
  let positiveAge = false;
  const token = /^[!#$%&'*+.^_`|~0-9a-z-]+$/i;
  for (const directive of directives) {
    if (!directive.trim()) continue;
    const equals = directive.indexOf('=');
    const name = (equals < 0 ? directive : directive.slice(0, equals)).trim().toLowerCase();
    if (!token.test(name) || names.has(name)) return false;
    names.add(name);
    const value = equals < 0 ? null : directive.slice(equals + 1).trim();
    if (value !== null && !token.test(value)) {
      if (!value.startsWith('"') || !value.endsWith('"')) return false;
      for (let i = 1; i < value.length - 1; i++) {
        const code = value.charCodeAt(i);
        if (value[i] === '\\') {
          i++;
          if (i >= value.length - 1) return false;
          const escapedCode = value.charCodeAt(i);
          if (escapedCode !== 9 && (escapedCode < 32 || escapedCode > 126)) return false;
        } else if (value[i] === '"' || (code !== 9 && (code < 32 || code > 126))) return false;
      }
    }
    if (name === 'max-age') {
      const digits = value?.startsWith('"') ? value.slice(1, -1) : value;
      positiveAge =
        digits !== null && digits !== undefined && /^\d+$/.test(digits) && /[1-9]/.test(digits);
    }
    if (name === 'includesubdomains' && value !== null) return false;
  }
  return positiveAge;
}

/** Inspect framing directives only; this does not validate the overall CSP policy. */
function framingCsp(raw: string): { restricted: boolean; unknown: boolean } {
  let restricted = false;
  let unknown = false;
  for (const policy of raw.split(',')) {
    const seen = new Set<string>();
    for (const directive of policy.split(';')) {
      const [name = '', ...sources] = directive.trim().split(/\s+/);
      const key = name.toLowerCase();
      if (seen.has(key)) continue;
      seen.add(key);
      if (key !== 'frame-ancestors') continue;
      const recognized = sources.every(
        (source) =>
          source === "'self'" ||
          source === "'none'" ||
          source === '*' ||
          /^[a-z][a-z0-9+.-]*:$/i.test(source) ||
          /^(?:[a-z][a-z0-9+.-]*:\/\/)?(?:\*\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)*(?::(?:[0-9]+|\*))?(?:\/[^\s]*)?$/i.test(
            source,
          ),
      );
      if (!recognized) unknown = true;
      else if (!sources.includes('*')) restricted = true;
    }
  }
  return { restricted, unknown };
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
  else if (isHttps && hsts && !effectiveHsts(hsts))
    findings.push('HSTS does not contain a valid positive max-age policy.');
  if (!csp) findings.push('Content-Security-Policy is not set.');
  const frameTokens = xFrameOptions?.split(',').map((value) => value.trim().toUpperCase()) ?? [];
  const effectiveXfo =
    frameTokens.length > 0 &&
    frameTokens.every(
      (value) => value === frameTokens[0] && (value === 'DENY' || value === 'SAMEORIGIN'),
    );
  if (xFrameOptions && !effectiveXfo)
    findings.push('X-Frame-Options value is unsupported or conflicting.');
  const framePolicy = csp ? framingCsp(csp) : { restricted: false, unknown: false };
  if (framePolicy.unknown)
    findings.push(
      'Unrecognized CSP frame-ancestors source syntax; framing protection could not be confirmed for that policy.',
    );
  if (!effectiveXfo && !framePolicy.restricted) {
    findings.push('No clickjacking protection (X-Frame-Options or CSP frame-ancestors).');
  }
  if (xContentTypeOptions?.split(',')[0]?.trim().toLowerCase() !== 'nosniff')
    findings.push('X-Content-Type-Options: nosniff is not set.');
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
    if (c.sameSite === null) findings.push(`Cookie "${c.name}" has no SameSite attribute.`);
    else if (!['Strict', 'Lax', 'None'].includes(c.sameSite))
      findings.push(
        `Cookie "${c.name}" has an invalid SameSite value; browsers use their default policy.`,
      );
    if (c.sameSite === 'None' && !c.secure)
      findings.push(
        `Cookie "${c.name}" uses SameSite=None without Secure; modern browsers reject it.`,
      );
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

    ctx.signal?.throwIfAborted();
    const controller = new AbortController();
    const timer = setTimeout(
      () => controller.abort(new DOMException('The operation was aborted', 'TimeoutError')),
      timeoutMs,
    );
    const signal = ctx.signal
      ? AbortSignal.any([controller.signal, ctx.signal])
      : controller.signal;

    try {
      try {
        for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
          // SSRF guard on every hop target (also validates http/https scheme).
          await assertSafeUrl(currentUrl, signal);
          signal.throwIfAborted();
          const response = await withinBudget(
            fetch(currentUrl, {
              method: 'GET',
              redirect: 'manual',
              signal,
              headers: {
                'user-agent': ua,
                accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                origin: CORS_PROBE_ORIGIN,
              },
            }),
            signal,
          );

          const status = response.status;
          const location = response.headers.get('location');
          const isRedirect = status >= 300 && status < 400 && location;

          if (isRedirect) {
            // Release every redirect body, including the response that exhausts the hop limit.
            void response.body?.cancel().catch(() => {});
            if (hop === MAX_REDIRECTS) break;
            redirectChain.push({ url: currentUrl, status, location });
            // Resolve relative redirects against the current URL.
            currentUrl = new URL(location, currentUrl).toString();
            continue;
          }

          finalResponse = response;
          break;
        }
      } catch (err) {
        ctx.signal?.throwIfAborted();
        return {
          url: rawUrl,
          finalUrl: currentUrl,
          finalStatus: 0,
          redirectChain,
          headers: {},
          securityAudit: auditSecurity({}, [], false, false),
          technologies: [],
          bodyInspection: { status: 'not_read', error: null },
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
          bodyInspection: { status: 'not_read', error: null },
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
      let bodyInspection: HttpProbeResult['bodyInspection'];
      try {
        const body = await this.readBounded(finalResponse, BODY_PREFIX_BYTES, signal);
        bodyPrefix = body.text;
        bodyInspection = { status: body.status, error: null };
      } catch (err) {
        ctx.signal?.throwIfAborted();
        bodyInspection = {
          status: 'failed',
          error: err instanceof Error ? err.message : String(err),
        };
      }

      const technologies = fingerprint(headers, bodyPrefix);
      ctx.signal?.throwIfAborted();

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
        bodyInspection,
        checkedAt,
        transportError: null,
      };
    } finally {
      clearTimeout(timer);
    }
  }

  /** Read up to `maxBytes` of the response body as UTF-8, then abort the stream. */
  private async readBounded(
    response: Response,
    maxBytes: number,
    signal: AbortSignal,
  ): Promise<{ text: string; status: 'complete' | 'limited' }> {
    if (!response.body) {
      signal.throwIfAborted();
      return { text: '', status: 'complete' };
    }
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    let status: 'complete' | 'limited' = 'limited';
    try {
      while (total < maxBytes) {
        signal.throwIfAborted();
        const { done, value } = await withinBudget(reader.read(), signal);
        if (done) {
          status = 'complete';
          break;
        }
        if (value) {
          const bounded = value.subarray(0, maxBytes - total);
          chunks.push(bounded);
          total += bounded.byteLength;
        }
      }
    } finally {
      void reader.cancel().catch(() => {});
      reader.releaseLock();
    }
    const merged = new Uint8Array(total);
    let offset = 0;
    for (const c of chunks) {
      merged.set(c, offset);
      offset += c.byteLength;
    }
    return { text: new TextDecoder('utf-8', { fatal: false }).decode(merged), status };
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
