/**
 * @fileoverview HTTP probe domain types — redirect chain, security-header audit, tech fingerprint.
 * @module services/http/types
 */

/** One hop in a redirect chain. */
export interface RedirectHop {
  /** Location header value that drove the next hop, when present. */
  location?: string;
  /** HTTP status returned. */
  status: number;
  /** URL requested at this hop. */
  url: string;
}

/** A single technology detection with the evidence that triggered it (no fabricated confidence). */
export interface TechDetection {
  /** Category: server, framework, cdn, waf, cms, language, analytics, other. */
  category: 'server' | 'framework' | 'cdn' | 'waf' | 'cms' | 'language' | 'analytics' | 'other';
  /** The concrete evidence (header name/value or body marker) that triggered the detection. */
  evidence: string;
  /** Detected technology or product name. */
  name: string;
  /** Version string when disclosed by the evidence. */
  version?: string;
}

/** Result of the security-header audit. */
export interface SecurityHeaderAudit {
  /** Set-Cookie flags audit, one entry per cookie. */
  cookies: CookieAudit[];
  /** Access-Control-Allow-Origin value, or null when absent. */
  corsAllowOrigin: string | null;
  /** True when the server reflected an arbitrary Origin into ACAO (potential misconfiguration). */
  corsReflectsOrigin: boolean;
  /** Content-Security-Policy value, or null when absent. */
  csp: string | null;
  /** Human-readable findings for missing/weak headers. */
  findings: string[];
  /** HSTS (Strict-Transport-Security) header value, or null when absent. */
  hsts: string | null;
  /** Permissions-Policy value, or null when absent. */
  permissionsPolicy: string | null;
  /** Referrer-Policy value, or null when absent. */
  referrerPolicy: string | null;
  /** X-Content-Type-Options value, or null when absent. */
  xContentTypeOptions: string | null;
  /** X-Frame-Options value, or null when absent. */
  xFrameOptions: string | null;
}

/** Audit of one Set-Cookie header's security flags. */
export interface CookieAudit {
  /** Whether the HttpOnly flag is set. */
  httpOnly: boolean;
  /** Cookie name. */
  name: string;
  /** SameSite attribute value, or null when absent. */
  sameSite: string | null;
  /** Whether the Secure flag is set. */
  secure: boolean;
}

/** Full HTTP probe result for one URL. */
export interface HttpProbeResult {
  /** ISO 8601 timestamp of the probe. */
  checkedAt: string;
  /** Final HTTP status code. */
  finalStatus: number;
  /** Final URL after following redirects. */
  finalUrl: string;
  /** Final-response headers as a flat record (lower-cased keys). */
  headers: Record<string, string>;
  /** Redirect chain leading to the final response (empty when no redirects). */
  redirectChain: RedirectHop[];
  /** Security-header audit. */
  securityAudit: SecurityHeaderAudit;
  /** Technology fingerprint detections, each with its triggering evidence. */
  technologies: TechDetection[];
  /** Connection/transport error message, or null on success. */
  transportError: string | null;
  /** URL probed (the initial request URL). */
  url: string;
}
