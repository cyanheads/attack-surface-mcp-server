/**
 * @fileoverview Technology fingerprint ruleset. Each detection reports the concrete evidence
 * (header name/value or body marker) that triggered it — no fabricated confidence composites.
 * Passive: reads only the target's own single published response.
 * @module services/http/fingerprint
 */

import type { TechDetection } from './types.js';

/** A header-based fingerprint rule. */
interface HeaderRule {
  category: TechDetection['category'];
  header: string;
  /** When set, the header value must match this pattern. */
  match?: RegExp;
  name: string | ((value: string) => string);
  /** Optional capture of a version from the header value. */
  version?: RegExp;
}

/** A body-marker fingerprint rule (applied to a bounded prefix of the body). */
interface BodyRule {
  category: TechDetection['category'];
  marker: RegExp;
  name: string;
  version?: RegExp;
}

const HEADER_RULES: HeaderRule[] = [
  {
    header: 'server',
    name: (v) => v.split('/')[0] ?? v,
    category: 'server',
    version: /[\w-]+\/([\d.]+)/,
  },
  { header: 'x-powered-by', name: (v) => v, category: 'framework', version: /[\w-]+\/([\d.]+)/ },
  { header: 'x-aspnet-version', name: 'ASP.NET', category: 'framework', version: /([\d.]+)/ },
  {
    header: 'x-aspnetmvc-version',
    name: 'ASP.NET MVC',
    category: 'framework',
    version: /([\d.]+)/,
  },
  { header: 'x-generator', name: (v) => v, category: 'cms', version: /([\d.]+)/ },
  // CDNs
  { header: 'cf-ray', name: 'Cloudflare', category: 'cdn' },
  { header: 'x-amz-cf-id', name: 'Amazon CloudFront', category: 'cdn' },
  { header: 'x-amz-cf-pop', name: 'Amazon CloudFront', category: 'cdn' },
  { header: 'x-fastly-request-id', name: 'Fastly', category: 'cdn' },
  { header: 'x-served-by', match: /cache-/, name: 'Fastly', category: 'cdn' },
  { header: 'x-akamai-transformed', name: 'Akamai', category: 'cdn' },
  {
    header: 'x-cache',
    match: /(cloudfront|varnish)/i,
    name: (v) => (/cloudfront/i.test(v) ? 'Amazon CloudFront' : 'Varnish'),
    category: 'cdn',
  },
  { header: 'x-vercel-id', name: 'Vercel', category: 'cdn' },
  { header: 'x-nf-request-id', name: 'Netlify', category: 'cdn' },
  // WAFs
  { header: 'server', match: /cloudflare/i, name: 'Cloudflare', category: 'waf' },
  { header: 'x-sucuri-id', name: 'Sucuri WAF', category: 'waf' },
  { header: 'x-sucuri-cache', name: 'Sucuri WAF', category: 'waf' },
  { header: 'server', match: /awselb/i, name: 'AWS ELB', category: 'waf' },
  { header: 'x-amzn-waf-action', name: 'AWS WAF', category: 'waf' },
  // Frameworks / languages
  { header: 'x-drupal-cache', name: 'Drupal', category: 'cms' },
  { header: 'x-drupal-dynamic-cache', name: 'Drupal', category: 'cms' },
  { header: 'x-shopify-stage', name: 'Shopify', category: 'cms' },
  { header: 'x-runtime', name: 'Ruby on Rails', category: 'framework' },
  { header: 'x-turbo-charged-by', name: (v) => v, category: 'framework' },
];

const BODY_RULES: BodyRule[] = [
  {
    marker: /<meta[^>]+name=["']generator["'][^>]+content=["']WordPress\s*([\d.]+)?/i,
    name: 'WordPress',
    category: 'cms',
    version: /WordPress\s*([\d.]+)/i,
  },
  { marker: /\/wp-(content|includes)\//i, name: 'WordPress', category: 'cms' },
  {
    marker: /<meta[^>]+name=["']generator["'][^>]+content=["']Drupal\s*([\d.]+)?/i,
    name: 'Drupal',
    category: 'cms',
    version: /Drupal\s*([\d.]+)/i,
  },
  {
    marker: /<meta[^>]+name=["']generator["'][^>]+content=["']Joomla/i,
    name: 'Joomla',
    category: 'cms',
  },
  { marker: /__NEXT_DATA__/i, name: 'Next.js', category: 'framework' },
  { marker: /<div[^>]+id=["']__nuxt["']/i, name: 'Nuxt', category: 'framework' },
  {
    marker: /ng-version=["']([\d.]+)["']/i,
    name: 'Angular',
    category: 'framework',
    version: /ng-version=["']([\d.]+)["']/i,
  },
  {
    marker: /data-reactroot|react(?:-dom)?\.production\.min\.js/i,
    name: 'React',
    category: 'framework',
  },
  { marker: /<!--\s*Shopify/i, name: 'Shopify', category: 'cms' },
];

/** Extract a version using a regex against a value, returning undefined when no capture. */
function extractVersion(value: string, re?: RegExp): string | undefined {
  if (!re) return;
  const m = re.exec(value);
  return m?.[1];
}

/**
 * Run the fingerprint ruleset against response headers and a bounded body prefix.
 * Returns deduplicated detections (by name+category), each carrying its triggering evidence.
 */
export function fingerprint(headers: Record<string, string>, bodyPrefix: string): TechDetection[] {
  const detections: TechDetection[] = [];
  const seen = new Set<string>();

  const add = (d: TechDetection) => {
    const key = `${d.category}:${d.name.toLowerCase()}`;
    if (seen.has(key)) return;
    seen.add(key);
    detections.push(d);
  };

  for (const rule of HEADER_RULES) {
    const value = headers[rule.header];
    if (value === undefined) continue;
    if (rule.match && !rule.match.test(value)) continue;
    const name = typeof rule.name === 'function' ? rule.name(value) : rule.name;
    if (!name) continue;
    const version = extractVersion(value, rule.version);
    add({
      name,
      category: rule.category,
      ...(version ? { version } : {}),
      evidence: `${rule.header}: ${value}`,
    });
  }

  for (const rule of BODY_RULES) {
    if (!rule.marker.test(bodyPrefix)) continue;
    const matched = rule.marker.exec(bodyPrefix)?.[0] ?? rule.marker.source;
    const version = extractVersion(bodyPrefix, rule.version);
    add({
      name: rule.name,
      category: rule.category,
      ...(version ? { version } : {}),
      evidence: `body marker: ${matched.slice(0, 80)}`,
    });
  }

  return detections;
}
