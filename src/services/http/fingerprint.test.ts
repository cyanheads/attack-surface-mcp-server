/**
 * @fileoverview Tests for the technology fingerprint ruleset — header and body detections each carry
 * their triggering evidence; no detections are invented from absent data.
 * @module services/http/fingerprint.test
 */

import { describe, expect, it } from 'vitest';
import { fingerprint } from './fingerprint.js';

describe('fingerprint', () => {
  it.each([
    ['cloudflare', 'Cloudflare', 'cdn'],
    ['CloudFlare', 'Cloudflare', 'cdn'],
    ['awselb/2.0', 'AWS ELB', 'other'],
    ['AWSELB/2.0', 'AWS ELB', 'other'],
  ])('classifies the %s banner once without inferring a WAF', (server, name, category) => {
    expect(fingerprint({ server }, '')).toEqual([
      { name, category, evidence: `server: ${server}` },
    ]);
  });

  it('deduplicates Cloudflare banner and cf-ray CDN evidence', () => {
    expect(fingerprint({ server: 'cloudflare', 'cf-ray': 'abc-SEA' }, '')).toEqual([
      { name: 'Cloudflare', category: 'cdn', evidence: 'server: cloudflare' },
    ]);
  });

  it('detects a server from the Server header with version and evidence', () => {
    const hits = fingerprint({ server: 'nginx/1.25.3' }, '');
    const nginx = hits.find((h) => h.name === 'nginx');
    expect(nginx).toBeDefined();
    expect(nginx?.category).toBe('server');
    expect(nginx?.version).toBe('1.25.3');
    expect(nginx?.evidence).toContain('server: nginx/1.25.3');
  });

  it('detects Cloudflare from cf-ray', () => {
    const hits = fingerprint({ 'cf-ray': '8abc123-SEA' }, '');
    expect(hits.some((h) => h.name === 'Cloudflare' && h.category === 'cdn')).toBe(true);
  });

  it('keeps independent WAF evidence and category-aware deduplication', () => {
    expect(
      fingerprint(
        {
          server: 'Apache/2.4.62',
          'x-amzn-waf-action': 'allow',
          'x-sucuri-id': '123',
          'x-sucuri-cache': 'HIT',
        },
        '',
      ),
    ).toEqual([
      { name: 'Apache', category: 'server', version: '2.4.62', evidence: 'server: Apache/2.4.62' },
      { name: 'Sucuri WAF', category: 'waf', evidence: 'x-sucuri-id: 123' },
      { name: 'AWS WAF', category: 'waf', evidence: 'x-amzn-waf-action: allow' },
    ]);
    expect(
      fingerprint({ server: 'Drupal', 'x-drupal-cache': 'HIT' }, '').map(
        ({ category }) => category,
      ),
    ).toEqual(['server', 'cms']);
  });

  it('detects WordPress from a body generator marker with version', () => {
    const body = '<meta name="generator" content="WordPress 6.5.2" />';
    const hits = fingerprint({}, body);
    const wp = hits.find((h) => h.name === 'WordPress');
    expect(wp?.category).toBe('cms');
    expect(wp?.version).toBe('6.5.2');
    expect(wp?.evidence).toContain('body marker');
  });

  it.each([
    ['WordPress', '<meta name="generator" content="WordPress.com" />'],
    ['Drupal', '<meta name="generator" content="Drupal.org" />'],
  ])('omits version when %s generator marker carries a bare dot', (name, body) => {
    const hits = fingerprint({}, body);
    const hit = hits.find((h) => h.name === name);
    expect(hit).toBeDefined();
    expect(hit?.version).toBeUndefined();
  });

  it('detects Angular from a body marker with its version', () => {
    expect(fingerprint({}, '<app-root ng-version="21.0.1">')).toEqual([
      {
        name: 'Angular',
        category: 'framework',
        version: '21.0.1',
        evidence: 'body marker: ng-version="21.0.1"',
      },
    ]);
  });

  it.each([
    ['WordPress', '6.8.3'],
    ['Drupal', '10.5.2'],
  ])('uses the first %s generator marker for both version and evidence', (name, version) => {
    const prose = `<title>${name} 4.0 migration notes</title>`;
    const versioned = `<meta name="generator" content="${name} ${version}">`;
    const versionless = `<meta name="generator" content="${name}">`;
    expect(fingerprint({}, prose + versioned)).toEqual([
      { name, category: 'cms', version, evidence: `body marker: ${versioned.slice(0, -2)}` },
    ]);
    expect(fingerprint({}, versionless + prose + versioned)).toEqual([
      { name, category: 'cms', evidence: `body marker: ${versionless.slice(0, -2)}` },
    ]);
    expect(fingerprint({}, prose)).toEqual([]);
  });

  it('detects Next.js from a body marker', () => {
    const hits = fingerprint({}, '<script id="__NEXT_DATA__">{}</script>');
    expect(hits.some((h) => h.name === 'Next.js')).toBe(true);
  });

  it('returns nothing for an empty/unremarkable response (no fabricated detections)', () => {
    expect(fingerprint({}, '<html><body>hello</body></html>')).toEqual([]);
  });

  it('deduplicates the same technology seen via header and body', () => {
    const hits = fingerprint(
      { 'x-drupal-cache': 'HIT' },
      '<meta name="generator" content="Drupal 10" />',
    );
    expect(hits.filter((h) => h.name === 'Drupal')).toHaveLength(1);
  });
});
