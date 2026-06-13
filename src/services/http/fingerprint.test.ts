/**
 * @fileoverview Tests for the technology fingerprint ruleset — header and body detections each carry
 * their triggering evidence; no detections are invented from absent data.
 * @module services/http/fingerprint.test
 */

import { describe, expect, it } from 'vitest';
import { fingerprint } from './fingerprint.js';

describe('fingerprint', () => {
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

  it('detects WordPress from a body generator marker with version', () => {
    const body = '<meta name="generator" content="WordPress 6.5.2" />';
    const hits = fingerprint({}, body);
    const wp = hits.find((h) => h.name === 'WordPress');
    expect(wp?.category).toBe('cms');
    expect(wp?.version).toBe('6.5.2');
    expect(wp?.evidence).toContain('body marker');
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
