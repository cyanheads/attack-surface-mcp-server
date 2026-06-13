/**
 * @fileoverview Tests for edge input validation — domain/host/registration-target shapes and
 * domain normalization.
 * @module utils/validation.test
 */

import { describe, expect, it } from 'vitest';
import {
  isValidDomain,
  isValidHost,
  isValidRegistrationTarget,
  normalizeDomain,
} from './validation.js';

describe('isValidDomain', () => {
  it('accepts registrable domains and subdomains', () => {
    for (const d of [
      'example.com',
      'www.example.com',
      'a.b.c.example.co.uk',
      'xn--bcher-kva.com',
    ]) {
      expect(isValidDomain(d), d).toBe(true);
    }
  });
  it('rejects non-domains', () => {
    for (const d of [
      '',
      'example',
      'http://example.com',
      '192.168.1.1',
      'foo .com',
      '*.example.com',
    ]) {
      expect(isValidDomain(d), d).toBe(false);
    }
  });
});

describe('isValidHost', () => {
  it('accepts hostnames and IP literals', () => {
    for (const h of ['example.com', '8.8.8.8', '2606:4700:4700::1111']) {
      expect(isValidHost(h), h).toBe(true);
    }
  });
  it('rejects empty and garbage', () => {
    expect(isValidHost('')).toBe(false);
    expect(isValidHost('has space')).toBe(false);
  });
});

describe('isValidRegistrationTarget', () => {
  it('accepts domains, IPs, and CIDRs', () => {
    for (const t of ['example.com', '8.8.8.8', '8.8.8.0/24', '2606:4700::/32']) {
      expect(isValidRegistrationTarget(t), t).toBe(true);
    }
  });
  it('rejects out-of-range CIDR prefixes', () => {
    expect(isValidRegistrationTarget('8.8.8.0/33')).toBe(false);
    expect(isValidRegistrationTarget('2606:4700::/129')).toBe(false);
  });
});

describe('normalizeDomain', () => {
  it('lower-cases, strips scheme/path and trailing dot', () => {
    expect(normalizeDomain('HTTPS://Example.COM/path?x=1')).toBe('example.com');
    expect(normalizeDomain('example.com.')).toBe('example.com');
    expect(normalizeDomain('  Sub.Example.com  ')).toBe('sub.example.com');
  });
});
