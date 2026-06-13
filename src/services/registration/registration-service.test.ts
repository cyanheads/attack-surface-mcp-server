/**
 * @fileoverview Tests for registration target classification (domain vs IP/CIDR).
 * @module services/registration/registration-service.test
 */

import { describe, expect, it } from 'vitest';
import { classifyTarget } from './registration-service.js';

describe('classifyTarget', () => {
  it('classifies IPv4 and IPv6 literals as ip', () => {
    expect(classifyTarget('8.8.8.8')).toBe('ip');
    expect(classifyTarget('2606:4700:4700::1111')).toBe('ip');
  });
  it('classifies CIDRs as ip', () => {
    expect(classifyTarget('8.8.8.0/24')).toBe('ip');
    expect(classifyTarget('2606:4700::/32')).toBe('ip');
  });
  it('classifies domains as domain', () => {
    expect(classifyTarget('example.com')).toBe('domain');
    expect(classifyTarget('sub.example.co.uk')).toBe('domain');
  });
});
