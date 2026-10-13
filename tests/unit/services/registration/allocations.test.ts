/**
 * @fileoverview Exact allocation coverage and malformed-value boundary tests.
 * @module tests/unit/services/registration/allocations
 */
import { describe, expect, it } from 'vitest';
import { normalizeAllocation } from '@/services/registration/allocations.js';

describe('normalizeAllocation', () => {
  it.each([
    ['0.0.0.0 - 255.255.255.255', ['0.0.0.0/0']],
    [':: - ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff', ['::/0']],
    ['8.8.8.8 - 8.8.8.8', ['8.8.8.8/32']],
    ['2001:4860::1 - 2001:4860::1', ['2001:4860::1/128']],
    ['2001:04860::/32', []],
    ['2001:0486:0000:0000::/032', ['2001:486::/32']],
    ['::ffff:192.0.2.17/120', ['::ffff:c000:200/120']],
    ['8.8.8.8/33, ::/129, ::/1x, ::/1/2, ::/-1, ::/+1, ::/0x10, ::/, ::%en0/64', []],
    ['not an allocation, 8.8.8.2 - 8.8.8.1, 8.8.8.1 - ::1, 8.8.8.1 - 8.8.8.2 - 8.8.8.3', []],
  ])('normalizes %s', (value, expected) => {
    expect(normalizeAllocation(value)).toEqual(expected);
  });

  it('exactly covers every small unaligned IPv4 range without gaps or overlaps', () => {
    for (let start = 0; start < 16; start++) {
      for (let end = start; end < 16; end++) {
        const cidrs = normalizeAllocation(`8.8.8.${start} - 8.8.8.${end}`);
        const covered = cidrs.flatMap((cidr) => {
          const [address = '', prefix = ''] = cidr.split('/');
          const last = Number(address.split('.').at(-1));
          return Array.from({ length: 2 ** (32 - Number(prefix)) }, (_, i) => last + i);
        });
        expect(covered).toEqual(Array.from({ length: end - start + 1 }, (_, i) => start + i));
      }
    }
  });
});
