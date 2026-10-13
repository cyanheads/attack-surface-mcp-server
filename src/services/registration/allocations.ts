/**
 * @fileoverview Normalize WHOIS allocation CIDRs and exact IPv4/IPv6 range coverage.
 * @module services/registration/allocations
 */
import { isIP } from 'node:net';
import { isValidRegistrationTarget } from '@/utils/validation.js';

function addressValue(address: string, family: number): bigint {
  if (family === 4)
    return address.split('.').reduce((value, octet) => (value << 8n) | BigInt(octet), 0n);
  const canonical = new URL(`http://[${address}]/`).hostname.slice(1, -1);
  const [left = '', right] = canonical.split('::');
  const leading = left ? left.split(':') : [];
  const trailing = right ? right.split(':') : [];
  const groups =
    right === undefined
      ? leading
      : [...leading, ...Array<string>(8 - leading.length - trailing.length).fill('0'), ...trailing];
  return groups.reduce((value, group) => (value << 16n) | BigInt(`0x${group}`), 0n);
}

function addressText(value: bigint, family: number): string {
  if (family === 4)
    return [24n, 16n, 8n, 0n].map((shift) => String((value >> shift) & 255n)).join('.');
  const expanded = Array.from({ length: 8 }, (_, i) =>
    ((value >> BigInt((7 - i) * 16)) & 65535n).toString(16),
  ).join(':');
  return new URL(`http://[${expanded}]/`).hostname.slice(1, -1);
}

/** Return normalized CIDRs; invalid allocations remain solely in raw WHOIS evidence. */
export function normalizeAllocation(value: string): string[] {
  const out: string[] = [];
  for (const part of value.split(',')) {
    const entry = part.trim();
    if (entry.includes('/')) {
      if (!isValidRegistrationTarget(entry)) continue;
      const [address = '', bits = ''] = entry.split('/');
      const family = isIP(address);
      const width = family === 4 ? 32 : 128;
      const shift = BigInt(width - Number(bits));
      const base = (addressValue(address, family) >> shift) << shift;
      out.push(`${addressText(base, family)}/${Number(bits)}`);
      continue;
    }
    const [start = '', end = '', extra] = entry.split('-').map((address) => address.trim());
    const family = isIP(start);
    if (
      extra !== undefined ||
      !family ||
      family !== isIP(end) ||
      start.includes('%') ||
      end.includes('%')
    )
      continue;
    let current = addressValue(start, family);
    const last = addressValue(end, family);
    const width = family === 4 ? 32 : 128;
    while (current <= last) {
      let shift = 0;
      while (
        shift < width &&
        current % (1n << BigInt(shift + 1)) === 0n &&
        current + (1n << BigInt(shift + 1)) - 1n <= last
      )
        shift++;
      out.push(`${addressText(current, family)}/${width - shift}`);
      current += 1n << BigInt(shift);
    }
  }
  return out;
}
