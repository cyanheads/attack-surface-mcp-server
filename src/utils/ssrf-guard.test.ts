/**
 * @fileoverview Tests for the SSRF guard — the security spine. Verifies private/loopback/link-local/
 * metadata/reserved ranges (IPv4 + IPv6) are rejected, public targets pass, scheme is enforced, and
 * the opt-out env var disables the checks.
 * @module utils/ssrf-guard.test
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const dnsBoundary = vi.hoisted(() => ({ lookup: vi.fn() }));

vi.mock('node:dns/promises', () => ({ lookup: dnsBoundary.lookup }));

import {
  assertSafeDomain,
  assertSafeResolverIp,
  assertSafeUrl,
  resolveSafeHost,
} from './ssrf-guard.js';

beforeEach(() => {
  vi.useRealTimers();
  dnsBoundary.lookup.mockReset();
});

afterEach(() => {
  delete process.env.ATTACKSURFACE_ALLOW_PRIVATE_TARGETS;
  vi.useRealTimers();
});

describe('assertSafeResolverIp', () => {
  it('rejects private IPv4 ranges', () => {
    for (const ip of [
      '127.0.0.1',
      '10.0.0.1',
      '172.16.0.1',
      '192.168.1.1',
      '169.254.169.254',
      '100.64.0.1',
      '0.0.0.0',
    ]) {
      expect(() => assertSafeResolverIp(ip), ip).toThrow(/SSRF_BLOCKED/);
    }
  });

  it('rejects the cloud-metadata address explicitly', () => {
    expect(() => assertSafeResolverIp('169.254.169.254')).toThrow(/link-local|metadata/);
  });

  it('rejects private/loopback IPv6', () => {
    for (const ip of ['::1', 'fc00::1', 'fd12:3456::1', 'fe80::1', '::ffff:10.0.0.1', '::']) {
      expect(() => assertSafeResolverIp(ip), ip).toThrow(/SSRF_BLOCKED/);
    }
  });

  it('rejects IPv4-mapped loopback/metadata in pure-hex form', () => {
    // ::ffff:7f00:1 == 127.0.0.1, ::ffff:a9fe:a9fe == 169.254.169.254 — the hex form that the
    // dotted-only check used to miss.
    for (const ip of ['::ffff:7f00:1', '::ffff:a9fe:a9fe', '::ffff:c0a8:101']) {
      expect(() => assertSafeResolverIp(ip), ip).toThrow(/SSRF_BLOCKED/);
    }
  });

  it('rejects NAT64-embedded private IPv4', () => {
    expect(() => assertSafeResolverIp('64:ff9b::10.0.0.1')).toThrow(/SSRF_BLOCKED/);
  });

  it('accepts public resolver IPs', () => {
    for (const ip of ['8.8.8.8', '1.1.1.1', '9.9.9.9', '2606:4700:4700::1111']) {
      expect(() => assertSafeResolverIp(ip), ip).not.toThrow();
    }
  });

  it('classifies equivalent IPv6 forms consistently at every guard entry point', async () => {
    for (const ip of [
      '0:0:0:0:0:0:0:1',
      '0000:0000:0000:0000:0000:0000:0000:0001',
      '0:0:0:0:0:FFFF:7f00:1',
      '0:0:0:0:0:ffff:127.0.0.1',
      '64:ff9b::7f00:1',
      '::ffff:0:7f00:1',
      '2001:db8::1',
      '3fff::1',
      'fec0::1',
    ]) {
      expect(() => assertSafeResolverIp(ip), ip).toThrow(/SSRF_BLOCKED/);
      await expect(assertSafeDomain(ip), ip).rejects.toThrow(/SSRF_BLOCKED/);
      await expect(resolveSafeHost(ip), ip).rejects.toThrow(/SSRF_BLOCKED/);
      await expect(assertSafeUrl(`https://[${ip}]/`), ip).rejects.toThrow(/SSRF_BLOCKED/);
    }
  });

  it('does not treat native IPv6 low bits as an embedded private IPv4 address', async () => {
    for (const ip of ['2606:4700::127.0.0.1', '2606:4700::7f00:1', '64:ff9b::808:808']) {
      expect(() => assertSafeResolverIp(ip)).not.toThrow();
      await expect(resolveSafeHost(ip)).resolves.toBeNull();
      await expect(assertSafeUrl(`https://[${ip}]/`)).resolves.toBeUndefined();
    }
  });

  it.each(['64:ff9b:1::1', '100:0:0:1::1', '5f00::1'])(
    'rejects non-global IANA special-purpose prefix %s',
    async (ip) => {
      expect(() => assertSafeResolverIp(ip)).toThrow(/SSRF_BLOCKED/);
      dnsBoundary.lookup.mockResolvedValue([
        { address: '8.8.8.8', family: 4 },
        { address: ip, family: 6 },
      ]);
      await expect(resolveSafeHost('example.test')).rejects.toThrow(/SSRF_BLOCKED/);
      await expect(assertSafeUrl(`https://[${ip}]/`)).rejects.toThrow(/SSRF_BLOCKED/);
    },
  );

  it('does not over-block public IPv6 sharing leading hex with reserved ranges', () => {
    for (const ip of ['2606:4700:4700::1111', '2001:4860:4860::8888', '2a00:1450:4001::1']) {
      expect(() => assertSafeResolverIp(ip), ip).not.toThrow();
    }
  });

  it('no-ops when private targets are explicitly allowed', () => {
    process.env.ATTACKSURFACE_ALLOW_PRIVATE_TARGETS = 'true';
    expect(() => assertSafeResolverIp('127.0.0.1')).not.toThrow();
  });
});

describe('assertSafeDomain', () => {
  it('preserves discovery cancellation while the host safety lookup is pending', async () => {
    dnsBoundary.lookup.mockImplementation(() => new Promise(() => {}));
    const controller = new AbortController();
    const domain = assertSafeDomain('example.test', controller.signal);
    const pinned = resolveSafeHost('example.test', controller.signal);
    const assertions = Promise.all([
      expect(domain).rejects.toMatchObject({ name: 'AbortError' }),
      expect(pinned).rejects.toMatchObject({ name: 'AbortError' }),
    ]);
    controller.abort();
    await assertions;
  });
  it('rejects a literal private IP without a DNS round-trip', async () => {
    await expect(assertSafeDomain('169.254.169.254')).rejects.toThrow(/SSRF_BLOCKED/);
    await expect(assertSafeDomain('127.0.0.1')).rejects.toThrow(/SSRF_BLOCKED/);
  });

  it('accepts a literal public IP', async () => {
    await expect(assertSafeDomain('8.8.8.8')).resolves.toBeUndefined();
  });

  it('no-ops on private literals when allowed', async () => {
    process.env.ATTACKSURFACE_ALLOW_PRIVATE_TARGETS = 'true';
    await expect(assertSafeDomain('127.0.0.1')).resolves.toBeUndefined();
  });
});

describe('assertSafeUrl', () => {
  it('rejects non-http(s) schemes', async () => {
    await expect(assertSafeUrl('file:///etc/passwd')).rejects.toThrow(/Scheme/);
    await expect(assertSafeUrl('ftp://example.com')).rejects.toThrow(/Scheme/);
    process.env.ATTACKSURFACE_ALLOW_PRIVATE_TARGETS = 'true';
    await expect(assertSafeUrl('file:///etc/passwd')).rejects.toThrow(/Scheme/);
  });

  it('rejects a malformed URL', async () => {
    await expect(assertSafeUrl('not a url')).rejects.toThrow(/SSRF_BLOCKED/);
  });

  it('rejects a URL pointing at a private literal IP', async () => {
    await expect(assertSafeUrl('http://169.254.169.254/latest/meta-data')).rejects.toThrow(
      /SSRF_BLOCKED/,
    );
  });

  it('accepts a public https URL', async () => {
    await expect(assertSafeUrl('https://8.8.8.8/')).resolves.toBeUndefined();
  });

  it('honors cancellation while hostname validation is waiting on DNS', async () => {
    vi.useFakeTimers();
    dnsBoundary.lookup.mockImplementation(
      () =>
        new Promise((resolve) =>
          setTimeout(() => resolve([{ address: '8.8.8.8', family: 4 }]), 60_000),
        ),
    );
    const controller = new AbortController();

    const pending = assertSafeUrl('https://rdap.example.test/', controller.signal);
    const rejection = expect(pending).rejects.toMatchObject({ name: 'AbortError' });
    controller.abort();
    await vi.runAllTimersAsync();

    await rejection;
  });
});

describe('resolveSafeHost', () => {
  it('throws on a private literal rather than returning it', async () => {
    await expect(resolveSafeHost('127.0.0.1')).rejects.toThrow(/SSRF_BLOCKED/);
    await expect(resolveSafeHost('169.254.169.254')).rejects.toThrow(/SSRF_BLOCKED/);
  });

  it('returns null for a public literal IP (caller already holds the target)', async () => {
    await expect(resolveSafeHost('8.8.8.8')).resolves.toBeNull();
  });

  it('returns null when private targets are explicitly allowed (connect by hostname)', async () => {
    process.env.ATTACKSURFACE_ALLOW_PRIVATE_TARGETS = 'true';
    await expect(resolveSafeHost('127.0.0.1')).resolves.toBeNull();
  });

  it('pins a single-address host to that address', async () => {
    dnsBoundary.lookup.mockResolvedValue([{ address: '104.26.10.117', family: 4 }]);
    await expect(resolveSafeHost('example.test')).resolves.toBe('104.26.10.117');
  });

  it('pins a dual-stack host to IPv4 even when the resolver lists AAAA records first', async () => {
    // Bun's lookup returns AAAA ahead of A; dialing IPv6 first fails on networks with no v6 route.
    dnsBoundary.lookup.mockResolvedValue([
      { address: '2606:4700:20::681a:a75', family: 6 },
      { address: '2606:4700:20::681a:b75', family: 6 },
      { address: '104.26.10.117', family: 4 },
      { address: '172.67.72.95', family: 4 },
    ]);
    await expect(resolveSafeHost('example.test')).resolves.toBe('104.26.10.117');
  });

  it('pins an IPv6-only host to its IPv6 address', async () => {
    dnsBoundary.lookup.mockResolvedValue([{ address: '2606:4700:20::681a:a75', family: 6 }]);
    await expect(resolveSafeHost('example.test')).resolves.toBe('2606:4700:20::681a:a75');
  });

  it('still rejects a host when any resolved address is private, wherever it sits in the list', async () => {
    dnsBoundary.lookup.mockResolvedValue([
      { address: '2606:4700:20::681a:a75', family: 6 },
      { address: '104.26.10.117', family: 4 },
      { address: '10.0.0.5', family: 4 },
    ]);
    await expect(resolveSafeHost('example.test')).rejects.toThrow(/SSRF_BLOCKED.*10\.0\.0\.5/);
  });
});
