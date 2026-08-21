/**
 * @fileoverview Boundary tests for DNS resolution with node:dns fully faked.
 * @module services/dns/dns-service.test
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const dnsBoundary = vi.hoisted(() => ({
  lookup: vi.fn(),
  query: vi.fn(),
  reverse: vi.fn(),
  setServers: vi.fn(),
}));

vi.mock('node:dns/promises', () => ({
  lookup: dnsBoundary.lookup,
  Resolver: class FakeResolver {
    private server = '';

    setServers(servers: string[]) {
      this.server = servers[0] ?? '';
      dnsBoundary.setServers(servers);
    }

    resolve4(host: string) {
      return dnsBoundary.query('A', host, this.server);
    }

    resolve6(host: string) {
      return dnsBoundary.query('AAAA', host, this.server);
    }

    resolveCname(host: string) {
      return dnsBoundary.query('CNAME', host, this.server);
    }

    resolveMx(host: string) {
      return dnsBoundary.query('MX', host, this.server);
    }

    resolveNs(host: string) {
      return dnsBoundary.query('NS', host, this.server);
    }

    resolveTxt(host: string) {
      return dnsBoundary.query('TXT', host, this.server);
    }

    resolveCaa(host: string) {
      return dnsBoundary.query('CAA', host, this.server);
    }

    reverse(ip: string) {
      return dnsBoundary.reverse(ip);
    }
  },
}));

import { DnsService } from '@/services/dns/dns-service.js';
import { ALL_RECORD_TYPES } from '@/services/dns/types.js';

function dnsError(code: string, message = code): Error & { code: string } {
  return Object.assign(new Error(message), { code });
}

describe('DnsService', () => {
  beforeEach(() => {
    vi.unstubAllEnvs();
    dnsBoundary.lookup.mockReset();
    dnsBoundary.query.mockReset();
    dnsBoundary.reverse.mockReset();
    dnsBoundary.setServers.mockReset();
    dnsBoundary.lookup.mockResolvedValue([{ address: '93.184.216.34', family: 4 }]);
    dnsBoundary.query.mockRejectedValue(dnsError('ENODATA'));
    dnsBoundary.reverse.mockRejectedValue(dnsError('ENODATA'));
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it('normalizes every record type, detects propagation differences, and resolves PTRs', async () => {
    dnsBoundary.query.mockImplementation(async (type, _host, resolver) => {
      if (resolver === '1.1.1.1' && type === 'A') return ['93.184.216.35'];
      switch (type) {
        case 'A':
          return ['93.184.216.34'];
        case 'AAAA':
          return ['2606:2800:220:1:248:1893:25c8:1946'];
        case 'CNAME':
          return ['edge.example.net'];
        case 'MX':
          return [
            { priority: 10, exchange: 'mail.example.com' },
            { priority: 0, exchange: '' },
          ];
        case 'NS':
          return ['ns2.example.com', 'ns1.example.com'];
        case 'TXT':
          return [['v=spf1', ' -all']];
        case 'CAA':
          return [
            { critical: 0, issue: 'letsencrypt.org' },
            { critical: 128, issuewild: ';' },
            { critical: 0, iodef: 'mailto:security@example.com' },
            { critical: 0, contactemail: 'security@example.com' },
          ];
        default:
          throw dnsError('ENODATA');
      }
    });
    dnsBoundary.reverse.mockResolvedValue(['ptr.example.com']);

    const [result] = await new DnsService().resolveHosts(
      ['example.com'],
      ALL_RECORD_TYPES,
      ['8.8.8.8', '1.1.1.1'],
      true,
    );

    expect(result).toEqual({
      host: 'example.com',
      records: {
        A: ['93.184.216.34'],
        AAAA: ['2606:2800:220:1:248:1893:25c8:1946'],
        CNAME: ['edge.example.net'],
        MX: ['0 .', '10 mail.example.com'],
        NS: ['ns1.example.com', 'ns2.example.com'],
        TXT: ['v=spf1 -all'],
        CAA: [
          '0 iodef "mailto:security@example.com"',
          '0 issue "letsencrypt.org"',
          '128 issuewild ";"',
          '{"critical":0,"contactemail":"security@example.com"}',
        ],
      },
      resolverResults: expect.arrayContaining([
        expect.objectContaining({ resolver: '8.8.8.8', queryError: null }),
        expect.objectContaining({ resolver: '1.1.1.1', queryError: null }),
      ]),
      propagationMismatches: ['A'],
      reverse: [
        { ip: '93.184.216.34', hostnames: ['ptr.example.com'], lookupError: null },
        {
          ip: '2606:2800:220:1:248:1893:25c8:1946',
          hostnames: ['ptr.example.com'],
          lookupError: null,
        },
      ],
      resolved: true,
      hostError: null,
    });
    expect(dnsBoundary.setServers).toHaveBeenCalledWith(['8.8.8.8']);
    expect(dnsBoundary.setServers).toHaveBeenCalledWith(['1.1.1.1']);
  });

  it('treats missing records as normal while surfacing resolver timeouts', async () => {
    dnsBoundary.query.mockImplementation(async (type) => {
      if (type === 'A') throw dnsError('ETIMEOUT', 'resolver timed out');
      throw dnsError('ENODATA');
    });

    const [result] = await new DnsService().resolveHosts(
      ['empty.example.com'],
      ['A', 'AAAA'],
      ['8.8.8.8'],
      false,
    );

    expect(result).toMatchObject({
      records: {},
      resolved: false,
      hostError: 'resolver timed out',
      resolverResults: [{ records: {}, queryError: 'resolver timed out' }],
    });
    expect(result?.reverse).toBeUndefined();
  });

  // Known defect: https://github.com/cyanheads/attack-surface-mcp-server/issues/3
  it.skip('surfaces SERVFAIL as a resolver failure rather than a no-record answer', async () => {
    dnsBoundary.query.mockRejectedValue(dnsError('ESERVFAIL', 'upstream SERVFAIL'));

    const [result] = await new DnsService().resolveHosts(
      ['broken.example.com'],
      ['A'],
      ['8.8.8.8'],
      false,
    );

    expect(result?.error).toBe('upstream SERVFAIL');
    expect(result?.resolverResults[0]?.error).toBe('upstream SERVFAIL');
  });

  it('degrades a host that resolves to a private address without querying it', async () => {
    dnsBoundary.lookup.mockResolvedValue([{ address: '10.0.0.8', family: 4 }]);

    const [result] = await new DnsService().resolveHosts(
      ['internal.example.com'],
      ['A'],
      ['8.8.8.8'],
      false,
    );

    expect(result).toMatchObject({
      host: 'internal.example.com',
      resolved: false,
      records: {},
      resolverResults: [],
      hostError: expect.stringMatching(/^SSRF_BLOCKED:/),
    });
    expect(dnsBoundary.query).not.toHaveBeenCalled();
  });

  it('deduplicates liveness addresses from A and AAAA answers', async () => {
    dnsBoundary.query.mockImplementation(async (type) =>
      type === 'A' ? ['93.184.216.34', '93.184.216.34'] : ['2606:2800:220:1:248:1893:25c8:1946'],
    );

    await expect(new DnsService().resolveAddresses('www.example.com')).resolves.toEqual([
      '93.184.216.34',
      '2606:2800:220:1:248:1893:25c8:1946',
    ]);
  });

  it('distinguishes no PTR record from a reverse resolver error', async () => {
    dnsBoundary.reverse.mockImplementation(async (ip) => {
      if (ip === '93.184.216.34') throw dnsError('ENOTFOUND');
      throw dnsError('ETIMEOUT', 'PTR timed out');
    });

    await expect(new DnsService().reverseLookup(['93.184.216.34', '8.8.8.8'])).resolves.toEqual([
      { ip: '93.184.216.34', hostnames: [], lookupError: null },
      { ip: '8.8.8.8', hostnames: [], lookupError: 'PTR timed out' },
    ]);
  });
});
