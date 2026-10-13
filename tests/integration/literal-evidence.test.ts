/**
 * @fileoverview Per-tool wiring tests for literal upstream evidence rendering.
 * @module tests/integration/literal-evidence
 */
import { describe, expect, it } from 'vitest';
import { inspectTlsTool } from '@/mcp-server/tools/definitions/inspect-tls.tool.js';
import { lookupHostTool } from '@/mcp-server/tools/definitions/lookup-host.tool.js';
import { probeHttpTool } from '@/mcp-server/tools/definitions/probe-http.tool.js';
import { resolveDnsTool } from '@/mcp-server/tools/definitions/resolve-dns.tool.js';

const evidence = (field: string) => `<section>*${field}* \`x\`</section>`;
const multiline = (field: string) =>
  `first ${field}\n\`\`\`\`\`\n<section>*${field}*</section>\nlast`;

function assertEvidence(blocks: unknown, singles: string[], multiples: string[]) {
  expect(blocks).toEqual([{ type: 'text', text: expect.any(String) }]);
  const text = (blocks as Array<{ text: string }>)[0]?.text;
  for (const value of singles) expect(text).toContain(`\`\`${value}\`\``);
  for (const value of multiples) expect(text).toContain(`\`\`\`\`\`\`\n${value}\n\`\`\`\`\`\``);
}

describe('literal evidence formatter wiring', () => {
  it('renders HTTP headers, body evidence, cookies, and redirects literally', () => {
    const singles = ['location', 'header', 'hsts', 'cookie', 'sameSite', 'cors', 'finding'].map(
      evidence,
    );
    const body = multiline('body');
    const result = probeHttpTool.output.parse({
      url: 'https://example.com',
      finalUrl: 'https://example.com',
      finalStatus: 200,
      redirectChain: [{ url: 'https://example.com', status: 302, location: singles[0] }],
      headers: { 'x-evidence': singles[1] },
      checkedAt: 'now',
      transportError: null,
      bodyInspection: { status: 'complete', error: null },
      securityAudit: {
        hsts: singles[2],
        csp: null,
        xFrameOptions: null,
        xContentTypeOptions: null,
        referrerPolicy: null,
        permissionsPolicy: null,
        cookies: [{ name: singles[3], secure: true, httpOnly: true, sameSite: singles[4] }],
        corsAllowOrigin: singles[5],
        corsReflectsOrigin: false,
        findings: [singles[6]],
      },
      technologies: [{ name: 'test', category: 'other', evidence: body }],
    });
    const before = structuredClone(result);
    const blocks = probeHttpTool.format?.(result);
    assertEvidence(blocks, singles, [body]);
    expect(result).toEqual(before);
  });

  it('renders every TLS certificate string and multi-host findings literally', () => {
    const singles = [
      'cipher',
      'subject',
      'issuer',
      'organization',
      'from',
      'to',
      'serial',
      'fingerprint',
      'eku',
      'validation',
      'identity',
    ].map(evidence);
    const san = multiline('san');
    const finding = multiline('tls-finding');
    const record = {
      host: 'example.com',
      port: 443,
      protocol: 'TLSv1.3',
      cipher: singles[0],
      certificate: {
        subjectCommonName: singles[1],
        subjectAltNames: [san],
        issuerCommonName: singles[2],
        issuerOrganization: singles[3],
        validFrom: singles[4],
        validTo: singles[5],
        daysUntilExpiry: null,
        serialNumber: singles[6],
        fingerprintSha256: singles[7],
        extendedKeyUsages: [singles[8]],
      },
      chainDepth: 1,
      validationAuthorized: false,
      validationError: singles[9],
      identityAuthorized: false,
      identityError: singles[10],
      handshakeError: null,
      findings: [finding],
      checkedAt: 'now',
    };
    const result = inspectTlsTool.output.parse({
      results: [record, { ...record, host: 'second.example.com' }],
    });
    const before = structuredClone(result);
    const blocks = inspectTlsTool.format?.(result);
    assertEvidence(blocks, singles, [san, finding]);
    const text = (blocks as Array<{ text: string }>)[0]?.text ?? '';
    for (const value of singles) expect(text.split(`\`\`${value}\`\``)).toHaveLength(3);
    expect(result).toEqual(before);
  });

  it('renders canonical, each resolver, and reverse DNS text literally', () => {
    const singles = [
      'canonical',
      'resolver-one',
      'query-error',
      'resolver-two',
      'ptr',
      'reverse-error',
    ].map(evidence);
    const canonical = multiline('canonical-multiline');
    const resolver = multiline('resolver-multiline');
    const result = resolveDnsTool.output.parse({
      results: [
        {
          host: 'example.com',
          resolved: true,
          records: { TXT: [singles[0], canonical] },
          resolverResults: [
            {
              resolver: '8.8.8.8',
              latencyInMs: 1,
              records: { TXT: [singles[1], resolver] },
              queryError: singles[2],
            },
            {
              resolver: '1.1.1.1',
              latencyInMs: 2,
              records: { TXT: [singles[3]] },
              queryError: null,
            },
          ],
          propagationMismatches: ['TXT'],
          reverse: [{ ip: '8.8.8.8', hostnames: [singles[4]], lookupError: singles[5] }],
          hostError: null,
        },
      ],
      resolversUsed: ['8.8.8.8', '1.1.1.1'],
    });
    const before = structuredClone(result);
    const blocks = resolveDnsTool.format?.(result);
    assertEvidence(blocks, singles, [canonical, resolver]);
    expect(result).toEqual(before);
  });

  it('renders Shodan banners, search matches, and facet buckets literally', () => {
    const singles = [
      'hostname',
      'product',
      'org',
      'search-product',
      'search-org',
      'facet-name',
      'facet-value',
    ].map(evidence);
    const banner = multiline('banner');
    for (const result of [
      lookupHostTool.output.parse({
        mode: 'host',
        host: {
          ip: '8.8.8.8',
          hostnames: [singles[0]],
          ports: [443],
          services: [{ port: 443, product: singles[1], banner }],
          org: singles[2],
        },
      }),
      lookupHostTool.output.parse({
        mode: 'search',
        search: {
          total: 1,
          matches: [{ ip: '8.8.8.8', port: 443, product: singles[3], org: singles[4] }],
          facets: { [singles[5] ?? '']: [{ value: singles[6], count: 1 }] },
        },
      }),
    ]) {
      const before = structuredClone(result);
      const blocks = lookupHostTool.format?.(result);
      assertEvidence(
        blocks,
        result.host ? singles.slice(0, 3) : singles.slice(3),
        result.host ? [banner] : [],
      );
      expect(result).toEqual(before);
    }
  });
});
