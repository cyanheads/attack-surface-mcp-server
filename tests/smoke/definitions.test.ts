/**
 * @fileoverview Offline smoke checks for the complete MCP definition catalog.
 * @module tests/smoke/definitions.test
 */

import { describe, expect, it } from 'vitest';
import { allResourceDefinitions } from '@/mcp-server/resources/definitions/index.js';
import { allToolDefinitions } from '@/mcp-server/tools/definitions/index.js';

describe('MCP definition catalog', () => {
  it('exports every public tool with an executable, schema-backed definition', () => {
    expect(allToolDefinitions.map((definition) => definition.name)).toEqual([
      'attacksurface_map_domain',
      'attacksurface_enumerate_subdomains',
      'attacksurface_resolve_dns',
      'attacksurface_inspect_tls',
      'attacksurface_probe_http',
      'attacksurface_lookup_registration',
      'attacksurface_lookup_host',
      'attacksurface_recon_guidance',
    ]);

    for (const definition of allToolDefinitions) {
      expect(definition.title).toBe(definition.name);
      expect(definition.description.length).toBeGreaterThan(20);
      expect(definition.handler).toBeTypeOf('function');
      expect(definition.input.safeParse).toBeTypeOf('function');
      expect(definition.output.safeParse).toBeTypeOf('function');
    }
  });

  it('exports a listable domain-surface resource', async () => {
    expect(allResourceDefinitions).toHaveLength(1);
    const [definition] = allResourceDefinitions;
    expect(definition?.name).toBe('domain-surface-snapshot');
    expect(definition?.title).toBe('attacksurface://surface/{domain}');
    expect(definition?.handler).toBeTypeOf('function');

    await expect(definition?.list?.()).resolves.toEqual({
      resources: [
        {
          uri: 'attacksurface://surface/example.com',
          name: 'Domain surface snapshot (example)',
          mimeType: 'application/json',
        },
      ],
    });
  });
});
