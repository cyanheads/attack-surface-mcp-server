/**
 * @fileoverview Server-specific configuration for attack-surface-mcp-server. Lazy-parsed Zod schema,
 * separate from the framework's core config. No variable is required — the server boots and delivers
 * its keyless core (CT enumeration, DNS, TLS, HTTP, RDAP/WHOIS) with an empty environment.
 * @module config/server-config
 */

import { isIP } from 'node:net';
import { z } from '@cyanheads/mcp-ts-core';
import { parseEnvConfig } from '@cyanheads/mcp-ts-core/config';
import { configurationError } from '@cyanheads/mcp-ts-core/errors';

const DEFAULT_RESOLVERS = '8.8.8.8,1.1.1.1,9.9.9.9';
const RESOLVER_ENV = 'ATTACKSURFACE_DEFAULT_RESOLVERS';
const DEFAULT_USER_AGENT =
  'attack-surface-mcp-server/passive-recon (+https://github.com/cyanheads/attack-surface-mcp-server)';

const ServerConfigSchema = z.object({
  /** Shodan API key — enables `attacksurface_lookup_host`. Absent → that one tool degrades. */
  shodanApiKey: z.string().optional().describe('Shodan API key for host intelligence.'),
  /** Certspotter API key — raises CT-fallback rate limits. Absent → free unauthenticated tier. */
  certspotterApiKey: z
    .string()
    .optional()
    .describe('Certspotter API key for higher CT-fallback rate limits.'),
  /** Explicit resolver IPs used by DNS tools, discovery and connection safety checks. */
  defaultResolvers: z
    .string()
    .default(DEFAULT_RESOLVERS)
    .refine((raw) => {
      const ips = parseResolverList(raw);
      return ips.length > 0 && ips.every((ip) => isIP(ip) !== 0 && !ip.includes('%'));
    }, 'Provide at least one valid DNS resolver IP.')
    .describe('Comma-separated default DNS resolver IPs.'),
  /** Default User-Agent for `attacksurface_probe_http` (overridable per call). */
  httpUserAgent: z
    .string()
    .default(DEFAULT_USER_AGENT)
    .describe('Default User-Agent string for HTTP probes.'),
  /** Map/snapshot resolution cap; enumeration also applies a 50-candidate page ceiling. */
  maxSubdomains: z.coerce
    .number()
    .int()
    .min(1)
    .max(5000)
    .default(200)
    .describe(
      'Maximum map/snapshot resolution work; enumeration resolves min(this value, 50, requested limit) candidates per page.',
    ),
  /** RDAP bootstrap base; override for a private/mirrored RDAP. */
  rdapBootstrapUrl: z
    .string()
    .url()
    .default('https://rdap.org')
    .describe('RDAP bootstrap base URL.'),
});

export type ServerConfig = z.infer<typeof ServerConfigSchema>;

let _config: ServerConfig | undefined;

/** Lazily parse and cache the server config from the environment. */
export function getServerConfig(): ServerConfig {
  // The framework normalizes empty environment values to undefined. An explicitly empty resolver
  // list is a configuration error rather than permission to choose a different resolver.
  if (process.env[RESOLVER_ENV]?.trim() === '') {
    throw configurationError(`${RESOLVER_ENV} must contain at least one DNS resolver IP.`);
  }
  _config ??= parseEnvConfig(ServerConfigSchema, {
    shodanApiKey: 'SHODAN_API_KEY',
    certspotterApiKey: 'CERTSPOTTER_API_KEY',
    defaultResolvers: RESOLVER_ENV,
    httpUserAgent: 'ATTACKSURFACE_HTTP_USER_AGENT',
    maxSubdomains: 'ATTACKSURFACE_MAX_SUBDOMAINS',
    rdapBootstrapUrl: 'ATTACKSURFACE_RDAP_BOOTSTRAP_URL',
  });
  return _config;
}

/** Reset cached config (test isolation). */
export function resetServerConfig(): void {
  _config = undefined;
}

/** Parse the comma-separated resolver list into a deduplicated array of trimmed IPs. */
export function parseResolverList(raw: string): string[] {
  return [
    ...new Set(
      raw
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean),
    ),
  ];
}
