/**
 * @fileoverview Server-specific configuration for attack-surface-mcp-server. Lazy-parsed Zod schema,
 * separate from the framework's core config. No variable is required — the server boots and delivers
 * its keyless core (CT enumeration, DNS, TLS, HTTP, RDAP/WHOIS) with an empty environment.
 * @module config/server-config
 */

import { z } from '@cyanheads/mcp-ts-core';
import { parseEnvConfig } from '@cyanheads/mcp-ts-core/config';

const DEFAULT_RESOLVERS = '8.8.8.8,1.1.1.1,9.9.9.9';
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
  /** Comma-separated public resolver IPs used by `attacksurface_resolve_dns` by default. */
  defaultResolvers: z
    .string()
    .default(DEFAULT_RESOLVERS)
    .describe('Comma-separated default DNS resolver IPs.'),
  /** Default User-Agent for `attacksurface_probe_http` (overridable per call). */
  httpUserAgent: z
    .string()
    .default(DEFAULT_USER_AGENT)
    .describe('Default User-Agent string for HTTP probes.'),
  /** Cap on subdomains resolved during a `map_domain` run — bounds fan-out cost. */
  maxSubdomains: z.coerce
    .number()
    .int()
    .min(1)
    .max(5000)
    .default(200)
    .describe('Maximum subdomains resolved per map_domain run.'),
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
  _config ??= parseEnvConfig(ServerConfigSchema, {
    shodanApiKey: 'SHODAN_API_KEY',
    certspotterApiKey: 'CERTSPOTTER_API_KEY',
    defaultResolvers: 'ATTACKSURFACE_DEFAULT_RESOLVERS',
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
