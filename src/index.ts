#!/usr/bin/env node
/**
 * @fileoverview attack-surface-mcp-server entry point. Passive, non-intrusive external
 * attack-surface mapping (EASM) for authorized, defensive security assessment. Initializes the six
 * domain services (CT, DNS, TLS, HTTP, registration, Shodan) in setup(), then registers the tool and
 * resource surface. Core capabilities are keyless; Shodan is the one optional-key enrichment path.
 * @module index
 */

import { createApp } from '@cyanheads/mcp-ts-core';
import { getServerConfig } from './config/server-config.js';
import { allResourceDefinitions } from './mcp-server/resources/definitions/index.js';
import { allToolDefinitions } from './mcp-server/tools/definitions/index.js';
import { initCtService } from './services/ct/ct-service.js';
import { initDnsService } from './services/dns/dns-service.js';
import { initHttpService } from './services/http/http-service.js';
import { initRegistrationService } from './services/registration/registration-service.js';
import { initShodanService } from './services/shodan/shodan-service.js';
import { initTlsService } from './services/tls/tls-service.js';

await createApp({
  name: 'attack-surface-mcp-server',
  title: 'attack-surface-mcp-server',
  instructions:
    'Passive, non-intrusive external attack-surface mapping. Assess only assets you own or are ' +
    'explicitly authorized to test. This server reads public records (Certificate Transparency, ' +
    "DNS, RDAP/WHOIS) and the target's own published surface (one TLS handshake and one HTTP GET " +
    'per host) — it never port-scans, exploits, brute-forces, fuzzes, or probes for ' +
    'vulnerabilities. Output is descriptive (what exists, what the posture is), not an ' +
    'exploitation plan. Start with attacksurface_map_domain for a full surface map; the per-aspect ' +
    'tools (enumerate_subdomains, resolve_dns, inspect_tls, probe_http, lookup_registration) back ' +
    'it for targeted follow-up. All core capabilities are keyless; attacksurface_lookup_host needs ' +
    'SHODAN_API_KEY and returns source_unavailable without it while everything else keeps working.',
  tools: allToolDefinitions,
  resources: allResourceDefinitions,
  setup(core) {
    const config = getServerConfig();
    initDnsService();
    initTlsService();
    initHttpService(config.httpUserAgent);
    initCtService(config);
    initRegistrationService(config);
    initShodanService(config);
    core.logger.info(
      `attack-surface services initialized (shodan=${Boolean(config.shodanApiKey)}, ` +
        `certspotterKeyed=${Boolean(config.certspotterApiKey)}, maxSubdomains=${config.maxSubdomains})`,
    );
  },
});
