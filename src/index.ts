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
    "Passive, non-intrusive external attack-surface mapping. Assess only assets you own or are explicitly authorized to test. This server reads public records (Certificate Transparency, DNS, RDAP/WHOIS) and the target's own published surface (TLS handshakes and HTTP GETs); it never port-scans, exploits, brute-forces, fuzzes, or probes for vulnerabilities. Output describes observed assets and posture, never an exploitation plan. Start with attacksurface_map_domain and inspect its coverage and operational notes before drawing estate-wide conclusions; use per-aspect tools for targeted follow-up. Core capabilities are keyless; attacksurface_lookup_host requires SHODAN_API_KEY and returns source_unavailable without it while the other tools remain available.",
  // No per-session state or ctx.requestInput; an explicit MCP_SESSION_MODE still overrides this.
  sessionMode: 'stateless',
  tools: allToolDefinitions,
  resources: allResourceDefinitions,
  skills: 'skills',
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
