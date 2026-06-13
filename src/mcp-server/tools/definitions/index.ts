/**
 * @fileoverview Barrel — collects all tool definitions into `allToolDefinitions` for createApp().
 * @module mcp-server/tools/definitions/index
 */

import { enumerateSubdomainsTool } from './enumerate-subdomains.tool.js';
import { inspectTlsTool } from './inspect-tls.tool.js';
import { lookupHostTool } from './lookup-host.tool.js';
import { lookupRegistrationTool } from './lookup-registration.tool.js';
import { mapDomainTool } from './map-domain.tool.js';
import { probeHttpTool } from './probe-http.tool.js';
import { reconGuidanceTool } from './recon-guidance.tool.js';
import { resolveDnsTool } from './resolve-dns.tool.js';

export const allToolDefinitions = [
  mapDomainTool,
  enumerateSubdomainsTool,
  resolveDnsTool,
  inspectTlsTool,
  probeHttpTool,
  lookupRegistrationTool,
  lookupHostTool,
  reconGuidanceTool,
];
