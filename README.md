<div align="center">
  <h1>@cyanheads/attack-surface-mcp-server</h1>
  <p><b>Passive external attack-surface mapping: CT subdomains, DNS, TLS, HTTP posture, RDAP/WHOIS, Shodan via MCP. STDIO or Streamable HTTP.</b>
  <div>8 Tools • 1 Resource</div>
  </p>
</div>

<div align="center">

[![Version](https://img.shields.io/badge/Version-0.2.1-blue.svg?style=flat-square)](./CHANGELOG.md) [![License](https://img.shields.io/badge/License-Apache%202.0-orange.svg?style=flat-square)](./LICENSE) [![Docker](https://img.shields.io/badge/Docker-ghcr.io-2496ED?style=flat-square&logo=docker&logoColor=white)](https://github.com/users/cyanheads/packages/container/package/attack-surface-mcp-server) [![MCP SDK](https://img.shields.io/badge/MCP%20SDK-^2.0.0-green.svg?style=flat-square)](https://modelcontextprotocol.io/) [![npm](https://img.shields.io/npm/v/%40cyanheads%2Fattack-surface-mcp-server?style=flat-square&logo=npm&logoColor=white)](https://www.npmjs.com/package/@cyanheads/attack-surface-mcp-server) [![TypeScript](https://img.shields.io/badge/TypeScript-^7.0.2-3178C6.svg?style=flat-square)](https://www.typescriptlang.org/) [![Bun](https://img.shields.io/badge/Bun-v1.3.0%2B-blueviolet.svg?style=flat-square)](https://bun.sh/)

</div>

<div align="center">

[![Install in Claude Desktop](https://img.shields.io/badge/Install_in-Claude_Desktop-D97757?style=for-the-badge&logo=anthropic&logoColor=white)](https://github.com/cyanheads/attack-surface-mcp-server/releases/latest/download/attack-surface-mcp-server.mcpb) [![Install in Cursor](https://cursor.com/deeplink/mcp-install-dark.svg)](https://cursor.com/en/install-mcp?name=attack-surface-mcp-server&config=eyJjb21tYW5kIjoibnB4IiwiYXJncyI6WyIteSIsIkBjeWFuaGVhZHMvYXR0YWNrLXN1cmZhY2UtbWNwLXNlcnZlciJdfQ==) [![Install in VS Code](https://img.shields.io/badge/VS_Code-Install_Server-0098FF?style=for-the-badge&logo=visualstudiocode&logoColor=white)](https://vscode.dev/redirect?url=vscode:mcp/install?%7B%22name%22%3A%22attack-surface-mcp-server%22%2C%22command%22%3A%22npx%22%2C%22args%22%3A%5B%22-y%22%2C%22%40cyanheads%2Fattack-surface-mcp-server%22%5D%7D)

[![Framework](https://img.shields.io/badge/Built%20on-@cyanheads/mcp--ts--core-67E8F9?style=flat-square)](https://www.npmjs.com/package/@cyanheads/mcp-ts-core)

</div>

---

> [!IMPORTANT]
> **Authorized, defensive use only.** Point this server only at assets you own or are explicitly authorized to assess. It performs **passive, non-intrusive** reconnaissance — it reads public records (Certificate Transparency logs, DNS, RDAP/WHOIS) and each target's *own* published surface (one TLS handshake and one HTTP GET per host). It does **not** port-scan, exploit, brute-force, fuzz, or probe for vulnerabilities; that capability is excluded from the surface by design, not gated behind a flag. Output is descriptive — what exists and what the security posture is — never an exploitation plan. Every outbound connection passes an SSRF guard that refuses private, loopback, link-local, and cloud-metadata targets.

---

## Tools

Eight tools organized around the recon workflow — `attacksurface_map_domain` orchestrates the full flow end to end, the per-aspect tools back it for targeted follow-up, and `attacksurface_recon_guidance` synthesizes findings into a defensive review plan. Seven are keyless; one (`attacksurface_lookup_host`) needs a Shodan key and degrades gracefully without it.

| Tool | Description |
|:---|:---|
| `attacksurface_map_domain` | Flagship workflow. Maps a domain's external surface end to end: CT-log subdomain discovery → DNS liveness → (standard+) DNS records, TLS posture, HTTP headers/tech → optional RDAP/WHOIS → (thorough + key) per-IP Shodan enrichment. Returns a structured surface map and a defensive assessment of observable facts. |
| `attacksurface_enumerate_subdomains` | Passive subdomain discovery from Certificate Transparency logs (crt.sh → Certspotter → TLS-SAN fallback chain), with DNS resolution to mark which names are live. Per-source provenance; no DNS brute-forcing. |
| `attacksurface_resolve_dns` | Resolve and enumerate DNS records (A/AAAA/CNAME/MX/NS/TXT/CAA) for one or more hosts across multiple public resolvers, with optional reverse DNS (PTR). Per-resolver values surface propagation gaps. |
| `attacksurface_inspect_tls` | Inspect TLS/SSL posture via a real read-only handshake: protocol, cipher, full certificate chain, SANs, validity window, days-to-expiry, issuer, validation status. Reports invalid/expired/self-signed certs instead of failing. |
| `attacksurface_probe_http` | Passive HTTP(S) probe: one GET following redirects. Returns status, redirect chain, headers, a security-header audit (HSTS/CSP/X-Frame-Options/cookie flags/CORS reflection), and an evidence-bound technology fingerprint. |
| `attacksurface_lookup_registration` | Registration and ownership lookup via RDAP (JSON; WHOIS fallback). A domain returns registrar, status, lifecycle events, nameservers, DNSSEC; an IP/CIDR returns netblock, allocation CIDRs, origin ASN, country. |
| `attacksurface_lookup_host` | Infrastructure intelligence for a single IP (open ports, banners, software versions, ASN, geo) or a faceted internet-wide search, via Shodan. **Requires `SHODAN_API_KEY`** — returns a typed `source_unavailable` error when unset; the rest of the server is unaffected. |
| `attacksurface_recon_guidance` | Offline synthesis over findings gathered so far. Returns a prioritized **defensive** review plan plus pre-filled follow-up calls (which certs to renew, which hosts to inspect, which software versions to check for CVEs against an external NVD/OSV server). No external calls. |

### `attacksurface_map_domain`

The spine of most engagements — one call maps a domain end to end.

- `depth` control: `quick` = subdomains + liveness only; `standard` = + DNS records, TLS, and HTTP posture; `thorough` = + Shodan enrichment (when a key is present, otherwise skipped with a note)
- `includeRegistration` adds an RDAP/WHOIS lookup for the apex at standard+ depth
- All per-host fan-out uses `Promise.allSettled` — one failed source or unreachable host degrades to a note, never tanks the call
- Subdomain resolution is capped (`ATTACKSURFACE_MAX_SUBDOMAINS`, default 200) with the cap disclosed when hit
- The `assessment` block synthesizes only observable facts — expiring certs, missing HSTS/CSP, weak TLS versions, failed chain validation — never an exploitation path

---

### `attacksurface_enumerate_subdomains`

Passive subdomain discovery from public Certificate Transparency logs.

- Three sources with a fallback chain: crt.sh (primary), Certspotter (fallback — crt.sh is frequently overloaded), and the apex's own TLS certificate SAN list (always available)
- Every discovered name carries its source provenance
- DNS resolution marks which names are live; `includeUnresolved: false` returns only live hosts
- Reads public logs — it does not brute-force or probe the target's resolvers

---

### `attacksurface_resolve_dns`

Multi-resolver DNS enumeration with propagation visibility.

- Queries A, AAAA, CNAME, MX, NS, TXT, and CAA across multiple public resolvers (default `8.8.8.8`, `1.1.1.1`, `9.9.9.9`)
- Reports per-resolver answers so propagation gaps and split-horizon DNS are visible
- Optional reverse DNS (PTR) on resolved addresses
- Each host passes the SSRF guard; private/loopback resolver IPs are rejected; one failing host degrades to a per-host error

---

### `attacksurface_inspect_tls`

Read-only TLS posture inspection — surfacing problems is the point.

- A real handshake per host reports negotiated protocol and cipher, the full certificate chain, SANs, validity window, days-to-expiry, issuer, and chain-validation status
- Invalid, expired, and self-signed certificates are inspected and reported rather than throwing
- Posture findings flag short expiry windows, deprecated protocols, and self-signed chains
- One handshake per host; no application data is sent; SSRF-guarded

---

### `attacksurface_probe_http`

A single passive HTTP(S) GET with a security read-out.

- Follows redirects and reports the final status plus the full redirect chain
- Security-header audit: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, cookie Secure/HttpOnly/SameSite flags, and CORS origin-reflection
- Evidence-bound technology fingerprint (server, framework, CDN, WAF, CMS) — every detection names the header or body marker that triggered it
- Strictly one request per host — no path traversal, parameter injection, or multi-method probing; every redirect hop is re-checked against the SSRF guard

---

### `attacksurface_lookup_registration`

Registration and ownership from public registries.

- RDAP first (structured JSON, manual 302-follow with a fresh 5s timeout covering SSRF validation and the request for each hop, plus a five-redirect cap), WHOIS port-43 fallback for TLDs without RDAP or when a hop is unresponsive
- Domain lookups return registrar, EPP status codes, registration/expiry/updated events, nameservers, and DNSSEC
- IP/CIDR lookups return the netblock name, allocation CIDRs, origin ASN, and country
- Registry data is frequently redacted or sparse — absent fields are reported as unknown, never inferred

---

### `attacksurface_lookup_host`

Shodan infrastructure intelligence — the one optional-key path.

- `mode: "host"` (default) — a free single-IP lookup: open ports, service banners, software versions, hostnames, ASN, geo
- `mode: "search"` — a faceted internet-wide query that consumes paid Shodan query credits
- Requires `SHODAN_API_KEY`; without it the tool returns a typed `source_unavailable` error and every other tool keeps working
- Shodan data reflects Shodan's last scan, not a live port state — the server itself never scans ports

---

### `attacksurface_recon_guidance`

State-aware synthesis — no network calls, just reasoning over what you've found.

- Takes the findings gathered so far (live hosts, TLS/cert state, missing headers, software versions, open ports) and returns a prioritized defensive review plan as markdown plus structured priority items
- Pre-fills concrete follow-up calls — re-inspecting hosts that lack posture data, and chaining disclosed software versions to an external NVD (`nist-nvd-mcp-server`) or OSV (`osv-advisory-mcp-server`) server for CVE context
- Output is a remediation/visibility plan, never an exploitation playbook

## Resources

| Type | Name | Description |
|:---|:---|:---|
| Resource | `attacksurface://surface/{domain}` | Read-once snapshot of a domain's mapped surface (subdomains, live hosts, per-host TLS/HTTP posture summary), equivalent to a standard-depth `attacksurface_map_domain` call. |

All resource data is also reachable via tools — tool-only clients lose nothing, since `attacksurface_map_domain` covers the same ground. Large maps disclose a truncation count rather than returning unbounded host detail. The server exposes no prompts; `attacksurface_recon_guidance` supplies the one "structure the next steps" pattern as a state-aware tool instead of a static template.

## Features

Built on [`@cyanheads/mcp-ts-core`](https://www.npmjs.com/package/@cyanheads/mcp-ts-core):

- Declarative tool and resource definitions — single file per primitive, framework handles registration and validation
- Unified error handling — handlers throw, framework catches, classifies, and formats
- Pluggable auth: `none`, `jwt`, `oauth`
- Swappable storage backends: `in-memory`, `filesystem`, `Supabase`, `Cloudflare KV/R2/D1`
- Structured logging with optional OpenTelemetry tracing
- STDIO and Streamable HTTP transports

Attack-surface-specific:

- Passive and non-intrusive by mandate — public records plus each target's own single published response; active scanning, exploitation, and brute-forcing are excluded from the surface, not toggled by a flag
- Keyless core — CT subdomain enumeration, DNS, TLS, HTTP/tech, and RDAP/WHOIS all work with zero API keys; Shodan is strictly additive depth
- SSRF guard on every outbound connection — rejects private, loopback, link-local, cloud-metadata, and reserved IPv4/IPv6 ranges before connecting (opt out for trusted internal assessment via `ATTACKSURFACE_ALLOW_PRIVATE_TARGETS`)
- Multi-source aggregation with fallback chains — CT discovery falls through crt.sh → Certspotter → TLS-SAN; registration falls through RDAP → WHOIS

Agent-friendly output:

- Provenance on every result — source labels (`source: crt.sh | certspotter | tls-san`, `source: rdap | whois`) and per-source status so agents can assess completeness and trust
- Graceful partial failure — multi-target and multi-source tools return per-item/per-source `error` fields and operational `notes` instead of failing the whole call; only malformed input throws
- Discriminated, typed contracts — typed error reasons (`source_unavailable`, `blocked_target`, `all_sources_failed`) and union output (`kind: domain | ip`) let callers branch on data, not string parsing
- No fabricated signal — technology detections carry their triggering evidence; absent CT/DNS/RDAP fields are reported as unknown, never inferred

## Getting started

Add the following to your MCP client configuration file. Every tool except `attacksurface_lookup_host` works with no configuration — the keyless core boots on an empty environment.

```json
{
  "mcpServers": {
    "attack-surface-mcp-server": {
      "type": "stdio",
      "command": "bunx",
      "args": ["@cyanheads/attack-surface-mcp-server@latest"],
      "env": {
        "MCP_TRANSPORT_TYPE": "stdio",
        "MCP_LOG_LEVEL": "info"
      }
    }
  }
}
```

Or with npx (no Bun required):

```json
{
  "mcpServers": {
    "attack-surface-mcp-server": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "@cyanheads/attack-surface-mcp-server@latest"],
      "env": {
        "MCP_TRANSPORT_TYPE": "stdio",
        "MCP_LOG_LEVEL": "info"
      }
    }
  }
}
```

Or with Docker:

```json
{
  "mcpServers": {
    "attack-surface-mcp-server": {
      "type": "stdio",
      "command": "docker",
      "args": ["run", "-i", "--rm", "-e", "MCP_TRANSPORT_TYPE=stdio", "ghcr.io/cyanheads/attack-surface-mcp-server:latest"]
    }
  }
}
```

To enable Shodan host intelligence (`attacksurface_lookup_host`), add `SHODAN_API_KEY` to the `env` block.

For Streamable HTTP, set the transport and start the server:

```sh
MCP_TRANSPORT_TYPE=http MCP_HTTP_PORT=3010 bun run start:http
# Server listens at http://localhost:3010/mcp
```

Refer to "your MCP client configuration file" generically — different clients use different config paths and this server isn't client-specific.

### Prerequisites

- [Bun v1.3.0](https://bun.sh/) or higher (or Node.js v24+).
- No API key required for the core tools. Optional: a [Shodan API key](https://account.shodan.io/) for `attacksurface_lookup_host`, and a [Certspotter API key](https://sslmate.com/certspotter/api/) to raise CT-fallback rate limits.

### Installation

1. **Clone the repository:**

```sh
git clone https://github.com/cyanheads/attack-surface-mcp-server.git
```

2. **Navigate into the directory:**

```sh
cd attack-surface-mcp-server
```

3. **Install dependencies:**

```sh
bun install
```

4. **Configure environment (optional):**

```sh
cp .env.example .env
# edit .env only if you want Shodan, a Certspotter key, or non-default behavior
```

## Configuration

All variables are optional — the server boots and delivers its keyless core with an empty environment.

| Variable | Description | Default |
|:---------|:------------|:--------|
| `SHODAN_API_KEY` | Enables `attacksurface_lookup_host`. Absent → that tool returns `source_unavailable`; every other tool keeps working. | — |
| `CERTSPOTTER_API_KEY` | Raises Certspotter rate limits for the CT-log subdomain fallback. Absent → free unauthenticated tier (rate-limited but functional). | — |
| `ATTACKSURFACE_DEFAULT_RESOLVERS` | Comma-separated default DNS resolver IPs for `attacksurface_resolve_dns`. | `8.8.8.8,1.1.1.1,9.9.9.9` |
| `ATTACKSURFACE_HTTP_USER_AGENT` | Default User-Agent for `attacksurface_probe_http` (overridable per call). | identifies the server honestly |
| `ATTACKSURFACE_MAX_SUBDOMAINS` | Cap on subdomains resolved during a `map_domain` run — bounds fan-out cost. | `200` |
| `ATTACKSURFACE_RDAP_BOOTSTRAP_URL` | RDAP bootstrap base URL; override for a private/mirrored RDAP. | `https://rdap.org` |
| `ATTACKSURFACE_ALLOW_PRIVATE_TARGETS` | Set `true` to disable the SSRF guard for internal-network assessment. **Leave `false` on any public deployment** — it is the safety boundary that keeps the server from being pointed at internal infrastructure. | `false` |
| `MCP_TRANSPORT_TYPE` | Transport: `stdio` or `http`. | `stdio` |
| `MCP_HTTP_PORT` | Port for HTTP server. | `3010` |
| `MCP_AUTH_MODE` | Auth mode: `none`, `jwt`, or `oauth`. | `none` |
| `MCP_LOG_LEVEL` | Log level (RFC 5424). | `info` |
| `OTEL_ENABLED` | Enable [OpenTelemetry instrumentation](https://github.com/cyanheads/mcp-ts-core/tree/main/docs/telemetry). | `false` |

See [`.env.example`](./.env.example) for the full list of optional overrides.

## Running the server

### Local development

- **Build and run:**

  ```sh
  # One-time build
  bun run rebuild

  # Run the built server
  bun run start:stdio
  # or
  bun run start:http
  ```

- **Run checks and tests:**

  ```sh
  bun run devcheck   # Lint, format, typecheck, security
  bun run test       # Vitest test suite
  bun run lint:mcp   # Validate MCP definitions against spec
  ```

### Docker

```sh
docker build -t attack-surface-mcp-server .
docker run --rm -e MCP_TRANSPORT_TYPE=http -p 3010:3010 attack-surface-mcp-server
```

The Dockerfile defaults to HTTP transport, stateless session mode, and logs to `/var/log/attack-surface-mcp-server`. OpenTelemetry peer dependencies are installed by default — build with `--build-arg OTEL_ENABLED=false` to omit them.

## Project structure

| Directory | Purpose |
|:----------|:--------|
| `src/index.ts` | `createApp()` entry point — registers tools/resources and inits the six services. |
| `src/config` | Server-specific environment variable parsing and validation with Zod. |
| `src/mcp-server/tools` | Tool definitions (`*.tool.ts`). |
| `src/mcp-server/resources` | Resource definitions (`*.resource.ts`). |
| `src/services` | Domain service integrations (`ct`, `dns`, `tls`, `http`, `registration`, `shodan`). |
| `src/utils` | SSRF guard and input validation. |
| `tests/` | Unit and integration tests mirroring `src/`. |

## Development guide

See [`CLAUDE.md`/`AGENTS.md`](./CLAUDE.md) for development guidelines and architectural rules. The short version:

- Handlers throw, framework catches — no `try/catch` in tool logic
- Use `ctx.log` for request-scoped logging, `ctx.state` for tenant-scoped storage
- Register new tools and resources via the barrels in `src/mcp-server/*/definitions/index.ts`
- Every outbound connection to a user-supplied target must pass the SSRF guard (`assertSafeDomain` / `assertSafeUrl` / `assertSafeResolverIp`) before connecting
- Wrap external API calls: validate raw → normalize to domain type → return output schema; never fabricate missing fields

## Contributing

Issues and pull requests are welcome. Run checks and tests before submitting:

```sh
bun run devcheck
bun run test
```

## License

Apache-2.0 — see [LICENSE](LICENSE) for details.
