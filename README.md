<div align="center">
  <h1>@cyanheads/attack-surface-mcp-server</h1>
  <p><b>Passive external attack-surface mapping: CT subdomains, DNS, TLS, HTTP posture, RDAP/WHOIS, Shodan via MCP. STDIO or Streamable HTTP.</b>
  <div>8 Tools • 1 Resource</div>
  </p>
</div>

<div align="center">

[![Version](https://img.shields.io/badge/Version-0.2.3-blue.svg?style=flat-square)](./CHANGELOG.md) [![License](https://img.shields.io/badge/License-Apache%202.0-orange.svg?style=flat-square)](./LICENSE) [![Docker](https://img.shields.io/badge/Docker-ghcr.io-2496ED?style=flat-square&logo=docker&logoColor=white)](https://github.com/users/cyanheads/packages/container/package/attack-surface-mcp-server) [![MCP SDK](https://img.shields.io/badge/MCP%20SDK-^2.1.0-green.svg?style=flat-square)](https://modelcontextprotocol.io/) [![npm](https://img.shields.io/npm/v/%40cyanheads%2Fattack-surface-mcp-server?style=flat-square&logo=npm&logoColor=white)](https://www.npmjs.com/package/@cyanheads/attack-surface-mcp-server) [![TypeScript](https://img.shields.io/badge/TypeScript-^7.0.2-3178C6.svg?style=flat-square)](https://www.typescriptlang.org/) [![Bun](https://img.shields.io/badge/Bun-v1.4.2%2B-blueviolet.svg?style=flat-square)](https://bun.sh/)

</div>

<div align="center">

[![Install in Claude Desktop](https://img.shields.io/badge/Install_in-Claude_Desktop-D97757?style=for-the-badge&logo=anthropic&logoColor=white)](https://github.com/cyanheads/attack-surface-mcp-server/releases/latest/download/attack-surface-mcp-server.mcpb) [![Install in Cursor](https://cursor.com/deeplink/mcp-install-dark.svg)](https://cursor.com/en/install-mcp?name=attack-surface-mcp-server&config=eyJjb21tYW5kIjoibnB4IiwiYXJncyI6WyIteSIsIkBjeWFuaGVhZHMvYXR0YWNrLXN1cmZhY2UtbWNwLXNlcnZlciJdfQ==) [![Install in VS Code](https://img.shields.io/badge/VS_Code-Install_Server-0098FF?style=for-the-badge&logo=visualstudiocode&logoColor=white)](https://vscode.dev/redirect?url=vscode:mcp/install?%7B%22name%22%3A%22attack-surface-mcp-server%22%2C%22command%22%3A%22npx%22%2C%22args%22%3A%5B%22-y%22%2C%22%40cyanheads%2Fattack-surface-mcp-server%22%5D%7D)

[![Framework](https://img.shields.io/badge/Built%20on-@cyanheads/mcp--ts--core-67E8F9?style=flat-square)](https://www.npmjs.com/package/@cyanheads/mcp-ts-core)

</div>

---

> [!IMPORTANT]
> **Authorized, defensive use only.** Point this server only at assets you own or are explicitly authorized to assess. It performs **passive, non-intrusive** reconnaissance — it reads public records (Certificate Transparency logs, DNS, RDAP/WHOIS) and each target's *own* published surface (one TLS handshake and one HTTP GET per host). It does **not** port-scan, exploit, brute-force, fuzz, or probe for vulnerabilities; that capability is excluded from the surface by design, not gated behind a flag. Output is descriptive — what exists and what the security posture is — never an exploitation plan. Every outbound connection passes an SSRF guard that refuses private, loopback, link-local, and cloud-metadata targets.

---

## Overview

Passive external attack-surface mapping (EASM) over Certificate Transparency logs, DNS, TLS, HTTP, and RDAP/WHOIS registries, with optional Shodan host intelligence. Discover subdomains, resolve DNS records, and inspect TLS and HTTP security posture across a domain's live hosts. Runs as a stdio process or a local Streamable HTTP server.

### Tools

| Tool | Description |
|:---|:---|
| `attacksurface_map_domain` | Flagship workflow. Maps a domain's external surface end to end: CT-log subdomain discovery → DNS liveness → (standard+) DNS records, TLS posture, HTTP headers/tech → optional RDAP/WHOIS → (thorough + key) per-IP Shodan enrichment. Returns a structured surface map and a defensive assessment of observable facts. |
| `attacksurface_enumerate_subdomains` | Passive subdomain discovery from Certificate Transparency logs (crt.sh → Certspotter → TLS-SAN fallback chain), with DNS resolution to mark which names are live. Per-source provenance; no DNS brute-forcing. |
| `attacksurface_resolve_dns` | Resolve and enumerate DNS records (A/AAAA/CNAME/MX/NS/TXT/CAA) for one or more hosts across multiple public resolvers, with optional reverse DNS (PTR). Per-resolver values surface propagation gaps. |
| `attacksurface_inspect_tls` | Inspect TLS/SSL posture via a real read-only handshake: protocol, cipher, leaf certificate and chain depth, SANs, validity window, days-to-expiry, issuer, validation status. Reports invalid/expired/self-signed certs instead of failing. |
| `attacksurface_probe_http` | Passive HTTP(S) probe: one GET following redirects. Returns status, redirect chain, headers, a security-header audit (HSTS/CSP/X-Frame-Options/cookie flags/CORS reflection), and an evidence-bound technology fingerprint. |
| `attacksurface_lookup_registration` | Registration and ownership lookup via RDAP (JSON; WHOIS fallback). A domain returns registrar, status, lifecycle events, nameservers, DNSSEC; an IP/CIDR returns netblock, allocation CIDRs, origin ASN, country. |
| `attacksurface_lookup_host` | Infrastructure intelligence for a single IP (open ports, banners, software versions, ASN, geo) or a faceted internet-wide search, via Shodan. **Requires `SHODAN_API_KEY`** — returns a typed `source_unavailable` error when unset; the rest of the server is unaffected. |
| `attacksurface_recon_guidance` | Offline synthesis over findings gathered so far. Returns a prioritized **defensive** review plan plus pre-filled follow-up calls (which certs to renew, which hosts to inspect, which software versions to check for CVEs against an external NVD/OSV server). No external calls. |

### Resources

| Resource | Description |
|:---|:---|
| `attacksurface://surface/{domain}` | Read-once snapshot of a domain's mapped external surface (subdomains, live hosts, per-host TLS/HTTP posture summary), equivalent to a standard-depth `attacksurface_map_domain` call. |

All resource data is also reachable via tools — tool-only clients lose nothing, since `attacksurface_map_domain` covers the same ground.

## Capability reference

### `attacksurface_map_domain` <sub>tool</sub>

- `depth`: `quick` discovers subdomains and liveness; `standard` adds DNS records, TLS, and HTTP posture; `thorough` adds per-IP Shodan data when a key is present, otherwise a note.
- Returns a structured surface map and defensive `assessment` of observable facts. Failed sources or unreachable hosts become notes; subdomain resolution is capped by `ATTACKSURFACE_MAX_SUBDOMAINS` (default 200), with truncation disclosed.
- `includeRegistration` adds RDAP/WHOIS data for the apex at standard or thorough depth.

---

### `attacksurface_enumerate_subdomains` <sub>tool</sub>

- Discovers names through crt.sh → Certspotter → the apex TLS certificate SANs, then resolves DNS liveness. `includeUnresolved: false` keeps only live hosts.
- Returns each name's source provenance and per-source status; no DNS brute-forcing or target-resolver probing.

---

### `attacksurface_resolve_dns` <sub>tool</sub>

- Accepts up to 50 hosts and queries A, AAAA, CNAME, MX, NS, TXT, and CAA across public resolvers (default `8.8.8.8`, `1.1.1.1`, `9.9.9.9`); reverse DNS (PTR) is optional.
- Returns per-resolver answers to expose propagation gaps. Private or loopback resolver IPs produce `blocked_resolver`; an individual host failure becomes a per-host error.
- Canonical records come from the first configured resolver. Resolver failures (including SERVFAIL) remain in `queryError` and `hostError` alongside any successful records; absent records are error-free.

---

### `attacksurface_inspect_tls` <sub>tool</sub>

- Accepts up to 50 hosts; port defaults to 443 and handshake timeout to 8000ms (1000–30000ms).
- Returns negotiated protocol, cipher, leaf certificate and chain depth, SANs, issuer, validity window, days to expiry, and validation status. Invalid, expired, and self-signed certificates are reported; one host failure becomes a per-host error.
- Unparseable validity bounds retain their raw values and add findings. `daysUntilExpiry` is null only when expiry cannot be parsed; a malformed start date does not erase a known expiry.

---

### `attacksurface_probe_http` <sub>tool</sub>

- Accepts one HTTP(S) URL; timeout defaults to 10000ms (1000–30000ms). Follows up to ten redirects with an SSRF check at every hop; a refused target produces `blocked_target`. Another redirect at the limit returns `finalStatus: 0` and a `transportError`.
- Returns status, redirect chain, headers, security-header findings (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, cookie flags, CORS reflection), and technology detections with their triggering evidence.
- Cloudflare server banners identify a CDN; AWS ELB banners identify edge infrastructure (`other`). Neither banner alone establishes WAF protection.

---

### `attacksurface_lookup_registration` <sub>tool</sub>

- Accepts a domain, IP, or CIDR; `type` (`auto` / `domain` / `ip`) controls interpretation. Uses RDAP first, then WHOIS port 43 when needed.
- Domain results include registrar, EPP statuses, lifecycle events, nameservers, and DNSSEC; IP/CIDR results include netblock, allocation CIDRs, ASN, and country. Sparse or redacted fields stay unknown.

---

### `attacksurface_lookup_host` <sub>tool</sub>

- `mode: "host"` (default) looks up one IP; `mode: "search"` accepts an internet-wide query with optional `facets` and may consume Shodan query credits. Requires `SHODAN_API_KEY`.
- Both modes reject blank targets. Host mode accepts bare IPv4/IPv6 addresses and returns `invalid_target` for other syntax before contacting Shodan; search queries are preserved verbatim.
- Returns ports, banners, software versions, hostnames, ASN, and geography from Shodan's last scan. Missing credentials produce `source_unavailable`; no host data produces `no_data`. The server performs no port scans.

---

### `attacksurface_recon_guidance` <sub>tool</sub>

- Takes prior findings (hosts, certificates, missing headers, software versions, ports); `topic` (`triage` / `posture` / `coverage`) selects the plan's emphasis.
- Returns markdown guidance, structured priority items, and pre-filled follow-up calls, including external NVD/OSV lookups. Runs offline and produces a defensive remediation or visibility plan.

---

### `attacksurface://surface/{domain}` <sub>resource</sub>

- Takes a domain and returns an `application/json` snapshot equivalent to a standard-depth `attacksurface_map_domain` call.
- Includes subdomain and live-host counts plus per-host TLS/HTTP posture. Caps host detail at 50 live hosts, discloses omissions, and points to `attacksurface_map_domain` for the full set.

## Features

Built on [`@cyanheads/mcp-ts-core`](https://github.com/cyanheads/mcp-ts-core): stdio and Streamable HTTP transports, pluggable auth (`none` / `jwt` / `oauth`), swappable storage (`in-memory`, `filesystem`, `Supabase`, `Cloudflare KV/R2/D1`), structured logging with optional OpenTelemetry tracing.

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

### Prerequisites

- [Bun v1.4.0](https://bun.sh/) or higher (or Node.js v24+).
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
| `ATTACKSURFACE_HTTP_USER_AGENT` | Default User-Agent for `attacksurface_probe_http` (overridable per call). | `attack-surface-mcp-server/passive-recon (+https://github.com/cyanheads/attack-surface-mcp-server)` |
| `ATTACKSURFACE_MAX_SUBDOMAINS` | Cap on subdomains resolved during a `map_domain` run — bounds fan-out cost. | `200` |
| `ATTACKSURFACE_RDAP_BOOTSTRAP_URL` | RDAP bootstrap base URL; override for a private/mirrored RDAP. | `https://rdap.org` |
| `ATTACKSURFACE_ALLOW_PRIVATE_TARGETS` | Set `true` to disable the SSRF guard for internal-network assessment. **Leave `false` on any public deployment** — it is the safety boundary that keeps the server from being pointed at internal infrastructure. | `false` |
| `MCP_TRANSPORT_TYPE` | Transport: `stdio` or `http`. | `stdio` |
| `MCP_HTTP_PORT` | Port for HTTP server. | `3010` |
| `MCP_SESSION_MODE` | HTTP session mode: `stateless`, `stateful`, or `auto`. The server declares `stateless`; a value set here overrides it. Ignored under stdio. | `stateless` |
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

Issues are welcome. Run checks and tests before submitting:

```sh
bun run devcheck
bun run test
```

## License

Apache-2.0 — see [LICENSE](LICENSE) for details.
