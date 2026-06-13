# attack-surface-mcp-server — Design

> **Authorized, defensive use only.** This server performs **passive, non-intrusive** external attack-surface mapping (EASM) and asset reconnaissance. It reads public records (Certificate Transparency, DNS, RDAP/WHOIS) and a target's own published surface (TLS handshake, HTTP response headers). It does **not** port-scan, exploit, brute-force, fuzz, or probe for vulnerabilities. Assess only assets you own or are explicitly authorized to test.

## MCP Surface

### Tools

| Name | Description | Key Inputs | Annotations |
|:-----|:------------|:-----------|:------------|
| `attacksurface_map_domain` | Flagship workflow. Maps a domain's external surface end to end: CT-log subdomain discovery → DNS resolution of each candidate → TLS posture + HTTP headers/tech for live hosts → optional Shodan host enrichment. Returns a structured surface map (subdomains, live hosts, per-host posture, registration) with a `depth` control. | `domain`, `depth` (`quick`\|`standard`\|`thorough`), `include_registration` | `readOnlyHint: true`, `openWorldHint: true` |
| `attacksurface_enumerate_subdomains` | Passive subdomain discovery from Certificate Transparency logs, with DNS resolution to mark which are live. crt.sh primary, Certspotter fallback, TLS SAN list as a third source. No DNS brute-forcing. | `domain`, `include_unresolved`, `sources` | `readOnlyHint: true`, `openWorldHint: true` |
| `attacksurface_resolve_dns` | Resolve and enumerate DNS records (A/AAAA/MX/NS/TXT/CAA/CNAME) for one or more hosts across multiple public resolvers, plus optional reverse DNS (PTR) for resolved IPs. Reports per-resolver values to surface propagation gaps. | `hosts[]`, `record_types[]`, `resolvers[]`, `reverse` | `readOnlyHint: true`, `openWorldHint: true`, `idempotentHint: true` |
| `attacksurface_inspect_tls` | Inspect TLS/SSL posture for one or more hosts via a real read-only handshake: negotiated protocol + cipher, full certificate chain, SANs, validity window, days-to-expiry, issuer, and validation status. Inspects invalid/expired/self-signed certs without failing. | `hosts[]`, `port`, `timeout_ms` | `readOnlyHint: true`, `openWorldHint: true`, `idempotentHint: true` |
| `attacksurface_probe_http` | Passive HTTP(S) probe of a URL: a single GET, following redirects. Returns status, the redirect chain, response headers, a security-header audit (HSTS/CSP/X-Frame-Options/cookie flags/CORS reflection), and a technology fingerprint (server, framework, CDN, WAF, CMS) from headers and lightweight body markers. One request per host — no path traversal, no parameter injection, no multi-method probing. | `url`, `user_agent`, `timeout_ms` | `readOnlyHint: true`, `openWorldHint: true` |
| `attacksurface_lookup_registration` | Registration and ownership lookup via RDAP (JSON; WHOIS fallback for TLDs without RDAP). Accepts a domain (registrar, status, created/expiry/updated events, nameservers, DNSSEC) or an IP/CIDR (netblock, allocation, origin ASN, country). | `target`, `type` (`auto`\|`domain`\|`ip`) | `readOnlyHint: true`, `openWorldHint: true` |
| `attacksurface_lookup_host` | Infrastructure intelligence for a single IP or a faceted internet-wide search, powered by Shodan. Single-host lookup (open ports, service banners, software versions, hostnames, ASN, geo) uses the free host endpoint; faceted search (`mode: search`) consumes paid query credits. **Requires `SHODAN_API_KEY`** — fails with a typed `source_unavailable` error when unset, and the rest of the server still works. | `target`, `mode` (`host`\|`search`), `facets[]` | `readOnlyHint: true`, `openWorldHint: true` |
| `attacksurface_recon_guidance` | Instruction tool. Given the findings gathered so far (passed in from prior tool calls), returns a prioritized, **defensive** review plan as markdown plus pre-filled follow-up tool calls — which hosts to inspect next, which expiring certs to flag, which software versions warrant a CVE lookup against an external NVD server. Read-only; no writes, no external calls. | `findings`, `topic` (`triage`\|`posture`\|`coverage`) | `readOnlyHint: true`, `openWorldHint: false` |

**8 tools.** Seven keyless-core (1–6, 8); one optional-key (7, Shodan).

### Resources

| URI Template | Description | Pagination |
|:-------------|:------------|:-----------|
| `attacksurface://surface/{domain}` | Read-once snapshot of a domain's mapped surface (subdomains + live hosts + per-host posture summary), equivalent to a `standard`-depth `attacksurface_map_domain` call. Convenience for clients that support injectable context; the same data is fully reachable via the tool. | None (single document; large maps truncate host detail with a disclosed count) |

One resource. Tool-only clients lose nothing — `attacksurface_map_domain` covers it.

### Prompts

None. The workflow is data/action-oriented, and `attacksurface_recon_guidance` already supplies the one "structure the next steps" pattern as a state-aware tool (reachable by tool-only clients) rather than a static template.

## Overview

`attack-surface-mcp-server` is a **multi-source external attack-surface-mapping server for authorized, defensive security assessment**. The user workflow is *"I have a target I own or am authorized to assess — map its external surface and characterize its security posture from public records and its own published endpoints."* It serves blue-team engineers auditing their own estate, authorized pentesters/bug-bounty hunters in the passive-recon phase, and developers checking their own apps' header/TLS hygiene.

It is a **multi-source aggregation server**: the tool surface is organized around the recon workflow (discover subdomains → resolve → inspect posture → look up ownership → enrich), and the individual data sources (crt.sh, Certspotter, DoH resolvers, `node:dns`, `node:tls`, RDAP/WHOIS, Shodan) are service-layer details the agent never selects by name. The agent says "map this domain"; the server routes to the best available source and degrades when an optional one is missing.

**Core capabilities are keyless and passive.** CT-log subdomain enumeration, DNS resolution/enumeration, reverse DNS, TLS/certificate inspection, HTTP header + tech fingerprinting, and RDAP/WHOIS lookups all work with **zero API keys**. A single optional key (Shodan) deepens host/network intelligence; the server detects its absence and returns a typed `source_unavailable` error from the one tool that needs it, leaving every other tool fully functional.

This composes with the rest of the cyanheads fleet: detected software versions chain to `nist-nvd-mcp-server` (CVE context) and `osv-advisory-mcp-server`; discovered IPs/domains chain to `threat-intel-mcp-server` for indicator enrichment. `attacksurface_recon_guidance` pre-fills those cross-server follow-ups.

## Requirements

- **Passive and non-intrusive only.** Reconnaissance from public records (CT logs, DNS, RDAP/WHOIS) and the target's own published surface (one TLS handshake, one HTTP GET per host). **Explicitly excluded:** active port scanning, vulnerability probing, exploitation, brute-forcing (DNS or otherwise), parameter/path fuzzing, multi-method HTTP probing, and authentication attacks. These are out of scope by design — not gated behind a flag.
- **Keyless core, optional-key enrichment.** Tools 1–6 and 8 require no credentials. Tool 7 (`attacksurface_lookup_host`) requires `SHODAN_API_KEY` and degrades gracefully when unset.
- **SSRF-safe by construction.** Every outbound connection to a user-supplied target (DNS resolution, TLS handshake, HTTP GET) must pass an SSRF guard that rejects hosts resolving to private, loopback, link-local, or cloud-metadata (`169.254.169.254`) ranges, and rejects private/loopback resolver IPs. This is the security spine of a server that connects to arbitrary user-named hosts. (Pattern proven in `devops-status-mcp-server`'s `ssrf-guard.ts`; port this repo's own copy — see Implementation Order.) The guard exports three functions: `assertSafeDomain(domain)` for bare host inputs (DNS, TLS), `assertSafeUrl(rawUrl)` for URL inputs (`probe_http`), and `assertSafeResolverIp(ip)` for resolver IP validation — all must be called before any outbound connection.
- **Authorized-use framing on the surface.** The server `instructions`, the flagship tool description, and the guidance tool all state that the target must be owned or authorized for assessment. Output is descriptive (what exists, what the posture is), never an exploitation plan.
- **Graceful per-target degradation.** Multi-target tools (`resolve_dns`, `inspect_tls`) and multi-source tools (`enumerate_subdomains`, `map_domain`) use `Promise.allSettled`: one failing host or one down source degrades to a per-item/per-source `error` field, never tanks the whole call. Only malformed *input* throws.
- **Source provenance in output.** Every aggregated result names which source(s) supplied it (`source: 'crt.sh' | 'certspotter' | 'tls-san'`, `enriched_by: 'shodan'`) so the agent and human can assess completeness and trust.
- **Rate-limit resilience.** crt.sh is unreliable (frequent 502s, observed live during design); the CT source is a fallback chain (crt.sh → Certspotter → TLS SAN), not a single dependency. Shodan and Certspotter free tiers are rate-limited; service layer uses `withRetry` with calibrated backoff.
- **No fabricated signal.** Tech fingerprinting reports detections with the evidence that triggered them (header name/value, body marker) — no invented "confidence %" composites. Absent CT/DNS/RDAP fields are reported as unknown, never inferred.

## Services

| Service | Wraps | Used By |
|:--------|:------|:--------|
| `ct-service` | crt.sh JSON API (`/json?q=`) + Certspotter issuances API (`api.certspotter.com/v1/issuances`); fallback chain | `enumerate_subdomains`, `map_domain` |
| `dns-service` | `node:dns/promises` `Resolver` (multi-resolver, `setServers`) + reverse PTR | `resolve_dns`, `enumerate_subdomains`, `map_domain` |
| `tls-service` | `node:tls` read-only handshake (`rejectUnauthorized: false`) → cert chain, protocol, cipher | `inspect_tls`, `map_domain` |
| `http-service` | `fetchWithTimeout` GET + header/cookie parsing + tech-fingerprint ruleset | `probe_http`, `map_domain` |
| `registration-service` | RDAP over `rdap.org` bootstrap (follows 302 redirect to authoritative RR) + WHOIS fallback (`node:net` 43) | `lookup_registration`, `map_domain` |
| `shodan-service` | Shodan REST (`/shodan/host/{ip}` free, `/shodan/host/search` paid) | `lookup_host`, `map_domain` (opportunistic) |

Each external-API service (`ct`, `registration`, `shodan`) carries its own retry/backoff and parse-classification config. `dns`/`tls`/`http` are pure-runtime (Node built-ins) with timeouts but no upstream auth. The SSRF guard (`src/utils/ssrf-guard.ts`) is a shared util consumed by `dns`, `tls`, and `http` services — not a service itself. Init/accessor pattern; all wired in `createApp().setup()`.

## Config

| Env Var | Required | Description |
|:--------|:---------|:------------|
| `SHODAN_API_KEY` | No | Enables `attacksurface_lookup_host`. Absent → that tool returns `source_unavailable`; rest of server unaffected. |
| `CERTSPOTTER_API_KEY` | No | Raises Certspotter rate limits for the CT fallback. Absent → free unauthenticated tier (rate-limited but functional). |
| `ATTACKSURFACE_DEFAULT_RESOLVERS` | No | Comma-separated resolver IPs for `resolve_dns` (default `8.8.8.8,1.1.1.1,9.9.9.9`). |
| `ATTACKSURFACE_HTTP_USER_AGENT` | No | Default UA for `probe_http` (default identifies the server honestly; overridable per call). |
| `ATTACKSURFACE_MAX_SUBDOMAINS` | No | Cap on subdomains resolved during a `map_domain` run (default 200) — bounds fan-out cost. |
| `ATTACKSURFACE_RDAP_BOOTSTRAP_URL` | No | RDAP bootstrap base (default `https://rdap.org`); override for a private/mirrored RDAP. |

All in `src/config/server-config.ts` as a separate Zod schema via `parseEnvConfig`. `z.stringbool()` for any boolean flags. No required vars — the server boots and delivers core value with an empty environment.

## Implementation Order

1. **Config + server setup** — `server-config.ts` (schema above), `createApp()` with identity (`name`/`title` = `attack-surface-mcp-server`) and authorized-use `instructions`. Strip echo definitions.
2. **`ssrf-guard.ts` util** — port `assertSafeDomain` / `assertSafeResolverIp` from `devops-status-mcp-server`. **Hard prerequisite** for any tool that connects out; build and unit-test it first (private/loopback/link-local/metadata ranges, IPv6).
3. **Pure-runtime services** — `dns-service`, `tls-service`, `http-service` (Node built-ins, SSRF-guarded). Independently testable against live hosts you control.
4. **External-API services** — `ct-service` (crt.sh + Certspotter fallback), `registration-service` (RDAP + WHOIS). `withRetry` + parse classification.
5. **Read-only tools, keyless first** — `resolve_dns`, `inspect_tls`, `probe_http`, `lookup_registration`, `enumerate_subdomains`. Each maps to the services above; soft per-target errors.
6. **`shodan-service` + `lookup_host`** — the one key-gated path; `source_unavailable` contract when key absent.
7. **`map_domain`** — the flagship workflow that composes all services (fan-out via `Promise.allSettled`, `depth` gating, opportunistic Shodan).
8. **`recon_guidance`** instruction tool — pure synthesis over passed-in findings; `nextToolSuggestions` pre-filled (incl. cross-server NVD/OSV/threat-intel calls).
9. **`attacksurface://surface/{domain}` resource** — thin wrapper over `map_domain` at `standard` depth.
10. **Tests + field-test + security-pass** — sparse-payload cases (CT down, RDAP `country: null`, invalid cert), SSRF rejection cases, fuzz.

Each step is independently testable.

## Workflow Analysis

`attacksurface_map_domain` is the only multi-call tool. Call flow by `depth`:

| # | Call | Source | Purpose | Depth gate |
|:--|:-----|:-------|:--------|:-----------|
| 1 | CT search | crt.sh → Certspotter | Enumerate subdomain candidates from issued certs | always |
| 2 | DNS resolve (per candidate, capped, parallel) | `node:dns` | Mark which candidates are live; collect IPs | always |
| 3 | DNS records (apex + live hosts) | `node:dns` | A/AAAA/MX/NS/TXT/CAA enumeration | `standard`+ |
| 4 | TLS handshake (per live host, parallel) | `node:tls` | Cert + protocol/cipher posture | `standard`+ |
| 5 | HTTP GET (per live host, parallel) | `fetchWithTimeout` | Headers, security-header audit, tech fingerprint | `standard`+ |
| 6 | RDAP/WHOIS (apex domain) | `rdap.org` | Registration + ownership | when `include_registration` |
| 7 | Shodan host (per distinct IP) | Shodan | Open ports / banners enrichment | `thorough` **and** key present |

`quick` = steps 1–2 only (CT + resolution: "what subdomains exist and which are live"). `standard` = 1–6 (full passive posture). `thorough` = 1–7 (adds Shodan when keyed; silently skips when not — surfaced as a `notes` entry, not an error). All per-host fan-out uses `Promise.allSettled`; the apex `ATTACKSURFACE_MAX_SUBDOMAINS` cap bounds cost and is disclosed via `ctx.enrich.truncated()` when hit. The map's `assessment` block synthesizes only observable facts (expiring certs, missing HSTS/CSP, weak TLS versions, wildcard exposure) — never an exploitation path.

## Design Decisions

### Source selection — why these, and the fallback chains
- **CT logs over DNS brute-forcing for subdomains.** Certificate Transparency is fully passive (querying public logs, not touching the target) and high-yield. DNS wordlist brute-forcing — the usual alternative — generates traffic against the target's resolvers and edges toward active probing; it's deliberately excluded. CT is sourced as a **fallback chain**: crt.sh primary (richest), Certspotter fallback (crt.sh 502'd on 3 of 5 live probes during design — it is genuinely unreliable), and the TLS handshake's SAN list as a third, always-available source. Each subdomain carries its `source`. **Verified response shape (both sources):** both crt.sh `/json?q=%.{domain}` and Certspotter `/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names` return an array with identical fields: `id`, `tbs_sha256`, `cert_sha256`, `dns_names` (string array of SANs), `pubkey_sha256`, `not_before`, `not_after` (ISO-8601 UTC), `revoked` (boolean). Extract subdomain names from `dns_names`; strip wildcard prefix (`*.`) before deduplication.
- **DoH and `node:dns` both available; `node:dns` multi-resolver is the default.** `node:dns` `Resolver` with `setServers([...])` gives per-resolver propagation visibility (matching `devops-status`'s proven pattern). DoH (`dns.google/resolve?name={n}&type={t}` and `cloudflare-dns.com/dns-query?name={n}&type={t}` with `Accept: application/dns-json`) is the Workers-portable path where `node:dns` is unavailable. **Verified response shape (both providers, identical):** `{ Status: 0|3, TC: bool, RD: bool, RA: bool, AD: bool, CD: bool, Question: [{name, type}], Answer: [{name, type, TTL, data}] }`. `Status: 0` = NOERROR; `Status: 3` = NXDOMAIN. `Answer` absent (not null) when no records. `data` is always a string (IP address for A/AAAA, target for CNAME/MX/PTR).
- **RDAP over raw WHOIS.** RDAP returns structured JSON (`events[]` for registration/expiry/last-changed, `nameservers[]`, `entities[].roles`, `secureDNS`, and for IPs `cidr0_cidrs` + `arin_originas0_originautnums` origin-ASN). `rdap.org` bootstraps and **302-redirects** to the authoritative registry (verified: 302 → `https://rdap.arin.net/registry/ip/…` for 8.8.8.8) — **the client must follow redirects** (`fetch` with `redirect: 'follow'` or equivalent; do not treat 3xx as an error). Note: `rdap.org` domain lookups can be slow/timeout; implement a per-request deadline (5s) and fall back to WHOIS rather than hanging. WHOIS (port 43 text) is the fallback only for TLDs/registries without RDAP or when `rdap.org` is unresponsive. RDAP fields are sparse (`country` came back `null` for 8.8.8.8 ARIN) — reported as unknown, never inferred.
- **Node `node:tls` direct handshake with `rejectUnauthorized: false`.** Verified shape: `getPeerCertificate()` returns `{ subject: {CN}, issuer: {C,O,CN}, subjectaltname: "DNS:foo.com, DNS:www.foo.com", valid_from, valid_to, serialNumber, fingerprint256, ext_key_usage: string[] }`. `getProtocol()` → `"TLSv1.3"` string. `getCipher()` → `{ name, standardName, version }` object. `socket.authorized` (boolean) and `socket.authorizationError` (Error | null) distinguish valid vs invalid/expired/self-signed certs. Disabling rejection lets the server *inspect and report* invalid/expired/self-signed certs rather than throwing — posture findings are the point. Note: `ext_key_usage` is an array of OID strings (e.g. `["1.3.6.1.5.5.7.3.1"]`), not human-readable names — convert for display.

### Keyless-core vs optional-key enrichment + degradation strategy
- **The split is the core product decision.** Everything an EASM workflow fundamentally needs — subdomains, DNS, TLS posture, HTTP/tech, registration — is free and keyless. Paid sources (Shodan) are strictly additive depth, never a gate on core value. This keeps the server immediately useful on a bare `bunx`/Docker install with no signup, and hostable on the public fleet (the keyless tools front the hosted endpoint; Shodan stays user-keyed).
- **Degradation is explicit and typed, not silent.** `attacksurface_lookup_host` declares an `errors: [{ reason: 'source_unavailable', code: ServiceUnavailable, when: 'SHODAN_API_KEY not configured', recovery: 'Set SHODAN_API_KEY to enable host intelligence; the rest of the server works without it.' }]` contract — the agent gets an actionable reason, not a crash. `map_domain` treats Shodan as opportunistic: present → enrich at `thorough`; absent → a `notes` line ("Shodan enrichment skipped: no API key"), never an error. Certspotter degrades from keyed to unauthenticated-rate-limited transparently.

### The passive-only scope boundary
- **Reframed from the original idea sketch.** The `docs/idea.md` sketch included `recon_find_vulns` (reflected-XSS/SQLi/SSRF/path-traversal indicator probing), an `active` mode on endpoint probing (multi-method, path traversal, parameter reflection), and a full Shodan port-scan posture. **All of that is cut.** This server is passive/non-intrusive by mandate: it reads public records and each target's *own* single published response. `probe_http` is one GET, redirects followed, no parameter manipulation; there is no vuln-detection tool. The security *analysis* the server does perform (header/TLS/CORS misconfiguration) is read from a normal response, not induced by adversarial input.
- **Why the boundary is structural, not a flag.** A `mode: 'active'` toggle would make the dual-use risk a per-call decision and invite misuse on unauthorized targets. Excluding active capability from the surface entirely means the tool *cannot* be pointed at a third party as a weapon — it can only describe what is already public. `openWorldHint: true` on the live-connecting tools is honest (they reach arbitrary external hosts); the SSRF guard ensures those hosts are public, not internal.

### Authorized-use framing
- Baked into three places: (1) server `instructions` — "Assess only assets you own or are explicitly authorized to test; this server is passive and reads public records and the target's own published surface"; (2) the `attacksurface_map_domain` description and the `domain` param; (3) `attacksurface_recon_guidance`, whose output is a *defensive review* plan (prioritize remediation, flag expiring certs, suggest CVE lookups for visibility) — never an exploitation playbook. Descriptions stay consumer-facing (no "the agent should…"), but the authorization expectation is a capability statement, not meta-coaching.

### Tool consolidation and naming
- **`attacksurface_` prefix** (not `recon_`, the sketch's prefix): the prefix shows up in every tool call and should name the *server's domain* so an agent scanning a tool list reads "attack surface" → EASM. `recon_` is generic. Three-segment `{prefix}_{verb}_{noun}` throughout (`map_domain`, `enumerate_subdomains`, `lookup_registration`); `probe_http`/`inspect_tls` keep the protocol as the noun.
- **`map_domain` is the spine; per-aspect tools back-fill.** Most engagements start with one `map_domain` call. The sketch's separate `recon_audit_security` tool is **dissolved**: security posture is the *analysis layer* over data that `inspect_tls` (TLS) and `probe_http` (headers/CORS) already gather, and `map_domain` already synthesizes it into an `assessment`. A standalone audit tool would duplicate their outputs. The single-aspect tools remain for targeted follow-up (inspect one host's TLS without re-mapping).
- **Shodan's single-host and search collapse into one `lookup_host`** with a `mode` enum (`host` free-tier / `search` paid-credits), routing by mode — the agent sees one host-intelligence tool, not a Shodan wrapper split across two endpoints. The cost difference (free vs. query-credit) is documented on the `mode` param.

### Overlap with `devops-status-mcp-server` (honest boundary)
- devops-status already ships `devops_check_dns` and `devops_check_certs`. Those are **single-asset health monitoring** for infra you operate ("is *my* cert expiring, is *my* DNS propagated") — a SOC/SRE workflow. attack-surface is **adversarial surface discovery** for a target estate ("what subdomains/hosts/tech exist, what's the posture across all of them") — a recon/assessment workflow with CT enumeration, tech fingerprinting, RDAP ownership, and Shodan that devops-status has no reason to carry. The DNS/TLS *mechanics* are shared (same `node:dns`/`node:tls` patterns, same SSRF guard) and this server reuses those proven implementations rather than reinventing them; the *workflow, output shape, and audience* differ. The two compose rather than duplicate.

## Known Limitations

- **CT enumeration finds only names that appear in issued certificates.** Subdomains never given a public cert (internal-only, IP-only, or pre-CT) won't surface. The TLS-SAN and DNS-resolution steps partially backfill, but this is inherent to passive CT-based discovery — and the deliberate cost of excluding DNS brute-forcing.
- **crt.sh reliability is poor.** The Certspotter fallback and TLS-SAN source mitigate, but a CT-only `quick` run can still return a partial set when crt.sh is down and Certspotter is rate-limited; output discloses which sources answered.
- **rdap.org domain lookups can be slow or timeout.** Verified: `rdap.org/ip/{ip}` responds quickly (302 → ARIN within ~1s); `rdap.org/domain/{domain}` can hang indefinitely (timed out in multiple live tests). The `registration-service` must apply a strict per-request deadline (5s) and fall back to WHOIS rather than waiting. IP lookups are the reliable path via `rdap.org`.
- **Shodan data is as fresh as Shodan's last scan**, not live — banners/ports may be stale. Reported with Shodan's own timestamp; never presented as a real-time port state (the server itself never scans ports).
- **RDAP/WHOIS privacy redaction** means registrant contact details are frequently redacted (GDPR/registrar privacy). The server reports what the registry returns and marks redacted/absent fields as unknown. RDAP fields can be sparse at the data level too — `country` returned `null` for ARIN netblocks (verified for 8.8.8.0/24); implementation must treat every RDAP field as optional.
