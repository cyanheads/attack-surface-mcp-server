# Changelog

All notable changes to this project. Each entry links to its full per-version file in [changelog/](changelog/).

## [0.2.2](changelog/0.2.x/0.2.2.md) — 2026-09-21

Defaults HTTP sessions to stateless, pins dual-stack TLS/WHOIS connections to IPv4, and adopts mcp-ts-core 0.13.6.

## [0.2.1](changelog/0.2.x/0.2.1.md) — 2026-08-30

Hardens RDAP redirects, preserves CIDR registration lookups, and fixes WHOIS field parsing.

## [0.2.0](changelog/0.2.x/0.2.0.md) — 2026-08-21 · ⚠️ Breaking

Reclassifies 0.1.2's per-target `error` field renames as the breaking change they are; no source change ships in 0.2.0, only the corrected version and migration guidance.

## [0.1.2](changelog/0.1.x/0.1.2.md) — 2026-08-21

Maintenance release on mcp-ts-core ^0.12.3: framework fetch/retry layer for upstream calls, per-item error fields renamed across tool outputs, typed no_data for unscanned Shodan hosts, reconciled unit/integration/smoke/fuzz suites, install-time supply-chain guards.

## [0.1.1](changelog/0.1.x/0.1.1.md) — 2026-06-14

Scope the README title to the published npm name @cyanheads/attack-surface-mcp-server.

## [0.1.0](changelog/0.1.x/0.1.0.md) — 2026-06-13

Passive external attack-surface mapping: 8 tools, 1 resource, 6 services. Keyless core (CT/DNS/TLS/HTTP/RDAP) with SSRF guard; optional Shodan.
