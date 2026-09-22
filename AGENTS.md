# Developer Protocol

**Server:** attack-surface-mcp-server
**Version:** 0.2.1
**Framework:** [@cyanheads/mcp-ts-core](https://www.npmjs.com/package/@cyanheads/mcp-ts-core) `^0.13.6`
**Engines:** Bun ≥1.4.0, Node ≥24.0.0
**MCP SDK:** `@modelcontextprotocol/server`/`client` ^2.0.0
**Zod:** ^4.6.5

> **Read the framework docs first:** `node_modules/@cyanheads/mcp-ts-core/CLAUDE.md` contains the full API reference — builders, Context, error codes, exports, patterns. This file covers server-specific conventions only.

---

## Authorized-use posture

This is a defensive external-attack-surface-mapping (EASM) server. It is **passive and non-intrusive by mandate**: it reads public records (Certificate Transparency, DNS, RDAP/WHOIS) and each target's *own* published surface (one TLS handshake, one HTTP GET per host). It does **not** port-scan, exploit, brute-force, fuzz, or probe for vulnerabilities — that capability is excluded from the surface by design, never gated behind a flag. Output is descriptive (what exists, what the posture is), never an exploitation plan.

- **Keep the framing in the surface.** The server `instructions`, the `attacksurface_map_domain` description, and `attacksurface_recon_guidance` all state the target must be owned or authorized for assessment. Preserve that when editing any of them. Don't add active/intrusive capability or a `mode: active` toggle — excluding it structurally is the safety property.
- **The SSRF guard is the security spine.** Every outbound connection to a user-supplied target (DNS, TLS, HTTP) must pass `assertSafeDomain` / `assertSafeUrl` / `assertSafeResolverIp` (`src/utils/ssrf-guard.ts`) before connecting. It rejects private, loopback, link-local, cloud-metadata, and reserved ranges. Never route a new outbound path around it.
- **No fabricated signal.** Report detections with their triggering evidence; report absent CT/DNS/RDAP fields as unknown. No invented confidence composites.

---

## Core Rules

- **Logic throws, framework catches.** Tool/resource handlers are pure — throw on failure, no `try/catch`. Plain `Error` is fine; the framework catches, classifies, and formats. Use error factories (`notFound()`, `validationError()`, etc.) when the error code matters.
- **Use `ctx.log`** for request-scoped logging. No `console` calls.
- **Use `ctx.state`** for tenant-scoped storage. Never access persistence directly.
- **Secrets in env vars only** — never hardcoded.
- **Cut noise.** Add only what earns its place: no speculative generality, no guards for states the framework already prevents (Zod-validated params, classified errors), no abstraction until a third caller proves it, no option nothing sets.
- **Close the loop on issues.** When implementing work tracked by a GitHub issue, comment on the issue with what landed and close it. Do both — a comment without a close leaves stale issues open; a close without a comment leaves no record of what shipped. The comment is for future readers — state the concrete changes, not the conversation that produced them.

---

## Patterns

### Tool

Real tools live in `src/mcp-server/tools/definitions/*.tool.ts`. `attacksurface_inspect_tls` is representative — a multi-target read-only tool with a typed error contract, per-target graceful degradation, and a `format()` twin. The display `title` is set explicitly to the snake_case tool name (never a Title Case label).

```ts
import { tool, z } from '@cyanheads/mcp-ts-core';
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { getTlsService } from '@/services/tls/tls-service.js';
import { isValidHost } from '@/utils/validation.js';

export const inspectTlsTool = tool('attacksurface_inspect_tls', {
  title: 'attacksurface_inspect_tls',
  description:
    'Inspect TLS/SSL posture for one or more hosts via a real read-only handshake … SSRF-guarded; per-host failures degrade to a per-host error. Use only on assets you own or are authorized to assess.',
  annotations: { readOnlyHint: true, openWorldHint: true, idempotentHint: true },
  input: z.object({
    hosts: z.array(z.string().describe('Hostname or IP to inspect.')).min(1).max(50)
      .describe('Hosts to inspect (1–50).'),
    port: z.number().int().min(1).max(65535).default(443).describe('TLS port to connect to.'),
  }),
  output: z.object({ results: z.array(/* TlsResultSchema */ z.unknown()).describe('Per-host results.') }),
  // Typed contract: `ctx.fail('invalid_host', …)` is type-checked against this reason union;
  // baseline codes (Timeout, ServiceUnavailable, …) bubble freely without declaring.
  errors: [
    { reason: 'invalid_host', code: JsonRpcErrorCode.ValidationError,
      when: 'A supplied host is not a syntactically valid hostname or IP.',
      recovery: 'Provide bare hostnames or IPs (no scheme/path), e.g. "secure.example.com".' },
  ],

  async handler(input, ctx) {
    for (const host of input.hosts) {
      if (!isValidHost(host)) {
        throw ctx.fail('invalid_host', `"${host}" is not a valid hostname or IP.`, {
          ...ctx.recoveryFor('invalid_host'),
        });
      }
    }
    // The service SSRF-checks each host before connecting; one failing host → per-host error, not a throw.
    const results = await getTlsService().inspectHosts(input.hosts, input.port);
    return { results };
  },

  // format() populates content[] — the markdown twin of structuredContent. Different clients read
  // different surfaces (Claude Code → structuredContent, Claude Desktop → content[]); both must
  // carry the same data. Enforced at lint time: every output field must appear in the rendered text.
  format: (result) => [{ type: 'text', text: renderTlsResults(result.results) }],
});
```

### Resource

The one resource, `attacksurface://surface/{domain}` (`src/mcp-server/resources/definitions/surface.resource.ts`), is a thin standard-depth `map_domain`. Validate the param at the edge; throw factories on bad input / no surface.

```ts
import { type Context, resource, z } from '@cyanheads/mcp-ts-core';
import { notFound, validationError } from '@cyanheads/mcp-ts-core/errors';
import { isValidDomain, normalizeDomain } from '@/utils/validation.js';

export const surfaceResource = resource('attacksurface://surface/{domain}', {
  description: "Read-once snapshot of a domain's mapped external surface … Assess only assets you own or are authorized to test.",
  name: 'domain-surface-snapshot',
  title: 'attacksurface://surface/{domain}',
  mimeType: 'application/json',
  params: z.object({ domain: z.string().describe('Apex domain to snapshot (e.g. "example.com").') }),
  async handler(params: { domain: string }, ctx: Context) {
    const domain = normalizeDomain(params.domain);
    if (!isValidDomain(domain)) throw validationError(`"${params.domain}" is not a valid domain.`, { domain: params.domain });
    // … CT enumerate → resolve liveness → per-host TLS/HTTP summary …
    // throw notFound(...) when no subdomains and the apex did not resolve
  },
});
```

There are **no prompts** — the workflow is action-oriented and `attacksurface_recon_guidance` supplies the one "structure the next steps" pattern as a state-aware tool (reachable by tool-only clients) rather than a static template.

### Server config

```ts
// src/config/server-config.ts — lazy-parsed, separate from framework config. No var is required —
// the keyless core (CT/DNS/TLS/HTTP/RDAP) boots on an empty environment.
import { z } from '@cyanheads/mcp-ts-core';
import { parseEnvConfig } from '@cyanheads/mcp-ts-core/config';

const ServerConfigSchema = z.object({
  shodanApiKey: z.string().optional().describe('Shodan API key for host intelligence.'),
  certspotterApiKey: z.string().optional().describe('Certspotter API key for higher CT-fallback rate limits.'),
  defaultResolvers: z.string().default('8.8.8.8,1.1.1.1,9.9.9.9').describe('Comma-separated default DNS resolver IPs.'),
  httpUserAgent: z.string().default('attack-surface-mcp-server/passive-recon (+…)').describe('Default User-Agent for HTTP probes.'),
  maxSubdomains: z.coerce.number().int().min(1).max(5000).default(200).describe('Max subdomains resolved per map_domain run.'),
  rdapBootstrapUrl: z.string().url().default('https://rdap.org').describe('RDAP bootstrap base URL.'),
});

let _config: z.infer<typeof ServerConfigSchema> | undefined;
export function getServerConfig() {
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
```

`parseEnvConfig` maps Zod schema paths → env var names so errors name the variable (`SHODAN_API_KEY`) not the path (`shodanApiKey`). Throws `ConfigurationError`, which the framework prints as a clean startup banner.

**`ATTACKSURFACE_ALLOW_PRIVATE_TARGETS` is deliberately *not* in this schema** — the SSRF guard (`src/utils/ssrf-guard.ts`) reads it directly from `process.env`, since the guard is a shared util consumed by the dns/tls/http services rather than a service with config access. Setting it `true` disables all SSRF checks (local/trusted internal-network assessment only).

For env booleans use `z.stringbool()`, never `z.coerce.boolean()` — `Boolean("false")` is `true`, so a coerced flag can't be disabled through the environment. `z.stringbool()` parses `true/false/1/0/yes/no/on/off` and rejects anything else, so `=false` actually disables.

### Server identity and instructions

`createApp()` accepts optional identity fields forwarded to the SDK's `initialize` response and the server manifest (`/.well-known/mcp.json`):

```ts
await createApp({
  name: 'my-mcp-server',
  title: 'My Server',                         // human-readable display name
  websiteUrl: 'https://github.com/owner/repo', // canonical homepage URL
  description: 'One-line description.',        // wins over MCP_SERVER_DESCRIPTION
  icons: [{ src: 'https://example.com/icon.png', sizes: ['48x48'], mimeType: 'image/png' }],
  instructions: 'Use shortcut alpha for the most common case.', // session-level context
});
```

`instructions` is optional server-level orientation, sent on every `initialize` as session-level context. Use it for deployment guidance (connection aliases, regional notes, scope hints) instead of repeating the same context across tool descriptions. Client adoption is uneven, but there's no downside when set.

### Session posture and shutdown

Two more `createApp()` options shape how the server runs rather than how it presents itself:

```ts
await createApp({
  sessionMode: 'stateless',          // or { default: 'stateful', require: 'stateful' }
  setup(core) { startMyWatcher(core.config); },
  async teardown() { await stopMyWatcher(); },
});
```

`sessionMode` declares the HTTP session posture in `src/` instead of leaving it to a deployment's `MCP_SESSION_MODE`, which still wins whenever it carries a meaningful value (an empty string and an unsubstituted `${…}` placeholder read as unset and fall through to the option). Add `require: 'stateful'` when a tool asks the caller for input mid-handler via `ctx.requestInput`: startup then fails with a `ConfigurationError` rather than serving a mode in which a 2025-era client can never answer the prompt. Stdio is never refused.

`teardown(core)` is the `setup()` counterpart — release a watcher, socket, or non-`unref()`'d timer there. It runs after the transport stops and before the logger closes, on every shutdown path, and a signal-triggered shutdown then exits the process explicitly (0, or 1 if a step never settles within the framework's 10 s ceiling).

**This server** declares `sessionMode: 'stateless'` in `src/index.ts` — it holds no per-session state and never calls `ctx.requestInput` — and passes no `teardown`: every service allocates its sockets and timers per request, so `setup()` leaves nothing to release. `tests/integration/session-mode.test.ts` pins both the default and the env override.

---

## Context

Handlers receive a unified `ctx` object. Key properties:

| Property | Description |
|:---------|:------------|
| `ctx.log` | Request-scoped logger — `.debug()`, `.info()`, `.notice()`, `.warning()`, `.error()`. Auto-correlates requestId, traceId, tenantId. |
| `ctx.fail` / `ctx.recoveryFor` | Typed-error throw — `ctx.fail(reason, msg, …)` against a tool's declared `errors[]` reason union; `ctx.recoveryFor(reason)` pulls the declared recovery metadata. The primary error path here (see every `*.tool.ts`). |
| `ctx.enrich` | Attach out-of-band metadata to a result — `ctx.enrich({ … })`, `ctx.enrich.notice(msg)`, `ctx.enrich.truncated({ shown, cap })`. Used to disclose the subdomain cap and "nothing found" guidance. |
| `ctx.signal` | `AbortSignal` for cancellation — wired into the service-layer fetch/handshake timeouts. |
| `ctx.requestId` | Unique request ID. |
| `ctx.tenantId` | Tenant ID from JWT or `'default'` for stdio. |

This server is stateless and non-interactive — it does not use `ctx.state` or the `inputRequired` elicitation surface.

---

## Errors

Handlers throw — the framework catches, classifies, and formats.

**Recommended: typed error contract.** Declare `errors: [{ reason, code, when, recovery, retryable?, severity?, thrownBy? }]` on `tool()` / `resource()` to receive `ctx.fail(reason, …)` typed against the reason union. TypeScript catches typos at compile time, `data.reason` is auto-populated for observability, linter enforces conformance against the handler body. `recovery` is required (≥ 5 words, lint-validated) — the single source of truth for the agent's next move. Pass `ctx.recoveryFor('reason')` as the throw's data to put it on the wire (`data.recovery.hint`, mirrored into `content[]` text unless the message already contains it verbatim); override with an explicit `{ recovery: { hint: '...' } }` when dynamic runtime context matters. Forwarding it is lint-enforced per throw site (`error-contract-recovery-unforwarded`). Mark an entry the service layer throws with `thrownBy: 'service'` so `error-contract-unthrown` skips it — lint-only metadata, nothing at runtime reads it. Baseline codes (`InternalError`, `ServiceUnavailable`, `Timeout`, `ValidationError`, `SerializationError`, `RequestCancelled`) bubble freely and don't need declaring.

```ts
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';

errors: [
  { reason: 'no_match', code: JsonRpcErrorCode.NotFound,
    when: 'No item matched the query',
    recovery: 'Broaden the query or check the spelling and try again.' },
],
async handler(input, ctx) {
  const item = await db.find(input.id);
  if (!item) throw ctx.fail('no_match', `No item ${input.id}`, ctx.recoveryFor('no_match'));
  return item;
}
```

**Declare contracts inline on each tool.** The contract is part of the tool's public surface — one file should give the full picture. Don't extract a shared `errors[]` constant; per-tool repetition is the intended cost of locality.

**Fallback (no contract entry fits):** throw via factories or plain `Error`.

```ts
// Error factories — explicit code
import { notFound, serviceUnavailable } from '@cyanheads/mcp-ts-core/errors';
throw notFound('Item not found', { itemId });
throw serviceUnavailable('API unavailable', { url }, { cause: err });

// Plain Error — framework auto-classifies from message patterns
throw new Error('Item not found');           // → NotFound
throw new Error('Invalid query format');     // → ValidationError

// McpError — when no factory exists for the code
import { McpError, JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
throw new McpError(JsonRpcErrorCode.InitializationFailed, 'Connection failed', { pool: 'primary' });
```

See framework CLAUDE.md and the `api-errors` skill for the full auto-classification table, all available factories, and the contract reference.

---

## Structure

```text
src/
  index.ts                              # createApp() entry point — registers tools/resources, inits 6 services
  config/
    server-config.ts                    # Server-specific env vars (Zod schema)
  utils/
    ssrf-guard.ts                       # SSRF guard — assertSafeDomain / assertSafeUrl / assertSafeResolverIp
    validation.ts                       # Host / domain / registration-target validators + normalizeDomain
  services/                             # init/accessor pattern; each with a types.ts
    ct/                                  # crt.sh + Certspotter + TLS-SAN fallback chain
    dns/                                 # node:dns multi-resolver + reverse PTR
    tls/                                 # node:tls read-only handshake
    http/                                # fetch GET + security-header audit + tech fingerprint
    registration/                        # RDAP (rdap.org bootstrap) + WHOIS fallback
    shodan/                              # Shodan REST (optional-key)
  mcp-server/
    tools/definitions/
      *.tool.ts                          # 8 tool definitions (+ index.ts barrel)
    resources/definitions/
      surface.resource.ts                # attacksurface://surface/{domain} (+ index.ts barrel)
```

No `prompts/` directory — this server ships no prompts.

---

## Naming

| What | Convention | Example |
|:-----|:-----------|:--------|
| Files | kebab-case with suffix | `search-docs.tool.ts` |
| Tool/resource/prompt names | snake_case | `search_docs` |
| Directories | kebab-case | `src/services/doc-search/` |
| Descriptions | Single string or template literal, no `+` concatenation | `'Search items by query and filter.'` |

---

## Skills

Skills are modular instructions in `framework-skills/` at the project root. Read them directly when a task matches — e.g., `framework-skills/add-tool/SKILL.md` when adding a tool. `bun run list-skills` prints the full registry. The directory is deliberately not `skills/`: Claude Code and Codex auto-load a plugin's root `skills/`, so a server that ships `.claude-plugin/` or `.codex-plugin/` would hand these development skills to every agent that installs it. Keep `skills/` free for skills meant for those agents.

**Agent skill directory:** Copy skills into the directory your agent discovers (Claude Code: `.claude/skills/`, others: equivalent). Skills then load as context without referencing `framework-skills/` paths. After framework updates, run the `maintenance` skill — Phase B re-syncs the agent directory.

Available skills:

| Skill | Purpose |
|:------|:--------|
| `setup` | Post-init project orientation |
| `design-mcp-server` | Design tool surface, resources, and services for a new server |
| `add-tool` | Scaffold a new tool definition |
| `add-app-tool` | Scaffold an MCP App tool + paired UI resource |
| `add-resource` | Scaffold a new resource definition |
| `add-prompt` | Scaffold a new prompt definition |
| `add-service` | Scaffold a new service integration |
| `add-test` | Scaffold test file for a tool, resource, or service |
| `field-test` | Exercise tools/resources/prompts with real inputs, verify behavior, report issues |
| `tool-defs-analysis` | Read-only audit of MCP definition language across the surface — voice, leaks, defaults, recovery hints, output descriptions |
| `security-pass` | Audit server for MCP-flavored security gaps: output injection, scope blast radius, input sinks, tenant isolation |
| `code-simplifier` | Post-session cleanup against `git diff` — modernize syntax, consolidate duplication, align with the codebase |
| `polish-docs-meta` | Finalize docs, README, metadata, and agent protocol for shipping |
| `git-wrapup` | Land working-tree changes as a commit stack — version bump, changelog, verify, commit by concern, release commit on top. No tag, no push to main; opens the release PR when the project declares release PR mode |
| `release-pr-review` | Review pass on an open release PR — simplifier + correctness review, fixes as ordinary commits on top of the stack, PR body kept in sync. Release PR mode only |
| `release-and-publish` | Fast-forward merge (release PR mode) + tag + push + npm + MCP Registry + GH Release + Docker. Picks up from `git-wrapup` |
| `maintenance` | Investigate changelogs, adopt upstream changes, sync skills to agent dirs |
| `orchestrations` | Chain task skills into a gated multi-phase pipeline — build-out, QA-fix, update-ship — when you can spawn sub-agents |
| `report-issue-framework` | File a bug or feature request against `@cyanheads/mcp-ts-core` via `gh` CLI |
| `report-issue-local` | File a bug or feature request against this server's own repo via `gh` CLI |
| `api-auth` | Auth modes, scopes, JWT/OAuth |
| `api-canvas` | DataCanvas: register tabular data, run SQL, export, plus the `spillover()` helper for big result sets — Tier 3 opt-in |
| `api-config` | AppConfig, parseConfig, env vars |
| `api-context` | Context interface, logger, state, progress |
| `api-errors` | McpError, JsonRpcErrorCode, error patterns |
| `api-linter` | Definition linter rule catalog — invoked by `bun run lint:mcp` and `devcheck` |
| `api-services` | LLM, Speech, Graph services |
| `api-testing` | createMockContext, test patterns |
| `api-utils` | Formatting, parsing, security, pagination, scheduling, telemetry helpers |
| `api-telemetry` | OTel catalog: spans, metrics, completion logs, env config, cardinality rules |
| `api-workers` | Cloudflare Workers runtime |
| `api-mirror` | MirrorService — persistent self-refreshing local mirror of a bulk upstream dataset (Tier 3). Not used here. |
| `techniques` | Catalog of response-/data-shaping techniques (overflow handling, payload shaping, retrieval) |

**Chaining skills into pipelines.** When the user wants a multi-phase effort — build this server out, QA-and-fix the surface, update-and-ship — *and you can spawn sub-agents*, `framework-skills/orchestrations/SKILL.md` sequences the task skills above into a gated pipeline with verification at each step. Read it to drive the run. Optional: skip it if you can't orchestrate sub-agents, and ignore it entirely if you were *spawned* as one — you've already been scoped to a single phase.

When you complete a skill's checklist, check the boxes and add a completion timestamp at the end (e.g., `Completed: 2026-03-11`).

---

## Commands

**Runtime:** Scripts use Bun's native TypeScript execution — `bun run <cmd>` is the standard invocation. `npm run <cmd>` also works (npm delegates to bun).

| Command | Purpose |
|:--------|:--------|
| `npm run build` | Compile TypeScript |
| `npm run rebuild` | Clean + build |
| `npm run clean` | Remove build artifacts |
| `npm run devcheck` | Lint + format + typecheck + security + changelog sync |
| `bun run audit:fix` | `bun audit fix` — upgrade vulnerable packages to the lowest safe version within existing ranges (`--dry-run` previews, `--latest` rewrites ranges). First response when `devcheck` flags a transitive advisory; then `bun update <name>`, then `bun dedupe` |
| `bun run audit:refresh` | Delete `bun.lock` and reinstall. Last resort after `audit:fix`, `bun update <name>`, and `bun dedupe` — re-resolves every ranged dep (the framework pin included) and rewrites the lockfile as `lockfileVersion: 2` |
| `npm run tree` | Generate directory structure doc |
| `npm run format` | Auto-fix formatting (safe fixes only) |
| `npm run format:unsafe` | Also apply Biome's unsafe autofixes — review the diff; they can change behavior |
| `npm run lint:mcp` | Validate MCP tool/resource definitions against the spec (format-parity, schema, naming) |
| `npm run lint:packaging` | Validate `manifest.json` ↔ `server.json` env-var consistency |
| `npm test` | Run tests |
| `npm run start:stdio` | Production mode (stdio) |
| `npm run start:http` | Production mode (HTTP) |
| `npm run changelog:build` | Regenerate `CHANGELOG.md` from `changelog/*.md` |
| `npm run changelog:check` | Verify `CHANGELOG.md` is in sync (used by devcheck) |
| `npm run bundle` | Build, pack, and clean a `.mcpb` for one-click Claude Desktop install |
| `npm run release:github` | Create the GitHub release from the annotated tag |
| `bun run list-skills` | List the project skills in `.claude/skills/` with paths |

**CI is one file.** `.github/workflows/codeql.yml` (scaffolded) is the only GitHub Actions workflow: CodeQL is GitHub-owned end to end, and the file runs only while the repo's CodeQL *default setup* is turned off. Verification — `devcheck`, tests, the release gates — runs locally; don't add a workflow that re-runs it.

---

## Bundling

`npm run bundle` produces a `.mcpb` extension bundle for one-click install in Claude Desktop. The pack step is followed by `scripts/clean-mcpb.ts`, which prunes dev dependencies (`mcpb clean`) and strips dependency-shipped agent docs (`node_modules/**` `framework-skills/`, `skills/`, `.claude/`, `.agents/`, `SKILL.md`) that root-anchored `.mcpbignore` patterns cannot reach. MCPB is stdio-only — HTTP and Cloudflare Workers deployments are unaffected. Consumers who don't need it can delete `manifest.json` and `.mcpbignore`; `lint:packaging` skips cleanly.

**Adding an env var requires both files:** `server.json` (registry discovery, `environmentVariables[]`) and `manifest.json` (bundle install UX, `mcp_config.env` + `user_config`). `lint:packaging` (run by `devcheck`) verifies the env var names match, that every `user_config` option is wired into `mcp_config.env` as `"X": "${user_config.X}"` (the host substitutes nothing else — `"${X}"` reaches the server as that literal string), and that an optional string option carries `"default": ""`.

**README install badges** (Claude Desktop `.mcpb`, Cursor, VS Code) and the `base64` / `encodeURIComponent` config-generation commands are ship-time concerns — run the `polish-docs-meta` skill, which carries the badge format, layout, and generation snippets in `framework-skills/polish-docs-meta/references/readme.md`.

---

## Changelog

Directory-based, grouped by minor series via the `.x` semver-wildcard convention. Source of truth: `changelog/<major.minor>.x/<version>.md` (e.g. `changelog/0.1.x/0.1.0.md`) — one file per release, shipped in the npm package. At release, author the per-version file with a concrete version and date, then run `npm run changelog:build` to regenerate the rollup. `changelog/template.md` is a **pristine format reference** — never edited or moved; read it for the frontmatter + section layout when scaffolding. `CHANGELOG.md` is a **navigation index** (header + link + summary per version), regenerated by `npm run changelog:build` — devcheck hard-fails on drift; never hand-edit it.

Each per-version file opens with YAML frontmatter:

```markdown
---
summary: "One-line headline, ≤350 chars"  # required — powers the rollup index
breaking: false                            # optional — true flags breaking changes
security: false                            # optional — true ONLY for a source-code security fix, never a dependency CVE bump
---

# 0.1.0 — YYYY-MM-DD
...
```

`breaking: true` renders a `· ⚠️ Breaking` badge — use it when consumers must update code on upgrade (signature changes, removed APIs, config renames). `security: true` renders a `· 🛡️ Security` badge and pairs with a `## Security` body section — set it only for a security fix in this server's *own source code*, never for a routine dependency or transitive CVE bump (record those under `## Dependencies`). When both are set, badges render `· ⚠️ Breaking · 🛡️ Security`.

`agent-notes` is an optional free-form field for maintenance agents processing the release downstream. Content here won't appear in the rendered CHANGELOG — it's consumed by agents running the `maintenance` skill. Use it for adoption instructions that don't fit the human-facing sections: new files to create, fields to populate, one-time migration steps. Omit entirely when there's nothing to say.

**Section order:** the Keep a Changelog sequence — Added, Changed, Deprecated, Removed, Fixed, Security — then `Dependencies` last. Include only sections with entries — don't ship empty headers.

**Tag annotations** render as GitHub Release bodies via `--notes-from-tag`. They must be structured markdown — never a flat comma-separated string. Subject omits the version number (GitHub prepends it). See `changelog/template.md` for the full format reference.

---

## Publishing

**Every release goes through a release PR, straight-through** — `git-wrapup`'s "Release PR mode", mode `straight-through`. One run: `git-wrapup` lands the commit stack on `release/<version>`, pushes it, and opens the PR (title = the release commit subject, body = the changelog entry plus a gates section); `release-and-publish` then fast-forwards `main` locally with `git merge --ff-only`, creates the tag on `main`'s tip, pushes `main` and the tag, deletes the branch, and publishes. A caller's brief may run a given release as `gated` instead — a `release-pr-review` pass on the open PR before `release-and-publish`. **Never merge through the GitHub UI or `gh pr merge`**: squash and rebase-merge are disabled in the repo settings because both rewrite the stack (rebase-merge also strips the SSH signatures), and a merge commit breaks the linear history.

---

## Imports

```ts
// Framework — z is re-exported, no separate zod import needed
import { tool, z } from '@cyanheads/mcp-ts-core';
import { McpError, JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';

// Server's own code — via path alias
import { getTlsService } from '@/services/tls/tls-service.js';
import { assertSafeDomain } from '@/utils/ssrf-guard.js';
import { isValidHost, normalizeDomain } from '@/utils/validation.js';
```

---

## Checklist

- [ ] Zod schemas: all fields have `.describe()`, only JSON-Schema-serializable types (no `z.custom()`, `z.date()`, `z.transform()`, `z.bigint()`, `z.symbol()`, `z.void()`, `z.map()`, `z.set()`, `z.function()`, `z.nan()`)
- [ ] Optional nested objects: handler guards for empty inner values from form-based clients (`if (input.obj?.field && ...)`, not just `if (input.obj)`). When regex/length constraints matter, use `z.union([z.literal(''), z.string().regex(...).describe(...)])` — literal variants are exempt from `describe-on-fields`.
- [ ] JSDoc `@fileoverview` + `@module` on every file
- [ ] `ctx.log` for logging (this server is stateless — no `ctx.state`)
- [ ] **Any outbound connection to a user-supplied target passes the SSRF guard** (`assertSafeDomain` / `assertSafeUrl` / `assertSafeResolverIp`) before connecting — no new path routes around it
- [ ] **Passive-only preserved** — no active/intrusive capability added; authorized-use framing kept in `instructions`, `attacksurface_map_domain`, and `attacksurface_recon_guidance`
- [ ] Handlers throw on failure — error factories or plain `Error`, no try/catch
- [ ] `format()` renders all data the LLM needs — different clients forward different surfaces (Claude Code → `structuredContent`, Claude Desktop → `content[]`); both must carry the same data
- [ ] If wrapping external API: raw/domain/output schemas reviewed against real upstream sparsity/nullability before finalizing required vs optional fields
- [ ] If wrapping external API: normalization and `format()` preserve uncertainty; do not fabricate facts from missing upstream data
- [ ] If wrapping external API: tests include at least one sparse payload case with omitted upstream fields
- [ ] Registered in `createApp()` arrays (directly or via barrel exports)
- [ ] Tests use `createMockContext()` from `@cyanheads/mcp-ts-core/testing`
- [ ] `.codex-plugin/plugin.json` populated — `name`, `version`, `description`, `repository`, `license` from `package.json`; `interface.displayName` = the unscoped repo name (never the npm scope — `lint:packaging` enforces this); `interface.shortDescription` from `package.json` description
- [ ] `.codex-plugin/mcp.json` updated — server name key is the unscoped repo name; every user-supplied variable (API key, contact email, instance URL) is listed in `env_vars` so Codex forwards it from the user's environment. Never write `"KEY": ""` into `env` — an empty value replaces the user's exported key and is read as unset
- [ ] `.claude-plugin/plugin.json` populated — `name`, `version`, `description`, `author`, `repository`, `license`, `keywords` from `package.json`; inline `mcpServers` entry keyed by the unscoped repo name. Every user-supplied variable is declared under `userConfig` (`type`, `title`, `description`; `sensitive: true` for keys and tokens; `required: true` or `default: ""`) and referenced from `env` as `"KEY": "${user_config.<option>}"` — mirror the `user_config` block in `manifest.json`. Never write `"KEY": ""` into `env`
- [ ] `npm run devcheck` passes
