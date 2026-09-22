# attack-surface-mcp-server - Directory Structure

Generated on: 2026-09-22 03:48:28

```text
attack-surface-mcp-server/
├── .claude-plugin/
│   └── plugin.json
├── .codex-plugin/
│   ├── mcp.json
│   └── plugin.json
├── .github/
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.yml
│   │   ├── config.yml
│   │   └── feature_request.yml
│   ├── workflows/
│   │   └── codeql.yml
│   ├── CODE_OF_CONDUCT.md
│   ├── CONTRIBUTING.md
│   ├── FUNDING.yml
│   └── SECURITY.md
├── .vscode/
│   ├── extensions.json
│   └── settings.json
├── changelog/
│   ├── 0.1.x/
│   ├── 0.2.x/
│   └── template.md
├── docs/
│   └── design.md
├── framework-skills/
│   ├── add-app-tool/
│   │   └── SKILL.md
│   ├── add-prompt/
│   │   └── SKILL.md
│   ├── add-resource/
│   │   └── SKILL.md
│   ├── add-service/
│   │   └── SKILL.md
│   ├── add-test/
│   │   └── SKILL.md
│   ├── add-tool/
│   │   └── SKILL.md
│   ├── api-auth/
│   │   └── SKILL.md
│   ├── api-canvas/
│   │   └── SKILL.md
│   ├── api-config/
│   │   └── SKILL.md
│   ├── api-context/
│   │   └── SKILL.md
│   ├── api-errors/
│   │   └── SKILL.md
│   ├── api-linter/
│   │   └── SKILL.md
│   ├── api-mirror/
│   │   └── SKILL.md
│   ├── api-services/
│   │   ├── references/
│   │   │   ├── graph.md
│   │   │   ├── llm.md
│   │   │   └── speech.md
│   │   └── SKILL.md
│   ├── api-telemetry/
│   │   └── SKILL.md
│   ├── api-testing/
│   │   └── SKILL.md
│   ├── api-utils/
│   │   ├── references/
│   │   │   ├── formatting.md
│   │   │   ├── parsing.md
│   │   │   └── security.md
│   │   └── SKILL.md
│   ├── api-workers/
│   │   └── SKILL.md
│   ├── code-simplifier/
│   │   └── SKILL.md
│   ├── design-mcp-server/
│   │   └── SKILL.md
│   ├── field-test/
│   │   └── SKILL.md
│   ├── git-wrapup/
│   │   └── SKILL.md
│   ├── maintenance/
│   │   └── SKILL.md
│   ├── orchestrations/
│   │   ├── workflows/
│   │   │   ├── field-test-fix.md
│   │   │   ├── fix-wrapup-release.md
│   │   │   ├── greenfield-build.md
│   │   │   └── maintenance-release.md
│   │   └── SKILL.md
│   ├── polish-docs-meta/
│   │   ├── references/
│   │   │   ├── agent-protocol.md
│   │   │   ├── package-meta.md
│   │   │   ├── readme.md
│   │   │   └── server-json.md
│   │   └── SKILL.md
│   ├── release-and-publish/
│   │   └── SKILL.md
│   ├── release-pr-review/
│   │   └── SKILL.md
│   ├── report-issue-framework/
│   │   └── SKILL.md
│   ├── report-issue-local/
│   │   └── SKILL.md
│   ├── security-pass/
│   │   └── SKILL.md
│   ├── setup/
│   │   └── SKILL.md
│   ├── techniques/
│   │   ├── references/
│   │   │   └── outline-on-overflow.md
│   │   └── SKILL.md
│   └── tool-defs-analysis/
│       └── SKILL.md
├── scripts/
│   ├── build-changelog.ts
│   ├── build.ts
│   ├── check-dependency-specifiers.ts
│   ├── check-docs-sync.ts
│   ├── check-framework-antipatterns.ts
│   ├── check-skill-versions.ts
│   ├── check-skills-sync.ts
│   ├── clean-mcpb.ts
│   ├── clean.ts
│   ├── devcheck.ts
│   ├── lint-mcp.ts
│   ├── lint-packaging.ts
│   ├── list-skills.ts
│   ├── release-github.ts
│   └── tree.ts
├── src/
│   ├── config/
│   │   └── server-config.ts
│   ├── mcp-server/
│   │   ├── prompts/
│   │   │   └── definitions/
│   │   ├── resources/
│   │   │   └── definitions/
│   │   │       ├── index.ts
│   │   │       └── surface.resource.ts
│   │   └── tools/
│   │       └── definitions/
│   │           ├── enumerate-subdomains.tool.ts
│   │           ├── index.ts
│   │           ├── inspect-tls.tool.ts
│   │           ├── lookup-host.tool.ts
│   │           ├── lookup-registration.tool.ts
│   │           ├── map-domain.tool.ts
│   │           ├── probe-http.tool.ts
│   │           ├── recon-guidance.fuzz.test.ts
│   │           ├── recon-guidance.tool.test.ts
│   │           ├── recon-guidance.tool.ts
│   │           ├── resolve-dns.tool.test.ts
│   │           └── resolve-dns.tool.ts
│   ├── services/
│   │   ├── ct/
│   │   │   ├── ct-service.ts
│   │   │   └── types.ts
│   │   ├── dns/
│   │   │   ├── dns-service.ts
│   │   │   └── types.ts
│   │   ├── http/
│   │   │   ├── fingerprint.test.ts
│   │   │   ├── fingerprint.ts
│   │   │   ├── http-service.ts
│   │   │   └── types.ts
│   │   ├── registration/
│   │   │   ├── registration-service.test.ts
│   │   │   ├── registration-service.ts
│   │   │   └── types.ts
│   │   ├── shodan/
│   │   │   ├── shodan-service.ts
│   │   │   └── types.ts
│   │   └── tls/
│   │       ├── tls-service.ts
│   │       └── types.ts
│   ├── utils/
│   │   ├── ssrf-guard.test.ts
│   │   ├── ssrf-guard.ts
│   │   ├── validation.test.ts
│   │   └── validation.ts
│   └── index.ts
├── tests/
│   ├── fuzz/
│   │   ├── ct-service.fuzz.test.ts
│   │   ├── dns-service.fuzz.test.ts
│   │   ├── http-service.fuzz.test.ts
│   │   ├── registration-service.fuzz.test.ts
│   │   └── tls-service.fuzz.test.ts
│   ├── integration/
│   │   ├── enumerate-subdomains.tool.test.ts
│   │   ├── inspect-tls.tool.test.ts
│   │   ├── lookup-host.tool.test.ts
│   │   ├── lookup-registration.tool.test.ts
│   │   ├── map-domain.tool.test.ts
│   │   ├── probe-http.tool.test.ts
│   │   ├── recon-guidance.tool.test.ts
│   │   ├── resolve-dns.tool.test.ts
│   │   └── session-mode.test.ts
│   ├── prompts/
│   ├── resources/
│   ├── smoke/
│   │   └── definitions.test.ts
│   ├── tools/
│   └── unit/
│       └── services/
│           ├── ct/
│           │   └── ct-service.test.ts
│           ├── dns/
│           │   └── dns-service.test.ts
│           ├── http/
│           │   └── http-service.test.ts
│           ├── registration/
│           │   └── registration-service.test.ts
│           ├── shodan/
│           │   └── shodan-service.test.ts
│           └── tls/
│               └── tls-service.test.ts
├── .dockerignore
├── .env.example
├── .gitattributes
├── .gitignore
├── .mcpbignore
├── AGENTS.md
├── biome.json
├── bun.lock
├── bunfig.toml
├── CHANGELOG.md
├── CLAUDE.md
├── devcheck.config.json
├── Dockerfile
├── LICENSE
├── manifest.json
├── package.json
├── README.md
├── server.json
├── tsconfig.build.json
├── tsconfig.json
└── vitest.config.ts
```

_Note: This tree excludes files and directories matched by .gitignore and default patterns._
