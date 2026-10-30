/**
 * @fileoverview Bundle pruning removes package-root agent docs while preserving executable SDK skills.
 * @module tests/scripts/bundle-agent-docs
 */
import { describe, expect, it } from 'vitest';
import { filterAgentDocEntries } from '../../scripts/clean-mcpb.js';

const packagingModule: unknown = await import(
  new URL('../../scripts/lint-packaging.ts', import.meta.url).href
);
if (
  typeof packagingModule !== 'object' ||
  packagingModule === null ||
  !('AGENT_DOC_ENTRY' in packagingModule) ||
  !(packagingModule.AGENT_DOC_ENTRY instanceof RegExp)
) {
  throw new TypeError('Packaging linter must export the agent documentation pattern.');
}
const agentDocEntry = packagingModule.AGENT_DOC_ENTRY;

describe('bundle agent documentation pruning', () => {
  it('strips agent trees at scoped, unscoped, and nested package roots', () => {
    const entries = [
      'node_modules/@cyanheads/mcp-ts-core/framework-skills/add-tool/SKILL.md',
      'node_modules/example/skills/review/SKILL.md',
      'node_modules/example/.claude/settings.json',
      'node_modules/example/.agents/skills/review/SKILL.md',
      'node_modules/example/SKILL.md',
      'node_modules/example/node_modules/@scope/nested/skills/review/SKILL.md',
    ];
    expect(filterAgentDocEntries(entries)).toEqual(entries);
    expect(entries.filter((entry) => agentDocEntry.test(entry))).toEqual(entries);
  });

  it('keeps executable skills extensions and the server published tree', () => {
    const entries = [
      'node_modules/@modelcontextprotocol/server/dist/esm/ext/skills/index.js',
      'node_modules/@modelcontextprotocol/server/dist/esm/ext/skills/index.d.ts',
      'node_modules/example/dist/skills/runtime.js',
      'node_modules/example/node_modules/@scope/nested/dist/skills/runtime.js',
      'skills/passive-assessment/SKILL.md',
    ];
    expect(filterAgentDocEntries(entries)).toEqual([]);
    expect(entries.filter((entry) => agentDocEntry.test(entry))).toEqual([]);
  });
});
