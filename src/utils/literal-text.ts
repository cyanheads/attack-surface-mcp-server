/**
 * @fileoverview Literal Markdown evidence, preserving multiline values in fenced blocks.
 * @module utils/literal-text
 */
import { markdown } from '@cyanheads/mcp-ts-core/utils';

/** Render upstream text literally without altering the structured value. */
export function literalText(value: string): string {
  if (value === '') return '';
  if (/[\r\n]/.test(value)) return `\n\n${markdown().codeBlock(value).build()}\n\n`;
  return markdown().inlineCode(value).build();
}
