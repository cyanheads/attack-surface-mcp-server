/**
 * @fileoverview Shared literal-text boundary tests, independent of tool wiring.
 * @module tests/unit/literal-text
 */
import { describe, expect, it } from 'vitest';
import { literalText } from '@/utils/literal-text.js';

describe('literalText', () => {
  it.each([
    ['plain', '`plain`'],
    ['<section>*audit*</section>', '`<section>*audit*</section>`'],
    ['`edge`', '`` `edge` ``'],
    ['a``b', '```a``b```'],
    [' leading and trailing ', '`  leading and trailing  `'],
    ['   ', '`   `'],
    ['', ''],
  ])('preserves single-line %j', (value, expected) => {
    expect(literalText(value)).toBe(expected);
  });
  it.each(['first\nlast', 'first\r\n```\r\nlast', 'first\n`````\n</details>\nlast'])(
    'fences multiline %j',
    (value) => {
      const text = literalText(value);
      const longest = Math.max(3, ...[...value.matchAll(/`+/g)].map(([run]) => run.length + 1));
      const fence = '`'.repeat(longest);
      expect(text).toBe(`\n\n${fence}\n${value}\n${fence}\n\n`);
    },
  );
});
