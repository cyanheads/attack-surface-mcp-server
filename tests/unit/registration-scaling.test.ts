/**
 * @fileoverview Thread-CPU guard against quadratic scans over adversarial registration evidence.
 * @module tests/unit/registration-scaling
 */
import { describe, expect, it } from 'vitest';
import { normalizeAllocation } from '@/services/registration/allocations.js';
import { literalText } from '@/utils/literal-text.js';
import { isValidRegistrationTarget } from '@/utils/validation.js';

describe('registration scan scaling', () => {
  it('bounds caller-sized delimiter and digit scans on thread CPU', () => {
    for (const size of [16_384, 262_144, 1_048_576]) {
      const digits = `8.8.8.8/${'2'.repeat(size)}x`;
      const ticks = '`x'.repeat(size / 2);
      const started = process.threadCpuUsage();
      expect(isValidRegistrationTarget(digits)).toBe(false);
      expect(normalizeAllocation(digits)).toEqual([]);
      expect(literalText(ticks)).toBe(`\`\` ${ticks} \`\``);
      const cpu = process.threadCpuUsage(started);
      // Thread CPU excludes scheduling delay while bounding pathological scans.
      expect(cpu.user + cpu.system).toBeLessThan(500_000);
    }
  });

  it('keeps full-span scan growth below quadratic scaling', () => {
    const scans = [
      (size: number) => () => isValidRegistrationTarget(`8.8.8.8/${'2'.repeat(size)}x`),
      (size: number) => () => normalizeAllocation(`8.8.8.8/${'2'.repeat(size)}x`),
      (size: number) => () => literalText('`x'.repeat(size / 2)),
    ];
    for (const scan of scans) {
      const small = scan(16_384);
      const large = scan(1_048_576);
      for (let i = 0; i < 20; i++) small();
      const start = process.threadCpuUsage();
      let repetitions = 0;
      let smallCpu = 0;
      do {
        for (let i = 0; i < 10; i++) small();
        repetitions += 10;
        const elapsed = process.threadCpuUsage(start);
        smallCpu = elapsed.user + elapsed.system;
      } while (smallCpu < 10_000);
      const largeStart = process.threadCpuUsage();
      for (let i = 0; i < repetitions; i++) large();
      const elapsed = process.threadCpuUsage(largeStart);
      expect((elapsed.user + elapsed.system) / smallCpu).toBeLessThan(256);
    }
  });
});
