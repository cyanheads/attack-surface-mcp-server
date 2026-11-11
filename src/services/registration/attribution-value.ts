/**
 * @fileoverview Distinguish disclosed registration attribution values from registry placeholders.
 * @module services/registration/attribution-value
 */

/** Identify disclosed registration attribution values, preserving their text. */
export function attributionValue(value: unknown): string | undefined {
  if (typeof value !== 'string') return;
  const text = value.trim();
  if (!text) return;
  const marker = text.toLowerCase();
  if (
    marker === 'redacted' ||
    marker.startsWith('redacted for ') ||
    marker.startsWith('[redacted') ||
    marker.startsWith('data redacted') ||
    marker === 'not disclosed' ||
    marker === 'not published' ||
    marker === 'withheld for privacy' ||
    marker === 'n/a' ||
    /^\*+$/.test(text)
  )
    return;
  return value;
}
