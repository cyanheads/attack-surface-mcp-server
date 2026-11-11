/**
 * @fileoverview Schema and literal text rendering for registration abuse contacts.
 * @module mcp-server/tools/registration-abuse-contact
 */
import { z } from '@cyanheads/mcp-ts-core';
import { literalText } from '@/utils/literal-text.js';

/** Public fields attributed to one abuse contact. */
export const RegistrationAbuseContactSchema = z.object({
  name: z.string().optional().describe('Published abuse contact name.'),
  email: z.string().optional().describe('Published abuse contact email address.'),
});

/** Render each disclosed value with its label and literal Markdown formatting. */
export function formatRegistrationAbuseContact(
  label: string,
  contact: z.infer<typeof RegistrationAbuseContactSchema>,
): string[] {
  return [
    ...(contact.name ? [`**${label} name:** ${literalText(contact.name)}`] : []),
    ...(contact.email ? [`**${label} email:** ${literalText(contact.email)}`] : []),
  ];
}
