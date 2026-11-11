/**
 * @fileoverview Read attribution from the entity roles and jCards embedded in an RDAP response.
 * @module services/registration/rdap-attribution
 */
import { attributionValue } from './attribution-value.js';
import type { DomainRegistration, IpRegistration, RegistrationAbuseContact } from './types.js';

/** The entity fields used for role-based attribution. */
export interface RdapEntity {
  entities?: RdapEntity[];
  handle?: string;
  roles?: string[];
  vcardArray?: unknown;
}

function jcardValues(entity: RdapEntity, key: string): string[] {
  const card = entity.vcardArray;
  if (!Array.isArray(card) || card[0] !== 'vcard' || !Array.isArray(card[1])) return [];
  const values: string[] = [];
  for (const field of card[1] as unknown[]) {
    if (!Array.isArray(field) || field[0] !== key) continue;
    const value = attributionValue(field[3]);
    if (value !== undefined) values.push(value);
  }
  return values;
}

function registrarName(entity: RdapEntity): string | undefined {
  const card = entity.vcardArray;
  if (Array.isArray(card) && Array.isArray(card[1])) {
    for (const field of card[1] as unknown[]) {
      if (Array.isArray(field) && field[0] === 'fn' && typeof field[3] === 'string')
        return field[3];
    }
  }
  return entity.handle;
}

function singleValue(values: string[]): string | undefined {
  const first = values[0];
  return values.every((value) => value === first) ? first : undefined;
}

function hasRole(entity: RdapEntity, role: string): boolean {
  return Array.isArray(entity?.roles) && entity.roles.includes(role);
}

function abuseContact(
  entities: RdapEntity[],
  subtrees: RdapEntity[],
): RegistrationAbuseContact | undefined {
  const candidates = [...entities];
  const pending = [...subtrees];
  while (pending.length > 0) {
    const entity = pending.pop();
    if (!Array.isArray(entity?.entities)) continue;
    for (const child of entity.entities) {
      candidates.push(child);
      pending.push(child);
    }
  }
  let contact: RegistrationAbuseContact | undefined;
  for (const entity of candidates) {
    if (!hasRole(entity, 'abuse')) continue;
    const name = singleValue(jcardValues(entity, 'fn'));
    const email = singleValue(jcardValues(entity, 'email'));
    if (!name && !email) continue;
    if (contact && (contact.name !== name || contact.email !== email)) return;
    contact = { ...(name && { name }), ...(email && { email }) };
  }
  return contact;
}

/** Attribute an IP record to its direct organizational registrant and associated abuse contact. */
export function ipRdapAttribution(
  entities?: RdapEntity[],
): Pick<IpRegistration, 'organization' | 'abuseContact'> {
  if (!Array.isArray(entities)) return {};
  const registrants = entities.filter((entity) => hasRole(entity, 'registrant'));
  const organization = singleValue(
    registrants.flatMap((entity) =>
      singleValue(jcardValues(entity, 'kind')) === 'org' ? jcardValues(entity, 'fn') : [],
    ),
  );
  const contact = abuseContact(entities, registrants);
  return { ...(organization && { organization }), ...(contact && { abuseContact: contact }) };
}

/** Read the registrar and any abuse contact in the same registrar's subtree. */
export function domainRdapAttribution(
  entities?: RdapEntity[],
): Pick<DomainRegistration, 'registrar' | 'registrarAbuseContact'> {
  if (!Array.isArray(entities)) return {};
  let selected: RdapEntity | undefined;
  let registrar: string | undefined;
  const registrars = entities.filter((entity) => hasRole(entity, 'registrar'));
  for (const entity of registrars) {
    registrar = registrarName(entity);
    if (registrar === undefined) continue;
    selected = entity;
    break;
  }
  if (!selected && registrars.length === 1) selected = registrars[0];
  const contact = selected && abuseContact([], [selected]);
  return { ...(registrar && { registrar }), ...(contact && { registrarAbuseContact: contact }) };
}
