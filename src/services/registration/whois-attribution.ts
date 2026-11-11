/**
 * @fileoverview Extract WHOIS attribution tied to the selected registration object.
 * @module services/registration/whois-attribution
 */
import { coveringAllocationSize } from './allocations.js';
import { attributionValue } from './attribution-value.js';
import type { IpRegistration, RegistrationAbuseContact } from './types.js';

type WhoisObject = Map<string, string[]>;
const ALLOCATION_FIELDS = [
  'netrange',
  'cidr',
  'inetnum',
  'inet6num',
  'netblock',
  'network:ip-network',
];

function objectsFrom(text: string): WhoisObject[] {
  const objects: WhoisObject[] = [];
  let fields: WhoisObject = new Map();
  for (const row of text.split('\n')) {
    const line = row.trim();
    if (!line) {
      if (fields.size > 0) objects.push(fields);
      fields = new Map();
      continue;
    }
    if (line.startsWith('#') || line.startsWith('%')) continue;
    const separator = line.toLowerCase().startsWith('network:')
      ? line.indexOf(':', 8)
      : line.indexOf(':');
    if (separator < 0) continue;
    const key = line.slice(0, separator).toLowerCase();
    const value = attributionValue(line.slice(separator + 1).trim());
    if (!value) continue;
    const previous = fields.get(key);
    if (previous) previous.push(value);
    else fields.set(key, [value]);
  }
  if (fields.size > 0) objects.push(fields);
  return objects;
}

function field(object: WhoisObject | undefined, ...keys: string[]): string | undefined {
  const values = keys.flatMap((key) => object?.get(key) ?? []);
  const first = values[0];
  return values.every((value) => value === first) ? first : undefined;
}

function one<T>(matches: T[]): T | undefined {
  return matches.length === 1 ? matches[0] : undefined;
}

function covers(object: WhoisObject, target: string): bigint | undefined {
  // Explicit range boundaries take precedence over CIDR projections of the same allocation.
  for (const key of ALLOCATION_FIELDS) {
    const value = field(object, key);
    if (value) return coveringAllocationSize(value, target);
  }
  return undefined;
}

function allocationFor(objects: WhoisObject[], target: string): WhoisObject | undefined {
  let best: WhoisObject | undefined;
  let bestSize: bigint | undefined;
  for (const object of objects) {
    const size = covers(object, target);
    if (size === undefined) continue;
    if (bestSize === undefined || size < bestSize) {
      best = object;
      bestSize = size;
    } else if (size === bestSize) best = undefined;
  }
  return best;
}

function linkedObject(
  objects: WhoisObject[],
  id: string | undefined,
  ...keys: string[]
): WhoisObject | undefined {
  if (!id) return;
  return one(
    objects.filter((object) => field(object, ...keys)?.toLowerCase() === id.toLowerCase()),
  );
}

/** Read explicit organization and abuse mailbox fields for the matched allocation. */
export function ipWhoisAttribution(
  target: string,
  text: string,
): Pick<IpRegistration, 'organization' | 'abuseContact'> {
  const objects = objectsFrom(text);
  const allocation = allocationFor(objects, target);
  if (!allocation) return {};
  const otherObjects = objects.filter(
    (object) => !ALLOCATION_FIELDS.some((key) => object.has(key)),
  );
  const arinOrganization = field(allocation, 'organization');
  const orgId =
    field(allocation, 'orgid', 'org') ??
    (arinOrganization?.endsWith(')') && arinOrganization.includes('(')
      ? arinOrganization.slice(arinOrganization.lastIndexOf('(') + 1, -1)
      : undefined);
  const org = linkedObject(otherObjects, orgId, 'orgid', 'organisation', 'organization');
  const contactId =
    field(allocation, 'orgabusehandle', 'abuse-c', 'mnt-irt') ??
    field(org, 'orgabusehandle', 'abuse-c', 'mnt-irt');
  const contact = linkedObject(
    otherObjects.filter((object) => object !== org),
    contactId,
    'orgabusehandle',
    'nic-hdl',
    'irt',
  );
  const organization =
    field(allocation, 'orgname', 'org-name') ?? field(org, 'orgname', 'org-name');
  const email =
    field(allocation, 'orgabuseemail', 'abuse-mailbox') ??
    field(org, 'orgabuseemail', 'abuse-mailbox') ??
    field(contact, 'orgabuseemail', 'abuse-mailbox');
  return { ...(organization && { organization }), ...(email && { abuseContact: { email } }) };
}

/** Read an abuse mailbox from the same WHOIS object as the reported registrar. */
export function domainWhoisAbuseContact(
  target: string,
  text: string,
  registrar: string | undefined,
): RegistrationAbuseContact | undefined {
  if (!registrar) return;
  const objects = objectsFrom(text);
  const domains = objects.filter((object) => object.has('domain name') || object.has('domain'));
  const selected =
    domains.length > 0
      ? one(
          domains.filter(
            (object) =>
              field(object, 'domain name', 'domain')?.toLowerCase().replace(/\.$/, '') === target,
          ),
        )
      : one(objects.filter((object) => object.has('registrar')));
  if (field(selected, 'registrar') !== registrar) return;
  const email = field(selected, 'registrar abuse contact email');
  return email ? { email } : undefined;
}
