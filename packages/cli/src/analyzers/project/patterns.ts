import { ROLE_PATTERN } from '../../model/raw.js';

/** Roles cds never turns into XSUAA scopes. */
export const PSEUDO_ROLES: readonly string[] = [
  'any',
  'authenticated-user',
  'identified-user',
  'registered-user',
  'internal-user',
  'system-user',
  'privileged-user',
];

/** A role name as it may appear in `@requires` or `@restrict.to`. */
export const ROLE_SHAPE = ROLE_PATTERN;

/*
 * Field names that identify a person on their own. Entries are compared
 * against the lowercased field name with `_` and `-` removed: a plain entry
 * matches the whole name, `x*` matches a prefix and `*x` a suffix
 * (`mobilePhone`, `workEmail`).
 */
export const STRONG_PERSONAL_FIELDS: readonly string[] = [
  'email',
  'e-mail',
  'mail',
  'phone',
  'mobile',
  'telephone',
  'fax',
  'firstname',
  'lastname',
  'givenname',
  'familyname',
  'surname',
  'fullname',
  'birthdate',
  'birthday',
  'dateofbirth',
  'dob',
  'ssn',
  'socialsecurity',
  'taxid',
  'vatid',
  'passport',
  'nationalid',
  'iban',
  'bic',
  'creditcard*',
  'cardnumber',
  'salary',
  'gender',
  'religion',
  'nationality',
  'ethnicity',
  '*phone',
  '*mail',
  '*fax',
  '*email',
];

/** Field names that are personal only together with a strong field or a personal entity. */
export const WEAK_PERSONAL_FIELDS: readonly string[] = [
  'street*',
  'city',
  'postcode',
  'zipcode',
  'latitude',
  'longitude',
  'country',
];

/** Entity names that make weak fields count as personal data. */
export const PERSONAL_ENTITY_NAME =
  /address|contact|person|customer|employee|user|patient|member|applicant/i;

function normalize(name: string): string {
  return name.toLowerCase().replace(/[_-]/g, '');
}

function matchesPattern(normalized: string, entry: string): boolean {
  const pattern = normalize(entry);
  if (pattern.startsWith('*')) {
    const suffix = pattern.slice(1);
    return normalized.length > suffix.length && normalized.endsWith(suffix);
  }
  if (pattern.endsWith('*')) return normalized.startsWith(pattern.slice(0, -1));
  return normalized === pattern;
}

export function isStrongPersonalField(name: string): boolean {
  const normalized = normalize(name);
  return STRONG_PERSONAL_FIELDS.some((entry) => matchesPattern(normalized, entry));
}

export function isWeakPersonalField(name: string): boolean {
  const normalized = normalize(name);
  return WEAK_PERSONAL_FIELDS.some((entry) => matchesPattern(normalized, entry));
}
