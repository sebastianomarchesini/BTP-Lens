import { describe, expect, it } from 'vitest';
import {
  PERSONAL_ENTITY_NAME,
  PSEUDO_ROLES,
  ROLE_SHAPE,
  STRONG_PERSONAL_FIELDS,
  WEAK_PERSONAL_FIELDS,
  isStrongPersonalField,
  isWeakPersonalField,
} from '../../../src/analyzers/project/patterns.js';

describe('personal field patterns', () => {
  it.each([
    'email',
    'E-Mail',
    'e_mail',
    'firstName',
    'last_name',
    'dateOfBirth',
    'DOB',
    'creditCardNo',
    'creditcard_number',
    'cardNumber',
    'IBAN',
    'mobilePhone',
    'workEmail',
    'homeFax',
    'voiceMail',
    'salary',
    'nationality',
  ])('%s is a strong personal field', (name) => {
    expect(isStrongPersonalField(name)).toBe(true);
    expect(isWeakPersonalField(name)).toBe(false);
  });

  it.each([
    'street',
    'streetAddress',
    'street_2',
    'city',
    'postCode',
    'zipCode',
    'latitude',
    'longitude',
    'country',
  ])('%s is a weak personal field', (name) => {
    expect(isWeakPersonalField(name)).toBe(true);
    expect(isStrongPersonalField(name)).toBe(false);
  });

  it.each([
    'ID',
    'title',
    'description',
    'amount',
    'emailsSent',
    'phonetic',
    'cityCode',
    'phone_count',
    'status',
  ])('%s is neither', (name) => {
    expect(isStrongPersonalField(name)).toBe(false);
    expect(isWeakPersonalField(name)).toBe(false);
  });

  it('matches whole names only, except for the starred prefix and suffix entries', () => {
    // `phone` is also a suffix entry, so `cellPhone` matches but `phoneCount` does not.
    expect(isStrongPersonalField('cellPhone')).toBe(true);
    expect(isStrongPersonalField('phoneCount')).toBe(false);
    // A bare suffix is the whole-name entry, not a suffix match of itself.
    expect(isStrongPersonalField('phone')).toBe(true);
    expect(isStrongPersonalField('creditCardExpiry')).toBe(true);
    expect(isStrongPersonalField('cardholder')).toBe(false);
    expect(STRONG_PERSONAL_FIELDS).toContain('ssn');
    expect(WEAK_PERSONAL_FIELDS).toContain('street*');
  });

  it('names entities that make weak fields personal', () => {
    for (const name of [
      'Addresses',
      'Contacts',
      'Persons',
      'Customers',
      'Employees',
      'Users',
      'Patients',
      'Members',
      'Applicants',
      'SupplierContact',
    ]) {
      expect(PERSONAL_ENTITY_NAME.test(name), name).toBe(true);
    }
    for (const name of ['Warehouses', 'Orders', 'Products']) {
      expect(PERSONAL_ENTITY_NAME.test(name), name).toBe(false);
    }
  });

  it('lists the cds pseudo-roles and the role shape', () => {
    expect(PSEUDO_ROLES).toEqual([
      'any',
      'authenticated-user',
      'identified-user',
      'registered-user',
      'internal-user',
      'system-user',
      'privileged-user',
    ]);
    expect(ROLE_SHAPE.test('admin')).toBe(true);
    expect(ROLE_SHAPE.test('$XSAPPNAME.admin')).toBe(true);
    expect(ROLE_SHAPE.test('role with space')).toBe(false);
    expect(ROLE_SHAPE.test('')).toBe(false);
    expect(ROLE_SHAPE.test('x'.repeat(65))).toBe(false);
  });
});
