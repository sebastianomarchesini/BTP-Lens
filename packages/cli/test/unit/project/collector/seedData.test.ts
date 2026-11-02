import { describe, expect, it } from 'vitest';
import {
  MAX_HEADER_FIELDS,
  MAX_ROWS_CHECKED,
  isCardNumber,
  isIban,
  parseCsvRows,
  scanSeedCsv,
  sensitiveKindOf,
  sniffDelimiter,
} from '../../../../src/collectors/project/seedData.js';

const scan = (text: string) => scanSeedCsv(text, 'db/data/x.csv');

describe('seed CSV header', () => {
  it('accepts identifier-shaped headers and counts columns and rows', () => {
    const result = scan('ID,name,price\n1,Lamp,39.90\n2,Chair,189\n\n');
    expect(result).toEqual({
      file: 'db/data/x.csv',
      columnCount: 3,
      headerRejected: false,
      rowsChecked: 2,
      sensitiveColumns: [],
    });
  });

  it('rejects a header-less file and checks no value', () => {
    const result = scan('Poison,Person,poison.row2@example.com,5500000000000004\n');
    expect(result).toEqual({
      file: 'db/data/x.csv',
      columnCount: 0,
      headerRejected: true,
      rowsChecked: 0,
      sensitiveColumns: [],
    });
  });

  it('rejects headers with a non-identifier field, an empty file and too many fields', () => {
    expect(scan('ID,first name\n1,x').headerRejected).toBe(true);
    expect(scan('ID,1st\n1,x').headerRejected).toBe(true);
    expect(scan('ID,,x\n1,2,3').headerRejected).toBe(true);
    expect(scan('').headerRejected).toBe(true);
    expect(scan(`${'a'.repeat(65)}\nx`).headerRejected).toBe(true);
    const many = Array.from({ length: MAX_HEADER_FIELDS + 1 }, (_, i) => `c${i}`);
    expect(scan(`${many.join(',')}\n`).headerRejected).toBe(true);
    expect(scan(`${many.slice(0, MAX_HEADER_FIELDS).join(',')}\n`).columnCount).toBe(
      MAX_HEADER_FIELDS,
    );
  });

  it('tolerates a BOM, CRLF, a `;` delimiter and dotted names', () => {
    const result = scan('﻿code;descr;status.code\r\nN;New;1\r\nA;Assigned;2\r\n');
    expect(result).toMatchObject({ columnCount: 3, headerRejected: false, rowsChecked: 2 });
    expect(sniffDelimiter('a;b;c')).toBe(';');
    expect(sniffDelimiter('a,b;c')).toBe(',');
    expect(sniffDelimiter('"a;b",c')).toBe(',');
  });

  it('parses RFC-style quotes with delimiters, newlines and doubled quotes inside', () => {
    expect(parseCsvRows('a,"b,c","d\ne","f""g"\n1,2,3,4', ',', 10)).toEqual([
      ['a', 'b,c', 'd\ne', 'f"g'],
      ['1', '2', '3', '4'],
    ]);
    expect(parseCsvRows('a\n1\n2\n3', ',', 2)).toEqual([['a'], ['1']]);
  });

  it(`checks at most ${MAX_ROWS_CHECKED} data rows`, () => {
    const rows = Array.from({ length: MAX_ROWS_CHECKED + 50 }, () => '4111111111111111');
    const result = scan(`cardNumber\n${rows.join('\n')}\n`);
    expect(result.rowsChecked).toBe(MAX_ROWS_CHECKED);
    expect(result.sensitiveColumns).toEqual([
      { columnIndex: 1, kind: 'card', rowsMatching: MAX_ROWS_CHECKED },
    ]);
  });
});

describe('sensitive column names', () => {
  it.each([
    ['creditCardNo', 'card'],
    ['CreditCardNumber', 'card'],
    ['debitcard', 'card'],
    ['paymentCardNum', 'card'],
    ['ccnum', 'card'],
    ['card', 'card'],
    ['PAN', 'card'],
    ['IBAN', 'iban'],
    ['bankIban', 'iban'],
    ['password', 'secret'],
    ['passwd', 'secret'],
    ['clientSecret', 'secret'],
    ['api_key', 'secret'],
    ['apiKey', 'secret'],
    ['private-key', 'secret'],
    ['accessToken', 'secret'],
    ['refresh_token', 'secret'],
    ['id_token', 'secret'],
  ])('%s is %s', (column, kind) => {
    expect(sensitiveKindOf(column)).toBe(kind);
  });

  it.each([
    'idcard',
    'businessCard',
    'boardingCard',
    'giftcard',
    'loyaltyCard',
    'memberCard',
    'keycard',
    'sdcard',
    'simCard',
    'scorecard',
    'postcard',
    'cardinality',
    'tokenizer',
    'email',
    'name',
  ])('%s is not sensitive', (column) => {
    expect(sensitiveKindOf(column)).toBeNull();
  });
});

describe('value checks', () => {
  it('accepts Luhn-valid card numbers of 13 to 19 digits, with spaces or dashes', () => {
    expect(isCardNumber('4111111111111111')).toBe(true);
    expect(isCardNumber('4111 1111 1111 1111')).toBe(true);
    expect(isCardNumber('5500-0000-0000-0004')).toBe(true);
    expect(isCardNumber('4111111111111112')).toBe(false);
    expect(isCardNumber('411111111111')).toBe(false);
    expect(isCardNumber('not-a-card')).toBe(false);
    expect(isCardNumber('')).toBe(false);
  });

  it('accepts IBANs that pass mod 97', () => {
    expect(isIban('DE89370400440532013000')).toBe(true);
    expect(isIban('DE89 3704 0044 0532 0130 00')).toBe(true);
    expect(isIban('GB82WEST12345698765432')).toBe(true);
    expect(isIban('DE89370400440532013001')).toBe(false);
    expect(isIban('de89370400440532013000')).toBe(false);
    expect(isIban('XX')).toBe(false);
  });

  it('counts matching rows per sensitive column and stores neither a value nor a name', () => {
    const result = scan(
      [
        'ID,firstName,creditCardNo,iban,password,notes',
        '1,Mary,4111111111111111,DE89370400440532013000,POISON_pw,"prefers e-mail"',
        '2,Tom,not-a-card,DE00,,',
        '3,Ann,5500000000000004,,  ,',
      ].join('\n'),
    );
    expect(result.sensitiveColumns).toEqual([
      { columnIndex: 3, kind: 'card', rowsMatching: 2 },
      { columnIndex: 4, kind: 'iban', rowsMatching: 1 },
      { columnIndex: 5, kind: 'secret', rowsMatching: 1 },
    ]);
    const text = JSON.stringify(result);
    expect(text).not.toContain('POISON');
    expect(text).not.toContain('4111');
    expect(text).not.toContain('Mary');
    expect(text).not.toContain('firstName');
    expect(text).not.toContain('creditCardNo');
    expect(text).not.toContain('password');
    expect(text).not.toContain('notes');
  });

  it('keeps a first-row cell value out of the result when a header-less file looks like a header', () => {
    // Every field of the first row is identifier-shaped, so it is taken for a
    // header; the "column name" that matches the secret pattern is a cell value.
    const result = scanSeedCsv(
      'admin,POISON_password_cell,berlin\nbob,POISON_hunter2,paris\n',
      'test/data/users.csv',
    );
    expect(result).toEqual({
      file: 'test/data/users.csv',
      columnCount: 3,
      headerRejected: false,
      rowsChecked: 1,
      sensitiveColumns: [{ columnIndex: 2, kind: 'secret', rowsMatching: 1 }],
    });
    expect(JSON.stringify(result)).not.toMatch(/POISON|admin|berlin|bob|paris/);
  });
});
