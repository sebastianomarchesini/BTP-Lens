import type { RawSeedData, RawSeedSensitiveColumn, SeedSensitiveKind } from '../../model/raw.js';

/*
 * Seed CSV files: header shape and value checks only. The header is accepted
 * when every field is identifier-shaped; then the first rows are checked for
 * card numbers (Luhn), IBANs (mod 97) and non-empty secrets in columns whose
 * name says so. Only the 1-based positions of sensitive columns, their kind
 * and counts are kept: no header name (a header-less file whose first row is
 * identifier-shaped would otherwise leak a cell value), and never a value.
 */

export const MAX_ROWS_CHECKED = 200;
export const MAX_HEADER_FIELDS = 200;
const BOM = '\uFEFF';
const HEADER_FIELD = /^[A-Za-z_][A-Za-z0-9_.]{0,63}$/;

const CARD_COLUMN = /(credit|debit|payment|cc)?card(no|num|number)?$|^pan$|^ccnum/i;
const NOT_A_CARD_COLUMN = /^(id|business|boarding|gift|loyalty|member|key|sd|sim|score|post)card/i;
const IBAN_COLUMN = /iban/i;
const SECRET_COLUMN =
  /passw(or)?d|secret|api[_-]?key|private[_-]?key|(access|auth|refresh|bearer|id)[_-]?token$/i;

export function sensitiveKindOf(column: string): SeedSensitiveKind | null {
  if (CARD_COLUMN.test(column) && !NOT_A_CARD_COLUMN.test(column)) return 'card';
  if (IBAN_COLUMN.test(column)) return 'iban';
  if (SECRET_COLUMN.test(column)) return 'secret';
  return null;
}

export function isLuhnValid(digits: string): boolean {
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i -= 1) {
    let digit = digits.charCodeAt(i) - 48;
    if (double) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    double = !double;
  }
  return sum % 10 === 0;
}

export function isCardNumber(value: string): boolean {
  const digits = value.replace(/[\s-]/g, '');
  return /^\d{13,19}$/.test(digits) && isLuhnValid(digits);
}

export function isIban(value: string): boolean {
  const compact = value.replace(/\s/g, '');
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/.test(compact)) return false;
  const rearranged = compact.slice(4) + compact.slice(0, 4);
  let remainder = 0;
  for (const c of rearranged) {
    const piece = c >= 'A' ? String(c.charCodeAt(0) - 55) : c;
    for (const digit of piece) remainder = (remainder * 10 + (digit.charCodeAt(0) - 48)) % 97;
  }
  return remainder === 1;
}

function valueMatches(kind: SeedSensitiveKind, value: string): boolean {
  switch (kind) {
    case 'card':
      return isCardNumber(value);
    case 'iban':
      return isIban(value);
    case 'secret':
      return value.trim() !== '';
  }
}

/** `,` or `;`, whichever the header line uses more (outside quotes). */
export function sniffDelimiter(headerLine: string): ',' | ';' {
  let commas = 0;
  let semicolons = 0;
  let quoted = false;
  for (const c of headerLine) {
    if (c === '"') quoted = !quoted;
    else if (!quoted && c === ',') commas += 1;
    else if (!quoted && c === ';') semicolons += 1;
  }
  return semicolons > commas ? ';' : ',';
}

/**
 * RFC 4180-style rows: quoted fields may contain the delimiter, newlines and
 * doubled quotes. Stops after `maxRows` rows.
 */
export function parseCsvRows(text: string, delimiter: ',' | ';', maxRows: number): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = '';
  let quoted = false;
  let i = 0;
  const endRow = (): void => {
    row.push(field);
    rows.push(row);
    row = [];
    field = '';
  };
  while (i < text.length && rows.length < maxRows) {
    const c = text[i] ?? '';
    if (quoted) {
      if (c === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i += 2;
          continue;
        }
        quoted = false;
      } else {
        field += c;
      }
      i += 1;
    } else if (c === '"' && field === '') {
      quoted = true;
      i += 1;
    } else if (c === delimiter) {
      row.push(field);
      field = '';
      i += 1;
    } else if (c === '\n' || c === '\r') {
      if (c === '\r' && text[i + 1] === '\n') i += 1;
      endRow();
      i += 1;
    } else {
      field += c;
      i += 1;
    }
  }
  if (rows.length < maxRows && (field !== '' || row.length > 0)) endRow();
  return rows;
}

function firstLine(text: string): string {
  const end = text.search(/\r|\n/);
  return end === -1 ? text : text.slice(0, end);
}

export function scanSeedCsv(text: string, file: string): RawSeedData {
  const body = text.startsWith(BOM) ? text.slice(1) : text;
  const delimiter = sniffDelimiter(firstLine(body));
  const rows = parseCsvRows(body, delimiter, MAX_ROWS_CHECKED + 1);
  const header = rows[0] ?? [];
  const headerOk =
    header.length > 0 &&
    header.length <= MAX_HEADER_FIELDS &&
    header.every((field) => HEADER_FIELD.test(field));
  if (!headerOk) {
    return { file, columnCount: 0, headerRejected: true, rowsChecked: 0, sensitiveColumns: [] };
  }
  const dataRows = rows.slice(1).filter((row) => row.length > 1 || (row[0] ?? '') !== '');
  const sensitiveColumns: RawSeedSensitiveColumn[] = [];
  header.forEach((column, index) => {
    const kind = sensitiveKindOf(column);
    if (kind === null) return;
    const rowsMatching = dataRows.filter((row) => valueMatches(kind, row[index] ?? '')).length;
    sensitiveColumns.push({ columnIndex: index + 1, kind, rowsMatching });
  });
  return {
    file,
    columnCount: header.length,
    headerRejected: false,
    rowsChecked: dataRows.length,
    sensitiveColumns,
  };
}
