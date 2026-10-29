import {
  IDENTIFIER_PATTERN,
  ROLE_PATTERN,
  type RawCdsAnnotate,
  type RawCdsAssociation,
  type RawCdsEntity,
  type RawCdsFile,
  type RawCdsService,
  type RawCdsUsing,
} from '../../model/raw.js';

/*
 * A structural scanner for CDS source, not a parser. Comments and string
 * contents are blanked first (keeping positions, so line numbers hold), then
 * definitions are recognised by keyword and brace depth. Of the annotations,
 * only the values of `requires` and of `to` inside `restrict` objects are
 * read from the original text, and only when they are role-shaped. `where`,
 * `grant`, titles, formats, defaults and every other value stay unread. All
 * loops are linear in the input and every list has a cap, so a hostile file
 * can neither stall the scan nor grow the snapshot.
 */

export const CDS_LIMITS = {
  usings: 500,
  services: 500,
  entities: 2000,
  annotates: 2000,
  serviceEntities: 2000,
  actions: 500,
  fields: 200,
  associations: 200,
  roles: 50,
} as const;

/** Words that start a statement; a missing `;` ends the previous one here. */
const STATEMENT_KEYWORDS: ReadonlySet<string> = new Set([
  'namespace',
  'using',
  'service',
  'entity',
  'annotate',
  'action',
  'function',
  'type',
  'aspect',
  'context',
  'extend',
  'event',
  'view',
  'define',
  'abstract',
]);

/** Element modifiers that precede the element name. */
const ELEMENT_MODIFIERS: ReadonlySet<string> = new Set(['key', 'virtual', 'masked', 'localized']);

const WORD_START = /[A-Za-z_$]/;
const WORD_CHAR = /[A-Za-z0-9_$.]/;
const WHITESPACE = /\s/;
const OPENERS = '([{';
const CLOSERS = ')]}';

/** Blanks comments and string contents; length, newlines and quote characters are kept. */
export function maskCds(text: string): string {
  const parts: string[] = [];
  let i = 0;
  let codeStart = 0;
  const blank = (from: number, to: number): void => {
    parts.push(text.slice(codeStart, from), text.slice(from, to).replace(/[^\n\r]/g, ' '));
    codeStart = to;
  };
  while (i < text.length) {
    const c = text[i];
    const next = text[i + 1];
    if (c === '/' && next === '/') {
      let end = text.indexOf('\n', i);
      if (end === -1) end = text.length;
      blank(i, end);
      i = end;
    } else if (c === '/' && next === '*') {
      const close = text.indexOf('*/', i + 2);
      const end = close === -1 ? text.length : close + 2;
      blank(i, end);
      i = end;
    } else if (c === "'" || c === '"') {
      // The quotes stay; a doubled quote inside a string is an escape.
      let j = i + 1;
      while (j < text.length) {
        if (text[j] === c) {
          if (text[j + 1] === c) {
            j += 2;
            continue;
          }
          break;
        }
        j += 1;
      }
      const end = Math.min(j, text.length);
      blank(i + 1, end);
      i = end + 1;
    } else {
      i += 1;
    }
  }
  parts.push(text.slice(codeStart));
  return parts.join('');
}

interface Region {
  start: number;
  end: number;
}

type HeaderStop = '{' | ';' | 'as' | 'none';

interface StatementEndOptions {
  /** `actions {` opens a block of bound actions instead of ending the statement. */
  allowActions: boolean;
  /** An annotation at statement level belongs to the next definition. */
  stopAtAnnotation: boolean;
}

class Scanner {
  readonly masked: string;
  pos = 0;
  private readonly lineStarts: number[] = [0];

  constructor(readonly text: string) {
    this.masked = maskCds(text);
    for (let i = 0; i < text.length; i += 1) {
      if (text.charCodeAt(i) === 10) this.lineStarts.push(i + 1);
    }
  }

  eof(): boolean {
    return this.pos >= this.masked.length;
  }

  peek(): string {
    return this.masked[this.pos] ?? '';
  }

  lineAt(index: number): number {
    let low = 0;
    let high = this.lineStarts.length - 1;
    while (low < high) {
      const mid = (low + high + 1) >> 1;
      if ((this.lineStarts[mid] ?? 0) <= index) low = mid;
      else high = mid - 1;
    }
    return low + 1;
  }

  skipWs(): void {
    while (!this.eof() && WHITESPACE.test(this.peek())) this.pos += 1;
  }

  /** An identifier-like word (dots included), or '' when none starts here. */
  readWord(): string {
    if (!WORD_START.test(this.peek())) return '';
    const start = this.pos;
    while (!this.eof() && WORD_CHAR.test(this.peek())) this.pos += 1;
    return this.masked.slice(start, this.pos);
  }

  /** From an opener to past its matching closer; any bracket kind counts. */
  skipGroup(): void {
    let depth = 0;
    while (!this.eof()) {
      const c = this.peek();
      this.pos += 1;
      if (OPENERS.includes(c)) depth += 1;
      else if (CLOSERS.includes(c)) {
        depth -= 1;
        if (depth <= 0) return;
      }
    }
  }

  /** A quoted string (contents blanked), a bracketed group or a bare value. */
  skipValue(): void {
    this.skipWs();
    const c = this.peek();
    if (c === "'" || c === '"') {
      const close = this.masked.indexOf(c, this.pos + 1);
      this.pos = close === -1 ? this.masked.length : close + 1;
    } else if (OPENERS.includes(c)) {
      this.skipGroup();
    } else {
      while (!this.eof() && !/[\s;,{}()[\]]/.test(this.peek())) this.pos += 1;
    }
  }

  /** `@name`, `@name: value` or `@( … )`, starting at the `@`. */
  skipAnnotation(): void {
    this.pos += 1;
    this.readWord();
    this.skipWs();
    const c = this.peek();
    if (c === '(') this.skipGroup();
    else if (c === ':') {
      this.pos += 1;
      this.skipValue();
    }
  }

  /** The part between a definition name and its body, `as`, or `;`. */
  scanHeader(): HeaderStop {
    while (!this.eof()) {
      this.skipWs();
      const c = this.peek();
      if (c === '{' || c === ';') return c;
      if (c === '}') return 'none';
      if (c === '@') this.skipAnnotation();
      else if (c === '(' || c === '[') this.skipGroup();
      else if (WORD_START.test(c)) {
        if (this.readWord() === 'as') return 'as';
      } else this.pos += 1;
    }
    return 'none';
  }

  /** Consumes the rest of a statement; `actions` when a bound-actions block was opened. */
  scanStatementEnd(options: StatementEndOptions): 'end' | 'actions' {
    while (!this.eof()) {
      this.skipWs();
      const c = this.peek();
      if (c === ';') {
        this.pos += 1;
        return 'end';
      }
      if (c === '}' || c === '') return 'end';
      if (c === '@') {
        if (options.stopAtAnnotation) return 'end';
        this.skipAnnotation();
      } else if (OPENERS.includes(c)) this.skipGroup();
      else if (WORD_START.test(c)) {
        const save = this.pos;
        const word = this.readWord();
        if (STATEMENT_KEYWORDS.has(word)) {
          this.pos = save;
          return 'end';
        }
        if (word === 'actions' && options.allowActions) {
          this.skipWs();
          if (this.peek() === '{') {
            this.pos += 1;
            return 'actions';
          }
        }
      } else this.pos += 1;
    }
    return 'end';
  }
}

/** Absolute offsets just past each `KEY:` written bare (`@key:`) or in a group (`(key:`, `, key:`). */
function annotationKeys(scanner: Scanner, regions: Region[], key: string): number[] {
  const pattern = new RegExp(`(?:@|[(,]\\s*)${key}\\s*:\\s*`, 'g');
  const found: number[] = [];
  for (const region of regions) {
    pattern.lastIndex = region.start;
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(scanner.masked)) !== null && match.index < region.end) {
      found.push(match.index + match[0].length);
    }
  }
  return found;
}

function hasToken(scanner: Scanner, regions: Region[], token: string): boolean {
  const pattern = new RegExp(`(?:@|[(,]\\s*)${token.replace(/\./g, '\\.')}\\b`, 'g');
  return regions.some((region) => {
    pattern.lastIndex = region.start;
    const match = pattern.exec(scanner.masked);
    return match !== null && match.index < region.end;
  });
}

/** The string or bare values at `index`: `'x'`, `x`, or `['a', b]`. */
function readValues(scanner: Scanner, index: number): string[] {
  const { masked, text } = scanner;
  const quoted = (at: number): { value: string; end: number } | null => {
    const quote = masked[at] ?? '';
    const close = masked.indexOf(quote, at + 1);
    return close === -1 ? null : { value: text.slice(at + 1, close), end: close + 1 };
  };
  const bare = (at: number): { value: string; end: number } => {
    let end = at;
    while (end < masked.length && WORD_CHAR.test(masked[end] ?? '')) end += 1;
    return { value: masked.slice(at, end), end };
  };
  let i = index;
  while (i < masked.length && WHITESPACE.test(masked[i] ?? '')) i += 1;
  const c = masked[i] ?? '';
  if (c === "'" || c === '"') {
    const q = quoted(i);
    return q === null ? [] : [q.value];
  }
  if (WORD_START.test(c)) return [bare(i).value];
  if (c !== '[') return [];
  const values: string[] = [];
  let depth = 0;
  for (let k = i; k < masked.length;) {
    const ch = masked[k] ?? '';
    if (ch === '[') depth += 1;
    if (ch === ']') {
      depth -= 1;
      if (depth === 0) break;
    }
    if (ch === "'" || ch === '"') {
      const q = quoted(k);
      if (q === null) break;
      values.push(q.value);
      k = q.end;
    } else if (WORD_START.test(ch)) {
      const b = bare(k);
      values.push(b.value);
      k = b.end;
    } else k += 1;
  }
  return values;
}

function roles(values: string[]): string[] {
  return [...new Set(values.filter((value) => ROLE_PATTERN.test(value)))].slice(
    0,
    CDS_LIMITS.roles,
  );
}

function requiresIn(scanner: Scanner, regions: Region[]): string[] {
  return roles(
    annotationKeys(scanner, regions, 'requires').flatMap((at) => readValues(scanner, at)),
  );
}

/** `to` values of every object in each `restrict: [ … ]` array. */
function restrictToIn(scanner: Scanner, regions: Region[]): string[] {
  const { masked } = scanner;
  const values: string[] = [];
  for (const at of annotationKeys(scanner, regions, 'restrict')) {
    if (masked[at] !== '[') continue;
    let depth = 0;
    let end = at;
    while (end < masked.length) {
      const c = masked[end] ?? '';
      if (c === '[') depth += 1;
      else if (c === ']') {
        depth -= 1;
        if (depth === 0) break;
      }
      end += 1;
    }
    const toKey = /(?:[{,]\s*)to\s*:\s*/g;
    toKey.lastIndex = at;
    let match: RegExpExecArray | null;
    while ((match = toKey.exec(masked)) !== null && match.index < end) {
      values.push(...readValues(scanner, match.index + match[0].length));
    }
  }
  return roles(values);
}

function protocolNoneIn(scanner: Scanner, regions: Region[]): boolean {
  return annotationKeys(scanner, regions, 'protocol').some((at) =>
    readValues(scanner, at).includes('none'),
  );
}

function isIdentifier(name: string): boolean {
  return IDENTIFIER_PATTERN.test(name);
}

type Frame =
  | { kind: 'top' }
  | { kind: 'service'; service: RawCdsService; stored: boolean }
  | { kind: 'actions'; service: RawCdsService | null };

function frameService(frame: Frame): RawCdsService | null {
  return frame.kind === 'top' ? null : frame.service;
}

/** `using a.b as c from '…'` and `using { a.b as c, d } from '…'`. */
function parseUsing(body: string, out: RawCdsUsing[]): void {
  const group = /^\s*\{([^}]*)\}/.exec(body);
  const entries = group ? (group[1] ?? '').split(',') : [body];
  for (const entry of entries) {
    const match = /^\s*([A-Za-z_$][\w.$]*)(?:\s+as\s+([A-Za-z_$][\w$]*))?/.exec(entry);
    if (match === null || match[1] === 'from' || out.length >= CDS_LIMITS.usings) continue;
    const target = match[1] ?? '';
    const alias = match[2] ?? target.slice(target.lastIndexOf('.') + 1);
    if (alias !== target && isIdentifier(alias) && isIdentifier(target))
      out.push({ alias, target });
  }
}

interface ElementFacts {
  fields: string[];
  associations: RawCdsAssociation[];
  personalData: boolean;
}

/** `Association to [many] T` / `Composition of [many] T`; stops before `;`, `{` or `}`. */
function parseElementType(scanner: Scanner, field: string, facts: ElementFacts): void {
  while (!scanner.eof()) {
    scanner.skipWs();
    const c = scanner.peek();
    if (c === ';' || c === '{' || c === '}' || c === '') return;
    if (c === '@') scanner.skipAnnotation();
    else if (c === '(' || c === '[') scanner.skipGroup();
    else if (WORD_START.test(c)) {
      const word = scanner.readWord();
      if (word !== 'Association' && word !== 'Composition') continue;
      scanner.skipWs();
      const link = scanner.readWord();
      if (link !== 'to' && link !== 'of') continue;
      scanner.skipWs();
      const save = scanner.pos;
      const cardinality = scanner.readWord();
      if (cardinality !== 'many' && cardinality !== 'one') scanner.pos = save;
      scanner.skipWs();
      const target = scanner.readWord();
      if (
        isIdentifier(target) &&
        isIdentifier(field) &&
        facts.associations.length < CDS_LIMITS.associations
      ) {
        facts.associations.push({ field, target });
      }
    } else scanner.pos += 1;
  }
}

/** The elements of an entity body, starting after its `{`; nested braces are flattened. */
function parseElements(scanner: Scanner, facts: ElementFacts): void {
  let depth = 1;
  let annotationStart: number | null = null;
  while (!scanner.eof()) {
    scanner.skipWs();
    const c = scanner.peek();
    if (c === '') return;
    if (c === '}') {
      scanner.pos += 1;
      depth -= 1;
      annotationStart = null;
      if (depth === 0) return;
    } else if (c === '{') {
      scanner.pos += 1;
      depth += 1;
      annotationStart = null;
    } else if (c === ';' || c === ',') {
      scanner.pos += 1;
      annotationStart = null;
    } else if (c === '@') {
      annotationStart ??= scanner.pos;
      scanner.skipAnnotation();
    } else if (c === '(' || c === '[') {
      scanner.skipGroup();
    } else if (WORD_START.test(c)) {
      const wordStart = scanner.pos;
      const word = scanner.readWord();
      if (ELEMENT_MODIFIERS.has(word)) continue;
      scanner.skipWs();
      if (scanner.peek() !== ':') continue;
      scanner.pos += 1;
      if (isIdentifier(word) && facts.fields.length < CDS_LIMITS.fields) facts.fields.push(word);
      parseElementType(scanner, word, facts);
      const region = { start: annotationStart ?? wordStart, end: scanner.pos };
      if (hasToken(scanner, [region], 'PersonalData')) facts.personalData = true;
      annotationStart = null;
    } else scanner.pos += 1;
  }
}

/** After `as`: `projection on T` or `select from T` → T as written, else null. */
function parseProjectionTarget(scanner: Scanner): string | null {
  scanner.skipWs();
  const kind = scanner.readWord();
  scanner.skipWs();
  const link = scanner.readWord();
  const isProjection =
    (kind === 'projection' && link === 'on') || (kind === 'select' && link === 'from');
  if (!isProjection) return null;
  scanner.skipWs();
  const target = scanner.readWord();
  return isIdentifier(target) ? target : null;
}

export function scanCds(text: string, file: string): RawCdsFile {
  const scanner = new Scanner(text);
  const out: RawCdsFile = { file, usings: [], services: [], entities: [], annotates: [] };
  const frames: Frame[] = [{ kind: 'top' }];
  let annotationStart: number | null = null;

  const pushActions = (service: RawCdsService | null): void => {
    frames.push({ kind: 'actions', service });
  };

  const parseService = (prefix: Region): void => {
    scanner.skipWs();
    const nameStart = scanner.pos;
    const name = scanner.readWord();
    const headerStart = scanner.pos;
    const stop = scanner.scanHeader();
    const regions = [prefix, { start: headerStart, end: scanner.pos }];
    const service: RawCdsService = {
      name,
      line: scanner.lineAt(nameStart),
      requires: requiresIn(scanner, regions),
      restrictTo: restrictToIn(scanner, regions),
      protocolNone: protocolNoneIn(scanner, regions),
      external: hasToken(scanner, regions, 'cds.external'),
      entities: [],
      actions: [],
    };
    const stored = isIdentifier(name) && out.services.length < CDS_LIMITS.services;
    if (stored) out.services.push(service);
    if (stop === '{') {
      scanner.pos += 1;
      frames.push({ kind: 'service', service, stored });
    } else if (stop === ';') scanner.pos += 1;
  };

  const parseEntity = (prefix: Region, frame: Frame): void => {
    scanner.skipWs();
    const nameStart = scanner.pos;
    const name = scanner.readWord();
    const line = scanner.lineAt(nameStart);
    const headerStart = scanner.pos;
    const stop = scanner.scanHeader();
    const regions = [prefix, { start: headerStart, end: scanner.pos }];
    const inService = frame.kind !== 'top';
    const facts: ElementFacts = {
      fields: [],
      associations: [],
      personalData: hasToken(scanner, regions, 'PersonalData'),
    };
    let projectionOf: string | null = null;
    let tail: 'end' | 'actions' = 'end';
    if (stop === 'as') {
      projectionOf = parseProjectionTarget(scanner);
      tail = scanner.scanStatementEnd({ allowActions: true, stopAtAnnotation: true });
    } else if (stop === '{') {
      // Elements are collected for model entities only; a service body is skipped.
      if (inService) scanner.skipGroup();
      else {
        scanner.pos += 1;
        parseElements(scanner, facts);
      }
      tail = scanner.scanStatementEnd({ allowActions: true, stopAtAnnotation: true });
    } else if (stop === ';') scanner.pos += 1;

    if (!isIdentifier(name)) {
      if (tail === 'actions') pushActions(frameService(frame));
      return;
    }
    if (frame.kind === 'service') {
      if (frame.service.entities.length < CDS_LIMITS.serviceEntities) {
        frame.service.entities.push({
          name,
          line,
          requires: requiresIn(scanner, regions),
          restrictTo: restrictToIn(scanner, regions),
          readonly: hasToken(scanner, regions, 'readonly'),
          projectionOf,
        });
      }
    } else if (frame.kind === 'top' && out.entities.length < CDS_LIMITS.entities) {
      const entity: RawCdsEntity = { name, line, ...facts };
      out.entities.push(entity);
    }
    if (tail === 'actions') pushActions(frameService(frame));
  };

  const parseAction = (prefix: Region, frame: Frame): void => {
    scanner.skipWs();
    const nameStart = scanner.pos;
    const name = scanner.readWord();
    const service = frameService(frame);
    if (service !== null && isIdentifier(name) && service.actions.length < CDS_LIMITS.actions) {
      service.actions.push({
        name,
        line: scanner.lineAt(nameStart),
        requires: requiresIn(scanner, [prefix]),
        restrictTo: restrictToIn(scanner, [prefix]),
      });
    }
    scanner.scanStatementEnd({ allowActions: false, stopAtAnnotation: true });
  };

  const parseAnnotate = (statementStart: number): void => {
    scanner.skipWs();
    const nameStart = scanner.pos;
    const target = scanner.readWord();
    scanner.scanStatementEnd({ allowActions: false, stopAtAnnotation: false });
    const regions = [{ start: statementStart, end: scanner.pos }];
    if (!isIdentifier(target) || out.annotates.length >= CDS_LIMITS.annotates) return;
    const annotate: RawCdsAnnotate = {
      target,
      line: scanner.lineAt(nameStart),
      personalData: hasToken(scanner, regions, 'PersonalData'),
      requires: requiresIn(scanner, regions),
      restrictTo: restrictToIn(scanner, regions),
    };
    out.annotates.push(annotate);
  };

  const parseContext = (): void => {
    scanner.skipWs();
    scanner.readWord();
    const stop = scanner.scanHeader();
    if (stop === '{' || stop === ';') scanner.pos += 1;
    // A context only namespaces its members; they are scanned like top-level ones.
    if (stop === '{') frames.push({ kind: 'top' });
  };

  const parseUsingStatement = (): void => {
    const start = scanner.pos;
    scanner.scanStatementEnd({ allowActions: false, stopAtAnnotation: true });
    parseUsing(scanner.masked.slice(start, scanner.pos), out.usings);
  };

  while (!scanner.eof()) {
    scanner.skipWs();
    const c = scanner.peek();
    if (c === '') break;
    if (c === '}') {
      scanner.pos += 1;
      if (frames.length > 1) frames.pop();
      annotationStart = null;
      continue;
    }
    if (c === ';') {
      scanner.pos += 1;
      annotationStart = null;
      continue;
    }
    if (c === '@') {
      annotationStart ??= scanner.pos;
      scanner.skipAnnotation();
      continue;
    }
    if (OPENERS.includes(c)) {
      scanner.skipGroup();
      annotationStart = null;
      continue;
    }
    const wordStart = scanner.pos;
    const word = scanner.readWord();
    if (word === '') {
      scanner.pos += 1;
      continue;
    }
    if (word === 'define' || word === 'abstract') continue;
    const frame = frames[frames.length - 1] ?? { kind: 'top' };
    const prefix = { start: annotationStart ?? wordStart, end: wordStart };
    switch (word) {
      case 'using':
        parseUsingStatement();
        break;
      case 'service':
        parseService(prefix);
        break;
      case 'entity':
        parseEntity(prefix, frame);
        break;
      case 'action':
      case 'function':
        parseAction(prefix, frame);
        break;
      case 'annotate':
        parseAnnotate(wordStart);
        break;
      case 'context':
        parseContext();
        break;
      default:
        scanner.scanStatementEnd({ allowActions: false, stopAtAnnotation: true });
        break;
    }
    annotationStart = null;
  }
  return out;
}
