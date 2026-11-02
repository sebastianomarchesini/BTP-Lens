import type { RawHtmlBootstrap, Ui5VersionForm } from '../../model/raw.js';

/*
 * SAPUI5 bootstrap scripts in HTML files: a `<script>` with
 * id="sap-ui-bootstrap" or a src ending in sap-ui-core.js. Attributes are
 * read with a small tokenizer, never a nested regex. Of an http(s) src only
 * origin and path survive (no userinfo, query or fragment), of a relative src
 * only the file name (a path could be absolute or climb out of the project);
 * the integrity value and every other attribute are never stored.
 */

const MAX_BOOTSTRAPS_PER_FILE = 200;
const MAX_SRC_LENGTH = 200;
/** A start tag longer than this is cut: no real bootstrap tag comes close. */
const MAX_TAG_LENGTH = 16 * 1024;
export const NON_HTTP_SRC = '[non-http]';

const SCHEME = /^[a-z][a-z0-9+.-]*:/i;
const TEST_PAGE_NAME = /(flpSandbox|\.qunit)\.html$/i;

interface ScriptTag {
  /** Offset of `<script` in the text. */
  index: number;
  /** Offset just after the closing `>` (or where the tag was cut). */
  end: number;
  attributes: Map<string, string>;
}

/** Reads the attributes of one start tag beginning at `<script`. */
function readTag(fullText: string, start: number): ScriptTag {
  const attributes = new Map<string, string>();
  const text = fullText.slice(start, start + MAX_TAG_LENGTH);
  const isSpace = (c: string): boolean => c === ' ' || c === '\t' || c === '\n' || c === '\r';
  let i = '<script'.length;
  while (i < text.length) {
    const c = text[i] ?? '';
    if (c === '>') break;
    if (isSpace(c) || c === '/') {
      i += 1;
      continue;
    }
    const nameStart = i;
    while (i < text.length && !isSpace(text[i] ?? '') && !'=/>'.includes(text[i] ?? '')) i += 1;
    const name = text.slice(nameStart, i);
    while (i < text.length && isSpace(text[i] ?? '')) i += 1;
    let value = '';
    if (text[i] === '=') {
      i += 1;
      while (i < text.length && isSpace(text[i] ?? '')) i += 1;
      const quote = text[i];
      if (quote === '"' || quote === "'") {
        const close = text.indexOf(quote, i + 1);
        value = text.slice(i + 1, close === -1 ? text.length : close);
        i = close === -1 ? text.length : close + 1;
      } else {
        const valueStart = i;
        while (i < text.length && !isSpace(text[i] ?? '') && text[i] !== '>') i += 1;
        value = text.slice(valueStart, i);
      }
    }
    if (name !== '') attributes.set(name.toLowerCase(), value);
  }
  return { index: start, end: start + Math.min(i + 1, text.length), attributes };
}

/**
 * The bootstrap tags of a page, at most MAX_BOOTSTRAPS_PER_FILE. Every
 * `<script` is examined; the scan resumes after each tag, so the text is
 * read once whatever the number of tags.
 */
function bootstrapTags(text: string): ScriptTag[] {
  const tags: ScriptTag[] = [];
  const pattern = /<script\b/gi;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(text)) !== null && tags.length < MAX_BOOTSTRAPS_PER_FILE) {
    const tag = readTag(text, match.index);
    if (isBootstrap(tag)) tags.push(tag);
    pattern.lastIndex = Math.max(pattern.lastIndex, tag.end);
  }
  return tags;
}

/** The path part of a src (before `?` or `#`). */
function pathPart(src: string): string {
  return src.replace(/[?#].*$/, '');
}

function isBootstrap(tag: ScriptTag): boolean {
  const src = tag.attributes.get('src');
  return (
    tag.attributes.get('id') === 'sap-ui-bootstrap' ||
    (src !== undefined && pathPart(src).endsWith('sap-ui-core.js'))
  );
}

export interface SafeSrc {
  src: string;
  external: boolean;
}

/** The file name part of a relative src (after the last `/`, before `?` or `#`). */
function fileNameOf(src: string): string {
  const path = pathPart(src);
  return path.slice(path.lastIndexOf('/') + 1);
}

/** Origin and path of an http(s) URL, the file name of a relative one, or the non-http marker. */
export function safeSrc(raw: string): SafeSrc {
  const trimmed = raw.trim();
  // A protocol-relative `//host/path` loads from the page's scheme, so it is external.
  const absolute = /^https?:\/\//i.test(trimmed) || trimmed.startsWith('//');
  if (absolute) {
    try {
      const url = new URL(trimmed.startsWith('//') ? `https:${trimmed}` : trimmed);
      return { src: `${url.origin}${url.pathname}`.slice(0, MAX_SRC_LENGTH), external: true };
    } catch {
      return { src: NON_HTTP_SRC, external: false };
    }
  }
  if (SCHEME.test(trimmed)) return { src: NON_HTTP_SRC, external: false };
  return { src: fileNameOf(trimmed).slice(0, MAX_SRC_LENGTH), external: false };
}

export function versionFormOf(src: string, external: boolean): Ui5VersionForm {
  if (!external) return 'none';
  if (/\/\d+\.\d+\.\d+\//.test(src)) return 'specific';
  if (/\/\d+\.\d+\//.test(src)) return 'evergreen';
  return 'latest';
}

export function isTestPage(file: string): boolean {
  const name = file.slice(file.lastIndexOf('/') + 1);
  return /(^|\/)test\//.test(file) || TEST_PAGE_NAME.test(name);
}

function lineOf(text: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index; i += 1) if (text.charCodeAt(i) === 10) line += 1;
  return line;
}

export function scanHtml(text: string, file: string): RawHtmlBootstrap[] {
  const testPage = isTestPage(file);
  return bootstrapTags(text).map((tag) => {
    const { src, external } = safeSrc(tag.attributes.get('src') ?? '');
    return {
      file,
      line: lineOf(text, tag.index),
      src,
      external,
      integrity: tag.attributes.has('integrity'),
      versionForm: versionFormOf(src, external),
      testPage,
    };
  });
}
