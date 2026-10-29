import { constants } from 'node:fs';
import { open } from 'node:fs/promises';
import { parseDocument } from 'yaml';
import { IDENTIFIER_PATTERN } from '../../model/raw.js';

/*
 * Safe file reads for the project collector. A file is opened without
 * following symlinks, checked with fstat to be a regular file within the size
 * limit, read at most once up to that limit and rejected when it looks
 * binary. Every failure is a reason code, never a message: the collector
 * records reasons, and messages from Node or a parser could carry a path or
 * file content.
 */

export const MAX_FILE_BYTES = 2 * 1024 * 1024;
/** A NUL byte in this many leading bytes marks a file as binary. */
export const NUL_SCAN_BYTES = 8 * 1024;

export type ReadFailure = 'too-large' | 'binary' | 'unreadable';

export type ReadResult =
  { ok: true; text: string; bytes: number } | { ok: false; reason: ReadFailure };

export async function readProjectFile(path: string): Promise<ReadResult> {
  // O_NOFOLLOW: a symlink planted at an allow-listed name is refused, not read
  // through. O_NONBLOCK: opening a FIFO for reading must not wait for a writer.
  const flags = constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0);
  let handle;
  try {
    handle = await open(path, flags);
  } catch {
    return { ok: false, reason: 'unreadable' };
  }
  try {
    const stats = await handle.stat();
    if (!stats.isFile()) return { ok: false, reason: 'unreadable' };
    if (stats.size > MAX_FILE_BYTES) return { ok: false, reason: 'too-large' };
    const buffer = Buffer.alloc(Math.min(stats.size, MAX_FILE_BYTES));
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
    const head = buffer.subarray(0, Math.min(bytesRead, NUL_SCAN_BYTES));
    if (head.includes(0)) return { ok: false, reason: 'binary' };
    return { ok: true, text: buffer.toString('utf8', 0, bytesRead), bytes: bytesRead };
  } catch {
    return { ok: false, reason: 'unreadable' };
  } finally {
    await handle.close().catch(() => undefined);
  }
}

/** JSON.parse without its message: a syntax error echoes the source text. */
export function parseJson(text: string): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return undefined;
  }
}

/**
 * YAML with alias expansion bounded (billion laughs), duplicate keys
 * tolerated (last wins, as the cds and mta tools do), merge keys (`<<`)
 * applied as the MTA build tool does, and no source lines in errors. With `logLevel: 'silent'` the parser collects syntax errors instead
 * of throwing them; a document with any is rejected as a whole, and the
 * errors themselves (which quote the source) are dropped.
 */
export function parseYaml(text: string): unknown {
  try {
    const document = parseDocument(text, {
      prettyErrors: false,
      logLevel: 'silent',
      uniqueKeys: false,
      merge: true,
    });
    if (document.errors.length > 0) return undefined;
    return document.toJS({ maxAliasCount: 100 }) as unknown;
  } catch {
    return undefined;
  }
}

export function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** The value when it is a string, else undefined. */
export function stringValue(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined;
}

/** The value when it is an identifier-shaped string, else null (never an `other` bucket). */
export function identifierOrNull(value: unknown): string | null {
  return typeof value === 'string' && IDENTIFIER_PATTERN.test(value) ? value : null;
}

export function isIdentifier(value: unknown): value is string {
  return typeof value === 'string' && IDENTIFIER_PATTERN.test(value);
}

/** Identifier-shaped strings of an array, in order, up to a limit. */
export function identifiers(value: unknown, max: number): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter(isIdentifier).slice(0, max);
}

/** Plain-object items of an array, up to a limit. */
export function objectItems(value: unknown, max: number): Record<string, unknown>[] {
  if (!Array.isArray(value)) return [];
  return value.filter(isPlainObject).slice(0, max);
}
