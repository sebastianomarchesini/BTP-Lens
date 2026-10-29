import { lstat, readdir } from 'node:fs/promises';
import { basename, dirname, join, relative, sep } from 'node:path';
import { isSafeRelativePath } from '../../model/paths.js';

/*
 * The directory walk lists candidate files only. It uses lstat and visits
 * regular files and directories: symlinks, FIFOs, sockets and devices are
 * skipped and never listed. A file is listed only when its name is on the
 * allow-list below; everything else, including the deny-listed names, is
 * invisible to the rest of the collector.
 */

export type FileKind =
  | 'package.json'
  | 'cdsrc.json'
  | 'cdsrc.yaml'
  | 'gitignore'
  | 'mta'
  | 'xs-security'
  | 'xs-app'
  | 'cds'
  | 'csv'
  | 'html'
  | 'mtar';

export interface WalkedFile {
  kind: FileKind;
  /** Absolute path, built from the real root without following links. */
  abs: string;
  /** `/`-separated path relative to the root; passes isSafeRelativePath. */
  rel: string;
  /** From lstat, for archives (never opened). */
  size: number;
}

export interface WalkOptions {
  /** Absolute, real paths of directories the walk must not enter. */
  excludeDirs?: string[];
}

export interface WalkResult {
  files: WalkedFile[];
  /** The entry limit was hit; the listing is incomplete. */
  truncated: boolean;
}

export const MAX_DEPTH = 12;
export const MAX_ENTRIES = 20_000;

export const SKIPPED_DIRS: ReadonlySet<string> = new Set([
  'node_modules',
  '.git',
  'gen',
  'dist',
  'dist-report',
  'target',
  'build',
  'coverage',
  '.vscode',
  '.idea',
]);

/** Directories where `*.csv` counts as seed data. */
const SEED_DIRS: ReadonlySet<string> = new Set(['data', 'csv']);

/**
 * Names that are never opened or listed. The allow-list below would not
 * match them anyway; this check runs first so that a future allow-list
 * change cannot reach them by accident.
 */
export function isDenied(name: string): boolean {
  return (
    name === '.cdsrc-private.json' ||
    name === '.cdsrc.js' ||
    name === 'default-env.json' ||
    name === 'manifest.json' ||
    name.startsWith('.env') ||
    name.endsWith('.mtaext') ||
    name.endsWith('-key.json') ||
    name.endsWith('.pem') ||
    name.endsWith('.key') ||
    name.endsWith('.http') ||
    name.endsWith('.md')
  );
}

/** The kind of an allow-listed file, by its `/`-separated relative path, or null. */
export function classify(rel: string): FileKind | null {
  const name = rel.includes('/') ? rel.slice(rel.lastIndexOf('/') + 1) : rel;
  if (isDenied(name)) return null;
  const atRoot = !rel.includes('/');
  if (atRoot) {
    if (name === 'package.json') return 'package.json';
    if (name === '.cdsrc.json') return 'cdsrc.json';
    if (name === '.cdsrc.yaml') return 'cdsrc.yaml';
    if (name === 'mta.yaml' || name === 'mta.yml') return 'mta';
  }
  if (name === '.gitignore') return 'gitignore';
  if (name === 'xs-security.json') return 'xs-security';
  if (name === 'xs-app.json') return 'xs-app';
  if (name.endsWith('.cds')) return 'cds';
  if (name.endsWith('.html')) return 'html';
  if (name.endsWith('.mtar')) return 'mtar';
  if (name.endsWith('.csv')) {
    const parent = atRoot ? '' : basename(dirname(rel));
    return SEED_DIRS.has(parent) ? 'csv' : null;
  }
  return null;
}

function shouldSkipDir(name: string, abs: string, depth: number, exclude: Set<string>): boolean {
  return depth > MAX_DEPTH || SKIPPED_DIRS.has(name) || name.startsWith('.') || exclude.has(abs);
}

/** Relative path with the platform separator turned into `/`, or null when unsafe. */
export function toRelativePath(realRoot: string, abs: string): string | null {
  const rel = relative(realRoot, abs).split(sep).join('/');
  return isSafeRelativePath(rel) ? rel : null;
}

export async function walkProject(
  realRoot: string,
  options: WalkOptions = {},
): Promise<WalkResult> {
  const exclude = new Set(options.excludeDirs ?? []);
  const files: WalkedFile[] = [];
  const pending: { abs: string; depth: number }[] = [{ abs: realRoot, depth: 0 }];
  let visited = 0;

  while (pending.length > 0) {
    const dir = pending.pop();
    if (dir === undefined) break;
    let names: string[];
    try {
      names = (await readdir(dir.abs)).sort();
    } catch {
      continue;
    }
    for (const name of names) {
      if (visited >= MAX_ENTRIES) return { files, truncated: true };
      visited += 1;
      const abs = join(dir.abs, name);
      let stats;
      try {
        stats = await lstat(abs);
      } catch {
        continue;
      }
      if (stats.isDirectory()) {
        if (!shouldSkipDir(name, abs, dir.depth + 1, exclude)) {
          pending.push({ abs, depth: dir.depth + 1 });
        }
      } else if (stats.isFile()) {
        const rel = toRelativePath(realRoot, abs);
        if (rel === null) continue;
        const kind = classify(rel);
        if (kind !== null) files.push({ kind, abs, rel, size: stats.size });
      }
    }
  }
  files.sort((a, b) => (a.rel < b.rel ? -1 : a.rel > b.rel ? 1 : 0));
  return { files, truncated: false };
}
