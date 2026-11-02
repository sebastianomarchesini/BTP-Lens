import { lstat, realpath, stat } from 'node:fs/promises';
import { basename, dirname, relative, resolve, sep } from 'node:path';
import { ConfigError } from '../../http/errors.js';
import {
  type CdsSource,
  type CdsView,
  PROJECT_ID_PATTERN,
  type RawProject,
  RawProjectSchema,
  type RawUnreadable,
  type UnreadableKind,
} from '../../model/raw.js';
import { scanCds } from './cdsFiles.js';
import {
  type CdsProfile,
  type CdsSourceValue,
  effectiveCdsViews,
  exceedsConfigDepth,
} from './cdsConfig.js';
import { type GitignoreLayer, isIgnored, parseGitignore } from './gitignore.js';
import { scanHtml } from './html.js';
import { parseMta } from './mta.js';
import { emptyPackageJson, parsePackageJson } from './packageJson.js';
import { isPlainObject, parseJson, parseYaml, readProjectFile } from './read.js';
import { scanSeedCsv } from './seedData.js';
import { type FileKind, type WalkedFile, walkProject } from './walk.js';
import { parseXsApp } from './xsApp.js';
import { parseXsSecurity } from './xsSecurity.js';

/*
 * The project collector: file-system reads only, no network, no child
 * processes, no git. The root is checked and resolved first; after that no
 * error escapes. Each file that cannot be read or parsed becomes an
 * `unreadable` entry with a reason code, so that neither a path nor file
 * content can reach a check reason, the terminal or a report
 * (docs/data-sources.md, "Local project files"). Outside the root only a
 * `.git` entry is looked for (lstat) and the `.gitignore` files between the
 * repository root and the project root are read for their archive decision;
 * nothing about them is stored.
 */

export interface CollectProjectOptions {
  /** Real paths of directories the walk must not enter (e.g. the resolved --out). */
  excludeDirs?: string[];
}

export const DEFAULT_PROJECT_ID = 'project';
export const MAX_FILES_OPENED = 2000;
export const MAX_TOTAL_BYTES = 64 * 1024 * 1024;
export const MAX_FILES_LISTED = 500;
/** Ancestors of the root checked for a `.git` entry. */
export const MAX_ANCESTORS = 64;
const MAX_UNREADABLE = 200;
const LIST_CAPS = {
  xsSecurity: 100,
  xsApps: 100,
  cdsFiles: 2000,
  seedData: 500,
  archives: 200,
  html: 200,
} as const;

/** Any one of these at the root makes a directory a project. */
export const PROJECT_MARKERS = [
  'package.json',
  'mta.yaml',
  'mta.yml',
  '.cdsrc.json',
  '.cdsrc.yaml',
];

export function projectIdFromName(name: string): string {
  return PROJECT_ID_PATTERN.test(name) ? name : DEFAULT_PROJECT_ID;
}

export function emptyCdsView(): CdsView {
  return {
    authKind: null,
    mockedUsers: 0,
    mockedUsersWithPassword: 0,
    restrictAllServices: null,
    auditLogKind: null,
    auditLogConfigured: false,
  };
}

/**
 * Root errors repeat the user's own --path and a fixed sentence per error
 * code; never the resolved path or the system message.
 */
function rootError(path: string, error: unknown): ConfigError {
  const code = (error as { code?: unknown } | null)?.code;
  const reason =
    code === 'ENOENT'
      ? 'does not exist'
      : code === 'ENOTDIR'
        ? 'is not a folder'
        : code === 'EACCES' || code === 'EPERM'
          ? 'cannot be read: permission denied'
          : code === 'ELOOP'
            ? 'is a symbolic link loop'
            : 'cannot be read';
  return new ConfigError(`Project path "${path}" ${reason}.`);
}

async function exists(path: string): Promise<boolean> {
  try {
    await lstat(path);
    return true;
  } catch {
    return false;
  }
}

async function isRegularFile(path: string): Promise<boolean> {
  try {
    return (await lstat(path)).isFile();
  } catch {
    return false;
  }
}

/** The real path of the project root, or a ConfigError about the user's --path. */
export async function resolveProjectRoot(path: string): Promise<string> {
  let root: string;
  try {
    root = await realpath(path);
    if (!(await stat(root)).isDirectory())
      throw new ConfigError(`Project path "${path}" is not a folder.`);
  } catch (error) {
    throw error instanceof ConfigError ? error : rootError(path, error);
  }
  const markers = await Promise.all(
    PROJECT_MARKERS.map((name) => isRegularFile(resolve(root, name))),
  );
  if (!markers.some(Boolean)) {
    throw new ConfigError(
      `Project path "${path}" does not look like a CAP or MTA project (no package.json, mta.yaml or .cdsrc.json).`,
    );
  }
  return root;
}

/** The reason recorded when a file of this kind cannot be read or parsed. */
function parseKindOf(kind: FileKind): UnreadableKind {
  switch (kind) {
    case 'package.json':
    case 'cdsrc.json':
    case 'xs-security':
    case 'xs-app':
      return 'json';
    case 'cdsrc.yaml':
    case 'mta':
      return 'yaml';
    case 'cds':
      return 'cds';
    case 'csv':
      return 'csv';
    case 'html':
      return 'html';
    case 'gitignore':
    case 'mtar':
      return 'binary';
  }
}

/** Mutable collection state; the final RawProject is built from it. */
class Collection {
  files: string[] = [];
  unreadable: RawUnreadable[] = [];
  truncated = false;
  opened = 0;
  bytes = 0;
  cdsSources: Partial<Record<CdsSource, unknown>> = {};
  packageJson = emptyPackageJson();
  mta: RawProject['mta'] = null;
  xsSecurity: RawProject['xsSecurity'] = [];
  xsApps: RawProject['xsApps'] = [];
  cdsFiles: RawProject['cdsFiles'] = [];
  seedData: RawProject['seedData'] = [];
  html: RawProject['html'] = [];
  archives: RawProject['archives'] = [];
  private readonly gitignores = new Map<string, GitignoreLayer | null>();

  markUnreadable(file: string, kind: UnreadableKind): void {
    if (this.unreadable.length < MAX_UNREADABLE) this.unreadable.push({ file, kind });
  }

  /** Reads one file within the budget; null when it could not be read (recorded). */
  async read(entry: WalkedFile): Promise<string | null> {
    if (this.opened >= MAX_FILES_OPENED || this.bytes >= MAX_TOTAL_BYTES) {
      this.truncated = true;
      return null;
    }
    this.opened += 1;
    const result = await readProjectFile(entry.abs);
    if (!result.ok) {
      this.markUnreadable(
        entry.rel,
        result.reason === 'unreadable' ? parseKindOf(entry.kind) : result.reason,
      );
      return null;
    }
    this.bytes += result.bytes;
    return result.text;
  }

  /** Reads and parses one file; a parse failure is recorded under the file's kind. */
  async collect<T>(entry: WalkedFile, parse: (text: string) => T | null): Promise<T | null> {
    const text = await this.read(entry);
    if (text === null) return null;
    let value: T | null;
    try {
      value = parse(text);
    } catch {
      value = null;
    }
    if (value === null) {
      this.markUnreadable(entry.rel, parseKindOf(entry.kind));
      return null;
    }
    this.files.push(entry.rel);
    return value;
  }

  /** The .gitignore layers for a file: the root one and those in its parent directories. */
  async gitignoreLayers(file: string, byRel: Map<string, WalkedFile>): Promise<GitignoreLayer[]> {
    const layers: GitignoreLayer[] = [];
    const segments = file.split('/');
    for (let depth = 0; depth < segments.length; depth += 1) {
      const base = segments.slice(0, depth).join('/');
      const rel = base === '' ? '.gitignore' : `${base}/.gitignore`;
      const entry = byRel.get(rel);
      if (entry === undefined) continue;
      let layer = this.gitignores.get(rel);
      if (layer === undefined) {
        const text = await this.collect(entry, (content) => content);
        layer = text === null ? null : { base, rules: parseGitignore(text) };
        this.gitignores.set(rel, layer);
      }
      if (layer !== null) layers.push(layer);
    }
    return layers;
  }
}

/** A cds configuration source: a plain object nested at most MAX_CONFIG_DEPTH levels deep. */
function configOrNull(value: unknown): Record<string, unknown> | null {
  return isPlainObject(value) && !exceedsConfigDepth(value) ? value : null;
}

/** The nearest directory, from the root upwards, with a `.git` entry (lstat only); null when none. */
async function findRepositoryRoot(root: string): Promise<string | null> {
  let dir = root;
  for (let level = 0; level < MAX_ANCESTORS; level += 1) {
    if (await exists(resolve(dir, '.git'))) return dir;
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return null;
}

/** The project root relative to the repository root, `/`-separated; `''` when they coincide. */
function ancestorPrefix(repositoryRoot: string, root: string): string {
  return relative(repositoryRoot, root).split(sep).join('/');
}

function joinRelative(prefix: string, path: string): string {
  if (prefix === '') return path;
  return path === '' ? prefix : `${prefix}/${path}`;
}

/**
 * The .gitignore layers of the directories from the repository root down to
 * the parent of the project root, with bases relative to the repository
 * root. They lie outside the project, so they are read directly: never
 * listed, counted or recorded as unreadable, and only their decision about
 * an archive is kept.
 */
async function ancestorGitignoreLayers(
  repositoryRoot: string,
  prefix: string,
): Promise<GitignoreLayer[]> {
  const layers: GitignoreLayer[] = [];
  if (prefix === '') return layers;
  const segments = prefix.split('/');
  for (let depth = 0; depth < segments.length; depth += 1) {
    const dirs = segments.slice(0, depth);
    const result = await readProjectFile(resolve(repositoryRoot, ...dirs, '.gitignore'));
    if (result.ok) layers.push({ base: dirs.join('/'), rules: parseGitignore(result.text) });
  }
  return layers;
}

/** The effective cds views; a defence against anything the merge might throw (nothing escapes). */
function cdsViewsOf(
  sources: CdsSourceValue[],
  collection: Collection,
): Record<CdsProfile, CdsView> {
  try {
    return effectiveCdsViews(sources);
  } catch {
    for (const { source } of sources) {
      collection.markUnreadable(source, source === '.cdsrc.yaml' ? 'yaml' : 'json');
    }
    sources.splice(0);
    return { development: emptyCdsView(), production: emptyCdsView() };
  }
}

/** mta ID, else the package name without scope, else the directory name, else `project`. */
function projectId(root: string, collection: Collection): string {
  if (collection.mta?.id) return collection.mta.id;
  const packageName = collection.packageJson.name;
  if (packageName !== null) {
    const unscoped = packageName.slice(packageName.lastIndexOf('/') + 1).slice(0, 64);
    if (PROJECT_ID_PATTERN.test(unscoped)) return unscoped;
  }
  return projectIdFromName(basename(root));
}

async function collectEntry(entry: WalkedFile, collection: Collection): Promise<void> {
  switch (entry.kind) {
    case 'package.json': {
      const result = await collection.collect(entry, (text) => {
        const parsed = parsePackageJson(text);
        return parsed !== null && exceedsConfigDepth(parsed.cds) ? null : parsed;
      });
      if (result === null) return;
      collection.packageJson = result.packageJson;
      if (result.cds !== undefined) collection.cdsSources['package.json'] = result.cds;
      return;
    }
    case 'cdsrc.json': {
      const value = await collection.collect(entry, (text) => configOrNull(parseJson(text)));
      if (value !== null) collection.cdsSources['.cdsrc.json'] = value;
      return;
    }
    case 'cdsrc.yaml': {
      const value = await collection.collect(entry, (text) => configOrNull(parseYaml(text)));
      if (value !== null) collection.cdsSources['.cdsrc.yaml'] = value;
      return;
    }
    case 'mta': {
      const file = entry.rel === 'mta.yml' ? 'mta.yml' : 'mta.yaml';
      const result = await collection.collect(entry, (text) => parseMta(text, file));
      if (result === null) return;
      collection.mta = result.mta;
      collection.xsSecurity.push(...result.xsSecurity);
      return;
    }
    case 'xs-security': {
      const value = await collection.collect(entry, (text) => parseXsSecurity(text, entry.rel));
      if (value !== null) collection.xsSecurity.push(value);
      return;
    }
    case 'xs-app': {
      const value = await collection.collect(entry, (text) => parseXsApp(text, entry.rel));
      if (value !== null) collection.xsApps.push(value);
      return;
    }
    case 'cds': {
      const value = await collection.collect(entry, (text) => scanCds(text, entry.rel));
      if (value !== null) collection.cdsFiles.push(value);
      return;
    }
    case 'csv': {
      const value = await collection.collect(entry, (text) => scanSeedCsv(text, entry.rel));
      if (value !== null) collection.seedData.push(value);
      return;
    }
    case 'html': {
      const value = await collection.collect(entry, (text) => scanHtml(text, entry.rel));
      if (value !== null) collection.html.push(...value);
      return;
    }
    case 'gitignore':
    case 'mtar':
      return;
  }
}

async function realPaths(dirs: string[]): Promise<string[]> {
  return Promise.all(
    dirs.map(async (dir) => {
      try {
        return await realpath(dir);
      } catch {
        return resolve(dir);
      }
    }),
  );
}

export async function collectProject(
  path: string,
  options: CollectProjectOptions = {},
): Promise<RawProject> {
  const root = await resolveProjectRoot(path);
  const excludeDirs = await realPaths(options.excludeDirs ?? []);
  const walk = await walkProject(root, { excludeDirs });
  const collection = new Collection();
  collection.truncated = walk.truncated;

  // Root configuration first (it decides the id), then everything else in path order.
  const isConfig = (f: WalkedFile): boolean =>
    f.kind === 'package.json' ||
    f.kind === 'cdsrc.json' ||
    f.kind === 'cdsrc.yaml' ||
    f.kind === 'mta';
  const ordered = [...walk.files.filter(isConfig), ...walk.files.filter((f) => !isConfig(f))];
  for (const entry of ordered) await collectEntry(entry, collection);

  // Archives are matched in the frame of the repository root, so that the
  // .gitignore files above the project root apply as git would apply them.
  const repositoryRoot = await findRepositoryRoot(root);
  const prefix = repositoryRoot === null ? '' : ancestorPrefix(repositoryRoot, root);
  const aboveLayers =
    repositoryRoot === null ? [] : await ancestorGitignoreLayers(repositoryRoot, prefix);
  const byRel = new Map(walk.files.map((f) => [f.rel, f] as const));
  for (const entry of walk.files.filter((f) => f.kind === 'mtar')) {
    if (collection.archives.length >= LIST_CAPS.archives) break;
    const layers = (await collection.gitignoreLayers(entry.rel, byRel)).map((layer) => ({
      ...layer,
      base: joinRelative(prefix, layer.base),
    }));
    collection.archives.push({
      file: entry.rel,
      bytes: entry.size,
      ignored: isIgnored([...aboveLayers, ...layers], joinRelative(prefix, entry.rel)),
    });
  }

  const sources: CdsSourceValue[] = (['.cdsrc.yaml', '.cdsrc.json', 'package.json'] as const)
    .filter((source) => collection.cdsSources[source] !== undefined)
    .map((source) => ({ source, value: collection.cdsSources[source] }));
  const files = [...new Set(collection.files)].sort();
  const cds = { effective: cdsViewsOf(sources, collection) };

  const project: RawProject = {
    id: projectId(root, collection),
    sourcesRead: sources.map((s) => s.source),
    files: files.slice(0, MAX_FILES_LISTED),
    filesTruncated: collection.truncated || files.length > MAX_FILES_LISTED,
    filesOpened: collection.opened,
    unreadable: [...collection.unreadable].sort((a, b) => (a.file < b.file ? -1 : 1)),
    repository: repositoryRoot !== null,
    gitIgnore: { present: await isRegularFile(resolve(root, '.gitignore')) },
    packageJson: collection.packageJson,
    cds,
    mta: collection.mta,
    xsSecurity: collection.xsSecurity.slice(0, LIST_CAPS.xsSecurity),
    xsApps: collection.xsApps.slice(0, LIST_CAPS.xsApps),
    cdsFiles: collection.cdsFiles.slice(0, LIST_CAPS.cdsFiles),
    seedData: collection.seedData.slice(0, LIST_CAPS.seedData),
    archives: collection.archives,
    html: collection.html.slice(0, LIST_CAPS.html),
  };
  const parsed = RawProjectSchema.safeParse(project);
  // A fixed sentence: a zod issue could name a value from the project.
  if (!parsed.success) throw new Error('the collected project data did not pass validation');
  return parsed.data;
}
