import { execFileSync } from 'node:child_process';
import { mkdir, mkdtemp, realpath, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { collectProject } from '../../../../src/collectors/project/index.js';
import {
  MAX_DEPTH,
  MAX_ENTRIES,
  SKIPPED_DIRS,
  classify,
  isDenied,
  toRelativePath,
  walkProject,
} from '../../../../src/collectors/project/walk.js';

const tmp = async () => realpath(await mkdtemp(join(tmpdir(), 'btp-lens-walk-')));

async function file(root: string, rel: string, content = ''): Promise<void> {
  const abs = join(root, ...rel.split('/'));
  await mkdir(join(abs, '..'), { recursive: true });
  await writeFile(abs, content);
}

function tryMkfifo(path: string): boolean {
  if (process.platform === 'win32') return false;
  try {
    execFileSync('mkfifo', [path], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

const rels = async (root: string) => (await walkProject(root)).files.map((f) => f.rel);

describe('deny-list', () => {
  it.each([
    '.cdsrc-private.json',
    '.cdsrc.js',
    'default-env.json',
    '.env',
    '.env.local',
    'mta-dev.mtaext',
    'service-key.json',
    'cert.pem',
    'private.key',
    'requests.http',
    'manifest.json',
    'README.md',
  ])('never lists %s', (name) => {
    expect(isDenied(name)).toBe(true);
    expect(classify(name)).toBeNull();
    expect(classify(`srv/${name}`)).toBeNull();
  });

  it('lists only allow-listed names, root config only at the root', () => {
    expect(classify('package.json')).toBe('package.json');
    expect(classify('srv/package.json')).toBeNull();
    expect(classify('.cdsrc.json')).toBe('cdsrc.json');
    expect(classify('app/.cdsrc.json')).toBeNull();
    expect(classify('.cdsrc.yaml')).toBe('cdsrc.yaml');
    expect(classify('mta.yaml')).toBe('mta');
    expect(classify('mta.yml')).toBe('mta');
    expect(classify('deploy/mta.yaml')).toBeNull();
    expect(classify('.gitignore')).toBe('gitignore');
    expect(classify('app/.gitignore')).toBe('gitignore');
    expect(classify('app/ui/xs-app.json')).toBe('xs-app');
    expect(classify('xs-security.json')).toBe('xs-security');
    expect(classify('srv/a.cds')).toBe('cds');
    expect(classify('app/ui/webapp/index.html')).toBe('html');
    expect(classify('mta_archives/a.mtar')).toBe('mtar');
    expect(classify('db/data/a.csv')).toBe('csv');
    expect(classify('db/csv/a.csv')).toBe('csv');
    expect(classify('test/data/a.csv')).toBe('csv');
    expect(classify('a.csv')).toBeNull();
    expect(classify('db/a.csv')).toBeNull();
    expect(classify('srv/server.js')).toBeNull();
    expect(classify('package-lock.json')).toBeNull();
    expect(classify('xs-security.yaml')).toBeNull();
  });
});

describe('walk', () => {
  it('visits regular files and directories only: symlinks, FIFOs are never listed', async () => {
    const root = await tmp();
    await file(root, 'package.json', '{}');
    await file(root, 'srv/a.cds', 'service A {}');
    await symlink('/etc/hostname', join(root, 'srv', 'link.cds'));
    await symlink('/etc', join(root, 'link-out'));
    await mkdir(join(root, 'db'));
    const fifo = tryMkfifo(join(root, 'db', 'pipe.cds'));
    const listed = await rels(root);
    expect(listed).toEqual(['package.json', 'srv/a.cds']);
    expect(listed).not.toContain('link-out');
    if (fifo) expect(listed).not.toContain('db/pipe.cds');
    const project = await collectProject(root);
    expect(JSON.stringify(project)).not.toMatch(/link|pipe/);
  });

  it('does not enter skipped, hidden or excluded directories', async () => {
    const root = await tmp();
    await file(root, 'package.json', '{}');
    for (const dir of SKIPPED_DIRS) await file(root, `${dir}/x.cds`, 'entity X {}');
    await file(root, '.hidden/x.cds', 'entity X {}');
    await file(root, 'out/x.cds', 'entity X {}');
    await file(root, 'srv/keep.cds', 'entity K {}');
    const result = await walkProject(root, { excludeDirs: [join(root, 'out')] });
    expect(result.files.map((f) => f.rel)).toEqual(['package.json', 'srv/keep.cds']);
    expect(result.truncated).toBe(false);
  });

  it(`stops at depth ${MAX_DEPTH}`, async () => {
    const root = await tmp();
    await file(root, 'package.json', '{}');
    const deep = Array.from({ length: MAX_DEPTH }, (_, i) => `d${i + 1}`).join('/');
    await file(root, `${deep}/in.cds`, 'entity A {}');
    await file(root, `${deep}/d${MAX_DEPTH + 1}/out.cds`, 'entity B {}');
    const listed = await rels(root);
    expect(listed).toContain(`${deep}/in.cds`);
    expect(listed.some((rel) => rel.endsWith('out.cds'))).toBe(false);
  });

  it(`stops after ${MAX_ENTRIES} entries and reports the listing as truncated`, async () => {
    const root = await tmp();
    await file(root, 'package.json', '{}');
    await mkdir(join(root, 'many'));
    const names = Array.from({ length: MAX_ENTRIES + 1 }, (_, i) => `f${i}.txt`);
    for (let i = 0; i < names.length; i += 500) {
      await Promise.all(
        names.slice(i, i + 500).map((name) => writeFile(join(root, 'many', name), '')),
      );
    }
    const result = await walkProject(root);
    expect(result.truncated).toBe(true);
    expect((await collectProject(root)).filesTruncated).toBe(true);
  }, 60_000);

  it('builds /-separated relative paths and drops unsafe ones', () => {
    expect(toRelativePath('/root', join('/root', 'a', 'b.cds'))).toBe('a/b.cds');
    expect(toRelativePath('/root', '/elsewhere/b.cds')).toBeNull();
    expect(toRelativePath('/root', '/root')).toBeNull();
  });
});
