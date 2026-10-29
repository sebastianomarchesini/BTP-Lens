import { mkdir, mkdtemp, realpath, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  DEFAULT_PROJECT_ID,
  PROJECT_MARKERS,
  collectProject,
  resolveProjectRoot,
} from '../../../../src/collectors/project/index.js';
import { ConfigError } from '../../../../src/http/errors.js';

const tmp = () => mkdtemp(join(tmpdir(), 'btp-lens-root-'));

async function rejection(promise: Promise<unknown>): Promise<Error> {
  try {
    await promise;
  } catch (error) {
    return error as Error;
  }
  throw new Error('expected a rejection');
}

describe('project root checks', () => {
  it('accepts a directory with any one project marker', async () => {
    for (const marker of PROJECT_MARKERS) {
      const dir = await tmp();
      await writeFile(join(dir, marker), marker.endsWith('.yaml') ? 'a: 1\n' : '{}\n');
      expect(await resolveProjectRoot(dir)).toBe(await realpath(dir));
    }
  });

  it('rejects a missing path with a fixed sentence that echoes the --path argument', async () => {
    const path = join(await tmp(), 'missing');
    const error = await rejection(collectProject(path));
    expect(error).toBeInstanceOf(ConfigError);
    expect(error.message).toBe(`Project path "${path}" does not exist.`);
  });

  it('rejects a file, naming the path the user gave and never its real path', async () => {
    const dir = await tmp();
    const file = join(dir, 'real-file.json');
    await writeFile(file, '{}\n');
    const link = join(dir, 'link-to-file');
    await symlink(file, link);
    const error = await rejection(collectProject(link));
    expect(error).toBeInstanceOf(ConfigError);
    expect(error.message).toBe(`Project path "${link}" is not a folder.`);
    expect(error.message).not.toContain('real-file');
  });

  it('rejects a path under a file (ENOTDIR) with the same fixed sentence', async () => {
    const dir = await tmp();
    await writeFile(join(dir, 'file'), 'x');
    const path = join(dir, 'file', 'below');
    const error = await rejection(collectProject(path));
    expect(error).toBeInstanceOf(ConfigError);
    expect(error.message).toBe(`Project path "${path}" is not a folder.`);
  });

  it('rejects a directory without markers and never shows the resolved path', async () => {
    const dir = await tmp();
    const real = await mkdir(join(dir, 'real-project'), { recursive: true });
    await writeFile(join(dir, 'real-project', 'README.md'), '# not a project\n');
    const link = join(dir, 'project-link');
    await symlink(join(dir, 'real-project'), link);
    const error = await rejection(collectProject(link));
    expect(error).toBeInstanceOf(ConfigError);
    expect(error.message).toBe(
      `Project path "${link}" does not look like a CAP or MTA project (no package.json, mta.yaml or .cdsrc.json).`,
    );
    expect(error.message).not.toContain('real-project');
    expect(real).toBeDefined();
  });

  it('does not count a marker that is a symlink or a directory', async () => {
    const dir = await tmp();
    await mkdir(join(dir, 'package.json'));
    await symlink(join(dir, 'nowhere.yaml'), join(dir, 'mta.yaml'));
    const error = await rejection(collectProject(dir));
    expect(error).toBeInstanceOf(ConfigError);
    expect(error.message).toContain('does not look like a CAP or MTA project');
  });
});

describe('project identity', () => {
  it('prefers the mta ID, then the unscoped package name, then the directory name', async () => {
    const withMta = await tmp();
    await writeFile(join(withMta, 'mta.yaml'), 'ID: from-mta\n');
    await writeFile(join(withMta, 'package.json'), '{ "name": "@scope/from-package" }\n');
    expect((await collectProject(withMta)).id).toBe('from-mta');

    const withPackage = await tmp();
    await writeFile(join(withPackage, 'package.json'), '{ "name": "@scope/from-package" }\n');
    expect((await collectProject(withPackage)).id).toBe('from-package');

    const dir = await mkdtemp(join(tmpdir(), 'dirname-'));
    await writeFile(join(dir, 'package.json'), '{}\n');
    const project = await collectProject(dir);
    expect(project.id).toBe(dir.slice(dir.lastIndexOf('/') + 1));
    expect(project.packageJson).toEqual({
      present: true,
      name: null,
      dependencies: [],
      devDependencies: [],
      nodeEngine: null,
    });
  });

  it('falls back to a fixed id when no candidate is identifier-shaped', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'odd name '));
    await writeFile(join(dir, 'package.json'), '{ "name": "not a valid name!" }\n');
    const project = await collectProject(dir);
    expect(project.id).toBe(DEFAULT_PROJECT_ID);
    expect(project.packageJson.name).toBeNull();
  });

  it('records a .git file or directory without reading it, and the root .gitignore', async () => {
    const dir = await tmp();
    await writeFile(join(dir, 'package.json'), '{}\n');
    await writeFile(join(dir, '.git'), 'gitdir: /home/poison-user/.git/worktrees/x\n');
    await writeFile(join(dir, '.gitignore'), '*.mtar\n');
    const project = await collectProject(dir);
    expect(project.repository).toBe(true);
    expect(project.gitIgnore).toEqual({ present: true });
    // Nothing was opened for either: only the listed, allow-listed files appear.
    expect(project.files).toEqual(['package.json']);
    expect(JSON.stringify(project)).not.toContain('poison-user');

    const plain = await tmp();
    await writeFile(join(plain, 'package.json'), '{}\n');
    const noRepo = await collectProject(plain);
    expect(noRepo.repository).toBe(false);
    expect(noRepo.gitIgnore).toEqual({ present: false });
  });
});
