import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

/**
 * The project scan reads files and nothing else: no child process, no
 * network, no worker, no dynamic import that could load either. A static
 * guard over the source files, so a future change cannot add one quietly.
 */
const SRC = fileURLToPath(new URL('../../../src/', import.meta.url));
const GUARDED = ['collectors/project', 'analyzers/project', 'project.ts'];

const FORBIDDEN_MODULES = [
  'node:child_process',
  'child_process',
  'node:http',
  'node:https',
  'node:net',
  'node:dns',
  'node:worker_threads',
];

async function sourceFiles(entry: string): Promise<string[]> {
  const path = join(SRC, entry);
  if (entry.endsWith('.ts')) return [path];
  const names = await readdir(path);
  return names.filter((name) => name.endsWith('.ts')).map((name) => join(path, name));
}

describe('project scan has no way out of the file system', () => {
  it('guards the collector, the analyzers and the command', async () => {
    const files = (await Promise.all(GUARDED.map(sourceFiles))).flat();
    expect(files.length).toBeGreaterThan(14);
    for (const file of files) {
      const text = await readFile(file, 'utf8');
      for (const module of FORBIDDEN_MODULES) {
        expect(text, `${file} imports ${module}`).not.toMatch(
          new RegExp(`from\\s+['"]${module}['"]|require\\(['"]${module}['"]\\)`),
        );
      }
      expect(text, `${file} calls fetch`).not.toMatch(/\bfetch\(/);
      expect(text, `${file} uses a dynamic import`).not.toMatch(/\bimport\(/);
    }
  });
});
