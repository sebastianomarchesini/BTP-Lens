import { describe, expect, it } from 'vitest';
import {
  type GitignoreLayer,
  isIgnored,
  parseGitignore,
  parseGitignoreLine,
} from '../../../../src/collectors/project/gitignore.js';

const root = (text: string): GitignoreLayer => ({ base: '', rules: parseGitignore(text) });
const ignored = (text: string, file: string) => isIgnored([root(text)], file);

describe('gitignore patterns', () => {
  it('skips comments and blank lines', () => {
    expect(parseGitignore('# comment\n\n   \n*.mtar\n')).toHaveLength(1);
    expect(parseGitignoreLine('#x')).toBeNull();
    expect(parseGitignoreLine('/')).toBeNull();
  });

  it('matches a pattern without a slash at any depth', () => {
    expect(ignored('*.mtar', 'a.mtar')).toBe(true);
    expect(ignored('*.mtar', 'mta_archives/a.mtar')).toBe(true);
    expect(ignored('*.mtar', 'deep/er/a.mtar')).toBe(true);
    expect(ignored('*.mtar', 'a.mtar.txt')).toBe(false);
    expect(ignored('a.mtar', 'x/a.mtar')).toBe(true);
  });

  it('anchors patterns with a leading slash or an inner slash', () => {
    expect(ignored('/a.mtar', 'a.mtar')).toBe(true);
    expect(ignored('/a.mtar', 'x/a.mtar')).toBe(false);
    expect(ignored('mta_archives/*.mtar', 'mta_archives/a.mtar')).toBe(true);
    expect(ignored('mta_archives/*.mtar', 'x/mta_archives/a.mtar')).toBe(false);
  });

  it('matches directories with a trailing slash, and everything inside them', () => {
    expect(ignored('mta_archives/', 'mta_archives/a.mtar')).toBe(true);
    expect(ignored('mta_archives/', 'mta_archives/deep/a.mtar')).toBe(true);
    expect(ignored('mta_archives/', 'mta_archives')).toBe(false);
    expect(ignored('build/', 'x/build/a.mtar')).toBe(true);
  });

  it('supports *, ? and ** and does not let * cross a slash', () => {
    expect(ignored('*.mta?', 'a.mtar')).toBe(true);
    expect(ignored('a?c', 'abc')).toBe(true);
    expect(ignored('a?c', 'ac')).toBe(false);
    expect(ignored('/out/*', 'out/a.mtar')).toBe(true);
    expect(ignored('/out/*', 'out/x/a.mtar')).toBe(true);
    expect(ignored('/out/*.mtar', 'out/x/a.mtar')).toBe(false);
    expect(ignored('**/archives/*.mtar', 'a/b/archives/x.mtar')).toBe(true);
    expect(ignored('**/archives/*.mtar', 'archives/x.mtar')).toBe(true);
    expect(ignored('build/**', 'build/a/b.mtar')).toBe(true);
    expect(ignored('a/**/b.mtar', 'a/b.mtar')).toBe(true);
    expect(ignored('a/**/b.mtar', 'a/x/y/b.mtar')).toBe(true);
    expect(ignored('[ab].mtar', 'a.mtar')).toBe(true);
    expect(ignored('[!ab].mtar', 'a.mtar')).toBe(false);
    expect(ignored('a\\*.mtar', 'a*.mtar')).toBe(true);
    expect(ignored('a\\*.mtar', 'ab.mtar')).toBe(false);
    expect(ignored('a.b', 'aXb')).toBe(false);
  });

  it('lets the last matching rule win, including negations', () => {
    expect(ignored('*.mtar\n!keep.mtar', 'keep.mtar')).toBe(false);
    expect(ignored('*.mtar\n!keep.mtar', 'drop.mtar')).toBe(true);
    expect(ignored('!keep.mtar\n*.mtar', 'keep.mtar')).toBe(true);
    // A file inside an ignored directory cannot be re-included.
    expect(ignored('out/\n!out/keep.mtar', 'out/keep.mtar')).toBe(true);
  });

  it('applies a deeper .gitignore after its parents, relative to its own directory', () => {
    const layers: GitignoreLayer[] = [
      root('*.mtar'),
      { base: 'app', rules: parseGitignore('!keep.mtar\n/local/') },
    ];
    expect(isIgnored(layers, 'app/keep.mtar')).toBe(false);
    expect(isIgnored(layers, 'app/other.mtar')).toBe(true);
    expect(isIgnored(layers, 'keep.mtar')).toBe(true);
    expect(isIgnored(layers, 'app/local/x.mtar')).toBe(true);
    expect(isIgnored(layers, 'other/local/x.txt')).toBe(false);
    expect(isIgnored(layers, 'app/local/x.txt')).toBe(true);
  });

  it('does not stall on long patterns and long paths', () => {
    const started = Date.now();
    const layer = root(`${'*'.repeat(500)}a${'?'.repeat(100)}\n${'**/'.repeat(200)}x.mtar`);
    expect(isIgnored([layer], `${'b/'.repeat(100)}${'b'.repeat(5_000)}.mtar`)).toBe(false);
    expect(Date.now() - started).toBeLessThan(2_000);
  });
});
