import { execFileSync } from 'node:child_process';
import { mkdtemp, realpath, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  MAX_FILE_BYTES,
  NUL_SCAN_BYTES,
  identifierOrNull,
  identifiers,
  objectItems,
  parseJson,
  parseYaml,
  readProjectFile,
} from '../../../../src/collectors/project/read.js';

const tmp = async () => realpath(await mkdtemp(join(tmpdir(), 'btp-lens-read-')));

describe('readProjectFile', () => {
  it('reads a regular file', async () => {
    const dir = await tmp();
    await writeFile(join(dir, 'a.cds'), 'entity A {}');
    expect(await readProjectFile(join(dir, 'a.cds'))).toEqual({
      ok: true,
      text: 'entity A {}',
      bytes: 11,
    });
  });

  it('refuses to follow a symlink, even to a readable file (O_NOFOLLOW)', async () => {
    const dir = await tmp();
    await writeFile(join(dir, 'target.cds'), 'entity Secret {}');
    await symlink(join(dir, 'target.cds'), join(dir, 'link.cds'));
    expect(await readProjectFile(join(dir, 'link.cds'))).toEqual({
      ok: false,
      reason: 'unreadable',
    });
  });

  it('refuses a FIFO without blocking (fstat is not a regular file)', async () => {
    if (process.platform === 'win32') return;
    const dir = await tmp();
    const fifo = join(dir, 'pipe.cds');
    try {
      execFileSync('mkfifo', [fifo], { stdio: 'ignore' });
    } catch {
      return; // no mkfifo here: nothing to test
    }
    expect(await readProjectFile(fifo)).toEqual({ ok: false, reason: 'unreadable' });
  }, 5_000);

  it('reports a missing file as unreadable without a message', async () => {
    const dir = await tmp();
    expect(await readProjectFile(join(dir, 'missing.cds'))).toEqual({
      ok: false,
      reason: 'unreadable',
    });
  });

  it(`rejects files over ${MAX_FILE_BYTES} bytes before reading them`, async () => {
    const dir = await tmp();
    const big = Buffer.alloc(MAX_FILE_BYTES + 1, 0x20);
    big.write('// POISON_big', 0, 'utf8');
    await writeFile(join(dir, 'big.cds'), big);
    expect(await readProjectFile(join(dir, 'big.cds'))).toEqual({ ok: false, reason: 'too-large' });

    const exact = Buffer.alloc(MAX_FILE_BYTES, 0x20);
    await writeFile(join(dir, 'exact.cds'), exact);
    const result = await readProjectFile(join(dir, 'exact.cds'));
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.bytes).toBe(MAX_FILE_BYTES);
  });

  it(`treats a NUL byte in the first ${NUL_SCAN_BYTES} bytes as binary`, async () => {
    const dir = await tmp();
    const binary = Buffer.concat([Buffer.from('entity A {}'), Buffer.from([0]), Buffer.from('x')]);
    await writeFile(join(dir, 'bin.cds'), binary);
    expect(await readProjectFile(join(dir, 'bin.cds'))).toEqual({ ok: false, reason: 'binary' });

    const late = Buffer.alloc(NUL_SCAN_BYTES + 10, 0x61);
    late[NUL_SCAN_BYTES + 5] = 0;
    await writeFile(join(dir, 'late.cds'), late);
    expect((await readProjectFile(join(dir, 'late.cds'))).ok).toBe(true);
  });
});

const POISON = 'POISON_syntax_value';

describe('parseJson / parseYaml', () => {
  it('returns undefined on a JSON syntax error instead of a message with the source', () => {
    expect(parseJson(`{ "a": ${POISON} }`)).toBeUndefined();
    expect(parseJson('')).toBeUndefined();
    expect(parseJson('{"a":1}')).toEqual({ a: 1 });
  });

  it('returns undefined on a YAML syntax error instead of a message with the source', () => {
    expect(parseYaml(`a: [${POISON}\nb: }`)).toBeUndefined();
    expect(parseYaml('a: 1\n')).toEqual({ a: 1 });
  });

  it('bounds alias expansion (billion laughs) and keeps the last duplicate key', () => {
    const laughs = [
      'a: &a ["lol", "lol", "lol", "lol", "lol", "lol", "lol", "lol", "lol"]',
      'b: &b [*a, *a, *a, *a, *a, *a, *a, *a, *a]',
      'c: &c [*b, *b, *b, *b, *b, *b, *b, *b, *b]',
      'd: &d [*c, *c, *c, *c, *c, *c, *c, *c, *c]',
      'e: &e [*d, *d, *d, *d, *d, *d, *d, *d, *d]',
      'f: &f [*e, *e, *e, *e, *e, *e, *e, *e, *e]',
      'g: &g [*f, *f, *f, *f, *f, *f, *f, *f, *f]',
      'h: &h [*g, *g, *g, *g, *g, *g, *g, *g, *g]',
      'i: &i [*h, *h, *h, *h, *h, *h, *h, *h, *h]',
    ].join('\n');
    const started = Date.now();
    expect(parseYaml(laughs)).toBeUndefined();
    expect(Date.now() - started).toBeLessThan(2_000);

    expect(parseYaml('a: 1\na: 2\n')).toEqual({ a: 2 });
  });

  it('never throws, whatever the input', () => {
    for (const text of ['', '\0', '---\n- - - [', '{', '!!js/function "x"', '&a [*a]']) {
      expect(() => parseYaml(text)).not.toThrow();
      expect(() => parseJson(text)).not.toThrow();
    }
  });
});

describe('shape helpers', () => {
  it('keeps identifier-shaped strings only and never an "other" bucket', () => {
    expect(identifierOrNull('Customers')).toBe('Customers');
    expect(identifierOrNull('$XSAPPNAME.admin')).toBe('$XSAPPNAME.admin');
    expect(identifierOrNull('has space')).toBeNull();
    expect(identifierOrNull('a@b')).toBeNull();
    expect(identifierOrNull(42)).toBeNull();
    expect(identifierOrNull(`x${'y'.repeat(200)}`)).toBeNull();
    expect(identifiers(['ok', 'not ok', 7, 'also.ok'], 10)).toEqual(['ok', 'also.ok']);
    expect(identifiers(['a', 'b', 'c'], 2)).toEqual(['a', 'b']);
    expect(identifiers('a', 2)).toEqual([]);
    expect(objectItems([{ a: 1 }, 'x', null, [1]], 5)).toEqual([{ a: 1 }]);
  });
});
