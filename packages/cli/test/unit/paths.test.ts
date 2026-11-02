import { describe, expect, it } from 'vitest';
import { FindingLocationSchema } from '../../src/model/finding.js';
import { RelativePathSchema, isSafeRelativePath } from '../../src/model/paths.js';

describe('isSafeRelativePath', () => {
  it.each([
    'a/../b',
    'db/..',
    'a\\b',
    '\\\\server\\share',
    'C:x',
    '/x',
    '../x',
    'a//b',
    '',
    './a',
    'a/./b',
    'a\nb',
    'a\rb',
    'a\0b',
    'x'.repeat(513),
  ])('rejects %j', (value) => {
    expect(isSafeRelativePath(value)).toBe(false);
    expect(RelativePathSchema.safeParse(value).success).toBe(false);
  });

  it.each(['srv/a.cds', 'db/data/x.csv', 'mta.yaml', 'a.b/c-d_e', 'x'.repeat(512)])(
    'accepts %j',
    (value) => {
      expect(isSafeRelativePath(value)).toBe(true);
      expect(RelativePathSchema.safeParse(value).success).toBe(true);
    },
  );

  it('guards finding locations', () => {
    expect(FindingLocationSchema.safeParse({ file: 'srv/a.cds', line: 3 }).success).toBe(true);
    expect(FindingLocationSchema.safeParse({ file: '/etc/passwd' }).success).toBe(false);
    expect(FindingLocationSchema.safeParse({ file: 'srv/a.cds', line: 0 }).success).toBe(false);
  });
});
