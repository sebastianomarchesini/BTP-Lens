import { mkdtemp, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { ensurePrivateDir, writePrivateFile } from '../../src/io/files.js';
import { MAX_SNAPSHOT_BYTES, readSnapshot } from '../../src/snapshot.js';

const posix = process.platform !== 'win32';

describe('private output files', () => {
  it.skipIf(!posix)('creates directories 0700 and files 0600', async () => {
    const base = await mkdtemp(join(tmpdir(), 'btp-lens-files-'));
    const dir = join(base, 'nested', 'reports');
    await ensurePrivateDir(dir);
    await writePrivateFile(join(dir, 'report.json'), '{}');
    expect((await stat(dir)).mode & 0o777).toBe(0o700);
    expect((await stat(join(dir, 'report.json'))).mode & 0o777).toBe(0o600);
  });
});

describe('readSnapshot limits', () => {
  it('refuses a snapshot above the size cap without parsing it', async () => {
    const base = await mkdtemp(join(tmpdir(), 'btp-lens-big-'));
    const path = join(base, 'huge.json');
    // A sparse file: the size is what matters, not the content.
    const handle = await import('node:fs/promises').then((fs) => fs.open(path, 'w'));
    await handle.truncate(MAX_SNAPSHOT_BYTES + 1);
    await handle.close();
    await expect(readSnapshot(path)).rejects.toThrow(/the limit is/);
  });

  it('rejects unknown schema versions with a clear message', async () => {
    const base = await mkdtemp(join(tmpdir(), 'btp-lens-ver-'));
    const path = join(base, 'old.json');
    await writeFile(path, JSON.stringify({ schemaVersion: 0 }));
    await expect(readSnapshot(path)).rejects.toThrow(/schema version 0/);
  });
});
