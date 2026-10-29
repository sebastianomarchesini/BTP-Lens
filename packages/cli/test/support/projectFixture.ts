import { execFileSync } from 'node:child_process';
import { cp, mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * The project fixtures (test/fixtures/projects) are copied to a temporary
 * directory before a scan, and the pieces that cannot live in the repository
 * are added there: a deployment archive, a `.git` file, symlinks pointing
 * outside, a FIFO, an oversized file, and the files the repository's
 * .gitignore would drop (`.env`, `*.pem`). Every scan of a fixture, including
 * the golden-file generation, uses the materialized copy.
 */

export type FixtureName = 'acme-incidents' | 'clean-cap';

export interface MaterializedFixture {
  root: string;
  cleanup(): Promise<void>;
}

const FIXTURES = fileURLToPath(new URL('../fixtures/projects/', import.meta.url));

/** 2 MiB + 1 byte: just over the read limit, with a poison value inside. */
export const BIG_FILE_BYTES = 2 * 1024 * 1024 + 1;

/** Creates a FIFO with mkfifo; silently skipped where the platform has none. */
function tryMkfifo(path: string): void {
  if (process.platform === 'win32') return;
  try {
    execFileSync('mkfifo', [path], { stdio: 'ignore' });
  } catch {
    // No mkfifo on this system: the walk test for FIFOs is then vacuous.
  }
}

async function addAcmeExtras(root: string): Promise<void> {
  await mkdir(join(root, 'mta_archives'), { recursive: true });
  await writeFile(join(root, 'mta_archives', 'acme-incidents_1.0.0.mtar'), Buffer.alloc(64, 0x50));
  await writeFile(join(root, '.git'), 'gitdir: /home/poison-user/.git/worktrees/acme\n');
  await writeFile(join(root, '.env'), 'CDS_REQUIRES_AUTH_KIND=POISON_env\n');
  await writeFile(
    join(root, 'POISON-secret.pem'),
    '-----BEGIN PRIVATE KEY-----\nPOISON-secret\n-----END PRIVATE KEY-----\n',
  );
  await symlink('/etc', join(root, 'link-out'));
  await symlink('/etc/hostname', join(root, 'srv', 'link.cds'));
  tryMkfifo(join(root, 'db', 'pipe.cds'));
  const big = Buffer.alloc(BIG_FILE_BYTES, 0x20);
  big.write('// POISON_big\n', 0, 'utf8');
  await writeFile(join(root, 'db', 'big.cds'), big);
}

async function addCleanExtras(root: string): Promise<void> {
  await mkdir(join(root, 'mta_archives'), { recursive: true });
  await writeFile(join(root, 'mta_archives', 'clean-cap_1.0.0.mtar'), Buffer.alloc(64, 0x50));
}

export async function materializeFixture(name: FixtureName): Promise<MaterializedFixture> {
  const root = await mkdtemp(join(tmpdir(), `btp-lens-${name}-`));
  await cp(join(FIXTURES, name), root, { recursive: true });
  if (name === 'acme-incidents') await addAcmeExtras(root);
  else await addCleanExtras(root);
  return {
    root,
    cleanup: () => rm(root, { recursive: true, force: true }),
  };
}
