import { mkdir, writeFile } from 'node:fs/promises';

/**
 * Reports describe a customer's landscape, so they are written readable by
 * the current user only (0700 directories, 0600 files). Windows has no POSIX
 * modes; Node ignores the option there.
 */
export const PRIVATE_DIR_MODE = 0o700;
export const PRIVATE_FILE_MODE = 0o600;

export async function ensurePrivateDir(dir: string): Promise<void> {
  await mkdir(dir, { recursive: true, mode: PRIVATE_DIR_MODE });
}

export async function writePrivateFile(path: string, content: string): Promise<void> {
  await writeFile(path, content, { encoding: 'utf8', mode: PRIVATE_FILE_MODE });
}
