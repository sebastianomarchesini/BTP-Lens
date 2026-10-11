import { constants } from 'node:fs';
import { chmod, mkdir, writeFile } from 'node:fs/promises';
import { ConfigError } from '../http/errors.js';

/**
 * Reports describe a customer's landscape, so they are written readable by
 * the current user only (0700 directories, 0600 files). Windows has no POSIX
 * modes; Node ignores the option there.
 */
export const PRIVATE_DIR_MODE = 0o700;
export const PRIVATE_FILE_MODE = 0o600;

/** One plain sentence for the file-system errors people actually hit. */
export function describeFsError(error: unknown): string {
  const code = (error as { code?: unknown } | null)?.code;
  switch (code) {
    case 'ENOENT':
      return 'the path does not exist';
    case 'ENOTDIR':
      return 'part of the path is a file, not a folder';
    case 'EISDIR':
      return 'the path is a folder, not a file';
    case 'EACCES':
    case 'EPERM':
      return 'permission denied';
    case 'EROFS':
      return 'the file system is read-only';
    case 'ENOSPC':
      return 'the disk is full';
    case 'ELOOP':
      return 'the path is a symbolic link, which is not followed';
    default:
      return error instanceof Error ? error.message : String(error);
  }
}

export async function ensurePrivateDir(dir: string): Promise<void> {
  try {
    await mkdir(dir, { recursive: true, mode: PRIVATE_DIR_MODE });
  } catch (error) {
    throw new ConfigError(`Cannot create the output folder ${dir}: ${describeFsError(error)}.`);
  }
}

export async function writePrivateFile(path: string, content: string): Promise<void> {
  // O_NOFOLLOW: a symlink planted at the output path is refused, not written through.
  const flag =
    constants.O_WRONLY | constants.O_CREAT | constants.O_TRUNC | (constants.O_NOFOLLOW ?? 0);
  try {
    await writeFile(path, content, { encoding: 'utf8', mode: PRIVATE_FILE_MODE, flag });
    // `mode` applies to new files only; an existing file keeps its mode otherwise.
    if (process.platform !== 'win32') await chmod(path, PRIVATE_FILE_MODE);
  } catch (error) {
    throw new ConfigError(`Cannot write ${path}: ${describeFsError(error)}.`);
  }
}
