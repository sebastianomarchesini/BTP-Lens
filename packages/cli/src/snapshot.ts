import { readFile, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { ConfigError } from './http/errors.js';
import { ensurePrivateDir, writePrivateFile } from './io/files.js';
import { SNAPSHOT_SCHEMA_VERSION, type Snapshot, SnapshotSchema } from './model/snapshot.js';

/** snapshot-20260929T031500Z.json: sortable, one file per scan. */
export function snapshotFileName(scannedAt: string): string {
  const stamp = scannedAt.replace(/\.\d+/, '').replace(/[-:]/g, '');
  return `snapshot-${stamp}.json`;
}

/** Larger files are refused before parsing: a snapshot is never this big. */
export const MAX_SNAPSHOT_BYTES = 256 * 1024 * 1024;

export async function writeSnapshot(snapshot: Snapshot, outDir: string): Promise<string> {
  await ensurePrivateDir(outDir);
  const path = join(outDir, snapshotFileName(snapshot.scannedAt));
  await writePrivateFile(path, `${JSON.stringify(snapshot, null, 2)}\n`);
  return path;
}

export async function readSnapshot(path: string): Promise<Snapshot> {
  let json: unknown;
  try {
    const { size } = await stat(path);
    if (size > MAX_SNAPSHOT_BYTES) {
      throw new Error(`file is ${size} bytes, the limit is ${MAX_SNAPSHOT_BYTES}`);
    }
    json = JSON.parse(await readFile(path, 'utf8'));
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    throw new ConfigError(`Could not read snapshot ${path}: ${reason}`);
  }
  const version = (json as { schemaVersion?: unknown } | null)?.schemaVersion;
  if (version !== SNAPSHOT_SCHEMA_VERSION) {
    throw new ConfigError(
      `Snapshot ${path} has schema version ${String(version)}; this btp-lens reads version ${SNAPSHOT_SCHEMA_VERSION}.`,
    );
  }
  const parsed = SnapshotSchema.safeParse(json);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    throw new ConfigError(
      `Snapshot ${path} is not valid: ${issue ? `${issue.path.join('.')}: ${issue.message}` : 'unknown error'}`,
    );
  }
  return parsed.data;
}
