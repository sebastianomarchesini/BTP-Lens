import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { ConfigError } from './http/errors.js';
import { SNAPSHOT_SCHEMA_VERSION, type Snapshot, SnapshotSchema } from './model/snapshot.js';

/** snapshot-20260929T031500Z.json: sortable, one file per scan. */
export function snapshotFileName(scannedAt: string): string {
  const stamp = scannedAt.replace(/\.\d+/, '').replace(/[-:]/g, '');
  return `snapshot-${stamp}.json`;
}

export async function writeSnapshot(snapshot: Snapshot, outDir: string): Promise<string> {
  await mkdir(outDir, { recursive: true });
  const path = join(outDir, snapshotFileName(snapshot.scannedAt));
  await writeFile(path, `${JSON.stringify(snapshot, null, 2)}\n`, 'utf8');
  return path;
}

export async function readSnapshot(path: string): Promise<Snapshot> {
  let json: unknown;
  try {
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
