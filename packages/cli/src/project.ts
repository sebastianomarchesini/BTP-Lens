import { resolve } from 'node:path';
import { analyze } from './analyzers/index.js';
import { CheckRecorder, COLLECTOR_CHECKS } from './checks.js';
import { collectProject } from './collectors/project/index.js';
import type { RawData, RawProject } from './model/raw.js';
import { SNAPSHOT_SCHEMA_VERSION, type Snapshot } from './model/snapshot.js';
import { TOOL_NAME, TOOL_VERSION } from './version.js';

export interface ScanProjectOptions {
  /** The project directory, as the user gave it. */
  path: string;
  /** Output directory; the walk never enters it. */
  outDir?: string;
  /** Injected in tests; defaults to the current time. */
  now?: () => Date;
  log?: (message: string) => void;
}

/**
 * Scans a local CAP / MTA project directory: file-system reads only, no
 * network, no child processes. The log carries counts and the project id
 * only, never a path or file content.
 */
export async function scanProject(options: ScanProjectOptions): Promise<Snapshot> {
  const log = options.log ?? (() => {});
  const scannedAt = (options.now?.() ?? new Date()).toISOString();
  const excludeDirs = options.outDir === undefined ? [] : [resolve(options.outDir)];

  const recorder = new CheckRecorder({ deep: false }, log);
  const project: RawProject | undefined = await recorder.run(COLLECTOR_CHECKS.project, () =>
    collectProject(options.path, { excludeDirs }),
  );
  const projects = project === undefined ? [] : [project];
  if (project !== undefined) {
    log(
      `Read ${project.files.length} project file(s)` +
        `${project.unreadable.length > 0 ? `, ${project.unreadable.length} unreadable` : ''}` +
        ` in project ${project.id}`,
    );
  }

  const raw: RawData = { orgs: [], spaces: [], apps: [], droplets: [], projects };
  const collectorChecks = recorder.list();
  const analysis = analyze(raw, scannedAt, collectorChecks);
  return {
    schemaVersion: SNAPSHOT_SCHEMA_VERSION,
    tool: { name: TOOL_NAME, version: TOOL_VERSION },
    scannedAt,
    scope: { orgs: [], projects: projects.map((p) => p.id) },
    options: { deep: false, probeRoutes: false },
    checks: [...collectorChecks, ...analysis.ruleChecks],
    raw,
    apps: analysis.apps,
    findings: analysis.findings,
  };
}
