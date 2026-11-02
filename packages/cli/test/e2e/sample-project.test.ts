import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ReportDataSchema, SnapshotSchema } from '../../src/model/snapshot.js';
import { scanProject } from '../../src/project.js';
import { renderJson } from '../../src/reporters/json.js';
import { toReportData } from '../../src/reporters/reportData.js';
import { NOW } from '../support/project.js';
import { type MaterializedFixture, materializeFixture } from '../support/projectFixture.js';

/**
 * Golden files built from the acme-incidents project fixture:
 *  - test/fixtures/sample-project-snapshot.json feeds `npm run sample`;
 *  - packages/ui/src/test/fixtures/report-project.json is the UI's test data
 *    for a project scan.
 * Regenerate both with `UPDATE_SAMPLE=1 npm test -w btp-lens`.
 */
const SAMPLE_SNAPSHOT = fileURLToPath(
  new URL('../fixtures/sample-project-snapshot.json', import.meta.url),
);
const UI_REPORT = fileURLToPath(
  new URL('../../../ui/src/test/fixtures/report-project.json', import.meta.url),
);

async function readOrEmpty(path: string): Promise<string> {
  try {
    return await readFile(path, 'utf8');
  } catch {
    return '';
  }
}

describe('sample project data', () => {
  let fixture: MaterializedFixture;
  beforeAll(async () => {
    fixture = await materializeFixture('acme-incidents');
  });
  afterAll(() => fixture.cleanup());

  it('matches the committed sample project snapshot and UI report fixture', async () => {
    const snapshot = await scanProject({ path: fixture.root, now: () => new Date(NOW) });
    const snapshotJson = `${JSON.stringify(snapshot, null, 2)}\n`;
    const reportJson = renderJson(toReportData(snapshot));

    if (process.env.UPDATE_SAMPLE) {
      for (const [path, content] of [
        [SAMPLE_SNAPSHOT, snapshotJson],
        [UI_REPORT, reportJson],
      ] as const) {
        await mkdir(dirname(path), { recursive: true });
        await writeFile(path, content, 'utf8');
      }
    }

    expect(SnapshotSchema.safeParse(JSON.parse(snapshotJson)).success).toBe(true);
    expect(ReportDataSchema.safeParse(JSON.parse(reportJson)).success).toBe(true);
    expect(await readOrEmpty(SAMPLE_SNAPSHOT), 'run UPDATE_SAMPLE=1 npm test -w btp-lens').toBe(
      snapshotJson,
    );
    expect(await readOrEmpty(UI_REPORT), 'run UPDATE_SAMPLE=1 npm test -w btp-lens').toBe(
      reportJson,
    );
  });
});
