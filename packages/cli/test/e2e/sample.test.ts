import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { ReportDataSchema, SnapshotSchema } from '../../src/model/snapshot.js';
import { renderJson } from '../../src/reporters/json.js';
import { toReportData } from '../../src/reporters/reportData.js';
import { scan } from '../../src/scan.js';
import { ACME, acmeFetch } from '../support/acme.js';

/**
 * Golden files built from the acme fixtures:
 *  - test/fixtures/sample-snapshot.json feeds `npm run sample` (the real CLI
 *    and the real HTML template, in CI);
 *  - packages/ui/src/test/fixtures/report.json is the UI's dev and test data.
 * Regenerate both with `UPDATE_SAMPLE=1 npm test -w btp-lens`.
 */
const SAMPLE_SNAPSHOT = fileURLToPath(new URL('../fixtures/sample-snapshot.json', import.meta.url));
const UI_REPORT = fileURLToPath(
  new URL('../../../ui/src/test/fixtures/report.json', import.meta.url),
);

async function readOrEmpty(path: string): Promise<string> {
  try {
    return await readFile(path, 'utf8');
  } catch {
    return '';
  }
}

describe('sample data', () => {
  it('matches the committed sample snapshot and UI report fixture', async () => {
    const snapshot = await scan({
      apiUrl: ACME.api,
      org: ACME.org,
      deep: false,
      probeRoutes: true,
      concurrency: 5,
      env: { BTP_LENS_ACCESS_TOKEN: ACME.token },
      fetch: acmeFetch().fetch,
      now: () => ACME.now,
    });
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
