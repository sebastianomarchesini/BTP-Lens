import { mkdtemp, readFile, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { DATA_PLACEHOLDER } from '../../src/reporters/html.js';
import { writeReports } from '../../src/reporters/index.js';
import { toReportData } from '../../src/reporters/reportData.js';
import { scan } from '../../src/scan.js';
import { writeSnapshot } from '../../src/snapshot.js';
import { ACME, acmeFetch } from '../support/acme.js';
import { ABSOLUTE_PATH, expectNoLeaks } from '../support/leak.js';

describe('no secrets or personal data in any output', () => {
  it('keeps poison values out of the snapshot and every report format', async () => {
    const out = await mkdtemp(join(tmpdir(), 'btp-lens-leak-'));
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
    await writeSnapshot(snapshot, out);
    await writeReports(toReportData(snapshot), ['html', 'json', 'csv', 'sarif'], out, {
      htmlTemplate: `<html><body>${DATA_PLACEHOLDER}</body></html>`,
    });

    const files = await readdir(out);
    expect(files).toHaveLength(6);
    const texts: Record<string, string> = {};
    for (const file of files) texts[file] = await readFile(join(out, file), 'utf8');
    expectNoLeaks(texts, [...ACME.poison], [ABSOLUTE_PATH]);
  });
});
