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

/** Patterns that look like secrets or personal data, whatever the value. */
const SUSPICIOUS = [
  // Domain must end in an alphabetic TLD, so "nodejs@1.8.40" is not an email.
  { name: 'email address', pattern: /[\w.+-]+@(?:[a-z0-9-]+\.)+[a-z]{2,}\b/i },
  { name: 'JWT', pattern: /eyJ[\w-]{10,}\.[\w-]{10,}/ },
  { name: 'bearer token', pattern: /bearer\s+[\w.-]{8,}/i },
  { name: 'URL with credentials', pattern: /[a-z]+:\/\/[^\s/"@]+:[^\s/"@]+@/i },
];

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
    for (const file of files) {
      const content = await readFile(join(out, file), 'utf8');
      for (const poison of ACME.poison) {
        expect(content, `${file} contains "${poison}"`).not.toContain(poison);
      }
      for (const { name, pattern } of SUSPICIOUS) {
        expect(pattern.test(content), `${file} contains a ${name}`).toBe(false);
      }
    }
  });
});
