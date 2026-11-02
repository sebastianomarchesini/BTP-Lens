import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { reanalyze } from '../../src/analyzers/index.js';
import { ReportDataSchema, type Snapshot, SnapshotSchema } from '../../src/model/snapshot.js';
import { toReportData } from '../../src/reporters/reportData.js';

/**
 * A snapshot written by btp-lens 0.1.0, frozen (never regenerated). Newer
 * versions must keep reading it: the schema version stays 1, new fields are
 * optional or defaulted, and `report --from` gives the same findings.
 */
const legacy: unknown = JSON.parse(
  readFileSync(new URL('../fixtures/legacy/snapshot-0.1.0.json', import.meta.url), 'utf8'),
);

describe('0.1.0 snapshot compatibility', () => {
  it('still parses, with the new fields defaulted', () => {
    const parsed = SnapshotSchema.safeParse(legacy);
    expect(parsed.success).toBe(true);
    const snapshot = parsed.data as Snapshot;
    expect(snapshot.raw.projects).toEqual([]);
    expect(snapshot.apps.every((app) => app.kind === 'app')).toBe(true);
    expect(snapshot.scope.apiEndpoint).toBe('https://api.cf.example.org/');
  });

  it('re-analyzes to the same three findings and omits the project rules', () => {
    const snapshot = SnapshotSchema.parse(legacy);
    const result = reanalyze(snapshot);
    expect(result.findings).toHaveLength(3);
    expect(result.findings).toEqual(snapshot.findings);
    expect(result.checks.map((c) => c.id)).toEqual([
      'collect.apps',
      'collect.droplets',
      'rule.APP_NO_RECENT_DEPLOY',
    ]);
  });

  it('produces valid report data', () => {
    const data = toReportData(reanalyze(SnapshotSchema.parse(legacy)));
    expect(ReportDataSchema.safeParse(data).success).toBe(true);
    expect(data.summary).toMatchObject({ apps: 8, projects: 0, findings: 3 });
  });
});
