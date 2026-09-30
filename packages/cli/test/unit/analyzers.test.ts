import { describe, expect, it } from 'vitest';
import { analyze, reanalyze } from '../../src/analyzers/index.js';
import { noRecentDeploy } from '../../src/analyzers/noRecentDeploy.js';
import { DAY_MS } from '../../src/analyzers/types.js';
import type { CheckResult } from '../../src/model/check.js';
import type { RawData, RawDroplet } from '../../src/model/raw.js';
import { SNAPSHOT_SCHEMA_VERSION, type Snapshot } from '../../src/model/snapshot.js';

const NOW = '2026-09-29T00:00:00.000Z';
const daysAgo = (days: number) => new Date(Date.parse(NOW) - days * DAY_MS).toISOString();

function droplet(appGuid: string, ageDays: number): RawDroplet {
  return {
    guid: `d-${appGuid}`,
    appGuid,
    state: 'STAGED',
    createdAt: daysAgo(ageDays),
    updatedAt: daysAgo(ageDays),
    lifecycleType: 'buildpack',
    stack: 'cflinuxfs4',
    buildpacks: [
      {
        name: 'nodejs_buildpack',
        buildpackName: 'nodejs',
        version: '1.8.40',
        detectOutput: 'nodejs',
      },
    ],
    image: null,
  };
}

function raw(ages: Record<string, number | null>): RawData {
  const apps = Object.keys(ages).map((name) => ({
    guid: name,
    name,
    spaceGuid: 's1',
    state: 'STARTED' as const,
    createdAt: daysAgo(900),
    updatedAt: daysAgo(10),
    lifecycleType: 'buildpack' as const,
    buildpacks: ['nodejs_buildpack'],
    stack: 'cflinuxfs4',
  }));
  return {
    orgs: [{ guid: 'o1', name: 'org' }],
    spaces: [{ guid: 's1', name: 'space', orgGuid: 'o1' }],
    apps,
    droplets: Object.entries(ages)
      .filter((entry): entry is [string, number] => entry[1] !== null)
      .map(([name, age]) => droplet(name, age)),
  };
}

const collectorsRan: CheckResult[] = [
  { id: 'collect.apps', title: 'apps', roles: ['SpaceAuditor'], status: 'ran' },
  { id: 'collect.droplets', title: 'droplets', roles: ['SpaceAuditor'], status: 'ran' },
];

describe('APP_NO_RECENT_DEPLOY', () => {
  it('uses 12 months as the threshold and 24 months for medium', () => {
    const { findings } = analyze(
      raw({ fresh: 30, edge: 365, low: 366, lowEdge: 730, medium: 731 }),
      NOW,
      collectorsRan,
      [noRecentDeploy],
    );
    const byApp = Object.fromEntries(findings.map((f) => [f.app.name, f.severity]));
    expect(byApp).toEqual({ low: 'low', lowEdge: 'low', medium: 'medium' });
  });

  it('records the evidence and a concrete remediation', () => {
    const { findings } = analyze(raw({ old: 400 }), NOW, collectorsRan, [noRecentDeploy]);
    expect(findings[0]).toMatchObject({
      id: 'APP_NO_RECENT_DEPLOY',
      title: 'Last deployed 13 months ago',
      app: { guid: 'old', name: 'old', space: 'space', org: 'org' },
      evidence: { ageDays: 400, thresholdDays: 365, lastDeployAt: daysAgo(400) },
    });
    expect(findings[0]?.remediation).toContain('cf restage');
  });

  it('ignores droplets of apps outside the inventory', () => {
    const data = raw({ known: 400 });
    data.droplets.push(droplet('ghost', 900));
    const { findings } = analyze(data, NOW, collectorsRan, [noRecentDeploy]);
    expect(findings.map((f) => f.app.name)).toEqual(['known']);
  });
});

describe('analyze', () => {
  it('skips a rule whose collector did not run', () => {
    const checks: CheckResult[] = [
      collectorsRan[0]!,
      { ...collectorsRan[1]!, status: 'skipped', reasonCode: 'insufficient_role' },
    ];
    const result = analyze(raw({ old: 900 }), NOW, checks, [noRecentDeploy]);
    expect(result.findings).toEqual([]);
    expect(result.ruleChecks).toEqual([
      expect.objectContaining({
        id: 'rule.APP_NO_RECENT_DEPLOY',
        status: 'skipped',
        reasonCode: 'dependency_skipped',
        reason: 'needs collect.droplets, which did not run',
      }),
    ]);
  });

  it('builds the inventory with counts, highest severity and risk order', () => {
    const result = analyze(raw({ a: 10, b: 400, c: 800, d: null }), NOW, collectorsRan);
    expect(result.apps.map((app) => [app.name, app.riskScore, app.highestSeverity])).toEqual([
      ['c', 5, 'medium'],
      ['b', 1, 'low'],
      ['a', 0, null],
      ['d', 0, null],
    ]);
    const d = result.apps.find((app) => app.name === 'd');
    expect(d).toMatchObject({
      lastDeployAt: null,
      buildpacks: [{ name: 'nodejs_buildpack', version: null }],
      findingCounts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    });
  });

  it('names unknown spaces instead of failing', () => {
    const data = raw({ lonely: 400 });
    data.spaces = [];
    const { findings } = analyze(data, NOW, collectorsRan);
    expect(findings[0]?.app).toMatchObject({ space: '(unknown)', org: '(unknown)' });
  });

  it('is deterministic: same input, same output', () => {
    const data = raw({ a: 400, b: 800, c: 900 });
    expect(analyze(data, NOW, collectorsRan)).toEqual(analyze(data, NOW, collectorsRan));
  });
});

describe('reanalyze', () => {
  it('keeps collector results and recomputes rules offline', () => {
    const data = raw({ old: 900 });
    const snapshot: Snapshot = {
      schemaVersion: SNAPSHOT_SCHEMA_VERSION,
      tool: { name: 'btp-lens', version: '0.0.0' },
      scannedAt: NOW,
      scope: { apiEndpoint: 'https://api.cf.example.org/', orgs: ['org'] },
      options: { deep: false, probeRoutes: true },
      checks: [
        ...collectorsRan,
        { id: 'rule.OLD_RULE', title: 'removed rule', roles: [], status: 'ran' },
      ],
      raw: data,
      apps: [],
      findings: [],
    };
    const result = reanalyze(snapshot);
    expect(result.checks.map((c) => c.id)).toEqual([
      'collect.apps',
      'collect.droplets',
      'rule.APP_NO_RECENT_DEPLOY',
    ]);
    expect(result.findings).toHaveLength(1);
    expect(result.apps).toHaveLength(1);
  });
});
