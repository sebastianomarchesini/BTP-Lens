import { describe, expect, it } from 'vitest';
import { ANALYZERS, analyze, compareFindings, reanalyze } from '../../../src/analyzers/index.js';
import { noRecentDeploy } from '../../../src/analyzers/noRecentDeploy.js';
import { PROJECT_ANALYZERS } from '../../../src/analyzers/project/index.js';
import { projectFinding } from '../../../src/analyzers/project/support.js';
import { type Analyzer, projectRef, ruleHelpUri } from '../../../src/analyzers/types.js';
import type { CheckResult } from '../../../src/model/check.js';
import type { Finding } from '../../../src/model/finding.js';
import { SNAPSHOT_SCHEMA_VERSION, type Snapshot } from '../../../src/model/snapshot.js';
import {
  NOW,
  PROJECT_COLLECTOR,
  PROJECT_COLLECTOR_SKIPPED,
  mta,
  rawData,
  rawProject,
  runRule,
} from '../../support/project.js';

/** A rule that emits one finding per subject, in the order given. */
function emitting(subjects: string[], location = false): Analyzer {
  return {
    rule: {
      id: 'TEST_RULE',
      title: 'Test rule',
      description: 'Emits findings for a test.',
      roles: [],
      owasp: ['A01:2025'],
      helpUri: ruleHelpUri('TEST_RULE'),
    },
    requires: ['collect.project'],
    analyze(context) {
      return context.raw.projects.flatMap((project) =>
        subjects.map((subject) =>
          projectFinding(context, project, {
            id: 'TEST_RULE',
            title: `About ${subject}`,
            subject,
            severity: { impact: 'moderate', easeOfAttack: 'advanced' },
            remediation: 'Fix it.',
            references: [],
            ...(location ? { location: { file: 'srv/a.cds', line: subject.charCodeAt(0) } } : {}),
          }),
        ),
      );
    },
  };
}

const cfCollectors: CheckResult[] = [
  { id: 'collect.apps', title: 'apps', roles: ['SpaceAuditor'], status: 'ran' },
  { id: 'collect.droplets', title: 'droplets', roles: ['SpaceAuditor'], status: 'ran' },
];

describe('analyze: which rules run', () => {
  it('omits a rule whose collector was not part of the scan', () => {
    const result = analyze(rawData(rawProject()), NOW, [PROJECT_COLLECTOR], [noRecentDeploy]);
    expect(result.ruleChecks).toEqual([]);
    expect(result.findings).toEqual([]);
  });

  it('records dependency_skipped when the collector was part of the scan but skipped', () => {
    const rule = emitting(['a']);
    const result = analyze(rawData(rawProject()), NOW, [PROJECT_COLLECTOR_SKIPPED], [rule]);
    expect(result.findings).toEqual([]);
    expect(result.ruleChecks).toEqual([
      expect.objectContaining({
        id: 'rule.TEST_RULE',
        status: 'skipped',
        reasonCode: 'dependency_skipped',
        reason: 'needs collect.project, which did not run',
      }),
    ]);
  });

  it('runs project rules and omits CF rules for a project scan', () => {
    const result = analyze(rawData(rawProject()), NOW, [PROJECT_COLLECTOR]);
    const ids = result.ruleChecks.map((c) => c.id);
    expect(ids).toHaveLength(PROJECT_ANALYZERS.length);
    expect(ids).not.toContain('rule.APP_NO_RECENT_DEPLOY');
    expect(ids).toContain('rule.CAP_SERVICE_NO_RESTRICTION');
  });

  it('omits project rules for a CF scan', () => {
    const raw = { orgs: [], spaces: [], apps: [], droplets: [], projects: [] };
    const result = analyze(raw, NOW, cfCollectors);
    expect(result.ruleChecks.map((c) => c.id)).toEqual(['rule.APP_NO_RECENT_DEPLOY']);
  });

  it('reanalyze() of a project snapshot keeps the project collector and omits CF rules', () => {
    const snapshot: Snapshot = {
      schemaVersion: SNAPSHOT_SCHEMA_VERSION,
      tool: { name: 'btp-lens', version: '0.0.0' },
      scannedAt: NOW,
      scope: { orgs: [], projects: ['acme'] },
      options: { deep: false, probeRoutes: false },
      checks: [PROJECT_COLLECTOR, { ...cfCollectors[0]!, id: 'rule.OLD_RULE' }],
      raw: rawData(rawProject()),
      apps: [],
      findings: [],
    };
    const result = reanalyze(snapshot);
    expect(result.checks[0]).toEqual(PROJECT_COLLECTOR);
    expect(result.checks.map((c) => c.id)).not.toContain('rule.APP_NO_RECENT_DEPLOY');
    expect(result.checks).toHaveLength(1 + PROJECT_ANALYZERS.length);
    expect(result.apps.map((a) => a.guid)).toEqual(['project:acme']);
  });

  it('lists the CF rules before the project rules', () => {
    expect(ANALYZERS.map((a) => a.rule.id)).toEqual([
      'APP_NO_RECENT_DEPLOY',
      ...PROJECT_ANALYZERS.map((a) => a.rule.id),
    ]);
  });
});

describe('compareFindings', () => {
  it('sorts two findings of one rule on one project the same whatever the emission order', () => {
    const project = rawProject();
    const forward = runRule(emitting(['b', 'a'], true), project);
    const backward = runRule(emitting(['a', 'b'], true), project);
    expect(forward).toEqual(backward);
    expect(forward.map((f) => f.evidence.subject)).toEqual(['a', 'b']);
  });

  it('breaks ties by file, line, subject and title, with missing locations last', () => {
    const base: Finding = {
      id: 'X',
      severity: 'low',
      title: 't',
      app: projectRef(rawProject()),
      evidence: {},
      remediation: '',
      references: [],
    };
    const at = (file: string, line?: number): Finding => ({ ...base, location: { file, line } });
    expect(compareFindings(at('a.cds'), at('b.cds'))).toBeLessThan(0);
    expect(compareFindings(at('a.cds', 1), at('a.cds', 2))).toBeLessThan(0);
    expect(compareFindings(at('a.cds', 2), at('a.cds'))).toBeLessThan(0);
    expect(compareFindings(at('a.cds'), base)).toBeLessThan(0);
    expect(compareFindings(base, at('a.cds'))).toBeGreaterThan(0);
    expect(
      compareFindings(
        { ...base, evidence: { subject: 'a' } },
        { ...base, evidence: { subject: 'b' } },
      ),
    ).toBeLessThan(0);
    expect(compareFindings({ ...base, title: 'a' }, { ...base, title: 'b' })).toBeLessThan(0);
    expect(compareFindings(base, { ...base })).toBe(0);
  });

  it('keeps severity first, then rule id, org, space and app', () => {
    const low: Finding = {
      id: 'B',
      severity: 'low',
      title: '',
      app: { guid: 'g', name: 'a', space: 's', org: 'o' },
      evidence: {},
      remediation: '',
      references: [],
    };
    expect(compareFindings({ ...low, severity: 'high' }, low)).toBeLessThan(0);
    expect(compareFindings({ ...low, id: 'A' }, low)).toBeLessThan(0);
    expect(compareFindings(low, { ...low, app: { ...low.app, name: 'b' } })).toBeLessThan(0);
  });
});

describe('buildInventory for projects', () => {
  it('adds one item per project with fixed CF fields and buildpack names from mta.yaml', () => {
    const project = rawProject({
      id: 'acme-incidents',
      mta: mta({
        modules: [
          { name: 'srv', buildpack: 'nodejs_buildpack' },
          { name: 'srv2', buildpack: 'nodejs_buildpack' },
          { name: 'ui', buildpack: 'https://github.com/acme/buildpack.git' },
          { name: 'java', buildpack: 'sap_java_buildpack' },
          { name: 'none', buildpack: null },
        ],
      }),
    });
    const result = analyze(rawData(project), NOW, [PROJECT_COLLECTOR], [emitting(['x'])]);
    expect(result.apps).toEqual([
      {
        guid: 'project:acme-incidents',
        name: 'acme-incidents',
        org: 'local',
        space: 'project',
        kind: 'project',
        state: null,
        lifecycleType: 'unknown',
        stack: null,
        buildpacks: [
          { name: 'nodejs_buildpack', version: null },
          { name: 'sap_java_buildpack', version: null },
        ],
        createdAt: null,
        updatedAt: null,
        lastDeployAt: null,
        findingCounts: { critical: 0, high: 0, medium: 1, low: 0, info: 0 },
        highestSeverity: 'medium',
        riskScore: 5,
      },
    ]);
  });

  it('resolves project guids through appRef and names the project in findings', () => {
    const project = rawProject({ id: 'acme' });
    let resolved;
    const probe: Analyzer = {
      ...emitting([]),
      analyze(context) {
        resolved = context.appRef('project:acme');
        return [];
      },
    };
    analyze(rawData(project), NOW, [PROJECT_COLLECTOR], [probe]);
    expect(resolved).toEqual({
      guid: 'project:acme',
      name: 'acme',
      space: 'project',
      org: 'local',
    });
    expect(projectRef(project)).toEqual(resolved);
  });
});
