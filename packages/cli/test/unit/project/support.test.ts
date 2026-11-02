import { describe, expect, it } from 'vitest';
import { PROJECT_ANALYZERS } from '../../../src/analyzers/project/index.js';
import { projectFinding } from '../../../src/analyzers/project/support.js';
import { type Analyzer, projectRef, ruleHelpUri } from '../../../src/analyzers/types.js';
import { FindingSchema } from '../../../src/model/finding.js';
import { OWASP_2025_IDS } from '../../../src/model/owasp.js';
import { RawDataSchema, RawProjectSchema } from '../../../src/model/raw.js';
import { RuleMetaSchema } from '../../../src/model/snapshot.js';
import {
  NOW,
  POISON,
  action,
  annotate,
  archive,
  cdsEffective,
  cdsFile,
  entity,
  expectDeterministic,
  expectNoValueLeak,
  htmlBootstrap,
  mta,
  packageJson,
  rawData,
  rawProject,
  runRule,
  seedCsv,
  service,
  serviceEntity,
  xsApp,
  xsSecurity,
} from '../../support/project.js';

const stub: Analyzer = {
  rule: {
    id: 'STUB_RULE',
    title: 'Stub rule',
    description: 'A stub.',
    roles: [],
    owasp: ['A02:2025'],
    helpUri: ruleHelpUri('STUB_RULE'),
  },
  requires: ['collect.project'],
  analyze(context) {
    return context.raw.projects.map((project) =>
      projectFinding(context, project, {
        id: 'STUB_RULE',
        title: 'Stub finding',
        subject: project.id,
        severity: 'info',
        remediation: 'Nothing.',
        references: ['https://example.org/'],
      }),
    );
  },
};

describe('project test factory', () => {
  it('builds a minimal project that passes the schema', () => {
    const project = rawProject();
    expect(RawProjectSchema.safeParse(project).success).toBe(true);
    expect(project.id).toBe('acme');
    expect(project.mta).toBeNull();
    expect(project.cds.effective.production.authKind).toBeNull();
    expect(RawDataSchema.safeParse(rawData(project)).success).toBe(true);
  });

  it('builds every collected shape so that the result still passes the schema', () => {
    const project = rawProject({
      id: 'acme-incidents',
      sourcesRead: ['package.json'],
      files: ['package.json', 'srv/services.cds'],
      packageJson: packageJson({ '@sap/cds': '^9' }, ['vitest'], '>=22'),
      cds: cdsEffective('production', { authKind: 'mocked', mockedUsersWithPassword: 1 }),
      mta: mta({
        id: 'acme-incidents',
        modules: [{ name: 'srv', buildpack: 'nodejs_buildpack', requires: ['acme-auth'] }],
        resources: [{ name: 'acme-auth', service: 'xsuaa', plan: 'application' }],
      }),
      xsSecurity: [
        xsSecurity({
          scopes: ['$XSAPPNAME.admin', { name: '$XSAPPNAME.cb', grantedToApps: true }],
          roleTemplates: [['admin', ['$XSAPPNAME.admin']]],
          attributes: ['region'],
        }),
      ],
      xsApps: [
        xsApp('app/xs-app.json', [{ source: '^/odata/(.*)$', csrfProtection: false }], {
          authenticationMethod: 'route',
        }),
      ],
      cdsFiles: [
        cdsFile('srv/services.cds', {
          usings: [{ alias: 'db', target: 'acme.incidents' }],
          services: [
            service('AdminService', {
              line: 3,
              requires: ['admin'],
              entities: [serviceEntity('Customers', { projectionOf: 'db.Customers' })],
              actions: [action('close', { restrictTo: ['support'] })],
            }),
          ],
          entities: [entity('Customers', ['ID', 'email'], { associations: [] })],
          annotates: [annotate('AdminService.Customers', { personalData: true })],
        }),
      ],
      seedData: [
        seedCsv('db/data/Customers.csv', {
          sensitiveColumns: [{ columnIndex: 6, kind: 'card', rowsMatching: 2 }],
        }),
      ],
      archives: [archive('mta_archives/acme.mtar', { bytes: 64 })],
      html: [htmlBootstrap('app/index.html', 'https://ui5.example.com/resources/sap-ui-core.js')],
    });
    const parsed = RawProjectSchema.safeParse(project);
    expect(parsed.error?.issues ?? []).toEqual([]);
    expect(parsed.success).toBe(true);
    expect(project.cds.effective.development.authKind).toBeNull();
    expect(project.xsApps[0]?.routes[0]).toMatchObject({
      authenticationType: 'xsuaa',
      target: 'destination',
      isLogoutPage: false,
    });
    expect(project.html[0]).toMatchObject({ external: true, versionForm: 'latest' });
    expect(htmlBootstrap('a.html', 'resources/sap-ui-core.js')).toMatchObject({
      external: false,
      versionForm: 'none',
    });
  });

  it('runs a rule the way a project scan does', () => {
    const findings = runRule(stub, rawProject({ id: 'one' }), rawProject({ id: 'two' }));
    expect(findings.map((f) => [f.app.guid, f.evidence.subject])).toEqual([
      ['project:one', 'one'],
      ['project:two', 'two'],
    ]);
    expect(findings.every((f) => FindingSchema.safeParse(f).success)).toBe(true);
    expectDeterministic(stub, rawProject());
    expectNoValueLeak(findings, POISON);
    expect(() => expectNoValueLeak(findings, ['project:one'])).toThrow(/contain/);
  });

  it('lists the poison values without duplicates', () => {
    expect(new Set(POISON).size).toBe(POISON.length);
    expect(NOW).toBe('2026-09-29T00:00:00.000Z');
  });
});

describe('projectFinding', () => {
  const project = rawProject({ id: 'acme' });
  const context = {
    now: new Date(NOW),
    raw: rawData(project),
    appRef: () => undefined,
    projectRef,
  };

  it('derives the severity from the matrix and records both inputs', () => {
    const finding = projectFinding(context, project, {
      id: 'X_RULE',
      title: 'Title',
      subject: 'AdminService',
      severity: { impact: 'severe', easeOfAttack: 'easy' },
      evidence: { writableEntities: 2 },
      location: { file: 'srv/services.cds', line: 3 },
      remediation: 'Do.',
      references: ['https://example.org/'],
    });
    expect(finding).toEqual({
      id: 'X_RULE',
      severity: 'critical',
      title: 'Title',
      app: { guid: 'project:acme', name: 'acme', space: 'project', org: 'local' },
      evidence: {
        subject: 'AdminService',
        writableEntities: 2,
        impact: 'severe',
        easeOfAttack: 'easy',
      },
      remediation: 'Do.',
      references: ['https://example.org/'],
      location: { file: 'srv/services.cds', line: 3 },
    });
    expect(FindingSchema.safeParse(finding).success).toBe(true);
  });

  it('keeps a fixed severity without matrix evidence and omits a missing location', () => {
    const finding = projectFinding(context, project, {
      id: 'X_RULE',
      title: 'Title',
      subject: 'x',
      severity: 'low',
      remediation: 'Do.',
      references: [],
    });
    expect(finding.severity).toBe('low');
    expect(finding.evidence).toEqual({ subject: 'x' });
    expect('location' in finding).toBe(false);
  });
});

describe('project rule stubs', () => {
  it('declare final metadata: ids, OWASP tags, no CF role, the project collector', () => {
    expect(PROJECT_ANALYZERS.map((a) => a.rule.id)).toEqual([
      'CAP_MOCKED_AUTH_IN_PROD',
      'CAP_MOCKED_USER_PASSWORD',
      'CAP_AUDITLOG_MISSING',
      'CAP_AUDITLOG_NOT_BOUND',
      'CAP_PERSONAL_DATA_UNANNOTATED',
      'CAP_SERVICE_NO_RESTRICTION',
      'CAP_ROLE_NOT_IN_XSUAA',
      'XSUAA_SCOPE_UNUSED',
      'APPROUTER_ROUTE_NO_AUTH',
      'APPROUTER_CSRF_DISABLED',
      'DEPLOY_ARTIFACT_IN_REPO',
      'SEED_DATA_SENSITIVE',
      'UI5_BOOTSTRAP_EXTERNAL',
    ]);
    for (const analyzer of PROJECT_ANALYZERS) {
      expect(RuleMetaSchema.safeParse(analyzer.rule).success).toBe(true);
      expect(analyzer.rule.roles).toEqual([]);
      expect(analyzer.requires).toEqual(['collect.project']);
      expect(analyzer.rule.owasp.length).toBeGreaterThan(0);
      expect(analyzer.rule.owasp.every((id) => OWASP_2025_IDS.includes(id))).toBe(true);
      expect(analyzer.rule.helpUri).toBe(ruleHelpUri(analyzer.rule.id));
      expect(analyzer.rule.title).not.toMatch(/\.$/);
    }
    const owasp = Object.fromEntries(PROJECT_ANALYZERS.map((a) => [a.rule.id, a.rule.owasp]));
    expect(owasp).toEqual({
      CAP_MOCKED_AUTH_IN_PROD: ['A07:2025'],
      CAP_MOCKED_USER_PASSWORD: ['A07:2025'],
      CAP_AUDITLOG_MISSING: ['A09:2025'],
      CAP_AUDITLOG_NOT_BOUND: ['A09:2025'],
      CAP_PERSONAL_DATA_UNANNOTATED: ['A04:2025', 'A09:2025'],
      CAP_SERVICE_NO_RESTRICTION: ['A01:2025'],
      CAP_ROLE_NOT_IN_XSUAA: ['A01:2025', 'A07:2025'],
      XSUAA_SCOPE_UNUSED: ['A02:2025'],
      APPROUTER_ROUTE_NO_AUTH: ['A07:2025'],
      APPROUTER_CSRF_DISABLED: ['A01:2025'],
      DEPLOY_ARTIFACT_IN_REPO: ['A03:2025'],
      SEED_DATA_SENSITIVE: ['A04:2025'],
      UI5_BOOTSTRAP_EXTERNAL: ['A08:2025'],
    });
  });
});
