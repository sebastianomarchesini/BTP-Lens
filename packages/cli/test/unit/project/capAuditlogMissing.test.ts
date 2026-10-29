import { describe, expect, it } from 'vitest';
import {
  AUDIT_LOGGING_PLUGIN,
  CDS_PACKAGE,
  LEGACY_AUDIT_LOGGING_LIBRARY,
  RULE_ID,
  TITLE_DECLARED,
  TITLE_DEV_ONLY,
  TITLE_INFERRED,
  TITLE_LEGACY,
  capAuditlogMissing,
} from '../../../src/analyzers/project/capAuditlogMissing.js';
import { FindingSchema } from '../../../src/model/finding.js';
import { owaspUrl } from '../../../src/model/owasp.js';
import type { RawCdsFile, RawProject } from '../../../src/model/raw.js';
import {
  POISON,
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
  rawProject,
  runRule,
  seedCsv,
  service,
  serviceEntity,
  xsApp,
  xsSecurity,
} from '../../support/project.js';

/** `Customers` annotated inline: personal data declared. */
function declaredModel(): RawCdsFile[] {
  return [
    cdsFile('db/schema.cds', {
      entities: [entity('Customers', ['ID', 'email', 'phone'], { personalData: true })],
    }),
  ];
}

/** `Customers` with an email field and no annotation: personal data inferred. */
function inferredModel(): RawCdsFile[] {
  return [cdsFile('db/schema.cds', { entities: [entity('Customers', ['ID', 'email'])] })];
}

function capProject(
  cdsFiles: RawCdsFile[],
  deps: string[] = [CDS_PACKAGE],
  overrides: Parameters<typeof rawProject>[0] = {},
): RawProject {
  return rawProject({ packageJson: packageJson(deps), cdsFiles, ...overrides });
}

/** Expected evidence for a finding without the legacy library or a dev-only plugin. */
function evidenceFor(declared: boolean, declaredEntities: number, inferredEntities: number) {
  return {
    subject: 'requires.audit-log',
    personalDataDeclared: declared,
    declaredEntities,
    inferredEntities,
    legacyLibrary: false,
    pluginInDevDependencies: false,
    impact: declared ? 'significant' : 'moderate',
    easeOfAttack: 'advanced',
  };
}

describe('CAP_AUDITLOG_MISSING', () => {
  it('names the packages it looks for and keeps the rule meta', () => {
    expect(RULE_ID).toBe('CAP_AUDITLOG_MISSING');
    expect(CDS_PACKAGE).toBe('@sap/cds');
    expect(AUDIT_LOGGING_PLUGIN).toBe('@cap-js/audit-logging');
    expect(LEGACY_AUDIT_LOGGING_LIBRARY).toBe('@sap/audit-logging');
    expect(capAuditlogMissing.rule.id).toBe(RULE_ID);
    expect(capAuditlogMissing.rule.title).toBe(TITLE_DECLARED);
    expect(capAuditlogMissing.rule.owasp).toEqual(['A09:2025']);
    expect(capAuditlogMissing.rule.roles).toEqual([]);
    expect(capAuditlogMissing.requires).toEqual(['collect.project']);
  });

  it('fires once, high, when @PersonalData is declared and nothing logs it', () => {
    const findings = runRule(capAuditlogMissing, capProject(declaredModel()));
    expect(findings).toHaveLength(1);
    const finding = findings[0]!;
    expect(finding.id).toBe(RULE_ID);
    expect(finding.severity).toBe('high');
    expect(finding.title).toBe(TITLE_DECLARED);
    expect(finding.app).toEqual({
      guid: 'project:acme',
      name: 'acme',
      space: 'project',
      org: 'local',
    });
    expect(finding.evidence).toEqual(evidenceFor(true, 1, 0));
    expect(finding.location).toEqual({ file: 'package.json' });
    expect(finding.remediation).toMatch(/^Add the `@cap-js\/audit-logging` plugin/);
    expect(finding.remediation).toContain('cds add audit-logging');
    expect(finding.remediation).toContain('cds env requires.audit-log --profile production');
    expect(FindingSchema.safeParse(finding).success).toBe(true);
  });

  it('fires medium when personal data is only inferred from field names', () => {
    const findings = runRule(capAuditlogMissing, capProject(inferredModel()));
    expect(findings).toHaveLength(1);
    const finding = findings[0]!;
    expect(finding.severity).toBe('medium');
    expect(finding.title).toBe(TITLE_INFERRED);
    expect(finding.evidence).toEqual(evidenceFor(false, 0, 1));
    expect(finding.location).toEqual({ file: 'package.json' });
    expect(finding.remediation).toMatch(/^Annotate .*@PersonalData.*, then add the/);
    expect(finding.remediation).toContain('cds add audit-logging');
  });

  it('fires low with the legacy title when @sap/audit-logging is used instead of the plugin', () => {
    const findings = runRule(
      capAuditlogMissing,
      capProject(declaredModel(), [CDS_PACKAGE, LEGACY_AUDIT_LOGGING_LIBRARY]),
    );
    expect(findings).toHaveLength(1);
    const finding = findings[0]!;
    expect(finding.severity).toBe('low');
    expect(finding.title).toBe(TITLE_LEGACY);
    expect(finding.evidence).toEqual({
      subject: 'requires.audit-log',
      personalDataDeclared: true,
      declaredEntities: 1,
      inferredEntities: 0,
      legacyLibrary: true,
      pluginInDevDependencies: false,
      impact: 'minor',
      easeOfAttack: 'complex',
    });
    expect(finding.remediation).toMatch(/^Replace `@sap\/audit-logging`/);
    expect(finding.remediation).toContain('@cap-js/audit-logging');
    expect(finding.remediation).not.toContain('Create an SAP Audit Log service instance');
  });

  it('keeps the legacy branch low and asks for annotations when personal data is only inferred', () => {
    const findings = runRule(
      capAuditlogMissing,
      capProject(inferredModel(), [CDS_PACKAGE, LEGACY_AUDIT_LOGGING_LIBRARY]),
    );
    expect(findings.map((f) => [f.severity, f.title, f.evidence.personalDataDeclared])).toEqual([
      ['low', TITLE_LEGACY, false],
    ]);
    expect(findings[0]!.remediation).toMatch(/^Annotate .*@PersonalData.*, then replace/);
  });

  describe('plugin listed under devDependencies only', () => {
    it('fires high with its own title when @PersonalData is declared', () => {
      const project = rawProject({
        packageJson: packageJson([CDS_PACKAGE], [AUDIT_LOGGING_PLUGIN]),
        cdsFiles: declaredModel(),
      });
      const findings = runRule(capAuditlogMissing, project);
      expect(findings).toHaveLength(1);
      const finding = findings[0]!;
      expect(finding.severity).toBe('high');
      expect(finding.title).toBe(TITLE_DEV_ONLY);
      expect(finding.evidence).toEqual({
        ...evidenceFor(true, 1, 0),
        pluginInDevDependencies: true,
      });
      expect(finding.remediation).toMatch(/^Move `@cap-js\/audit-logging` from `devDependencies`/);
      expect(finding.remediation).not.toContain('cds add audit-logging');
    });

    it('fires medium and asks for annotations when personal data is only inferred', () => {
      const project = rawProject({
        packageJson: packageJson([CDS_PACKAGE], [AUDIT_LOGGING_PLUGIN]),
        cdsFiles: inferredModel(),
      });
      const findings = runRule(capAuditlogMissing, project);
      expect(findings.map((f) => [f.severity, f.title])).toEqual([['medium', TITLE_DEV_ONLY]]);
      expect(findings[0]!.remediation).toMatch(/^Annotate .*, then move `@cap-js\/audit-logging`/);
    });

    it('yields to the legacy branch when @sap/audit-logging is a runtime dependency', () => {
      const project = rawProject({
        packageJson: packageJson(
          [CDS_PACKAGE, LEGACY_AUDIT_LOGGING_LIBRARY],
          [AUDIT_LOGGING_PLUGIN],
        ),
        cdsFiles: declaredModel(),
      });
      const finding = runRule(capAuditlogMissing, project)[0]!;
      expect(finding.title).toBe(TITLE_LEGACY);
      expect(finding.severity).toBe('low');
      expect(finding.evidence.legacyLibrary).toBe(true);
      expect(finding.evidence.pluginInDevDependencies).toBe(true);
    });
  });

  it('ignores @sap/audit-logging under devDependencies', () => {
    const project = rawProject({
      packageJson: packageJson([CDS_PACKAGE], [LEGACY_AUDIT_LOGGING_LIBRARY]),
      cdsFiles: declaredModel(),
    });
    const finding = runRule(capAuditlogMissing, project)[0]!;
    expect(finding.title).toBe(TITLE_DECLARED);
    expect(finding.severity).toBe('high');
    expect(finding.evidence.legacyLibrary).toBe(false);
  });

  describe('does not fire', () => {
    it('when @sap/cds is not a dependency', () => {
      expect(runRule(capAuditlogMissing, capProject(declaredModel(), ['express']))).toEqual([]);
      expect(runRule(capAuditlogMissing, rawProject({ cdsFiles: declaredModel() }))).toEqual([]);
    });

    it('when @sap/cds is a devDependency only (not a Node.js CAP app)', () => {
      const project = rawProject({
        packageJson: packageJson(['express'], [CDS_PACKAGE]),
        cdsFiles: declaredModel(),
      });
      expect(runRule(capAuditlogMissing, project)).toEqual([]);
    });

    it('when the model holds no personal data, declared or inferred', () => {
      expect(runRule(capAuditlogMissing, capProject([]))).toEqual([]);
      const warehouses = cdsFile('db/schema.cds', {
        entities: [entity('Warehouses', ['ID', 'city', 'postCode'])],
      });
      expect(runRule(capAuditlogMissing, capProject([warehouses]))).toEqual([]);
    });

    it('when @cap-js/audit-logging is a dependency', () => {
      const project = capProject(declaredModel(), [CDS_PACKAGE, AUDIT_LOGGING_PLUGIN]);
      expect(runRule(capAuditlogMissing, project)).toEqual([]);
    });

    it('when @cap-js/audit-logging is in both dependency lists', () => {
      const project = rawProject({
        packageJson: packageJson([CDS_PACKAGE, AUDIT_LOGGING_PLUGIN], [AUDIT_LOGGING_PLUGIN]),
        cdsFiles: declaredModel(),
      });
      expect(runRule(capAuditlogMissing, project)).toEqual([]);
    });

    it.each([
      'audit-log-to-restv2',
      'audit-log-to-alsng',
      'audit-log-to-console',
      'audit-log-to-library',
      'other',
      null,
    ] as const)('when requires.audit-log is configured for production (kind %s)', (kind) => {
      const project = capProject(declaredModel(), [CDS_PACKAGE], {
        cds: cdsEffective('production', { auditLogConfigured: true, auditLogKind: kind }),
      });
      expect(runRule(capAuditlogMissing, project)).toEqual([]);
    });

    it('when requires.audit-log is configured for production and the plugin is dev-only', () => {
      const project = rawProject({
        packageJson: packageJson([CDS_PACKAGE], [AUDIT_LOGGING_PLUGIN]),
        cdsFiles: declaredModel(),
        cds: cdsEffective('production', { auditLogConfigured: true, auditLogKind: null }),
      });
      expect(runRule(capAuditlogMissing, project)).toEqual([]);
    });

    it('when the plugin is present even though the legacy library is too', () => {
      const project = capProject(declaredModel(), [
        CDS_PACKAGE,
        LEGACY_AUDIT_LOGGING_LIBRARY,
        AUDIT_LOGGING_PLUGIN,
      ]);
      expect(runRule(capAuditlogMissing, project)).toEqual([]);
    });
  });

  it('still fires when requires.audit-log is configured for development only', () => {
    const project = capProject(declaredModel(), [CDS_PACKAGE], {
      cds: cdsEffective('development', {
        auditLogConfigured: true,
        auditLogKind: 'audit-log-to-console',
      }),
    });
    expect(runRule(capAuditlogMissing, project)).toHaveLength(1);
  });

  describe('evidence counts', () => {
    it('treats an annotate with @PersonalData as a declaration', () => {
      const project = capProject([
        cdsFile('db/schema.cds', { entities: [entity('Customers', ['ID', 'email'])] }),
        cdsFile('db/annotations.cds', {
          annotates: [annotate('Customers', { personalData: true })],
        }),
      ]);
      const finding = runRule(capAuditlogMissing, project)[0]!;
      expect(finding.severity).toBe('high');
      expect(finding.evidence.personalDataDeclared).toBe(true);
      expect(finding.evidence.declaredEntities).toBe(1);
      expect(finding.evidence.inferredEntities).toBe(0);
    });

    it('counts declared and inferred entities separately', () => {
      const project = capProject([
        cdsFile('db/schema.cds', {
          entities: [
            entity('Customers', ['ID', 'email'], { personalData: true }),
            entity('Employees', ['ID', 'salary']),
            entity('Addresses', ['ID', 'city'], {
              associations: [{ field: 'customer', target: 'Customers' }],
            }),
            entity('Warehouses', ['ID', 'city']),
          ],
        }),
      ]);
      const finding = runRule(capAuditlogMissing, project)[0]!;
      expect(finding.evidence.declaredEntities).toBe(1);
      expect(finding.evidence.inferredEntities).toBe(2);
    });

    it('counts a declaration that resolves to no db entity as declared with zero entities', () => {
      const project = capProject([
        cdsFile('srv/services.cds', {
          services: [service('AdminService', { entities: [serviceEntity('Customers')] })],
          annotates: [annotate('AdminService.Customers', { personalData: true })],
        }),
      ]);
      const finding = runRule(capAuditlogMissing, project)[0]!;
      expect(finding.severity).toBe('high');
      expect(finding.evidence.personalDataDeclared).toBe(true);
      expect(finding.evidence.declaredEntities).toBe(0);
      expect(finding.evidence.inferredEntities).toBe(0);
    });
  });

  it('links the CAP audit logging and annotation guides and OWASP A09:2025', () => {
    const finding = runRule(capAuditlogMissing, capProject(declaredModel()))[0]!;
    expect(finding.references).toEqual([
      'https://cap.cloud.sap/docs/guides/security/dpp-audit-logging',
      'https://cap.cloud.sap/docs/guides/security/dpp-annotations',
      owaspUrl('A09:2025'),
    ]);
  });

  it('emits one finding per project, in project order', () => {
    const findings = runRule(
      capAuditlogMissing,
      capProject(declaredModel()),
      capProject(inferredModel(), [CDS_PACKAGE], { id: 'other' }),
      capProject(declaredModel(), [CDS_PACKAGE, AUDIT_LOGGING_PLUGIN], { id: 'clean' }),
    );
    expect(findings.map((f) => [f.app.name, f.severity])).toEqual([
      ['acme', 'high'],
      ['other', 'medium'],
    ]);
  });

  it('sorts the same whatever the project order', () => {
    const first = capProject(declaredModel(), [CDS_PACKAGE], { id: 'zeta' });
    const second = capProject(inferredModel(), [CDS_PACKAGE], { id: 'alpha' });
    expect(runRule(capAuditlogMissing, first, second)).toEqual(
      runRule(capAuditlogMissing, second, first),
    );
  });

  it('is deterministic', () => {
    expectDeterministic(
      capAuditlogMissing,
      capProject([...declaredModel(), ...inferredModel()], [CDS_PACKAGE, 'express']),
    );
  });

  it('copies nothing from the project but counts, booleans and the fixed subject', () => {
    const poisoned = rawProject({
      sourcesRead: ['.cdsrc.json', 'package.json'],
      files: POISON,
      unreadable: POISON.map((file) => ({ file, kind: 'json' as const })),
      packageJson: {
        ...packageJson(
          { [CDS_PACKAGE]: POISON[0]!, ...Object.fromEntries(POISON.map((v) => [v, v])) },
          { [AUDIT_LOGGING_PLUGIN]: POISON[1]!, ...Object.fromEntries(POISON.map((v) => [v, v])) },
          POISON[1],
        ),
        name: POISON[2]!,
      },
      cds: cdsEffective('production', {
        authKind: 'mocked',
        mockedUsers: POISON.length,
        mockedUsersWithPassword: POISON.length,
      }),
      mta: mta({
        id: null,
        modules: POISON.map((value) => ({ name: value, buildpack: value, requires: [value] })),
        resources: POISON.map((value) => ({ name: value, service: value, plan: value })),
      }),
      xsSecurity: POISON.map((value) =>
        xsSecurity({
          file: value,
          scopes: [value],
          roleTemplates: [[value, [value]]],
          attributes: [value],
        }),
      ),
      xsApps: POISON.map((value) => xsApp(value, [{ source: value }])),
      cdsFiles: POISON.map((value) =>
        cdsFile(value, {
          usings: [{ alias: value, target: value }],
          services: [
            service(value, {
              requires: [value],
              restrictTo: [value],
              entities: [serviceEntity(value, { projectionOf: value })],
            }),
          ],
          entities: [
            entity(value, [value, 'email'], {
              personalData: true,
              associations: [{ field: value, target: value }],
            }),
            entity(`${value}Customer`, [value, 'city'], {
              associations: [{ field: value, target: value }],
            }),
          ],
          annotates: [annotate(value, { personalData: true, requires: [value] })],
        }),
      ),
      seedData: POISON.map((value) =>
        seedCsv(value, {
          sensitiveColumns: [{ column: value, kind: 'secret', rowsMatching: 1 }],
        }),
      ),
      archives: POISON.map((value) => archive(value)),
      html: POISON.map((value) => htmlBootstrap(value, value)),
    });
    const findings = runRule(capAuditlogMissing, poisoned);
    expect(findings).toHaveLength(1);
    expectNoValueLeak(findings, POISON);
    expect(findings[0]!.title).toBe(TITLE_DEV_ONLY);
    expect(findings[0]!.location).toEqual({ file: 'package.json' });
    expect(findings[0]!.evidence.declaredEntities).toBe(POISON.length);
  });
});
