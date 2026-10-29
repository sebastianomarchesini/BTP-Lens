import { describe, expect, it } from 'vitest';
import { analyze } from '../../../src/analyzers/index.js';
import {
  DEVELOPMENT_AUTH_KINDS,
  RULE_ID,
  SOURCES_NOT_READ,
  capMockedAuthInProd,
} from '../../../src/analyzers/project/capMockedAuthInProd.js';
import { FindingSchema } from '../../../src/model/finding.js';
import { owaspUrl } from '../../../src/model/owasp.js';
import type { CdsAuthKind, CdsSource, RawProject } from '../../../src/model/raw.js';
import {
  NOW,
  POISON,
  PROJECT_COLLECTOR_SKIPPED,
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
  xsApp,
  xsSecurity,
} from '../../support/project.js';

function productionAuth(authKind: CdsAuthKind | null, sourcesRead: CdsSource[] = []): RawProject {
  return rawProject({ sourcesRead, cds: cdsEffective('production', { authKind }) });
}

describe('CAP_MOCKED_AUTH_IN_PROD', () => {
  it('declares the development strategies cds documents', () => {
    expect(DEVELOPMENT_AUTH_KINDS).toEqual(['mocked', 'dummy', 'basic']);
    expect(RULE_ID).toBe('CAP_MOCKED_AUTH_IN_PROD');
  });

  it.each(['mocked', 'dummy', 'basic'] as const)(
    'fires once, critical, when production auth is %s',
    (authKind) => {
      const findings = runRule(capMockedAuthInProd, productionAuth(authKind, ['package.json']));
      expect(findings).toHaveLength(1);
      const finding = findings[0]!;
      expect(finding.id).toBe(RULE_ID);
      expect(finding.severity).toBe('critical');
      expect(finding.app).toEqual({
        guid: 'project:acme',
        name: 'acme',
        space: 'project',
        org: 'local',
      });
      expect(finding.evidence).toEqual({
        subject: 'requires.auth',
        authKind,
        sourcesRead: ['package.json'],
        sourcesNotRead: ['.cdsrc-private.json', '.cdsrc.js', '.env', 'CDS_* environment variables'],
        impact: 'severe',
        easeOfAttack: 'easy',
      });
      expect(finding.location).toEqual({ file: 'package.json' });
      expect(FindingSchema.safeParse(finding).success).toBe(true);
    },
  );

  it('names the strategy in the title', () => {
    const titleFor = (authKind: CdsAuthKind) =>
      runRule(capMockedAuthInProd, productionAuth(authKind))[0]?.title;
    expect(titleFor('mocked')).toBe('Mocked authentication is configured for production');
    expect(titleFor('dummy')).toBe('Dummy authentication is configured for production');
    expect(titleFor('basic')).toBe(
      'Basic authentication with mocked users is configured for production',
    );
  });

  it('uses the rule title for the mocked finding, as the sample snapshot pins both', () => {
    const finding = runRule(capMockedAuthInProd, productionAuth('mocked'))[0]!;
    expect(capMockedAuthInProd.rule.title).toBe(finding.title);
    expect(capMockedAuthInProd.rule.owasp).toEqual(['A07:2025']);
    expect(capMockedAuthInProd.requires).toEqual(['collect.project']);
  });

  it('emits nothing and records dependency_skipped when the collector was skipped', () => {
    const result = analyze(
      rawData(productionAuth('mocked', ['package.json'])),
      NOW,
      [PROJECT_COLLECTOR_SKIPPED],
      [capMockedAuthInProd],
    );
    expect(result.findings).toEqual([]);
    expect(result.ruleChecks.map((c) => [c.id, c.status, c.reasonCode])).toEqual([
      [`rule.${RULE_ID}`, 'skipped', 'dependency_skipped'],
    ]);
  });

  it('does not fire when production auth is unset: cds defaults to jwt', () => {
    expect(runRule(capMockedAuthInProd, productionAuth(null))).toEqual([]);
  });

  it.each(['jwt', 'xsuaa', 'ias', 'ams', 'other'] as const)(
    'does not fire when production auth is %s',
    (authKind) => {
      expect(runRule(capMockedAuthInProd, productionAuth(authKind, ['package.json']))).toEqual([]);
    },
  );

  it('does not fire for a development-only mocked configuration', () => {
    const project = rawProject({
      sourcesRead: ['package.json'],
      cds: cdsEffective('development', {
        authKind: 'mocked',
        mockedUsers: 3,
        mockedUsersWithPassword: 2,
      }),
    });
    expect(project.cds.effective.production.authKind).toBeNull();
    expect(runRule(capMockedAuthInProd, project)).toEqual([]);
  });

  it('ignores mocked users and restrict_all_services on their own', () => {
    const project = rawProject({
      cds: cdsEffective('production', {
        authKind: 'xsuaa',
        mockedUsers: 2,
        mockedUsersWithPassword: 1,
        restrictAllServices: false,
      }),
    });
    expect(runRule(capMockedAuthInProd, project)).toEqual([]);
  });

  describe('location', () => {
    it('points at the source cds applies last among those read', () => {
      const location = (sourcesRead: CdsSource[]) =>
        runRule(capMockedAuthInProd, productionAuth('mocked', sourcesRead))[0]?.location;
      expect(location(['.cdsrc.yaml', 'package.json', '.cdsrc.json'])).toEqual({
        file: 'package.json',
      });
      expect(location(['.cdsrc.json', '.cdsrc.yaml'])).toEqual({ file: '.cdsrc.json' });
      expect(location(['.cdsrc.yaml'])).toEqual({ file: '.cdsrc.yaml' });
    });

    it('is omitted, and the finding kept, when no source was read', () => {
      const findings = runRule(capMockedAuthInProd, productionAuth('dummy'));
      expect(findings).toHaveLength(1);
      expect('location' in findings[0]!).toBe(false);
      expect(findings[0]!.evidence.sourcesRead).toEqual([]);
      expect(FindingSchema.safeParse(findings[0]).success).toBe(true);
    });

    it('names each source once when the collector lists it twice', () => {
      const findings = runRule(
        capMockedAuthInProd,
        productionAuth('basic', ['package.json', '.cdsrc.json', 'package.json']),
      );
      expect(findings[0]!.evidence.sourcesRead).toEqual(['.cdsrc.json', 'package.json']);
      expect(findings[0]!.location).toEqual({ file: 'package.json' });
    });

    it('lists the sources read in cds priority order whatever the input order', () => {
      const findings = runRule(
        capMockedAuthInProd,
        productionAuth('mocked', ['package.json', '.cdsrc.yaml', '.cdsrc.json']),
      );
      expect(findings[0]!.evidence.sourcesRead).toEqual([
        '.cdsrc.yaml',
        '.cdsrc.json',
        'package.json',
      ]);
    });
  });

  it('records the sources it cannot see as a fixed list', () => {
    expect(SOURCES_NOT_READ).toEqual([
      '.cdsrc-private.json',
      '.cdsrc.js',
      '.env',
      'CDS_* environment variables',
    ]);
  });

  it('links the CAP authentication and cds env topics and OWASP A07:2025', () => {
    const finding = runRule(capMockedAuthInProd, productionAuth('mocked'))[0]!;
    expect(finding.references).toEqual([
      'https://cap.cloud.sap/docs/node.js/authentication',
      'https://cap.cloud.sap/docs/node.js/cds-env',
      owaspUrl('A07:2025'),
    ]);
    expect(finding.remediation).toContain('[production]');
    expect(finding.remediation).toContain('xsuaa');
  });

  it('emits one finding per project', () => {
    const findings = runRule(
      capMockedAuthInProd,
      productionAuth('mocked'),
      rawProject({ id: 'other', cds: cdsEffective('production', { authKind: 'basic' }) }),
      rawProject({ id: 'clean', cds: cdsEffective('production', { authKind: 'xsuaa' }) }),
    );
    expect(findings.map((f) => [f.app.name, f.evidence.authKind])).toEqual([
      ['acme', 'mocked'],
      ['other', 'basic'],
    ]);
  });

  it('is deterministic', () => {
    expectDeterministic(
      capMockedAuthInProd,
      productionAuth('mocked', ['.cdsrc.yaml', 'package.json', '.cdsrc.json']),
    );
  });

  it('copies nothing from the project but the strategy name and the source names', () => {
    const poisoned = rawProject({
      sourcesRead: ['.cdsrc.json', 'package.json'],
      files: POISON,
      unreadable: POISON.map((file) => ({ file, kind: 'json' as const })),
      packageJson: {
        ...packageJson(
          Object.fromEntries(POISON.map((value) => [value, value])),
          POISON,
          POISON[0],
        ),
        name: '@poison-scope/private',
      },
      cds: cdsEffective('production', {
        authKind: 'mocked',
        mockedUsers: POISON.length,
        mockedUsersWithPassword: POISON.length,
      }),
      mta: mta({
        id: 'mta-poison',
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
          services: [service(value, { requires: [value], restrictTo: [value] })],
          entities: [entity(value, [value])],
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
    const findings = runRule(capMockedAuthInProd, poisoned);
    expect(findings).toHaveLength(1);
    expectNoValueLeak(findings, POISON);
    expect(findings[0]!.location).toEqual({ file: 'package.json' });
  });
});
