import { describe, expect, it } from 'vitest';
import {
  RULE_ID,
  SUBJECT,
  capMockedUserPassword,
} from '../../../src/analyzers/project/capMockedUserPassword.js';
import { FindingSchema } from '../../../src/model/finding.js';
import { owaspUrl } from '../../../src/model/owasp.js';
import type { CdsAuthKind, CdsSource, CdsView, RawProject } from '../../../src/model/raw.js';
import {
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
  rawProject,
  runRule,
  seedCsv,
  service,
  serviceEntity,
  xsApp,
  xsSecurity,
} from '../../support/project.js';

type View = 'development' | 'production';

function withUsers(
  view: View,
  partial: Partial<CdsView>,
  sourcesRead: CdsSource[] = ['package.json'],
): RawProject {
  return rawProject({
    sourcesRead,
    cds: cdsEffective(view, { mockedUsers: 2, mockedUsersWithPassword: 1, ...partial }),
  });
}

describe('CAP_MOCKED_USER_PASSWORD', () => {
  it('declares its id and subject', () => {
    expect(RULE_ID).toBe('CAP_MOCKED_USER_PASSWORD');
    expect(SUBJECT).toBe('requires.auth.users');
    expect(capMockedUserPassword.rule.owasp).toEqual(['A07:2025']);
  });

  it('fires medium when production users carry passwords and production auth is real', () => {
    const findings = runRule(capMockedUserPassword, withUsers('production', { authKind: 'xsuaa' }));
    expect(findings).toHaveLength(1);
    const finding = findings[0]!;
    expect(finding.id).toBe(RULE_ID);
    expect(finding.severity).toBe('medium');
    expect(finding.title).toBe('Mocked users carry passwords in the production configuration');
    expect(finding.app).toEqual({
      guid: 'project:acme',
      name: 'acme',
      space: 'project',
      org: 'local',
    });
    expect(finding.evidence).toEqual({
      subject: SUBJECT,
      view: 'production',
      usersWithPassword: 1,
      mockedUsers: 2,
      authKind: 'xsuaa',
      impact: 'moderate',
      easeOfAttack: 'complex',
    });
    expect(finding.location).toEqual({ file: 'package.json' });
    expect(FindingSchema.safeParse(finding).success).toBe(true);
  });

  it.each([null, 'jwt', 'ias', 'ams', 'other'] as const)(
    'stays medium for production auth %s, which CAP_MOCKED_AUTH_IN_PROD does not report',
    (authKind) => {
      const finding = runRule(capMockedUserPassword, withUsers('production', { authKind }))[0]!;
      expect(finding.severity).toBe('medium');
      expect(finding.evidence.impact).toBe('moderate');
    },
  );

  it.each(['mocked', 'dummy', 'basic'] as const satisfies readonly CdsAuthKind[])(
    'drops to low when production auth is %s: the critical finding already covers it',
    (authKind) => {
      const findings = runRule(capMockedUserPassword, withUsers('production', { authKind }));
      expect(findings).toHaveLength(1);
      expect(findings[0]!.severity).toBe('low');
      expect(findings[0]!.evidence).toMatchObject({
        view: 'production',
        authKind,
        impact: 'minor',
        easeOfAttack: 'complex',
      });
    },
  );

  it('fires low for development-only passwords', () => {
    const findings = runRule(
      capMockedUserPassword,
      withUsers('development', { authKind: 'mocked', mockedUsers: 3, mockedUsersWithPassword: 3 }),
    );
    expect(findings).toHaveLength(1);
    const finding = findings[0]!;
    expect(finding.severity).toBe('low');
    expect(finding.title).toBe('Mocked users carry passwords in the development configuration');
    expect(finding.evidence).toEqual({
      subject: SUBJECT,
      view: 'development',
      usersWithPassword: 3,
      mockedUsers: 3,
      authKind: 'mocked',
      impact: 'minor',
      easeOfAttack: 'complex',
    });
    expect(FindingSchema.safeParse(finding).success).toBe(true);
  });

  it('stays low, naming the development view, when production auth is mocked without users', () => {
    // The acme-incidents fixture shape: `auth: 'mocked'` at the top level and
    // the users with passwords under `[development]` only.
    const project = rawProject({
      sourcesRead: ['.cdsrc.json', '.cdsrc.yaml', 'package.json'],
      cds: {
        effective: {
          development: {
            ...cdsEffective('development', {}).effective.development,
            authKind: 'mocked',
            mockedUsers: 2,
            mockedUsersWithPassword: 1,
          },
          production: {
            ...cdsEffective('production', {}).effective.production,
            authKind: 'mocked',
          },
        },
      },
    });
    const findings = runRule(capMockedUserPassword, project);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('low');
    expect(findings[0]!.title).toBe(
      'Mocked users carry passwords in the development configuration',
    );
    expect(findings[0]!.evidence).toMatchObject({
      view: 'development',
      usersWithPassword: 1,
      mockedUsers: 2,
      authKind: 'mocked',
    });
    expect(findings[0]!.location).toEqual({ file: 'package.json' });
  });

  it('reports the production view, low, when both views carry passwords under mocked production auth', () => {
    const project = rawProject({
      sourcesRead: ['package.json'],
      cds: {
        effective: {
          development: {
            ...cdsEffective('development', {}).effective.development,
            authKind: 'mocked',
            mockedUsers: 2,
            mockedUsersWithPassword: 2,
          },
          production: {
            ...cdsEffective('production', {}).effective.production,
            authKind: 'basic',
            mockedUsers: 1,
            mockedUsersWithPassword: 1,
          },
        },
      },
    });
    const findings = runRule(capMockedUserPassword, project);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('low');
    expect(findings[0]!.evidence).toMatchObject({
      view: 'production',
      usersWithPassword: 1,
      authKind: 'basic',
      impact: 'minor',
    });
    expect(FindingSchema.safeParse(findings[0]).success).toBe(true);
  });

  it('reports the production view once when both views carry passwords', () => {
    const project = rawProject({
      sourcesRead: ['package.json'],
      cds: {
        effective: {
          development: {
            ...cdsEffective('development', {}).effective.development,
            authKind: 'mocked',
            mockedUsers: 4,
            mockedUsersWithPassword: 4,
          },
          production: {
            ...cdsEffective('production', {}).effective.production,
            authKind: 'xsuaa',
            mockedUsers: 1,
            mockedUsersWithPassword: 1,
          },
        },
      },
    });
    const findings = runRule(capMockedUserPassword, project);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('medium');
    expect(findings[0]!.evidence).toMatchObject({
      view: 'production',
      usersWithPassword: 1,
      mockedUsers: 1,
    });
  });

  describe('does not fire', () => {
    it.each(['development', 'production'] as const)(
      'when %s mocked users have no password',
      (view) => {
        const project = withUsers(view, {
          authKind: 'mocked',
          mockedUsers: 5,
          mockedUsersWithPassword: 0,
        });
        expect(runRule(capMockedUserPassword, project)).toEqual([]);
      },
    );

    it('when no mocked users are configured at all', () => {
      expect(runRule(capMockedUserPassword, rawProject())).toEqual([]);
      expect(
        runRule(
          capMockedUserPassword,
          withUsers('production', { mockedUsers: 0, mockedUsersWithPassword: 0 }),
        ),
      ).toEqual([]);
    });

    it('on mocked production auth alone: that is CAP_MOCKED_AUTH_IN_PROD', () => {
      const project = withUsers('production', {
        authKind: 'mocked',
        mockedUsers: 0,
        mockedUsersWithPassword: 0,
        restrictAllServices: false,
      });
      expect(runRule(capMockedUserPassword, project)).toEqual([]);
    });
  });

  describe('location', () => {
    it('points at the source cds applies last among those read', () => {
      const location = (sourcesRead: CdsSource[]) =>
        runRule(capMockedUserPassword, withUsers('development', {}, sourcesRead))[0]?.location;
      expect(location(['.cdsrc.yaml', 'package.json', '.cdsrc.json'])).toEqual({
        file: 'package.json',
      });
      expect(location(['.cdsrc.json', '.cdsrc.yaml'])).toEqual({ file: '.cdsrc.json' });
      expect(location(['.cdsrc.yaml'])).toEqual({ file: '.cdsrc.yaml' });
    });

    it('is omitted, and the finding kept, when no source was read', () => {
      const findings = runRule(capMockedUserPassword, withUsers('production', {}, []));
      expect(findings).toHaveLength(1);
      expect('location' in findings[0]!).toBe(false);
    });
  });

  it('links the CAP mocked authentication and cds env topics and OWASP A07:2025', () => {
    const finding = runRule(capMockedUserPassword, withUsers('development', {}))[0]!;
    expect(finding.references).toEqual([
      'https://cap.cloud.sap/docs/node.js/authentication#mocked',
      'https://cap.cloud.sap/docs/node.js/cds-env',
      owaspUrl('A07:2025'),
    ]);
    expect(finding.remediation).toContain('cds.requires.auth.users');
    expect(finding.remediation).toContain('[development]');
    expect(finding.remediation).toContain('.cdsrc-private.json');
  });

  it('emits one finding per project, in severity order', () => {
    const findings = runRule(
      capMockedUserPassword,
      rawProject({
        id: 'dev-only',
        cds: cdsEffective('development', { mockedUsersWithPassword: 1 }),
      }),
      rawProject({
        id: 'clean',
        cds: cdsEffective('production', { authKind: 'xsuaa', mockedUsers: 2 }),
      }),
      rawProject({
        id: 'prod',
        cds: cdsEffective('production', { authKind: 'xsuaa', mockedUsersWithPassword: 2 }),
      }),
    );
    expect(findings.map((f) => [f.app.name, f.severity, f.evidence.view])).toEqual([
      ['prod', 'medium', 'production'],
      ['dev-only', 'low', 'development'],
    ]);
  });

  it('is deterministic', () => {
    expectDeterministic(
      capMockedUserPassword,
      withUsers('production', { authKind: 'xsuaa' }, [
        '.cdsrc.yaml',
        'package.json',
        '.cdsrc.json',
      ]),
    );
  });

  it('copies nothing from the project but counts, the view and the source name', () => {
    const poisoned = rawProject({
      id: 'acme',
      sourcesRead: ['.cdsrc.json', 'package.json'],
      files: POISON,
      unreadable: POISON.map((file) => ({ file, kind: 'json' as const })),
      packageJson: packageJson(
        Object.fromEntries(POISON.map((value) => [value, value])),
        POISON,
        POISON[0],
      ),
      cds: {
        effective: {
          development: {
            ...cdsEffective('development', {}).effective.development,
            authKind: 'mocked',
            mockedUsers: POISON.length,
            mockedUsersWithPassword: POISON.length,
          },
          production: {
            ...cdsEffective('production', {}).effective.production,
            authKind: 'xsuaa',
            mockedUsers: POISON.length,
            mockedUsersWithPassword: POISON.length,
          },
        },
      },
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
              entities: [
                serviceEntity(value, {
                  requires: [value],
                  restrictTo: [value],
                  projectionOf: value,
                }),
              ],
              actions: [action(value, { requires: [value], restrictTo: [value] })],
            }),
          ],
          entities: [entity(value, [value], { associations: [{ field: value, target: value }] })],
          annotates: [annotate(value, { requires: [value], restrictTo: [value] })],
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
    const findings = runRule(capMockedUserPassword, poisoned);
    expect(findings).toHaveLength(1);
    expectNoValueLeak(findings, POISON);
    expect(findings[0]!.location).toEqual({ file: 'package.json' });
    expect(findings[0]!.evidence.usersWithPassword).toBe(POISON.length);
  });
});
