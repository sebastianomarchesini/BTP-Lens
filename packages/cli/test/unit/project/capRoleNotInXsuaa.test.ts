import { describe, expect, it } from 'vitest';
import {
  AMS_PACKAGE,
  RULE_ID,
  SEVERITY,
  XSAPPNAME_PREFIX,
  capRoleNotInXsuaa,
} from '../../../src/analyzers/project/capRoleNotInXsuaa.js';
import { PSEUDO_ROLES } from '../../../src/analyzers/project/patterns.js';
import { FindingSchema } from '../../../src/model/finding.js';
import { owaspUrl } from '../../../src/model/owasp.js';
import type { RawCdsFile, RawProject, RawXsSecurity } from '../../../src/model/raw.js';
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

/** A service file restricted to the given roles, declared on the service itself. */
function restricted(requires: string[], restrictTo: string[] = []): RawCdsFile {
  return cdsFile('srv/admin.cds', {
    services: [service('AdminService', { line: 3, requires, restrictTo })],
  });
}

/** A descriptor defining the given roles as `$XSAPPNAME.<role>` scopes. */
function descriptor(roles: string[], opts: Partial<RawXsSecurity> = {}): RawXsSecurity {
  return {
    ...xsSecurity({ scopes: roles.map((role) => `${XSAPPNAME_PREFIX}${role}`) }),
    ...opts,
  };
}

function project(
  files: RawCdsFile[],
  descriptors: RawXsSecurity[],
  overrides: Partial<RawProject> = {},
): RawProject {
  return rawProject({ cdsFiles: files, xsSecurity: descriptors, ...overrides });
}

const subjects = (findings: ReturnType<typeof runRule>) => findings.map((f) => f.evidence.subject);

describe('CAP_ROLE_NOT_IN_XSUAA', () => {
  it('declares its constants', () => {
    expect(RULE_ID).toBe('CAP_ROLE_NOT_IN_XSUAA');
    expect(AMS_PACKAGE).toBe('@sap/ams');
    expect(XSAPPNAME_PREFIX).toBe('$XSAPPNAME.');
    expect(SEVERITY).toEqual({ impact: 'moderate', easeOfAttack: 'advanced' });
  });

  it('fires medium for a role in @requires that no descriptor defines as a scope', () => {
    const findings = runRule(
      capRoleNotInXsuaa,
      project([restricted(['auditor'])], [descriptor(['admin'])]),
    );
    expect(findings).toHaveLength(1);
    const finding = findings[0]!;
    expect(finding.id).toBe(RULE_ID);
    expect(finding.severity).toBe('medium');
    expect(finding.title).toBe(
      'Role referenced in the CDS model has no scope in the XSUAA descriptor',
    );
    expect(finding.app).toEqual({
      guid: 'project:acme',
      name: 'acme',
      space: 'project',
      org: 'local',
    });
    expect(finding.evidence).toEqual({
      subject: 'auditor',
      role: 'auditor',
      descriptors: ['xs-security.json'],
      scopesChecked: 1,
      impact: 'moderate',
      easeOfAttack: 'advanced',
    });
    expect(finding.location).toEqual({ file: 'srv/admin.cds', line: 3 });
    expect(FindingSchema.safeParse(finding).success).toBe(true);
  });

  describe('finds roles wherever the model names them', () => {
    const one = (files: RawCdsFile[]) =>
      subjects(runRule(capRoleNotInXsuaa, project(files, [descriptor(['admin'])])));

    it('in @restrict.to on the service', () => {
      expect(one([restricted([], ['auditor'])])).toEqual(['auditor']);
    });

    it('on an entity of the service', () => {
      const file = cdsFile('srv/admin.cds', {
        services: [
          service('AdminService', {
            entities: [serviceEntity('Incidents', { line: 7, restrictTo: ['auditor'] })],
          }),
        ],
      });
      const findings = runRule(capRoleNotInXsuaa, project([file], [descriptor(['admin'])]));
      expect(subjects(findings)).toEqual(['auditor']);
      expect(findings[0]!.location).toEqual({ file: 'srv/admin.cds', line: 7 });
    });

    it('on an action or function', () => {
      const file = cdsFile('srv/admin.cds', {
        services: [
          service('AdminService', {
            actions: [action('close', { line: 9, requires: ['closer'] })],
          }),
        ],
      });
      const findings = runRule(capRoleNotInXsuaa, project([file], [descriptor(['admin'])]));
      expect(subjects(findings)).toEqual(['closer']);
      expect(findings[0]!.location).toEqual({ file: 'srv/admin.cds', line: 9 });
    });

    it('in an annotate statement in another file', () => {
      const files = [
        restricted(['admin']),
        cdsFile('srv/auth.cds', {
          annotates: [annotate('AdminService.Incidents', { line: 12, restrictTo: ['auditor'] })],
        }),
      ];
      const findings = runRule(capRoleNotInXsuaa, project(files, [descriptor(['admin'])]));
      expect(subjects(findings)).toEqual(['auditor']);
      expect(findings[0]!.location).toEqual({ file: 'srv/auth.cds', line: 12 });
    });
  });

  describe('does not fire', () => {
    const none = (
      files: RawCdsFile[],
      descriptors: RawXsSecurity[],
      overrides?: Partial<RawProject>,
    ) => expect(runRule(capRoleNotInXsuaa, project(files, descriptors, overrides))).toEqual([]);

    it('when the project has no XSUAA descriptor at all', () => {
      none([restricted(['auditor'])], []);
    });

    it('when no descriptor declares a scope or a role template', () => {
      // `cds add xsuaa` writes `config: { xsappname, tenant-mode }` into mta.yaml next to
      // `path: ./xs-security.json`; when that file is generated or ignored, the inline block
      // is the only descriptor the collector sees and says nothing about roles.
      none(
        [restricted(['auditor'])],
        [xsSecurity({ file: 'mta.yaml', source: 'mta.yaml', scopes: [] })],
      );
      none(
        [restricted(['auditor'])],
        [
          xsSecurity({ file: 'mta.yaml', source: 'mta.yaml', scopes: [] }),
          xsSecurity({ scopes: [], attributes: ['Country'] }),
        ],
      );
    });

    it('when the scope is defined as $XSAPPNAME.<role>', () => {
      none([restricted(['auditor'])], [descriptor(['auditor'])]);
    });

    it('when the scope is defined with the bare role name', () => {
      none([restricted(['auditor'])], [xsSecurity({ scopes: ['auditor'] })]);
    });

    it('when any descriptor defines the scope, including one read from mta.yaml', () => {
      none(
        [restricted(['auditor', 'admin'])],
        [
          descriptor(['admin']),
          xsSecurity({ file: 'mta.yaml', source: 'mta.yaml', scopes: ['$XSAPPNAME.auditor'] }),
        ],
      );
    });

    it('when the scope is granted to other apps as well', () => {
      none(
        [restricted(['auditor'])],
        [xsSecurity({ scopes: [{ name: '$XSAPPNAME.auditor', grantedToApps: true }] })],
      );
    });

    it('when the role is only a pseudo-role', () => {
      for (const role of PSEUDO_ROLES) none([restricted([role])], [descriptor(['admin'])]);
    });

    it('when the role carries $ or : (an XSUAA-qualified or attribute-based name)', () => {
      none([restricted(['$XSAPPNAME.auditor'])], [descriptor(['admin'])]);
      none([restricted([], ['$REQUEST.auditor'])], [descriptor(['admin'])]);
      none([restricted(['xs:auditor'])], [descriptor(['admin'])]);
    });

    it('when a dotted role name has its dotted scope', () => {
      none([restricted(['acme.auditor'])], [descriptor(['acme.auditor'])]);
      none([restricted(['acme.auditor'])], [xsSecurity({ scopes: ['acme.auditor'] })]);
    });

    it('when @sap/ams is a dependency', () => {
      none([restricted(['auditor'])], [descriptor(['admin'])], {
        packageJson: packageJson({ '@sap/cds': '^9', [AMS_PACKAGE]: '^3' }),
      });
    });

    it('when @sap/ams is a dev dependency', () => {
      none([restricted(['auditor'])], [descriptor(['admin'])], {
        packageJson: packageJson({ '@sap/cds': '^9' }, { [AMS_PACKAGE]: '^3' }),
      });
    });

    it('when production authentication is ams', () => {
      none([restricted(['auditor'])], [descriptor(['admin'])], {
        cds: cdsEffective('production', { authKind: 'ams' }),
      });
    });

    it('when no role is referenced at all', () => {
      none([], [descriptor(['admin'])]);
      none([cdsFile('srv/open.cds', { services: [service('Open')] })], [descriptor(['admin'])]);
      none(
        [cdsFile('db/schema.cds', { entities: [entity('Books', ['title'])] })],
        [descriptor([])],
      );
    });
  });

  it('ignores the development view: ams there does not exempt the project', () => {
    const findings = runRule(
      capRoleNotInXsuaa,
      project([restricted(['auditor'])], [descriptor(['admin'])], {
        cds: cdsEffective('development', { authKind: 'ams' }),
      }),
    );
    expect(subjects(findings)).toEqual(['auditor']);
  });

  it('fires against a descriptor that has role templates but no scopes', () => {
    const findings = runRule(
      capRoleNotInXsuaa,
      project(
        [restricted(['auditor'])],
        [xsSecurity({ scopes: [], roleTemplates: [['auditor', ['$XSAPPNAME.auditor']]] })],
      ),
    );
    expect(subjects(findings)).toEqual(['auditor']);
    expect(findings[0]!.evidence).toMatchObject({
      descriptors: ['xs-security.json'],
      scopesChecked: 0,
    });
  });

  it('locates the role in the first file of the collector order, at its lowest line there', () => {
    // The collector sorts paths by code point (`B` before `a`), which is not locale order.
    const files = [
      cdsFile('srv/B.cds', {
        services: [
          service('Beta', {
            line: 9,
            entities: [serviceEntity('Items', { line: 11, restrictTo: ['auditor'] })],
            actions: [action('close', { line: 10, requires: ['auditor'] })],
          }),
        ],
        annotates: [annotate('Beta.Items', { line: 4, restrictTo: ['auditor'] })],
      }),
      cdsFile('srv/a.cds', { services: [service('Alpha', { line: 1, requires: ['auditor'] })] }),
    ];
    const findings = runRule(capRoleNotInXsuaa, project(files, [descriptor(['admin'])]));
    expect(findings).toHaveLength(1);
    expect(findings[0]!.location).toEqual({ file: 'srv/B.cds', line: 4 });
  });

  it('matches scope names exactly: case and prefix matter', () => {
    const findings = runRule(
      capRoleNotInXsuaa,
      project(
        [restricted(['auditor', 'Admin'])],
        [xsSecurity({ scopes: ['$XSAPPNAME.Auditor', '$XSAPPNAME.admin', 'app.auditor'] })],
      ),
    );
    expect(subjects(findings)).toEqual(['Admin', 'auditor']);
  });

  it('emits one finding per role, however often and wherever it is referenced', () => {
    // Files in collector order (sorted paths), as a scan delivers them.
    const files = [
      cdsFile('srv/a.cds', {
        services: [service('AlphaService', { line: 5, restrictTo: ['alpha'] })],
        annotates: [annotate('ZetaService', { line: 1, requires: ['zeta'] })],
      }),
      cdsFile('srv/z.cds', {
        services: [
          service('ZetaService', {
            line: 20,
            requires: ['zeta', 'alpha'],
            entities: [serviceEntity('Items', { line: 22, restrictTo: ['alpha', 'admin'] })],
          }),
        ],
      }),
    ];
    const findings = runRule(capRoleNotInXsuaa, project(files, [descriptor(['admin'])]));
    // Each role is located at its first reference (collector order, then line); the framework
    // then orders findings by location, so `zeta` (line 1) comes before `alpha` (line 5).
    expect(subjects(findings)).toEqual(['zeta', 'alpha']);
    expect(findings.map((f) => f.location)).toEqual([
      { file: 'srv/a.cds', line: 1 },
      { file: 'srv/a.cds', line: 5 },
    ]);
  });

  it('lists every descriptor checked, once each, sorted', () => {
    const descriptors = [
      descriptor(['admin'], { file: 'mta.yaml', source: 'mta.yaml' }),
      descriptor(['support'], { file: 'app/xs-security.json' }),
      descriptor(['viewer'], { file: 'app/xs-security.json' }),
      descriptor(['admin']),
    ];
    const findings = runRule(capRoleNotInXsuaa, project([restricted(['auditor'])], descriptors));
    expect(findings).toHaveLength(1);
    expect(findings[0]!.evidence).toMatchObject({
      descriptors: ['app/xs-security.json', 'mta.yaml', 'xs-security.json'],
      scopesChecked: 3,
    });
  });

  it('reports each project on its own', () => {
    const findings = runRule(
      capRoleNotInXsuaa,
      project([restricted(['auditor'])], [descriptor(['admin'])]),
      rawProject({
        id: 'other',
        cdsFiles: [restricted(['auditor'])],
        xsSecurity: [descriptor(['auditor'])],
      }),
      rawProject({ id: 'third', cdsFiles: [restricted(['auditor'])], xsSecurity: [] }),
      rawProject({
        id: 'fourth',
        cdsFiles: [restricted(['viewer'])],
        xsSecurity: [descriptor(['admin'])],
      }),
    );
    expect(findings.map((f) => [f.app.name, f.evidence.subject])).toEqual([
      ['acme', 'auditor'],
      ['fourth', 'viewer'],
    ]);
  });

  it('links the CAP role assignment and authorization topics, the descriptor syntax and OWASP A01/A07', () => {
    const finding = runRule(
      capRoleNotInXsuaa,
      project([restricted(['auditor'])], [descriptor(['admin'])]),
    )[0]!;
    expect(finding.references).toEqual([
      'https://cap.cloud.sap/docs/guides/security/cap-users#xsuaa-roles',
      'https://cap.cloud.sap/docs/guides/security/authorization',
      'https://help.sap.com/docs/btp/sap-business-technology-platform/application-security-descriptor-configuration-syntax',
      owaspUrl('A01:2025'),
      owaspUrl('A07:2025'),
    ]);
    expect(finding.remediation).toContain('$XSAPPNAME.<role>');
    expect(finding.remediation).toContain('cds compile srv --to xsuaa');
    expect(finding.remediation).toContain('@sap/ams');
  });

  it('is deterministic', () => {
    expectDeterministic(
      capRoleNotInXsuaa,
      project(
        [
          cdsFile('srv/z.cds', {
            services: [service('Zeta', { requires: ['zeta', 'alpha'] })],
          }),
          cdsFile('srv/a.cds', {
            services: [service('Alpha', { restrictTo: ['alpha'] })],
            annotates: [annotate('Zeta', { requires: ['admin', 'beta'] })],
          }),
        ],
        [descriptor(['admin'], { file: 'mta.yaml', source: 'mta.yaml' }), descriptor(['beta'])],
      ),
    );
  });

  it('copies nothing from the project but the role, the descriptor files, file and line', () => {
    // Every poison value is a role the model references AND a scope a descriptor defines,
    // so none of them fires; only `auditor` does. Descriptor file names reach the evidence
    // by design, so they stay benign here and the poison goes everywhere else.
    const poisoned = rawProject({
      sourcesRead: ['.cdsrc.json', 'package.json'],
      files: POISON,
      unreadable: POISON.map((file) => ({ file, kind: 'cds' as const })),
      packageJson: packageJson(
        Object.fromEntries(POISON.map((value) => [value, value])),
        POISON,
        POISON[0],
      ),
      cds: cdsEffective('production', {
        authKind: 'xsuaa',
        mockedUsers: POISON.length,
        mockedUsersWithPassword: POISON.length,
        restrictAllServices: false,
      }),
      mta: mta({
        id: null,
        modules: POISON.map((value) => ({ name: value, buildpack: value, requires: [value] })),
        resources: POISON.map((value) => ({ name: value, service: value, plan: value })),
      }),
      xsSecurity: [
        xsSecurity({
          scopes: POISON,
          roleTemplates: POISON.map((value) => [value, [value]]),
          attributes: POISON,
        }),
        xsSecurity({
          file: 'mta.yaml',
          source: 'mta.yaml',
          scopes: POISON.map((value) => `${XSAPPNAME_PREFIX}${value}`),
          roleTemplates: [['auditor', POISON]],
          attributes: POISON,
        }),
      ],
      xsApps: POISON.map((value) => xsApp(value, [{ source: value }])),
      cdsFiles: [
        // The one role that fires is referenced from a benign file, next to poisoned members.
        cdsFile('srv/admin.cds', {
          usings: POISON.map((value) => ({ alias: value, target: value })),
          services: [
            service('AdminService', {
              line: 2,
              requires: [...POISON, 'auditor'],
              restrictTo: POISON,
              entities: POISON.map((value) =>
                serviceEntity(value, {
                  projectionOf: value,
                  requires: [value],
                  restrictTo: [value],
                }),
              ),
              actions: POISON.map((value) => action(value, { requires: [value] })),
            }),
          ],
          entities: POISON.map((value) =>
            entity(value, POISON, { associations: [{ field: value, target: value }] }),
          ),
          annotates: POISON.map((value) =>
            annotate(value, { personalData: true, requires: [value], restrictTo: [value] }),
          ),
        }),
        // Poisoned file names hold only roles that are defined, so they never become a location.
        ...POISON.map((value) =>
          cdsFile(value, {
            usings: [{ alias: value, target: value }],
            services: [service(value, { requires: [value], restrictTo: [value] })],
            entities: [entity(value, [value])],
            annotates: [annotate(value, { requires: [value], restrictTo: [value] })],
          }),
        ),
      ],
      seedData: POISON.map((value) =>
        seedCsv(value, {
          sensitiveColumns: [{ columnIndex: 1, kind: 'secret', rowsMatching: 1 }],
        }),
      ),
      archives: POISON.map((value) => archive(value)),
      html: POISON.map((value) => htmlBootstrap(value, value)),
    });
    const findings = runRule(capRoleNotInXsuaa, poisoned);
    expect(findings).toHaveLength(1);
    expectNoValueLeak(findings, POISON);
    expect(findings[0]!.evidence).toEqual({
      subject: 'auditor',
      role: 'auditor',
      descriptors: ['mta.yaml', 'xs-security.json'],
      scopesChecked: 2 * POISON.length,
      impact: 'moderate',
      easeOfAttack: 'advanced',
    });
    expect(findings[0]!.location).toEqual({ file: 'srv/admin.cds', line: 2 });
  });
});
