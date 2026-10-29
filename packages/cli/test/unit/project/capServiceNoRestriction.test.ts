import { describe, expect, it } from 'vitest';
import {
  OPEN_AUTH_KINDS,
  RULE_ID,
  capServiceNoRestriction,
} from '../../../src/analyzers/project/capServiceNoRestriction.js';
import { FindingSchema } from '../../../src/model/finding.js';
import { owaspUrl } from '../../../src/model/owasp.js';
import type { RawCdsFile, RawProject } from '../../../src/model/raw.js';
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

/** A project with one service file; `cds` defaults to nothing configured. */
function project(files: RawCdsFile[], overrides: Partial<RawProject> = {}): RawProject {
  return rawProject({ cdsFiles: files, ...overrides });
}

function openService(opts: Parameters<typeof service>[1] = {}): RawCdsFile {
  return cdsFile('srv/catalog.cds', {
    services: [
      service('CatalogService', {
        line: 4,
        entities: [serviceEntity('Books', { line: 5 })],
        ...opts,
      }),
    ],
  });
}

const subjects = (findings: ReturnType<typeof runRule>) =>
  findings.map((f) => [f.evidence.subject, f.severity]);

describe('CAP_SERVICE_NO_RESTRICTION', () => {
  it('declares the strategies under which cds adds no implicit authenticated-user', () => {
    expect(OPEN_AUTH_KINDS).toEqual(['mocked', 'dummy', 'basic']);
    expect(RULE_ID).toBe('CAP_SERVICE_NO_RESTRICTION');
  });

  it('fires high for an unrestricted service with a writable entity', () => {
    const findings = runRule(capServiceNoRestriction, project([openService()]));
    expect(findings).toHaveLength(1);
    const finding = findings[0]!;
    expect(finding.id).toBe(RULE_ID);
    expect(finding.severity).toBe('high');
    expect(finding.title).toBe('Service is open to every authenticated user');
    expect(finding.app).toEqual({
      guid: 'project:acme',
      name: 'acme',
      space: 'project',
      org: 'local',
    });
    expect(finding.evidence).toEqual({
      subject: 'CatalogService',
      restrictAllServices: null,
      authKind: null,
      entities: 1,
      writableEntities: 1,
      actions: 0,
      impact: 'significant',
      easeOfAttack: 'advanced',
    });
    expect(finding.location).toEqual({ file: 'srv/catalog.cds', line: 4 });
    expect(FindingSchema.safeParse(finding).success).toBe(true);
  });

  describe('severity', () => {
    it('is high when at least one entity is writable among readonly ones', () => {
      const file = openService({
        entities: [
          serviceEntity('Books', { readonly: true }),
          serviceEntity('Orders'),
          serviceEntity('Authors', { readonly: true }),
        ],
      });
      const finding = runRule(capServiceNoRestriction, project([file]))[0]!;
      expect(finding.severity).toBe('high');
      expect(finding.evidence).toMatchObject({ entities: 3, writableEntities: 1, actions: 0 });
    });

    it('is high when every entity is readonly but an action exists', () => {
      const file = openService({
        entities: [serviceEntity('Books', { readonly: true })],
        actions: [action('submitOrder'), action('cancelOrder')],
      });
      const finding = runRule(capServiceNoRestriction, project([file]))[0]!;
      expect(finding.severity).toBe('high');
      expect(finding.evidence).toMatchObject({
        entities: 1,
        writableEntities: 0,
        actions: 2,
        impact: 'significant',
        easeOfAttack: 'advanced',
      });
    });

    it('is medium when every entity is readonly and there are no actions', () => {
      const file = openService({
        entities: [
          serviceEntity('Books', { readonly: true }),
          serviceEntity('Authors', { readonly: true }),
        ],
      });
      const finding = runRule(capServiceNoRestriction, project([file]))[0]!;
      expect(finding.severity).toBe('medium');
      expect(finding.evidence).toMatchObject({
        entities: 2,
        writableEntities: 0,
        actions: 0,
        impact: 'moderate',
        easeOfAttack: 'advanced',
      });
    });

    it('is medium for an empty service (nothing to write, nothing to call)', () => {
      const file = openService({ entities: [], actions: [] });
      const finding = runRule(capServiceNoRestriction, project([file]))[0]!;
      expect(finding.severity).toBe('medium');
      expect(finding.evidence).toMatchObject({ entities: 0, writableEntities: 0, actions: 0 });
    });

    it('is critical, "open to everyone", when production sets restrict_all_services: false', () => {
      const readonlyOnly = openService({ entities: [serviceEntity('Books', { readonly: true })] });
      const finding = runRule(
        capServiceNoRestriction,
        project([readonlyOnly], {
          cds: cdsEffective('production', { authKind: 'xsuaa', restrictAllServices: false }),
        }),
      )[0]!;
      expect(finding.severity).toBe('critical');
      expect(finding.title).toBe('Service is open to everyone');
      expect(finding.evidence).toMatchObject({
        restrictAllServices: false,
        authKind: 'xsuaa',
        impact: 'severe',
        easeOfAttack: 'easy',
      });
    });

    it.each(['mocked', 'dummy', 'basic'] as const)(
      'is critical when production authentication is %s',
      (authKind) => {
        const finding = runRule(
          capServiceNoRestriction,
          project([openService()], { cds: cdsEffective('production', { authKind }) }),
        )[0]!;
        expect(finding.severity).toBe('critical');
        expect(finding.title).toBe('Service is open to everyone');
        expect(finding.evidence).toMatchObject({ authKind, restrictAllServices: null });
      },
    );

    it('is critical under mocked authentication even when restrict_all_services is true', () => {
      // The acme-incidents fixture shape: mocked users still log in without a password.
      const finding = runRule(
        capServiceNoRestriction,
        project([openService()], {
          cds: cdsEffective('production', { authKind: 'mocked', restrictAllServices: true }),
        }),
      )[0]!;
      expect(finding.severity).toBe('critical');
      expect(finding.title).toBe('Service is open to everyone');
      expect(finding.evidence).toMatchObject({ authKind: 'mocked', restrictAllServices: true });
    });

    it.each(['jwt', 'xsuaa', 'ias', 'ams', 'other'] as const)(
      'stays high under production authentication %s',
      (authKind) => {
        const finding = runRule(
          capServiceNoRestriction,
          project([openService()], {
            cds: cdsEffective('production', { authKind, restrictAllServices: true }),
          }),
        )[0]!;
        expect(finding.severity).toBe('high');
        expect(finding.title).toBe('Service is open to every authenticated user');
        expect(finding.evidence).toMatchObject({ authKind, restrictAllServices: true });
      },
    );

    it('ignores the development view: mocked auth there does not make it critical', () => {
      const finding = runRule(
        capServiceNoRestriction,
        project([openService()], {
          cds: cdsEffective('development', { authKind: 'mocked', restrictAllServices: false }),
        }),
      )[0]!;
      expect(finding.severity).toBe('high');
      expect(finding.evidence).toMatchObject({ authKind: null, restrictAllServices: null });
    });
  });

  describe('does not fire', () => {
    const none = (files: RawCdsFile[]) =>
      expect(runRule(capServiceNoRestriction, project(files))).toEqual([]);

    it('when the service has @requires', () => {
      none([openService({ requires: ['admin'] })]);
    });

    it('when the service has @restrict', () => {
      none([openService({ restrictTo: ['admin'] })]);
    });

    it('when the service explicitly requires a pseudo-role', () => {
      none([openService({ requires: ['authenticated-user'] })]);
      none([openService({ requires: ['any'] })]);
    });

    it('when an entity has @requires or @restrict', () => {
      none([
        openService({
          entities: [serviceEntity('Books'), serviceEntity('Orders', { requires: ['buyer'] })],
        }),
      ]);
      none([
        openService({
          entities: [serviceEntity('Books'), serviceEntity('Orders', { restrictTo: ['buyer'] })],
        }),
      ]);
    });

    it('when an action has @requires or @restrict', () => {
      none([openService({ actions: [action('submitOrder', { requires: ['buyer'] })] })]);
      none([openService({ actions: [action('submitOrder', { restrictTo: ['buyer'] })] })]);
    });

    it('when an annotate in another file restricts the service, by name, alias or qualified name', () => {
      none([
        openService(),
        cdsFile('srv/auth.cds', {
          annotates: [annotate('CatalogService', { requires: ['admin'] })],
        }),
      ]);
      none([
        openService(),
        cdsFile('srv/auth.cds', {
          usings: [{ alias: 'Catalog', target: 'CatalogService' }],
          annotates: [annotate('Catalog', { restrictTo: ['admin'] })],
        }),
      ]);
      none([
        openService(),
        cdsFile('srv/auth.cds', {
          annotates: [annotate('acme.CatalogService', { requires: ['admin'] })],
        }),
      ]);
    });

    it('when an annotate restricts one of its entities or actions', () => {
      none([
        openService(),
        cdsFile('srv/auth.cds', {
          annotates: [annotate('CatalogService.Books', { restrictTo: ['viewer'] })],
        }),
      ]);
      none([
        openService({ actions: [action('submitOrder')] }),
        cdsFile('srv/auth.cds', {
          annotates: [annotate('CatalogService.submitOrder', { requires: ['buyer'] })],
        }),
      ]);
    });

    it('when the restriction is inherited from the projected db entity through an annotate', () => {
      // CAP propagates a db entity's restriction to the service entities projecting on it.
      const projecting = (projectionOf: string, usings: RawCdsFile['usings'] = []) =>
        cdsFile('srv/catalog.cds', {
          usings,
          services: [
            service('CatalogService', {
              entities: [serviceEntity('Books', { projectionOf })],
            }),
          ],
        });
      none([
        projecting('db.Books'),
        cdsFile('db/schema.cds', { entities: [entity('Books', ['title'])] }),
        cdsFile('db/auth.cds', { annotates: [annotate('db.Books', { restrictTo: ['buyer'] })] }),
      ]);
      none([
        projecting('db.Books', [{ alias: 'db', target: 'acme.db' }]),
        cdsFile('db/auth.cds', {
          annotates: [annotate('acme.db.Books', { requires: ['buyer'] })],
        }),
      ]);
      none([
        projecting('acme.db.Books'),
        cdsFile('db/auth.cds', {
          usings: [{ alias: 'schema', target: 'acme.db' }],
          annotates: [annotate('schema.Books', { restrictTo: ['buyer'] })],
        }),
      ]);
    });

    it('for an internal service (@protocol: none)', () => {
      none([openService({ protocolNone: true })]);
    });

    it('for an imported external service (@cds.external)', () => {
      none([openService({ external: true })]);
    });

    it('for a service declared under srv/external/, wherever that directory sits', () => {
      none([cdsFile('srv/external/Remote.cds', { services: [service('Remote')] })]);
      none([cdsFile('app/srv/external/Remote.cds', { services: [service('Remote')] })]);
    });

    it('when there are no services at all', () => {
      none([]);
      none([cdsFile('db/schema.cds', { entities: [entity('Books', ['title'])] })]);
    });
  });

  it('still fires when a restricting annotate targets a db entity the service does not project on', () => {
    const files = [
      cdsFile('srv/catalog.cds', {
        services: [
          service('CatalogService', {
            entities: [
              serviceEntity('Books', { projectionOf: 'db.Books' }),
              serviceEntity('Notes'),
            ],
          }),
        ],
      }),
      cdsFile('db/auth.cds', {
        annotates: [
          annotate('db.Orders', { restrictTo: ['buyer'] }),
          annotate('db.Books', { personalData: true }),
        ],
      }),
    ];
    expect(subjects(runRule(capServiceNoRestriction, project(files)))).toEqual([
      ['CatalogService', 'high'],
    ]);
  });

  it('does not exempt a service just because its file name mentions external', () => {
    const files = [cdsFile('srv/externalCatalog.cds', { services: [service('Catalog')] })];
    expect(subjects(runRule(capServiceNoRestriction, project(files)))).toEqual([
      ['Catalog', 'medium'],
    ]);
  });

  it('emits one finding per service, sorted by name, across files', () => {
    const files = [
      cdsFile('srv/z.cds', {
        services: [service('Zeta', { line: 9, entities: [serviceEntity('A')] })],
      }),
      cdsFile('srv/a.cds', {
        services: [
          service('Beta', { line: 2, requires: ['admin'] }),
          service('Alpha', { line: 7, entities: [serviceEntity('A', { readonly: true })] }),
        ],
      }),
    ];
    const findings = runRule(capServiceNoRestriction, project(files));
    expect(subjects(findings)).toEqual([
      ['Zeta', 'high'],
      ['Alpha', 'medium'],
    ]);
    expect(findings.map((f) => f.location)).toEqual([
      { file: 'srv/z.cds', line: 9 },
      { file: 'srv/a.cds', line: 7 },
    ]);
  });

  it('emits one finding per subject when the same service name appears twice', () => {
    const files = [
      cdsFile('srv/b.cds', { services: [service('Catalog', { line: 3 })] }),
      cdsFile('srv/a.cds', { services: [service('Catalog', { line: 8 })] }),
    ];
    const findings = runRule(capServiceNoRestriction, project(files));
    expect(findings).toHaveLength(1);
    expect(findings[0]!.location).toEqual({ file: 'srv/a.cds', line: 8 });
  });

  it('reports each project on its own', () => {
    const findings = runRule(
      capServiceNoRestriction,
      project([openService()]),
      rawProject({ id: 'other', cdsFiles: [openService({ requires: ['admin'] })] }),
      rawProject({
        id: 'third',
        cdsFiles: [openService()],
        cds: cdsEffective('production', { restrictAllServices: false }),
      }),
    );
    expect(findings.map((f) => [f.app.name, f.severity])).toEqual([
      ['third', 'critical'],
      ['acme', 'high'],
    ]);
  });

  it('links the CAP authorization and authentication topics and OWASP A01:2025', () => {
    const finding = runRule(capServiceNoRestriction, project([openService()]))[0]!;
    expect(finding.references).toEqual([
      'https://cap.cloud.sap/docs/guides/security/authorization',
      'https://cap.cloud.sap/docs/node.js/authentication',
      owaspUrl('A01:2025'),
    ]);
    expect(finding.remediation).toContain('@requires');
    expect(finding.remediation).toContain('@restrict');
    expect(finding.remediation).toContain('@readonly');
  });

  it('emits the same findings whatever the order of files and services', () => {
    const files = [
      cdsFile('srv/z.cds', {
        services: [service('Zeta', { actions: [action('go')] }), service('Alpha')],
      }),
      cdsFile('srv/a.cds', { services: [service('Beta', { entities: [serviceEntity('X')] })] }),
    ];
    const reversed = files
      .slice()
      .reverse()
      .map((file) => ({ ...file, services: file.services.slice().reverse() }));
    const findings = runRule(capServiceNoRestriction, project(files));
    expect(runRule(capServiceNoRestriction, project(reversed))).toEqual(findings);
    expect(subjects(findings)).toEqual([
      ['Beta', 'high'],
      ['Zeta', 'high'],
      ['Alpha', 'medium'],
    ]);
  });

  it('is deterministic', () => {
    expectDeterministic(
      capServiceNoRestriction,
      project(
        [
          cdsFile('srv/z.cds', { services: [service('Zeta', { actions: [action('go')] })] }),
          cdsFile('srv/a.cds', { services: [service('Alpha'), service('Beta')] }),
        ],
        { cds: cdsEffective('production', { authKind: 'mocked' }) },
      ),
    );
  });

  it('copies nothing from the project but the service name, file and line', () => {
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
        authKind: 'mocked',
        mockedUsers: POISON.length,
        mockedUsersWithPassword: POISON.length,
        restrictAllServices: false,
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
      cdsFiles: [
        // The one service that fires: its members, aliases and projections are poisoned.
        cdsFile('srv/open.cds', {
          usings: POISON.map((value) => ({ alias: value, target: value })),
          services: [
            service('OpenService', {
              line: 2,
              entities: POISON.map((value) =>
                serviceEntity(value, { projectionOf: value, readonly: false }),
              ),
              actions: POISON.map((value) => action(value)),
            }),
          ],
          entities: POISON.map((value) =>
            entity(value, POISON, { associations: [{ field: value, target: value }] }),
          ),
          annotates: POISON.map((value) => annotate(value, { personalData: true })),
        }),
        // Poisoned names everywhere else, on services that must not fire.
        ...POISON.map((value) =>
          cdsFile(value, {
            usings: [{ alias: value, target: value }],
            services: [
              service(value, { requires: [value], restrictTo: [value] }),
              service(`${value}.Internal`, { protocolNone: true }),
              service(`${value}.External`, { external: true }),
            ],
            entities: [entity(value, [value])],
            annotates: [
              annotate(value, { personalData: true }),
              annotate(`${value}.Internal`, { requires: [value], restrictTo: [value] }),
            ],
          }),
        ),
      ],
      seedData: POISON.map((value) =>
        seedCsv(value, {
          sensitiveColumns: [{ column: value, kind: 'secret', rowsMatching: 1 }],
        }),
      ),
      archives: POISON.map((value) => archive(value)),
      html: POISON.map((value) => htmlBootstrap(value, value)),
    });
    const findings = runRule(capServiceNoRestriction, poisoned);
    expect(findings).toHaveLength(1);
    expectNoValueLeak(findings, POISON);
    expect(findings[0]!.evidence).toEqual({
      subject: 'OpenService',
      restrictAllServices: false,
      authKind: 'mocked',
      entities: POISON.length,
      writableEntities: POISON.length,
      actions: POISON.length,
      impact: 'severe',
      easeOfAttack: 'easy',
    });
    expect(findings[0]!.location).toEqual({ file: 'srv/open.cds', line: 2 });
  });
});
