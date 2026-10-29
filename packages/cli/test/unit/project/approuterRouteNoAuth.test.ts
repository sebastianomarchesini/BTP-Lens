import { describe, expect, it } from 'vitest';
import {
  API_SOURCE,
  MTX_SOURCE_PREFIXES,
  RULE_ID,
  approuterRouteNoAuth,
} from '../../../src/analyzers/project/approuterRouteNoAuth.js';
import { FindingSchema } from '../../../src/model/finding.js';
import { owaspUrl } from '../../../src/model/owasp.js';
import type { RawProject, RawXsApp, RawXsAppRoute } from '../../../src/model/raw.js';
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

const FILE = 'app/incidents/xs-app.json';

function project(xsApps: RawXsApp[], overrides: Partial<RawProject> = {}): RawProject {
  return rawProject({ xsApps, ...overrides });
}

/** One xs-app.json with the given routes, authenticating per route. */
function routes(list: Partial<RawXsAppRoute>[], file = FILE): RawProject {
  return project([xsApp(file, list)]);
}

const open = (source: string, extra: Partial<RawXsAppRoute> = {}): Partial<RawXsAppRoute> => ({
  source,
  authenticationType: 'none',
  target: 'destination',
  ...extra,
});

const subjects = (findings: ReturnType<typeof runRule>) =>
  findings.map((f) => [f.evidence.subject, f.severity]);

describe('APPROUTER_ROUTE_NO_AUTH', () => {
  it('declares the API source pattern and the MTX prefixes', () => {
    expect(RULE_ID).toBe('APPROUTER_ROUTE_NO_AUTH');
    expect(MTX_SOURCE_PREFIXES).toEqual(['/-/cds/', '/mt/']);
    expect(API_SOURCE.test('^/odata/v4/catalog/(.*)$')).toBe(true);
    expect(API_SOURCE.test('^/public/(.*)$')).toBe(false);
  });

  it('fires medium for an unauthenticated route to a destination that is not API-like', () => {
    const findings = runRule(approuterRouteNoAuth, routes([open('^/public/(.*)$')]));
    expect(findings).toHaveLength(1);
    const finding = findings[0]!;
    expect(finding.id).toBe(RULE_ID);
    expect(finding.severity).toBe('medium');
    expect(finding.title).toBe('Approuter route forwards requests without authentication');
    expect(finding.app).toEqual({
      guid: 'project:acme',
      name: 'acme',
      space: 'project',
      org: 'local',
    });
    expect(finding.evidence).toEqual({
      subject: '^/public/(.*)$',
      target: 'destination',
      targetHint: 'other',
      apiLike: false,
      exemptedRoutes: 0,
      files: 1,
      impact: 'minor',
      easeOfAttack: 'easy',
    });
    expect(finding.location).toEqual({ file: FILE });
    expect(FindingSchema.safeParse(finding).success).toBe(true);
  });

  it('fires high when the destination name hints at an API', () => {
    const findings = runRule(
      approuterRouteNoAuth,
      routes([open('^/public/(.*)$', { targetHint: 'api' })]),
    );
    expect(subjects(findings)).toEqual([['^/public/(.*)$', 'high']]);
    expect(findings[0]!.evidence).toMatchObject({
      targetHint: 'api',
      apiLike: true,
      impact: 'moderate',
      easeOfAttack: 'easy',
    });
  });

  it.each([
    '^/odata/(.*)$',
    '^/api/(.*)$',
    '^/rest/(.*)$',
    '^/srv/(.*)$',
    '^/v2/(.*)$',
    '^/graphql$',
    '^/backend/ODATA/(.*)$',
  ])('fires high when the source %s looks like an API endpoint', (source) => {
    const findings = runRule(approuterRouteNoAuth, routes([open(source)]));
    expect(subjects(findings)).toEqual([[source, 'high']]);
    expect(findings[0]!.evidence).toMatchObject({ apiLike: true, targetHint: 'other' });
  });

  it('fires for an unauthenticated route to a service', () => {
    const findings = runRule(
      approuterRouteNoAuth,
      routes([open('^/(.*)$', { target: 'service', targetHint: 'html5-repo' })]),
    );
    expect(subjects(findings)).toEqual([['^/(.*)$', 'medium']]);
    expect(findings[0]!.evidence).toMatchObject({ target: 'service', targetHint: 'html5-repo' });
  });

  it('fires once per file, high, when authenticationMethod is none', () => {
    const findings = runRule(
      approuterRouteNoAuth,
      project([
        xsApp(FILE, [{ source: '^/odata/(.*)$' }, { source: '^/(.*)$', target: 'localDir' }], {
          authenticationMethod: 'none',
        }),
      ]),
    );
    expect(findings).toHaveLength(1);
    const finding = findings[0]!;
    expect(finding.severity).toBe('high');
    expect(finding.title).toBe('Approuter disables authentication for every route');
    expect(finding.evidence).toEqual({
      subject: FILE,
      authenticationMethod: 'none',
      routes: 2,
      impact: 'moderate',
      easeOfAttack: 'easy',
    });
    expect(finding.location).toEqual({ file: FILE });
    expect(finding.remediation).toContain('authenticationMethod');
    expect(FindingSchema.safeParse(finding).success).toBe(true);
  });

  it('does not repeat the routes of a file that disables authentication as a whole', () => {
    const findings = runRule(
      approuterRouteNoAuth,
      project([xsApp(FILE, [open('^/odata/(.*)$')], { authenticationMethod: 'none' })]),
    );
    expect(subjects(findings)).toEqual([[FILE, 'high']]);
  });

  describe('does not fire', () => {
    const none = (list: Partial<RawXsAppRoute>[]) =>
      expect(runRule(approuterRouteNoAuth, routes(list))).toEqual([]);

    it.each(['xsuaa', 'ias', 'basic', 'other', null] as const)(
      'for a route with authenticationType %s',
      (authenticationType) => {
        none([{ source: '^/odata/(.*)$', authenticationType, targetHint: 'api' }]);
      },
    );

    it('for an unauthenticated route to a localDir or an unknown target', () => {
      none([open('^/(.*)$', { target: 'localDir' })]);
      none([open('^/odata/(.*)$', { target: 'unknown', targetHint: 'api' })]);
    });

    it('for the MTX routes cds add approuter generates', () => {
      none([open('^/-/cds/.*', { targetHint: 'api' })]);
      none([open('^/mt/.*', { targetHint: 'api' })]);
      none([open('/-/cds/saas-provisioning/(.*)')]);
      none([open('/mt/(.*)')]);
    });

    it('for a route to the UI5 CDN', () => {
      none([open('^/resources/(.*)$', { targetHint: 'ui5-cdn' })]);
      none([open('^/odata/(.*)$', { targetHint: 'ui5-cdn' })]);
    });

    it('for the logout page', () => {
      none([open('^/logout.html$', { isLogoutPage: true })]);
      none([open('^/odata/logout$', { isLogoutPage: true, targetHint: 'api' })]);
    });

    it('for a file that authenticates per route, or says nothing, with only authenticated routes', () => {
      for (const authenticationMethod of ['route', 'other', null] as const) {
        expect(
          runRule(
            approuterRouteNoAuth,
            project([xsApp(FILE, [{ source: '^/odata/(.*)$' }], { authenticationMethod })]),
          ),
        ).toEqual([]);
      }
    });

    it('when the project has no xs-app.json or no routes', () => {
      expect(runRule(approuterRouteNoAuth, project([]))).toEqual([]);
      expect(runRule(approuterRouteNoAuth, project([xsApp(FILE, [])]))).toEqual([]);
    });

    it('for a source that only resembles an MTX route further in', () => {
      expect(subjects(runRule(approuterRouteNoAuth, routes([open('^/app/-/cds/(.*)$')])))).toEqual([
        ['^/app/-/cds/(.*)$', 'medium'],
      ]);
    });
  });

  it('counts the exempted routes of the file in the evidence', () => {
    const findings = runRule(
      approuterRouteNoAuth,
      routes([
        open('^/public/(.*)$'),
        open('^/-/cds/.*', { targetHint: 'api' }),
        open('^/resources/(.*)$', { targetHint: 'ui5-cdn' }),
        open('^/logout.html$', { isLogoutPage: true }),
        open('^/static/(.*)$', { target: 'localDir' }),
        { source: '^/odata/(.*)$', authenticationType: 'xsuaa' },
      ]),
    );
    expect(subjects(findings)).toEqual([['^/public/(.*)$', 'medium']]);
    expect(findings[0]!.evidence).toMatchObject({ exemptedRoutes: 3 });
  });

  it('emits one finding per source, sorted, whatever the route and file order', () => {
    const findings = runRule(
      approuterRouteNoAuth,
      project([
        xsApp('app/b/xs-app.json', [open('^/zeta/(.*)$'), open('^/beta/(.*)$')]),
        xsApp('app/a/xs-app.json', [
          open('^/alpha/(.*)$'),
          open('^/alpha/(.*)$', { targetHint: 'api' }),
        ]),
      ]),
    );
    expect(subjects(findings)).toEqual([
      ['^/alpha/(.*)$', 'medium'],
      ['^/beta/(.*)$', 'medium'],
      ['^/zeta/(.*)$', 'medium'],
    ]);
    expect(findings.map((f) => f.location?.file)).toEqual([
      'app/a/xs-app.json',
      'app/b/xs-app.json',
      'app/b/xs-app.json',
    ]);
    expect(findings.map((f) => f.evidence.files)).toEqual([1, 1, 1]);
  });

  it('emits one finding per source across files, keeping the API-like occurrence', () => {
    const findings = runRule(
      approuterRouteNoAuth,
      project([
        xsApp('app/a/xs-app.json', [open('^/public/(.*)$')]),
        xsApp('app/b/xs-app.json', [open('^/public/(.*)$', { targetHint: 'api' })]),
        xsApp('app/c/xs-app.json', [open('^/public/(.*)$')]),
      ]),
    );
    expect(subjects(findings)).toEqual([['^/public/(.*)$', 'high']]);
    expect(findings[0]!.location).toEqual({ file: 'app/b/xs-app.json' });
    expect(findings[0]!.evidence).toMatchObject({ files: 3, targetHint: 'api' });
  });

  it('lists file findings before route findings, each sorted by subject', () => {
    const findings = runRule(
      approuterRouteNoAuth,
      project([
        xsApp('app/z/xs-app.json', [{ source: '^/(.*)$' }], { authenticationMethod: 'none' }),
        xsApp('app/m/xs-app.json', [open('^/public/(.*)$')]),
        xsApp('app/a/xs-app.json', [{ source: '^/(.*)$' }], { authenticationMethod: 'none' }),
      ]),
    );
    expect(findings.map((f) => f.evidence.subject)).toEqual([
      'app/a/xs-app.json',
      'app/z/xs-app.json',
      '^/public/(.*)$',
    ]);
  });

  it('reports each project on its own', () => {
    const findings = runRule(
      approuterRouteNoAuth,
      routes([open('^/public/(.*)$')]),
      rawProject({ id: 'other', xsApps: [xsApp(FILE, [{ source: '^/odata/(.*)$' }])] }),
      rawProject({ id: 'third', xsApps: [xsApp(FILE, [open('^/odata/(.*)$')])] }),
    );
    expect(findings.map((f) => [f.app.name, f.evidence.subject, f.severity])).toEqual([
      ['third', '^/odata/(.*)$', 'high'],
      ['acme', '^/public/(.*)$', 'medium'],
    ]);
  });

  it('links the SAP Help approuter topics and OWASP A07:2025', () => {
    const finding = runRule(approuterRouteNoAuth, routes([open('^/public/(.*)$')]))[0]!;
    expect(finding.references).toEqual([
      'https://help.sap.com/docs/btp/sap-business-technology-platform/routes',
      'https://help.sap.com/docs/btp/sap-business-technology-platform/routing-configuration-file',
      owaspUrl('A07:2025'),
    ]);
    expect(finding.remediation).toContain('authenticationType: none');
    expect(finding.remediation).toContain('xsuaa');
  });

  it('is deterministic', () => {
    expectDeterministic(
      approuterRouteNoAuth,
      project([
        xsApp('app/b/xs-app.json', [open('^/zeta/(.*)$'), open('^/odata/(.*)$')]),
        xsApp('app/a/xs-app.json', [open('^/zeta/(.*)$', { targetHint: 'api' })]),
        xsApp('app/c/xs-app.json', [{ source: '^/(.*)$' }], { authenticationMethod: 'none' }),
      ]),
    );
  });

  it('copies nothing from the project but the route source and the file name', () => {
    const poisoned = rawProject({
      sourcesRead: ['.cdsrc.json', 'package.json'],
      files: POISON,
      unreadable: POISON.map((file) => ({ file, kind: 'json' as const })),
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
      xsApps: [
        // The one file that fires: every other route carries a poison source but is exempt.
        xsApp(FILE, [
          open('^/public/(.*)$'),
          ...POISON.map((value) => ({ source: value, authenticationType: 'xsuaa' as const })),
          ...POISON.map((value) => open(value, { target: 'localDir' as const })),
          ...POISON.map((value) => open(value, { targetHint: 'ui5-cdn' as const })),
          ...POISON.map((value) => open(value, { isLogoutPage: true })),
          ...POISON.map((value) => open(`^/-/cds/${value}`, { targetHint: 'api' as const })),
        ]),
        // Poisoned file names with nothing to report.
        ...POISON.map((value) => xsApp(value, [{ source: value, authenticationType: 'ias' }])),
      ],
      cdsFiles: POISON.map((value) =>
        cdsFile(value, {
          usings: [{ alias: value, target: value }],
          services: [
            service(value, {
              requires: [value],
              restrictTo: [value],
              entities: [serviceEntity(value, { projectionOf: value })],
              actions: [action(value)],
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
    const findings = runRule(approuterRouteNoAuth, poisoned);
    expect(findings).toHaveLength(1);
    expectNoValueLeak(findings, POISON);
    expect(findings[0]!.evidence).toEqual({
      subject: '^/public/(.*)$',
      target: 'destination',
      targetHint: 'other',
      apiLike: false,
      exemptedRoutes: POISON.length * 3,
      files: 1,
      impact: 'minor',
      easeOfAttack: 'easy',
    });
    expect(findings[0]!.location).toEqual({ file: FILE });
  });
});
