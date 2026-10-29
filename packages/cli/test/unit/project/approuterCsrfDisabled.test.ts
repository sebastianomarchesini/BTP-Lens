import { describe, expect, it } from 'vitest';
import {
  RULE_ID,
  approuterCsrfDisabled,
} from '../../../src/analyzers/project/approuterCsrfDisabled.js';
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
const ODATA = '^/odata/(.*)$';

function project(xsApps: RawXsApp[], overrides: Partial<RawProject> = {}): RawProject {
  return rawProject({ xsApps, ...overrides });
}

/** The `cds add app-frontend` shape: an authenticated odata route with the flag switched off. */
function odataRoute(overrides: Partial<RawXsAppRoute> = {}): Partial<RawXsAppRoute> {
  return { source: ODATA, csrfProtection: false, targetHint: 'api', ...overrides };
}

const subjects = (findings: ReturnType<typeof runRule>) =>
  findings.map((f) => [f.evidence.subject, f.severity]);

describe('APPROUTER_CSRF_DISABLED', () => {
  it('declares its rule id', () => {
    expect(RULE_ID).toBe('APPROUTER_CSRF_DISABLED');
    expect(approuterCsrfDisabled.rule.id).toBe(RULE_ID);
    expect(approuterCsrfDisabled.rule.owasp).toEqual(['A01:2025']);
    expect(approuterCsrfDisabled.requires).toEqual(['collect.project']);
  });

  it('fires medium for an authenticated destination route with csrfProtection false', () => {
    const findings = runRule(approuterCsrfDisabled, project([xsApp(FILE, [odataRoute()])]));
    expect(findings).toHaveLength(1);
    const finding = findings[0]!;
    expect(finding.id).toBe(RULE_ID);
    expect(finding.severity).toBe('medium');
    expect(finding.title).toBe('CSRF protection is disabled on an authenticated approuter route');
    expect(finding.app).toEqual({
      guid: 'project:acme',
      name: 'acme',
      space: 'project',
      org: 'local',
    });
    expect(finding.evidence).toEqual({
      subject: ODATA,
      authenticationType: 'xsuaa',
      authenticationMethod: 'route',
      targetHint: 'api',
      routes: 1,
      files: 1,
      impact: 'moderate',
      easeOfAttack: 'advanced',
    });
    expect(finding.location).toEqual({ file: FILE });
    expect(FindingSchema.safeParse(finding).success).toBe(true);
  });

  it('fires whatever the authentication type, as long as it is not none', () => {
    for (const authenticationType of ['xsuaa', 'ias', 'basic', 'other', null] as const) {
      const findings = runRule(
        approuterCsrfDisabled,
        project([xsApp(FILE, [odataRoute({ authenticationType })])]),
      );
      expect(subjects(findings), String(authenticationType)).toEqual([[ODATA, 'medium']]);
      expect(findings[0]!.evidence).toMatchObject({ authenticationType });
    }
  });

  it('fires whatever the file-level authentication method, as long as it is not none', () => {
    // The factory defaults a missing method to `route`, so the null case is set by hand.
    for (const authenticationMethod of ['route', 'other', null] as const) {
      const findings = runRule(
        approuterCsrfDisabled,
        project([{ ...xsApp(FILE, [odataRoute()]), authenticationMethod }]),
      );
      expect(subjects(findings), String(authenticationMethod)).toEqual([[ODATA, 'medium']]);
      expect(findings[0]!.evidence).toMatchObject({ authenticationMethod });
    }
  });

  it('fires whatever the destination looks like, including the logout page', () => {
    for (const targetHint of ['api', 'ui5-cdn', 'html5-repo', 'other'] as const) {
      const findings = runRule(
        approuterCsrfDisabled,
        project([xsApp(FILE, [odataRoute({ targetHint })])]),
      );
      expect(subjects(findings), targetHint).toEqual([[ODATA, 'medium']]);
      expect(findings[0]!.evidence).toMatchObject({ targetHint });
    }
    const logout = runRule(
      approuterCsrfDisabled,
      project([xsApp(FILE, [odataRoute({ source: '^/logout.html$', isLogoutPage: true })])]),
    );
    expect(subjects(logout)).toEqual([['^/logout.html$', 'medium']]);
  });

  it('is always medium: moderate impact, advanced to exploit', () => {
    const [finding] = runRule(approuterCsrfDisabled, project([xsApp(FILE, [odataRoute()])]));
    expect(finding!.severity).toBe('medium');
    expect(finding!.evidence).toMatchObject({ impact: 'moderate', easeOfAttack: 'advanced' });
  });

  describe('does not fire', () => {
    const none = (xsApps: RawXsApp[]) =>
      expect(runRule(approuterCsrfDisabled, project(xsApps))).toEqual([]);

    it('when csrfProtection is not set (the default is true)', () => {
      none([xsApp(FILE, [odataRoute({ csrfProtection: null })])]);
    });

    it('when csrfProtection is explicitly true', () => {
      none([xsApp(FILE, [odataRoute({ csrfProtection: true })])]);
    });

    it('for a route to a service, a local directory or an unknown target', () => {
      none([xsApp(FILE, [odataRoute({ target: 'service', targetHint: 'html5-repo' })])]);
      none([xsApp(FILE, [odataRoute({ target: 'localDir' })])]);
      none([xsApp(FILE, [odataRoute({ target: 'unknown' })])]);
    });

    it('for a public route (authenticationType none): CSRF protection does not apply there', () => {
      none([xsApp(FILE, [odataRoute({ authenticationType: 'none' })])]);
    });

    it('when the whole file disables authentication (authenticationMethod none)', () => {
      none([xsApp(FILE, [odataRoute()], { authenticationMethod: 'none' })]);
      none([
        xsApp(FILE, [odataRoute({ authenticationType: 'xsuaa' })], {
          authenticationMethod: 'none',
        }),
      ]);
    });

    it('when the project has no xs-app.json, or one without routes', () => {
      none([]);
      none([xsApp(FILE, [])]);
    });

    it('for the clean-cap shape: every route protected or public', () => {
      none([
        xsApp(FILE, [
          { source: ODATA, csrfProtection: true, targetHint: 'api' },
          { source: '^/resources/(.*)$', authenticationType: 'none', targetHint: 'ui5-cdn' },
          { source: '^(.*)$', target: 'service', targetHint: 'html5-repo' },
        ]),
      ]);
    });
  });

  it('reports only the affected routes of a file and counts all of its routes', () => {
    const findings = runRule(
      approuterCsrfDisabled,
      project([
        xsApp(FILE, [
          odataRoute(),
          { source: '^/public/(.*)$', authenticationType: 'none', csrfProtection: false },
          { source: '^/resources/(.*)$', authenticationType: 'none', targetHint: 'ui5-cdn' },
          { source: '^/api/(.*)$', csrfProtection: false, targetHint: 'api' },
          { source: '^(.*)$', target: 'service', targetHint: 'html5-repo' },
        ]),
      ]),
    );
    expect(subjects(findings)).toEqual([
      ['^/api/(.*)$', 'medium'],
      [ODATA, 'medium'],
    ]);
    expect(findings.map((f) => f.evidence.routes)).toEqual([5, 5]);
  });

  it('emits one finding per route source, sorted by source, whatever the file order', () => {
    const findings = runRule(
      approuterCsrfDisabled,
      project([
        xsApp('app/b/xs-app.json', [
          odataRoute({ source: '^/zeta/(.*)$' }),
          odataRoute({ source: '^/beta/(.*)$' }),
        ]),
        xsApp('app/a/xs-app.json', [
          odataRoute({ source: '^/alpha/(.*)$' }),
          odataRoute({ csrfProtection: true }),
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
  });

  it('emits one finding per subject when several files disable CSRF on the same source', () => {
    const findings = runRule(
      approuterCsrfDisabled,
      project([
        xsApp('app/b/xs-app.json', [odataRoute(), odataRoute()]),
        xsApp('app/a/xs-app.json', [odataRoute({ authenticationType: 'ias' })]),
      ]),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]!.location).toEqual({ file: 'app/a/xs-app.json' });
    expect(findings[0]!.evidence).toMatchObject({ authenticationType: 'ias', routes: 1, files: 2 });
  });

  it('reports each project on its own', () => {
    const findings = runRule(
      approuterCsrfDisabled,
      project([xsApp(FILE, [odataRoute()])]),
      rawProject({ id: 'other', xsApps: [xsApp(FILE, [odataRoute({ csrfProtection: true })])] }),
      rawProject({ id: 'third', xsApps: [xsApp(FILE, [odataRoute({ source: '^/api/(.*)$' })])] }),
    );
    expect(findings.map((f) => [f.app.name, f.evidence.subject])).toEqual([
      ['acme', ODATA],
      ['third', '^/api/(.*)$'],
    ]);
  });

  it('fires on the xs-app.json that cds add app-frontend writes (cds-dk 10.2.0 template)', () => {
    // Without xsuaa the template omits authenticationType, so the route is still authenticated
    // through the bindings; the catch-all route goes to the app-front service and is exempt.
    const findings = runRule(
      approuterCsrfDisabled,
      project([
        xsApp('app/incidents/public/xs-app.json', [
          {
            source: '^/?odata/(.*)$',
            authenticationType: null,
            csrfProtection: false,
            targetHint: 'api',
          },
          { source: '.*', target: 'service', targetHint: 'other' },
        ]),
      ]),
    );
    expect(subjects(findings)).toEqual([['^/?odata/(.*)$', 'medium']]);
    expect(findings[0]!.evidence).toMatchObject({ authenticationType: null, routes: 2 });
    expect(findings[0]!.location).toEqual({ file: 'app/incidents/public/xs-app.json' });
    expect(FindingSchema.safeParse(findings[0]).success).toBe(true);
  });

  it('does not fire on what cds add approuter, html5-repo and workzone-standard write', () => {
    // All three cds-dk 10.2.0 templates set csrfProtection true on the srv-api route.
    const srvApi: Partial<RawXsAppRoute> = {
      source: '^/?odata/(.*)$',
      csrfProtection: true,
      targetHint: 'api',
    };
    const html5Repo: Partial<RawXsAppRoute> = {
      source: '^(.*)$',
      target: 'service',
      targetHint: 'html5-repo',
    };
    const findings = runRule(
      approuterCsrfDisabled,
      project([
        xsApp('app/router/xs-app.json', [
          { source: '^/-/cds/.*', authenticationType: 'none', targetHint: 'api' },
          srvApi,
          html5Repo,
        ]),
        xsApp('app/catalog/xs-app.json', [srvApi, html5Repo]),
        xsApp('app/approuter/xs-app.json', [
          { source: '^/(.*)$', authenticationType: null, csrfProtection: true, targetHint: 'api' },
        ]),
      ]),
    );
    expect(findings).toEqual([]);
  });

  it('links the SAP Help route topics, the OWASP CSRF cheat sheet and OWASP A01:2025', () => {
    const finding = runRule(approuterCsrfDisabled, project([xsApp(FILE, [odataRoute()])]))[0]!;
    expect(finding.references).toEqual([
      'https://help.sap.com/docs/btp/sap-business-technology-platform/routes',
      'https://help.sap.com/docs/btp/sap-business-technology-platform/application-router-configuration',
      'https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html',
      owaspUrl('A01:2025'),
    ]);
    expect(finding.remediation).toContain('"csrfProtection": false');
    expect(finding.remediation).toContain('x-csrf-token: fetch');
    expect(finding.remediation).toContain('cds add app-frontend');
  });

  it('is deterministic', () => {
    expectDeterministic(
      approuterCsrfDisabled,
      project([
        xsApp('app/b/xs-app.json', [odataRoute({ source: '^/zeta/(.*)$' }), odataRoute()]),
        xsApp('app/a/xs-app.json', [odataRoute(), odataRoute({ source: '^/alpha/(.*)$' })]),
      ]),
    );
  });

  it('copies nothing from the project but the route source and the xs-app.json file', () => {
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
        // The one file that fires: its other routes are poisoned and exempt.
        xsApp(FILE, [
          odataRoute(),
          ...POISON.map((value) => ({ source: value, csrfProtection: true })),
          ...POISON.map((value) => ({
            source: value,
            csrfProtection: false,
            authenticationType: 'none' as const,
          })),
          ...POISON.map((value) => ({
            source: value,
            csrfProtection: false,
            target: 'service' as const,
          })),
          ...POISON.map((value) => ({
            source: value,
            csrfProtection: false,
            target: 'localDir' as const,
            isLogoutPage: true,
          })),
        ]),
        // Poisoned files whose authentication is off, so none of their routes fires.
        ...POISON.map((value) =>
          xsApp(value, [{ source: value, csrfProtection: false }], {
            authenticationMethod: 'none',
          }),
        ),
        // Poisoned files with poisoned sources whose routes are all protected.
        ...POISON.map((value) => xsApp(value, [{ source: value, csrfProtection: null }])),
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
          sensitiveColumns: [{ columnIndex: 1, kind: 'secret', rowsMatching: 1 }],
        }),
      ),
      archives: POISON.map((value) => archive(value)),
      html: POISON.map((value) => htmlBootstrap(value, value)),
    });
    const findings = runRule(approuterCsrfDisabled, poisoned);
    expect(findings).toHaveLength(1);
    expectNoValueLeak(findings, POISON);
    expect(findings[0]!.evidence).toEqual({
      subject: ODATA,
      authenticationType: 'xsuaa',
      authenticationMethod: 'route',
      targetHint: 'api',
      routes: 1 + 4 * POISON.length,
      files: 1,
      impact: 'moderate',
      easeOfAttack: 'advanced',
    });
    expect(findings[0]!.location).toEqual({ file: FILE });
  });
});
