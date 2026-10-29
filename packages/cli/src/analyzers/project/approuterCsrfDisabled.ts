import type { Finding } from '../../model/finding.js';
import { owaspUrl } from '../../model/owasp.js';
import type { RawProject, RawXsApp, RawXsAppRoute } from '../../model/raw.js';
import { type Analyzer, type AnalyzerContext, ruleHelpUri } from '../types.js';
import { type MatrixSeverity, projectFinding } from './support.js';

export const RULE_ID = 'APPROUTER_CSRF_DISABLED';

const SEVERITY: MatrixSeverity = { impact: 'moderate', easeOfAttack: 'advanced' };

const REMEDIATION =
  'Remove `"csrfProtection": false` from the route in xs-app.json (the default is `true`), so the ' +
  'application router answers 403 to every request other than GET and HEAD (PUT, POST, PATCH, ' +
  'DELETE, ...) that carries no valid `x-csrf-token` header. Clients obtain the token with a GET or ' +
  'HEAD request that sends `x-csrf-token: fetch`; the SAPUI5 OData models and the CAP Fiori preview ' +
  'do this on their own. If the route only ever serves GET and HEAD, CSRF protection costs nothing, ' +
  'so there is no reason to switch it off. If `cds add app-frontend` generated the route, set the ' +
  'flag back to `true` after generating and let the frontend fetch the token.';

const REFERENCES = [
  'https://help.sap.com/docs/btp/sap-business-technology-platform/routes',
  'https://help.sap.com/docs/btp/sap-business-technology-platform/application-router-configuration',
  'https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html',
  owaspUrl('A01:2025'),
];

/*
 * The application router applies CSRF protection only to routes that require
 * a login: a route with `authenticationType: none`, or any route in a file
 * with `authenticationMethod: none`, is public and the flag changes nothing
 * there. A missing `authenticationType` means the router picks xsuaa or ias
 * from its bindings, so the route is still authenticated.
 */
function isAuthenticated(xsApp: RawXsApp, route: RawXsAppRoute): boolean {
  return xsApp.authenticationMethod !== 'none' && route.authenticationType !== 'none';
}

function isCsrfDisabled(xsApp: RawXsApp, route: RawXsAppRoute): boolean {
  return (
    route.csrfProtection === false &&
    route.target === 'destination' &&
    isAuthenticated(xsApp, route)
  );
}

interface CsrfDisabledRoute {
  source: string;
  xsApp: RawXsApp;
  route: RawXsAppRoute;
  /** How many xs-app.json files disable CSRF protection on a route with this source. */
  files: number;
}

function compareFiles(a: RawXsApp, b: RawXsApp): number {
  return a.file.localeCompare(b.file);
}

/** Affected routes, one per source (the first file in name order), sorted by source. */
function csrfDisabledRoutes(project: RawProject): CsrfDisabledRoute[] {
  const bySource = new Map<string, CsrfDisabledRoute>();
  for (const xsApp of [...project.xsApps].sort(compareFiles)) {
    const seenInFile = new Set<string>();
    for (const route of xsApp.routes) {
      if (!isCsrfDisabled(xsApp, route) || seenInFile.has(route.source)) continue;
      seenInFile.add(route.source);
      const known = bySource.get(route.source);
      if (known === undefined) {
        bySource.set(route.source, { source: route.source, xsApp, route, files: 1 });
      } else {
        known.files += 1;
      }
    }
  }
  return [...bySource.values()].sort((a, b) => a.source.localeCompare(b.source));
}

function findingFor(
  context: AnalyzerContext,
  project: RawProject,
  affected: CsrfDisabledRoute,
): Finding {
  return projectFinding(context, project, {
    id: RULE_ID,
    title: approuterCsrfDisabled.rule.title,
    subject: affected.source,
    severity: SEVERITY,
    evidence: {
      authenticationType: affected.route.authenticationType,
      authenticationMethod: affected.xsApp.authenticationMethod,
      targetHint: affected.route.targetHint,
      routes: affected.xsApp.routes.length,
      files: affected.files,
    },
    location: { file: affected.xsApp.file },
    remediation: REMEDIATION,
    references: [...REFERENCES],
  });
}

/**
 * APPROUTER_CSRF_DISABLED: an xs-app.json route to a destination turns the
 * application router's CSRF check off while the route still requires a
 * login, so a page on another site can make the browser send state-changing
 * requests with the user's session cookie. See docs/rules.md.
 */
export const approuterCsrfDisabled: Analyzer = {
  rule: {
    id: RULE_ID,
    title: 'CSRF protection is disabled on an authenticated approuter route',
    description:
      "A route to a destination sets csrfProtection to false while still requiring a login, so a malicious page can make the browser send state-changing requests with the user's session.",
    roles: [],
    owasp: ['A01:2025'],
    helpUri: ruleHelpUri(RULE_ID),
  },
  requires: ['collect.project'],
  analyze(context): Finding[] {
    return context.raw.projects.flatMap((project) =>
      csrfDisabledRoutes(project).map((affected) => findingFor(context, project, affected)),
    );
  },
};
