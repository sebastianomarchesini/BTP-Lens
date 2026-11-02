import type { Finding } from '../../model/finding.js';
import { owaspUrl } from '../../model/owasp.js';
import type { RawProject, RawXsApp, RawXsAppRoute } from '../../model/raw.js';
import { type Analyzer, type AnalyzerContext, ruleHelpUri } from '../types.js';
import { type MatrixSeverity, projectFinding } from './support.js';

export const RULE_ID = 'APPROUTER_ROUTE_NO_AUTH';

/** Route sources that look like a data or API endpoint rather than static content. */
export const API_SOURCE = /odata|\/api|\/rest|\/srv|\/v\d+|graphql/i;

/*
 * `cds add approuter` generates `^/-/cds/.*` (Node.js MTX) and `^/mt/.*`
 * (Java) with `authenticationType: none`: the multitenancy APIs authenticate
 * the SaaS provisioning service themselves, so these routes are public by design.
 */
export const MTX_SOURCE_PREFIXES: readonly string[] = ['/-/cds/', '/mt/'];

/*
 * No login is needed, so the ease of attack is always `easy`. The impact is
 * `moderate` for an API-like target (the design table named `significant`,
 * which the matrix maps to `critical`; the named severity `high` was kept and
 * the impact lowered because the backend may still check the token itself)
 * and `minor` for other targets, which the matrix maps to `medium`.
 */
const API_SEVERITY: MatrixSeverity = { impact: 'moderate', easeOfAttack: 'easy' };
const OTHER_SEVERITY: MatrixSeverity = { impact: 'minor', easeOfAttack: 'easy' };
const FILE_SEVERITY: MatrixSeverity = { impact: 'moderate', easeOfAttack: 'easy' };

const FILE_TITLE = 'Approuter disables authentication for every route';

const ROUTE_REMEDIATION =
  'Remove `authenticationType: none` from the route, or set it to `xsuaa` (or `ias` when the ' +
  'approuter is bound to Identity Authentication), so the approuter forwards only requests with a ' +
  'valid session and passes the user token to the backend. Keep `none` only for routes that serve ' +
  'public static content from a `localDir` or the UI5 CDN, and for the logout page. If the ' +
  'destination must stay reachable without a login, make sure the backend enforces its own ' +
  'authentication and does not trust the approuter to have done it.';

const FILE_REMEDIATION =
  'Set `authenticationMethod` to `route` in xs-app.json (or remove the property; `route` is the ' +
  'default) so that each route decides with its own `authenticationType`, then mark only the ' +
  'routes that serve public static content with `authenticationType: none`.';

const REFERENCES = [
  'https://help.sap.com/docs/btp/sap-business-technology-platform/routes',
  'https://help.sap.com/docs/btp/sap-business-technology-platform/routing-configuration-file',
  owaspUrl('A07:2025'),
];

function sourcePath(route: RawXsAppRoute): string {
  return route.source.startsWith('^') ? route.source.slice(1) : route.source;
}

function isMtxRoute(route: RawXsAppRoute): boolean {
  const path = sourcePath(route);
  return MTX_SOURCE_PREFIXES.some((prefix) => path.startsWith(prefix));
}

/** A route that hands the request to a destination or service, as opposed to local files. */
function forwardsWithoutAuth(route: RawXsAppRoute): boolean {
  return (
    route.authenticationType === 'none' &&
    (route.target === 'destination' || route.target === 'service')
  );
}

function isExempt(route: RawXsAppRoute): boolean {
  return isMtxRoute(route) || route.targetHint === 'ui5-cdn' || route.isLogoutPage;
}

function isApiLike(route: RawXsAppRoute): boolean {
  return route.targetHint === 'api' || API_SOURCE.test(route.source);
}

interface OpenRoute {
  route: RawXsAppRoute;
  file: string;
  apiLike: boolean;
  /** Unauthenticated routes of the same file that the exemptions silenced. */
  exemptedRoutes: number;
  /** xs-app.json files in which this source forwards without authentication. */
  files: number;
}

function compareFiles(a: RawXsApp, b: RawXsApp): number {
  return a.file.localeCompare(b.file);
}

/** Across files, the API-like occurrence of a source wins, otherwise the earlier file. */
function preferred(current: OpenRoute | undefined, candidate: OpenRoute): OpenRoute {
  if (current === undefined) return candidate;
  const keep = current.apiLike || !candidate.apiLike;
  return { ...(keep ? current : candidate), files: current.files + 1 };
}

/** Open routes of files that authenticate per route, one per source, sorted by source. */
function openRoutes(project: RawProject): OpenRoute[] {
  const bySource = new Map<string, OpenRoute>();
  for (const xsApp of [...project.xsApps].sort(compareFiles)) {
    if (xsApp.authenticationMethod === 'none') continue;
    const candidates = xsApp.routes.filter(forwardsWithoutAuth);
    const exemptedRoutes = candidates.filter(isExempt).length;
    const seen = new Set<string>();
    for (const route of candidates) {
      if (isExempt(route) || seen.has(route.source)) continue;
      seen.add(route.source);
      const open: OpenRoute = {
        route,
        file: xsApp.file,
        apiLike: isApiLike(route),
        exemptedRoutes,
        files: 1,
      };
      bySource.set(route.source, preferred(bySource.get(route.source), open));
    }
  }
  return [...bySource.values()].sort((a, b) => a.route.source.localeCompare(b.route.source));
}

function openFiles(project: RawProject): RawXsApp[] {
  return project.xsApps.filter((xsApp) => xsApp.authenticationMethod === 'none').sort(compareFiles);
}

function routeFinding(context: AnalyzerContext, project: RawProject, open: OpenRoute): Finding {
  return projectFinding(context, project, {
    id: RULE_ID,
    title: approuterRouteNoAuth.rule.title,
    subject: open.route.source,
    severity: open.apiLike ? API_SEVERITY : OTHER_SEVERITY,
    evidence: {
      target: open.route.target,
      targetHint: open.route.targetHint,
      apiLike: open.apiLike,
      exemptedRoutes: open.exemptedRoutes,
      files: open.files,
    },
    location: { file: open.file },
    remediation: ROUTE_REMEDIATION,
    references: [...REFERENCES],
  });
}

function fileFinding(context: AnalyzerContext, project: RawProject, xsApp: RawXsApp): Finding {
  return projectFinding(context, project, {
    id: RULE_ID,
    title: FILE_TITLE,
    subject: xsApp.file,
    severity: FILE_SEVERITY,
    evidence: { authenticationMethod: 'none', routes: xsApp.routes.length },
    location: { file: xsApp.file },
    remediation: FILE_REMEDIATION,
    references: [...REFERENCES],
  });
}

/**
 * APPROUTER_ROUTE_NO_AUTH: an approuter route forwards requests to a
 * destination or service with `authenticationType: none`, or the whole
 * xs-app.json sets `authenticationMethod: none`, so the backend is reachable
 * without a login. See docs/rules.md.
 */
export const approuterRouteNoAuth: Analyzer = {
  rule: {
    id: RULE_ID,
    title: 'Approuter route forwards requests without authentication',
    description:
      'An approuter route to a destination or service has authenticationType none, or the whole xs-app.json disables authentication, so backend endpoints are reachable without a login.',
    roles: [],
    owasp: ['A07:2025'],
    helpUri: ruleHelpUri(RULE_ID),
  },
  requires: ['collect.project'],
  analyze(context): Finding[] {
    return context.raw.projects.flatMap((project) => [
      ...openFiles(project).map((xsApp) => fileFinding(context, project, xsApp)),
      ...openRoutes(project).map((open) => routeFinding(context, project, open)),
    ]);
  },
};
