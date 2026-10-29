import type { Finding } from '../../model/finding.js';
import { owaspUrl } from '../../model/owasp.js';
import type { CdsAuthKind, CdsView, RawProject } from '../../model/raw.js';
import { type Analyzer, type AnalyzerContext, ruleHelpUri } from '../types.js';
import { type EffectiveService, effectiveServices } from './cdsModel.js';
import { type MatrixSeverity, projectFinding } from './support.js';

export const RULE_ID = 'CAP_SERVICE_NO_RESTRICTION';

/**
 * Production strategies under which cds does not add the implicit
 * `@requires: 'authenticated-user'`, so an unrestricted service answers
 * anonymous requests as well.
 */
export const OPEN_AUTH_KINDS: readonly CdsAuthKind[] = ['mocked', 'dummy', 'basic'];

/** Imported remote services live here by convention; they are consumed, not served. */
const EXTERNAL_DIR = /(^|\/)srv\/external\//;

const TITLE_AUTHENTICATED = 'Service is open to every authenticated user';
const TITLE_EVERYONE = 'Service is open to everyone';

const REMEDIATION =
  "Restrict the service with `@requires`, for example `service AdminService @(requires: 'admin') { ... }`, " +
  'using a role that xs-security.json defines as a scope and role template, and add `@restrict` rules ' +
  "on entities or actions that need finer control (`@restrict: [{ grant: 'READ', to: 'viewer' }]`). " +
  'Mark data that must never be changed through the service with `@readonly`. A service that is only ' +
  "consumed in-process should declare `@protocol: 'none'`. If the service must stay open to every " +
  "authenticated user, say so explicitly with `@requires: 'authenticated-user'`. When the production " +
  'profile sets `restrict_all_services: false` or a development authentication strategy, remove that ' +
  'as well, since it lets unauthenticated callers in.';

const REFERENCES = [
  'https://cap.cloud.sap/docs/guides/security/authorization',
  'https://cap.cloud.sap/docs/node.js/authentication',
  owaspUrl('A01:2025'),
];

/** The implicit `authenticated-user` requirement is off: unrestricted means anonymous access. */
function isOpenToEveryone(production: CdsView): boolean {
  return (
    production.restrictAllServices === false ||
    (production.authKind !== null && OPEN_AUTH_KINDS.includes(production.authKind))
  );
}

function isUnrestricted(service: EffectiveService): boolean {
  return (
    service.requires.length === 0 &&
    service.restrictTo.length === 0 &&
    !service.protocolNone &&
    !service.external &&
    !EXTERNAL_DIR.test(service.file)
  );
}

function writableEntities(service: EffectiveService): number {
  return service.entities.filter((entity) => !entity.readonly).length;
}

function severityFor(service: EffectiveService, everyone: boolean): MatrixSeverity {
  if (everyone) return { impact: 'severe', easeOfAttack: 'easy' };
  if (writableEntities(service) > 0 || service.actions.length > 0) {
    return { impact: 'significant', easeOfAttack: 'advanced' };
  }
  return { impact: 'moderate', easeOfAttack: 'advanced' };
}

function compareServices(a: EffectiveService, b: EffectiveService): number {
  return a.name.localeCompare(b.name) || a.file.localeCompare(b.file) || a.line - b.line;
}

/** Unrestricted services, one per name (the first declaration in file order), sorted by name. */
function unrestrictedServices(project: RawProject): EffectiveService[] {
  const byName = new Map<string, EffectiveService>();
  for (const service of effectiveServices(project).filter(isUnrestricted).sort(compareServices)) {
    if (!byName.has(service.name)) byName.set(service.name, service);
  }
  return [...byName.values()];
}

function findingFor(
  context: AnalyzerContext,
  project: RawProject,
  service: EffectiveService,
): Finding {
  const production = project.cds.effective.production;
  const everyone = isOpenToEveryone(production);
  return projectFinding(context, project, {
    id: RULE_ID,
    title: everyone ? TITLE_EVERYONE : TITLE_AUTHENTICATED,
    subject: service.name,
    severity: severityFor(service, everyone),
    evidence: {
      restrictAllServices: production.restrictAllServices,
      authKind: production.authKind,
      entities: service.entities.length,
      writableEntities: writableEntities(service),
      actions: service.actions.length,
    },
    location: { file: service.file, line: service.line },
    remediation: REMEDIATION,
    references: [...REFERENCES],
  });
}

/**
 * CAP_SERVICE_NO_RESTRICTION: a served CDS service carries no `@requires` or
 * `@restrict` anywhere (service, entities, actions, annotates). In production
 * cds lets every authenticated user in; with `restrict_all_services: false` or
 * a development authentication strategy it lets everyone in. See docs/rules.md.
 */
export const capServiceNoRestriction: Analyzer = {
  rule: {
    id: RULE_ID,
    title: TITLE_AUTHENTICATED,
    description:
      'A CDS service declares no @requires or @restrict on the service, its entities or its actions. Every authenticated user, or everyone when authentication is mocked, can read and change its data.',
    roles: [],
    owasp: ['A01:2025'],
    helpUri: ruleHelpUri(RULE_ID),
  },
  requires: ['collect.project'],
  analyze(context): Finding[] {
    return context.raw.projects.flatMap((project) =>
      unrestrictedServices(project).map((service) => findingFor(context, project, service)),
    );
  },
};
