import type { Finding } from '../../model/finding.js';
import { owaspUrl } from '../../model/owasp.js';
import type { CdsAuditLogKind, RawMta, RawProject } from '../../model/raw.js';
import { type Analyzer, type AnalyzerContext, ruleHelpUri } from '../types.js';
import { projectFinding } from './support.js';

export const RULE_ID = 'CAP_AUDITLOG_NOT_BOUND';

/** The cds plugin whose production kinds need a bound SAP Audit Log service instance. */
export const AUDIT_LOGGING_PLUGIN = '@cap-js/audit-logging';
/** The CF service name of the SAP Audit Log service; the restv2 kind finds its binding by this VCAP label. */
export const AUDIT_LOG_SERVICE = 'auditlog';
/** The binding name the alsng kind (Audit Log Service NG) resolves. */
export const ALSNG_BINDING_NAME = 'auditlog-ng';

/** Resource types that bind an instance created outside the descriptor; the name is all we can go by. */
export const BOUND_RESOURCE_TYPES: readonly string[] = [
  'org.cloudfoundry.existing-service',
  'org.cloudfoundry.user-provided-service',
];
const AUDIT_RESOURCE_NAME = /audit/i;

/*
 * Kinds that write to a service binding. `null` counts because the plugin's
 * own defaults select `audit-log-to-restv2` for production and `cds add
 * audit-logging` writes only the dependency, never a `kind`; console, library
 * and unknown kinds need no binding or cannot be judged.
 */
const SERVICE_BACKED_KINDS: readonly (CdsAuditLogKind | null)[] = [
  null,
  'audit-log-to-restv2',
  'audit-log-to-alsng',
];

const REFERENCES = [
  'https://cap.cloud.sap/docs/guides/security/dpp-audit-logging',
  'https://github.com/cap-js/audit-logging',
  'https://help.sap.com/docs/btp/sap-business-technology-platform/audit-log-write-api-for-customers',
  owaspUrl('A09:2025'),
];

const REMEDIATION =
  'Add an SAP Audit Log service instance to the MTA descriptor and require it from the server ' +
  'module: a resource of type `org.cloudfoundry.managed-service` with `service: auditlog` and ' +
  '`service-plan: premium` (what `cds add audit-logging` generates), or ' +
  '`org.cloudfoundry.existing-service` named after an instance created with ' +
  '`cf create-service auditlog premium <name>`; then list the resource under the module ' +
  '`requires`. The plugin finds the `audit-log-to-restv2` binding by its VCAP label `auditlog`; ' +
  'with Audit Log Service NG (`audit-log-to-alsng`) the binding must be named `auditlog-ng`. ' +
  'Without a binding the audit log service cannot initialise in production and audit entries ' +
  'are not written. Verify with `cds env requires.audit-log --profile production` and `cf services`.';

/** A package in `dependencies` or `devDependencies`: either keeps the plugin loadable. */
function hasDependency(project: RawProject, name: string): boolean {
  const { dependencies, devDependencies } = project.packageJson;
  return [...dependencies, ...devDependencies].some((dependency) => dependency.name === name);
}

function bindsAuditLog(mta: RawMta): boolean {
  const byService = mta.resources.some((resource) => resource.service === AUDIT_LOG_SERVICE);
  const byName = mta.resources.some(
    (resource) =>
      resource.type !== null &&
      BOUND_RESOURCE_TYPES.includes(resource.type) &&
      AUDIT_RESOURCE_NAME.test(resource.name),
  );
  const byAlsng = mta.modules.some((module) => module.requires.includes(ALSNG_BINDING_NAME));
  return byService || byName || byAlsng;
}

function findingFor(context: AnalyzerContext, project: RawProject): Finding | undefined {
  const { mta } = project;
  if (mta === null || !hasDependency(project, AUDIT_LOGGING_PLUGIN)) return undefined;
  const production = project.cds.effective.production;
  if (!SERVICE_BACKED_KINDS.includes(production.auditLogKind)) return undefined;
  if (bindsAuditLog(mta)) return undefined;
  return projectFinding(context, project, {
    id: RULE_ID,
    title: capAuditlogNotBound.rule.title,
    subject: AUDIT_LOG_SERVICE,
    severity: { impact: 'moderate', easeOfAttack: 'advanced' },
    evidence: {
      auditLogKind: production.auditLogKind,
      auditLogConfigured: production.auditLogConfigured,
      modules: mta.modules.length,
      resources: mta.resources.length,
    },
    location: { file: mta.file },
    remediation: REMEDIATION,
    references: REFERENCES,
  });
}

/**
 * CAP_AUDITLOG_NOT_BOUND: the project depends on `@cap-js/audit-logging` and
 * its production kind writes to a service binding, but the MTA descriptor
 * declares no SAP Audit Log service instance, so the deployed app has no
 * binding to write to. See docs/rules.md.
 */
export const capAuditlogNotBound: Analyzer = {
  rule: {
    id: RULE_ID,
    title: 'Audit logging is installed but no audit log service is bound',
    description:
      'The project depends on @cap-js/audit-logging, but the MTA descriptor binds no audit log service, so audit entries go to the console or are dropped in production.',
    roles: [],
    owasp: ['A09:2025'],
    helpUri: ruleHelpUri(RULE_ID),
  },
  requires: ['collect.project'],
  analyze(context): Finding[] {
    return context.raw.projects.flatMap((project) => findingFor(context, project) ?? []);
  },
};
