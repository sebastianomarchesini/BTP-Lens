import type { Finding } from '../../model/finding.js';
import { owaspUrl } from '../../model/owasp.js';
import type { RawProject } from '../../model/raw.js';
import { type Analyzer, type AnalyzerContext, ruleHelpUri } from '../types.js';
import { effectiveEntities, hasPersonalDataDeclared, personalEntities } from './cdsModel.js';
import { type MatrixSeverity, projectFinding } from './support.js';

export const RULE_ID = 'CAP_AUDITLOG_MISSING';

export const CDS_PACKAGE = '@sap/cds';
/** The cds plugin that logs reads and changes of `@PersonalData` entities on its own. */
export const AUDIT_LOGGING_PLUGIN = '@cap-js/audit-logging';
/** The legacy client library: a programmatic API only, nothing is logged automatically. */
export const LEGACY_AUDIT_LOGGING_LIBRARY = '@sap/audit-logging';

/** The configuration key the finding is about, as `cds env requires.audit-log` prints it. */
const SUBJECT = 'requires.audit-log';

/** `cds add audit-logging` records the plugin here, so this is where the fix lands. */
const LOCATION = { file: 'package.json' } as const;

export const TITLE_DECLARED = 'Personal data is modelled but audit logging is not set up';
export const TITLE_INFERRED =
  'Fields that look like personal data are modelled but audit logging is not set up';
export const TITLE_DEV_ONLY =
  'Audit logging plugin is listed under devDependencies only, so it is inactive in production';
export const TITLE_LEGACY =
  'Audit logging uses the legacy client library; personal-data access is not logged automatically';

const REFERENCES = [
  'https://cap.cloud.sap/docs/guides/security/dpp-audit-logging',
  'https://cap.cloud.sap/docs/guides/security/dpp-annotations',
  owaspUrl('A09:2025'),
];

/* Remediation is assembled from steps; each step starts in lower case and ends with a space. */
const STEP_ANNOTATE =
  'annotate the entities that hold personal data with `@PersonalData` (`EntitySemantics` and ' +
  '`DataSubjectRole` on the entity; `FieldSemantics`, `IsPotentiallyPersonal` or ' +
  '`IsPotentiallySensitive` on the elements), then ';
const STEP_ADD_PLUGIN =
  'add the `@cap-js/audit-logging` plugin with `cds add audit-logging`: it configures ' +
  '`cds.requires.audit-log` with console output in development and the SAP Audit Log service ' +
  '(`audit-log-to-restv2`) in production and, when the project has an mta.yaml, adds an ' +
  '`auditlog` resource to it. Create an SAP Audit Log service instance (service `auditlog`, ' +
  'plan `premium`) in the target space and bind it to the app. ';
const STEP_MOVE_PLUGIN =
  'move `@cap-js/audit-logging` from `devDependencies` to `dependencies`: with ' +
  '`NODE_ENV=production` cds loads plugins from `dependencies` only, so the deployed app runs ' +
  'without audit logging. Make sure an SAP Audit Log service instance (service `auditlog`, plan ' +
  '`premium`) is bound to the app. ';
const STEP_REPLACE_LEGACY =
  'replace `@sap/audit-logging` with the `@cap-js/audit-logging` plugin (`cds add audit-logging`): ' +
  'the legacy library offers a programmatic API only, so reads and changes of `@PersonalData` ' +
  'entities are logged only where code calls it, while the plugin logs them generically. Keep ' +
  'the existing `auditlog` service binding. ';
const STEP_VERIFY =
  'The plugin logs only entities annotated with `@PersonalData`, so keep those annotations ' +
  'complete. Verify with `cds env requires.audit-log --profile production`.';

function capitalize(text: string): string {
  return text.charAt(0).toUpperCase() + text.slice(1);
}

/**
 * A package under `dependencies`. `devDependencies` do not count: cds loads
 * plugins from there only while `NODE_ENV` is not `production`, and the
 * production install drops them, so a plugin listed only there never logs
 * anything in the deployed app.
 */
function hasDependency(project: RawProject, name: string): boolean {
  return project.packageJson.dependencies.some((dependency) => dependency.name === name);
}

function hasDevDependency(project: RawProject, name: string): boolean {
  return project.packageJson.devDependencies.some((dependency) => dependency.name === name);
}

interface PersonalDataFacts {
  /** `@PersonalData` appears somewhere in the model, inline or through `annotate`. */
  declared: boolean;
  /** Entities marked `@PersonalData` after merging annotates. */
  declaredEntities: number;
  /** Entities that look personal by their fields or links but carry no `@PersonalData`. */
  inferredEntities: number;
}

function personalDataFacts(project: RawProject): PersonalDataFacts {
  return {
    declared: hasPersonalDataDeclared(project),
    declaredEntities: effectiveEntities(project).filter((entity) => entity.personalData).length,
    inferredEntities: personalEntities(project).filter((entity) => !entity.personalData).length,
  };
}

function hasAuditLogging(project: RawProject): boolean {
  return (
    hasDependency(project, AUDIT_LOGGING_PLUGIN) ||
    project.cds.effective.production.auditLogConfigured
  );
}

interface AuditLogFacts {
  /** `@sap/audit-logging` is a runtime dependency: the project chose audit logging, only the wrong client. */
  legacyLibrary: boolean;
  /** `@cap-js/audit-logging` is listed under `devDependencies` only. */
  pluginInDevDependencies: boolean;
}

function auditLogFacts(project: RawProject): AuditLogFacts {
  return {
    legacyLibrary: hasDependency(project, LEGACY_AUDIT_LOGGING_LIBRARY),
    pluginInDevDependencies: hasDevDependency(project, AUDIT_LOGGING_PLUGIN),
  };
}

interface Branch {
  title: string;
  severity: MatrixSeverity;
  remediation: string;
}

/* The legacy library wins: the project chose audit logging, only the wrong client. */
function branchFor(auditLog: AuditLogFacts, facts: PersonalDataFacts): Branch {
  const annotateFirst = facts.declared ? '' : STEP_ANNOTATE;
  if (auditLog.legacyLibrary) {
    return {
      title: TITLE_LEGACY,
      severity: { impact: 'minor', easeOfAttack: 'complex' },
      remediation: capitalize(annotateFirst + STEP_REPLACE_LEGACY + STEP_VERIFY),
    };
  }
  const severity: MatrixSeverity = facts.declared
    ? { impact: 'significant', easeOfAttack: 'advanced' }
    : { impact: 'moderate', easeOfAttack: 'advanced' };
  if (auditLog.pluginInDevDependencies) {
    return {
      title: TITLE_DEV_ONLY,
      severity,
      remediation: capitalize(annotateFirst + STEP_MOVE_PLUGIN + STEP_VERIFY),
    };
  }
  return {
    title: facts.declared ? TITLE_DECLARED : TITLE_INFERRED,
    severity,
    remediation: capitalize(annotateFirst + STEP_ADD_PLUGIN + STEP_VERIFY),
  };
}

function findingFor(context: AnalyzerContext, project: RawProject): Finding | undefined {
  if (!hasDependency(project, CDS_PACKAGE) || hasAuditLogging(project)) return undefined;
  const facts = personalDataFacts(project);
  if (!facts.declared && facts.inferredEntities === 0) return undefined;
  const auditLog = auditLogFacts(project);
  const branch = branchFor(auditLog, facts);
  return projectFinding(context, project, {
    id: RULE_ID,
    title: branch.title,
    subject: SUBJECT,
    severity: branch.severity,
    evidence: {
      personalDataDeclared: facts.declared,
      declaredEntities: facts.declaredEntities,
      inferredEntities: facts.inferredEntities,
      legacyLibrary: auditLog.legacyLibrary,
      pluginInDevDependencies: auditLog.pluginInDevDependencies,
    },
    location: LOCATION,
    remediation: branch.remediation,
    references: REFERENCES,
  });
}

/**
 * CAP_AUDITLOG_MISSING: the model holds personal data, declared with
 * `@PersonalData` or recognisable from field names, but the project neither
 * depends on `@cap-js/audit-logging` at runtime nor configures
 * `requires.audit-log` for production, so nobody can tell afterwards who read
 * or changed it. See docs/rules.md.
 */
export const capAuditlogMissing: Analyzer = {
  rule: {
    id: RULE_ID,
    title: TITLE_DECLARED,
    description:
      'The CDS model holds personal data, but neither @cap-js/audit-logging nor an audit-log configuration is present, so reads and changes of personal data are not logged.',
    roles: [],
    owasp: ['A09:2025'],
    helpUri: ruleHelpUri(RULE_ID),
  },
  requires: ['collect.project'],
  analyze(context): Finding[] {
    return context.raw.projects.flatMap((project) => findingFor(context, project) ?? []);
  },
};
