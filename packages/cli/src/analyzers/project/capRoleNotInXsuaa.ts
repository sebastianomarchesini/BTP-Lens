import type { Finding, FindingLocation } from '../../model/finding.js';
import { owaspUrl } from '../../model/owasp.js';
import type { RawProject, RawXsSecurity } from '../../model/raw.js';
import { type Analyzer, type AnalyzerContext, ruleHelpUri } from '../types.js';
import { referencedRoles } from './cdsModel.js';
import { type MatrixSeverity, projectFinding } from './support.js';

export const RULE_ID = 'CAP_ROLE_NOT_IN_XSUAA';

/** With AMS, roles come from policies, not from XSUAA scopes: the descriptor says nothing. */
export const AMS_PACKAGE = '@sap/ams';

/** Local scopes in an XSUAA descriptor carry this prefix; `cds compile --to xsuaa` writes it. */
export const XSAPPNAME_PREFIX = '$XSAPPNAME.';

/** A missing scope locks a role out, or hides a typo; the attacker still needs an account. */
export const SEVERITY: MatrixSeverity = { impact: 'moderate', easeOfAttack: 'advanced' };

const TITLE = 'Role referenced in the CDS model has no scope in the XSUAA descriptor';

const REMEDIATION =
  'Add a scope `$XSAPPNAME.<role>` and a role template `<role>` with that scope in its ' +
  '`scope-references` to xs-security.json (or regenerate the file from the model with ' +
  '`cds compile srv --to xsuaa > xs-security.json`), update the xsuaa service instance ' +
  'and assign the role through a role collection. If the name in `@requires` or ' +
  '`@restrict` is a typo, fix the annotation so that it matches an existing scope. When ' +
  'roles are meant to come from Authorization Management Service policies, add `@sap/ams` ' +
  'and configure `cds.requires.auth: ams` for production.';

const REFERENCES = [
  'https://cap.cloud.sap/docs/guides/security/cap-users#xsuaa-roles',
  'https://cap.cloud.sap/docs/guides/security/authorization',
  'https://help.sap.com/docs/btp/sap-business-technology-platform/application-security-descriptor-configuration-syntax',
  owaspUrl('A01:2025'),
  owaspUrl('A07:2025'),
];

/** A package in `dependencies` or `devDependencies`: either keeps the plugin loadable. */
function hasDependency(project: RawProject, name: string): boolean {
  const { dependencies, devDependencies } = project.packageJson;
  return [...dependencies, ...devDependencies].some((dependency) => dependency.name === name);
}

function usesAms(project: RawProject): boolean {
  return hasDependency(project, AMS_PACKAGE) || project.cds.effective.production.authKind === 'ams';
}

/**
 * A descriptor with neither scopes nor role templates says nothing about
 * roles: `cds add xsuaa` writes `config: { xsappname, tenant-mode }` into
 * mta.yaml next to `path: ./xs-security.json`, and when that file is
 * generated at build time or ignored, the inline block is all the collector
 * sees. Comparing against it would report every role.
 */
function declaresAuthorization(descriptor: RawXsSecurity): boolean {
  return descriptor.scopes.length > 0 || descriptor.roleTemplates.length > 0;
}

/** Every scope name in every descriptor, from xs-security.json files and mta.yaml xsuaa resources. */
function definedScopes(project: RawProject): Set<string> {
  return new Set(project.xsSecurity.flatMap((descriptor) => descriptor.scopes.map((s) => s.name)));
}

function hasScope(scopes: Set<string>, role: string): boolean {
  return scopes.has(role) || scopes.has(`${XSAPPNAME_PREFIX}${role}`);
}

/** Code-point order, like the collector's file lists, so the evidence is the same in every locale. */
function sortedUnique(values: string[]): string[] {
  return [...new Set(values)].sort();
}

/**
 * Where the role is first named: the first file in the collector's order
 * (code-point sorted paths), then the lowest line among the service, its
 * entities, its actions and the annotate statements. The place to fix a typo.
 */
function firstReference(project: RawProject, role: string): FindingLocation | undefined {
  const names = (holder: { requires: string[]; restrictTo: string[] }): boolean =>
    holder.requires.includes(role) || holder.restrictTo.includes(role);
  for (const file of project.cdsFiles) {
    const holders = [
      ...file.services.flatMap((service) => [service, ...service.entities, ...service.actions]),
      ...file.annotates,
    ];
    const lines = holders.filter(names).map((holder) => holder.line);
    if (lines.length > 0) return { file: file.file, line: Math.min(...lines) };
  }
  return undefined;
}

/** Referenced roles without a scope, sorted; none when there is no descriptor to check against. */
function missingRoles(project: RawProject): string[] {
  if (!project.xsSecurity.some(declaresAuthorization) || usesAms(project)) return [];
  const scopes = definedScopes(project);
  return referencedRoles(project).filter((role) => !hasScope(scopes, role));
}

function findingFor(context: AnalyzerContext, project: RawProject, role: string): Finding {
  const location = firstReference(project, role);
  return projectFinding(context, project, {
    id: RULE_ID,
    title: TITLE,
    subject: role,
    severity: SEVERITY,
    evidence: {
      role,
      descriptors: sortedUnique(project.xsSecurity.map((descriptor) => descriptor.file)),
      scopesChecked: definedScopes(project).size,
    },
    ...(location ? { location } : {}),
    remediation: REMEDIATION,
    references: [...REFERENCES],
  });
}

/**
 * CAP_ROLE_NOT_IN_XSUAA: a role named in `@requires` or `@restrict.to` has no
 * scope `$XSAPPNAME.<role>` (or `<role>`) in any XSUAA descriptor of the
 * project, so nobody can ever hold it: the restriction either locks every
 * user out or, when the name is a typo, is not the one that applies. Skipped
 * when no descriptor declares scopes or role templates, or the project takes
 * its roles from AMS policies.
 * See docs/rules.md.
 */
export const capRoleNotInXsuaa: Analyzer = {
  rule: {
    id: RULE_ID,
    title: TITLE,
    description:
      'A role named in @requires or @restrict has no matching scope in the XSUAA security descriptor, so nobody can be granted it: the restriction either locks everyone out or is bypassed by a misspelt role elsewhere.',
    roles: [],
    owasp: ['A01:2025', 'A07:2025'],
    helpUri: ruleHelpUri(RULE_ID),
  },
  requires: ['collect.project'],
  analyze(context): Finding[] {
    return context.raw.projects.flatMap((project) =>
      missingRoles(project).map((role) => findingFor(context, project, role)),
    );
  },
};
