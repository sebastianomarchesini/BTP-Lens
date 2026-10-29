import type { Finding } from '../../model/finding.js';
import { owaspUrl } from '../../model/owasp.js';
import type { RawProject, RawXsSecurity } from '../../model/raw.js';
import { type Analyzer, type AnalyzerContext, ruleHelpUri } from '../types.js';
import { type MatrixSeverity, projectFinding } from './support.js';

export const RULE_ID = 'XSUAA_SCOPE_UNUSED';

/** Local scopes are written `$XSAPPNAME.<name>`; a reference may use either spelling. */
export const XSAPPNAME_PREFIX = '$XSAPPNAME.';

const SEVERITY: MatrixSeverity = { impact: 'minor', easeOfAttack: 'complex' };

const REMEDIATION =
  'Reference the scope from a role template in the security descriptor, for example ' +
  '`"role-templates": [{ "name": "Admin", "scope-references": ["$XSAPPNAME.admin"] }]`, so it can be ' +
  'assigned through a role collection, or remove the scope. If another application is meant to call ' +
  'with it, grant it explicitly with `granted-apps` or `grant-as-authority-to-apps`. In a CAP project, ' +
  'regenerate the descriptor with `cds compile srv --to xsuaa` so scopes and role templates stay in ' +
  'step with the roles used in the CDS model.';

const REFERENCES = [
  'https://help.sap.com/docs/btp/sap-business-technology-platform/application-security-descriptor-configuration-syntax',
  'https://help.sap.com/docs/btp/sap-business-technology-platform/building-roles-and-role-collections-for-applications',
  'https://cap.cloud.sap/docs/guides/security/cap-users',
  owaspUrl('A02:2025'),
];

function localName(scope: string): string {
  return scope.startsWith(XSAPPNAME_PREFIX) ? scope.slice(XSAPPNAME_PREFIX.length) : scope;
}

/*
 * XSUAA merges the inline `config` of the mta.yaml resource with
 * xs-security.json at deployment, so a role template in either descriptor
 * makes the scope assignable; references are collected project-wide.
 */
function referencedScopes(descriptors: readonly RawXsSecurity[]): Set<string> {
  const names = new Set<string>();
  for (const descriptor of descriptors) {
    for (const template of descriptor.roleTemplates) {
      for (const reference of template.scopeReferences) names.add(localName(reference));
    }
  }
  return names;
}

interface UnusedScope {
  name: string;
  descriptor: RawXsSecurity;
}

/*
 * File order, then source. Two xsuaa resources of one mta.yaml share both, so
 * the descriptor with more role templates, then more scopes, comes first:
 * the evidence must not depend on the order the collector listed them in.
 */
function compareDescriptors(a: RawXsSecurity, b: RawXsSecurity): number {
  return (
    a.file.localeCompare(b.file) ||
    a.source.localeCompare(b.source) ||
    b.roleTemplates.length - a.roleTemplates.length ||
    b.scopes.length - a.scopes.length
  );
}

/**
 * Unreferenced scopes, one per local name (`$XSAPPNAME.x` and `x` are the
 * same scope, as they are for references), reported from the first
 * descriptor in file order and sorted by the name as written there.
 */
function unusedScopes(project: RawProject): UnusedScope[] {
  const referenced = referencedScopes(project.xsSecurity);
  const byLocalName = new Map<string, UnusedScope>();
  for (const descriptor of [...project.xsSecurity].sort(compareDescriptors)) {
    for (const scope of descriptor.scopes) {
      const name = localName(scope.name);
      if (scope.grantedToApps || referenced.has(name)) continue;
      if (!byLocalName.has(name)) byLocalName.set(name, { name: scope.name, descriptor });
    }
  }
  return [...byLocalName.values()].sort((a, b) => a.name.localeCompare(b.name));
}

function findingFor(context: AnalyzerContext, project: RawProject, scope: UnusedScope): Finding {
  return projectFinding(context, project, {
    id: RULE_ID,
    title: xsuaaScopeUnused.rule.title,
    subject: scope.name,
    severity: SEVERITY,
    evidence: {
      source: scope.descriptor.source,
      roleTemplates: scope.descriptor.roleTemplates.length,
      descriptors: project.xsSecurity.length,
    },
    location: { file: scope.descriptor.file },
    remediation: REMEDIATION,
    references: [...REFERENCES],
  });
}

/**
 * XSUAA_SCOPE_UNUSED: a scope in the security descriptor that no role
 * template references and that is not granted to another application can
 * never reach a role collection, so it is dead configuration that misstates
 * the authorization model. See docs/rules.md.
 */
export const xsuaaScopeUnused: Analyzer = {
  rule: {
    id: RULE_ID,
    title: 'Scope is defined but no role template references it',
    description:
      'A scope in the XSUAA security descriptor is neither referenced by a role template nor granted to another application, so no role collection can ever carry it; such leftovers hide the real authorization model.',
    roles: [],
    owasp: ['A02:2025'],
    helpUri: ruleHelpUri(RULE_ID),
  },
  requires: ['collect.project'],
  analyze(context): Finding[] {
    return context.raw.projects.flatMap((project) =>
      unusedScopes(project).map((scope) => findingFor(context, project, scope)),
    );
  },
};
