import type { Finding } from '../../model/finding.js';
import { owaspUrl } from '../../model/owasp.js';
import type { RawProject } from '../../model/raw.js';
import { type Analyzer, type AnalyzerContext, ruleHelpUri } from '../types.js';
import { type PersonalEntity, personalEntities } from './cdsModel.js';
import { type MatrixSeverity, projectFinding } from './support.js';

export const RULE_ID = 'CAP_PERSONAL_DATA_UNANNOTATED';

/** Why the entity counts as personal data; the title and evidence name it. */
export type PersonalDataReason = 'strong-fields' | 'linked-entity' | 'entity-name';

export const TITLE_STRONG_FIELDS = 'Entity holds personal data without @PersonalData annotations';
export const TITLE_LINKED_ENTITY =
  'Entity holds address data of a personal entity without @PersonalData annotations';
export const TITLE_ENTITY_NAME =
  'Entity whose name suggests personal data holds address data without @PersonalData annotations';

const TITLES: Record<PersonalDataReason, string> = {
  'strong-fields': TITLE_STRONG_FIELDS,
  'linked-entity': TITLE_LINKED_ENTITY,
  'entity-name': TITLE_ENTITY_NAME,
};

/*
 * The matrix is fixed: an attacker still needs a foothold to read the data
 * (advanced), and what is lost is the data-privacy handling CAP derives from
 * the annotations (moderate), not the data itself.
 */
const SEVERITY: MatrixSeverity = { impact: 'moderate', easeOfAttack: 'advanced' };

const REFERENCES = [
  'https://cap.cloud.sap/docs/guides/security/dpp-annotations',
  'https://cap.cloud.sap/docs/guides/security/dpp-audit-logging',
  owaspUrl('A04:2025'),
  owaspUrl('A09:2025'),
];

const REMEDIATION =
  'Annotate the entity, preferably in a separate `db/data-privacy.cds` file: ' +
  "`annotate <Entity> with @PersonalData: { EntitySemantics: 'DataSubject', DataSubjectRole: '<Role>' }` " +
  "for the entity that represents the person, or `EntitySemantics: 'DataSubjectDetails'` for an entity " +
  'that belongs to one through an association; mark the key, or the association to the data subject, ' +
  "with `@PersonalData.FieldSemantics: 'DataSubjectID'`, each personal element with " +
  '`@PersonalData.IsPotentiallyPersonal` and sensitive ones (salary, religion, card numbers) with ' +
  '`@PersonalData.IsPotentiallySensitive`. With the `@cap-js/audit-logging` plugin in place (see ' +
  'CAP_AUDITLOG_MISSING), changes of personal and reads of sensitive elements are then logged. The ' +
  'finding is inferred from element and entity names: if the elements are not personal data, rename ' +
  'them so they no longer look like it, or accept the finding.';

function reasonFor(entity: PersonalEntity): PersonalDataReason {
  if (entity.strongFields.length > 0) return 'strong-fields';
  return entity.linkedTo === null ? 'entity-name' : 'linked-entity';
}

/* Name first so one finding per subject survives the deduplication below; then file and line. */
function compareEntities(a: PersonalEntity, b: PersonalEntity): number {
  return a.name.localeCompare(b.name) || a.file.localeCompare(b.file) || a.line - b.line;
}

/** Unannotated personal entities, sorted, one per name. */
function unannotatedEntities(project: RawProject): PersonalEntity[] {
  const seen = new Set<string>();
  const result: PersonalEntity[] = [];
  const candidates = personalEntities(project).filter((entity) => !entity.personalData);
  for (const entity of candidates.sort(compareEntities)) {
    if (seen.has(entity.name)) continue;
    seen.add(entity.name);
    result.push(entity);
  }
  return result;
}

function findingFor(
  context: AnalyzerContext,
  project: RawProject,
  entity: PersonalEntity,
): Finding {
  const reason = reasonFor(entity);
  return projectFinding(context, project, {
    id: RULE_ID,
    title: TITLES[reason],
    subject: entity.name,
    severity: SEVERITY,
    evidence: {
      reason,
      strongFields: entity.strongFields,
      weakFields: entity.weakFields,
      linkedTo: entity.linkedTo,
    },
    location: { file: entity.file, line: entity.line },
    remediation: REMEDIATION,
    references: REFERENCES,
  });
}

/**
 * CAP_PERSONAL_DATA_UNANNOTATED: an entity has fields that identify a person
 * (name, contact details, identifiers), or address fields on an entity that
 * links to a personal entity or is named like one, but no `@PersonalData`
 * annotation inline or through `annotate`, so audit logging, data retention
 * and personal-data management cannot act on it. See docs/rules.md.
 */
export const capPersonalDataUnannotated: Analyzer = {
  rule: {
    id: RULE_ID,
    title: 'Entity holds personal data without @PersonalData annotations',
    description:
      'An entity has fields that look like personal data (names, contact details, identifiers) but no @PersonalData annotation, so CAP cannot log access to it or apply its data-privacy features.',
    roles: [],
    owasp: ['A04:2025', 'A09:2025'],
    helpUri: ruleHelpUri(RULE_ID),
  },
  requires: ['collect.project'],
  analyze(context): Finding[] {
    return context.raw.projects.flatMap((project) =>
      unannotatedEntities(project).map((entity) => findingFor(context, project, entity)),
    );
  },
};
