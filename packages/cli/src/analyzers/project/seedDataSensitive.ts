import type { Finding } from '../../model/finding.js';
import { owaspUrl } from '../../model/owasp.js';
import type { RawProject, RawSeedSensitiveColumn, SeedSensitiveKind } from '../../model/raw.js';
import { type Analyzer, type AnalyzerContext, ruleHelpUri } from '../types.js';
import { type MatrixSeverity, projectFinding } from './support.js';

export const RULE_ID = 'SEED_DATA_SENSITIVE';

/**
 * The subject is `<file>#<columnIndex>` (1-based): the collector keeps the
 * position of a sensitive column, never its name, since a header-less file
 * could put a cell value where the name is expected.
 */
export const SUBJECT_SEPARATOR = '#';

const SEVERITY: MatrixSeverity = { impact: 'significant', easeOfAttack: 'advanced' };

const TITLES: Record<SeedSensitiveKind, string> = {
  card: 'contains payment card numbers',
  iban: 'contains IBANs',
  secret: 'contains secret-looking values',
};

function titleOf(column: RawSeedSensitiveColumn): string {
  return `Seed data column ${column.columnIndex} ${TITLES[column.kind]}`;
}

const REMEDIATION =
  'Remove the real values from the CSV file: replace card numbers and IBANs with clearly synthetic, ' +
  'masked values that fail the format checks (for example `****-****-****-1111`), leave secret ' +
  'columns empty, or drop the column from the seed file altogether. Secrets belong in a service ' +
  'binding or a credential store, never in seed data. Keep `db/data` for configuration data and ' +
  'code lists that must reach production; test data belongs in `test/data`, which CAP loads in ' +
  'development only. If the values are real, treat them as exposed: rotate the secrets and remove ' +
  'the file from the repository history as well, since deleting it in a new commit leaves it in ' +
  'every clone.';

const REFERENCES = [
  'https://cap.cloud.sap/docs/guides/databases/initial-data',
  'https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html',
  owaspUrl('A04:2025'),
];

interface SensitiveSeed {
  subject: string;
  file: string;
  column: RawSeedSensitiveColumn;
  rowsChecked: number;
}

/** Code-point order, so the result does not depend on the process locale. */
function compareText(a: string, b: string): number {
  if (a === b) return 0;
  return a < b ? -1 : 1;
}

export function seedSubject(file: string, columnIndex: number): string {
  return `${file}${SUBJECT_SEPARATOR}${columnIndex}`;
}

/*
 * Which of two entries for one subject to report: the worst case first (more
 * matching rows, then more rows checked), then the kind in code-point order.
 * The order is total, so a snapshot that lists one subject twice yields the
 * same finding whatever the order of its entries.
 */
function outranks(candidate: SensitiveSeed, known: SensitiveSeed): boolean {
  return (
    (candidate.column.rowsMatching - known.column.rowsMatching ||
      candidate.rowsChecked - known.rowsChecked ||
      compareText(known.column.kind, candidate.column.kind)) > 0
  );
}

/*
 * One entry per (file, column position) with at least one matching value. A
 * snapshot that lists one subject twice (e.g. edited by hand) yields two
 * entries; the one that `outranks` the other is kept, so the evidence states
 * the worst case.
 */
function sensitiveSeeds(project: RawProject): SensitiveSeed[] {
  const bySubject = new Map<string, SensitiveSeed>();
  for (const seed of project.seedData) {
    for (const column of seed.sensitiveColumns) {
      if (column.rowsMatching === 0) continue;
      const subject = seedSubject(seed.file, column.columnIndex);
      const candidate = { subject, file: seed.file, column, rowsChecked: seed.rowsChecked };
      const known = bySubject.get(subject);
      if (known === undefined || outranks(candidate, known)) bySubject.set(subject, candidate);
    }
  }
  return [...bySubject.values()].sort(
    (a, b) => compareText(a.file, b.file) || a.column.columnIndex - b.column.columnIndex,
  );
}

function findingFor(context: AnalyzerContext, project: RawProject, seed: SensitiveSeed): Finding {
  return projectFinding(context, project, {
    id: RULE_ID,
    title: titleOf(seed.column),
    subject: seed.subject,
    severity: SEVERITY,
    evidence: {
      columnIndex: seed.column.columnIndex,
      kind: seed.column.kind,
      rowsChecked: seed.rowsChecked,
      rowsMatching: seed.column.rowsMatching,
    },
    location: { file: seed.file },
    remediation: REMEDIATION,
    references: [...REFERENCES],
  });
}

/**
 * SEED_DATA_SENSITIVE: a seed CSV column whose name says card number, IBAN
 * or secret and whose values pass the matching format check. Seed data is
 * committed with the project and deployed to every database, so such a
 * column spreads the values to each system and clone. See docs/rules.md.
 */
export const seedDataSensitive: Analyzer = {
  rule: {
    id: RULE_ID,
    title: 'Seed data contains card numbers, IBANs or secrets',
    description:
      'A CSV seed file has a column whose name and values look like payment card numbers, IBANs or secrets (reported by column position, never by name). Seed data is deployed to every system and committed with the project.',
    roles: [],
    owasp: ['A04:2025'],
    helpUri: ruleHelpUri(RULE_ID),
  },
  requires: ['collect.project'],
  analyze(context): Finding[] {
    return context.raw.projects.flatMap((project) =>
      sensitiveSeeds(project).map((seed) => findingFor(context, project, seed)),
    );
  },
};
