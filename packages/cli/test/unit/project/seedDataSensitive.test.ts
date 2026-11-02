import { describe, expect, it } from 'vitest';
import {
  RULE_ID,
  SUBJECT_SEPARATOR,
  seedDataSensitive,
  seedSubject,
} from '../../../src/analyzers/project/seedDataSensitive.js';
import { FindingSchema } from '../../../src/model/finding.js';
import { owaspUrl } from '../../../src/model/owasp.js';
import type { RawProject, RawSeedData } from '../../../src/model/raw.js';
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

const CUSTOMERS = 'db/data/acme.incidents-Customers.csv';

function project(seeds: RawSeedData[], overrides: Partial<RawProject> = {}): RawProject {
  return rawProject({ seedData: seeds, ...overrides });
}

/** A customers file whose sixth column (the card number) has three Luhn-valid values. */
function cardSeed(file = CUSTOMERS, rowsMatching = 3): RawSeedData {
  return seedCsv(file, {
    columnCount: 7,
    rowsChecked: 10,
    sensitiveColumns: [{ columnIndex: 6, kind: 'card', rowsMatching }],
  });
}

const subjects = (findings: ReturnType<typeof runRule>) =>
  findings.map((f) => [f.evidence.subject, f.severity]);

describe('SEED_DATA_SENSITIVE', () => {
  it('declares the rule id and the subject shape', () => {
    expect(RULE_ID).toBe('SEED_DATA_SENSITIVE');
    expect(SUBJECT_SEPARATOR).toBe('#');
    expect(seedSubject('db/data/a.csv', 3)).toBe('db/data/a.csv#3');
  });

  it('fires high for a card column with matching values', () => {
    const findings = runRule(seedDataSensitive, project([cardSeed()]));
    expect(findings).toHaveLength(1);
    const finding = findings[0]!;
    expect(finding.id).toBe(RULE_ID);
    expect(finding.severity).toBe('high');
    expect(finding.title).toBe('Seed data column 6 contains payment card numbers');
    expect(finding.app).toEqual({
      guid: 'project:acme',
      name: 'acme',
      space: 'project',
      org: 'local',
    });
    expect(finding.evidence).toEqual({
      subject: `${CUSTOMERS}#6`,
      columnIndex: 6,
      kind: 'card',
      rowsChecked: 10,
      rowsMatching: 3,
      impact: 'significant',
      easeOfAttack: 'advanced',
    });
    expect(finding.location).toEqual({ file: CUSTOMERS });
    expect(FindingSchema.safeParse(finding).success).toBe(true);
  });

  it('fires for an IBAN column and names the kind in the title', () => {
    const findings = runRule(
      seedDataSensitive,
      project([
        seedCsv('db/data/Accounts.csv', {
          sensitiveColumns: [{ columnIndex: 2, kind: 'iban', rowsMatching: 1 }],
        }),
      ]),
    );
    expect(subjects(findings)).toEqual([['db/data/Accounts.csv#2', 'high']]);
    expect(findings[0]!.title).toBe('Seed data column 2 contains IBANs');
    expect(findings[0]!.evidence).toMatchObject({ kind: 'iban', rowsChecked: 10, rowsMatching: 1 });
  });

  it('fires for a secret column, also under test/data', () => {
    const findings = runRule(
      seedDataSensitive,
      project([
        seedCsv('test/data/Users.csv', {
          rowsChecked: 2,
          sensitiveColumns: [{ columnIndex: 3, kind: 'secret', rowsMatching: 2 }],
        }),
      ]),
    );
    expect(subjects(findings)).toEqual([['test/data/Users.csv#3', 'high']]);
    expect(findings[0]!.title).toBe('Seed data column 3 contains secret-looking values');
    expect(findings[0]!.location).toEqual({ file: 'test/data/Users.csv' });
  });

  it('is always high: significant impact, advanced to exploit', () => {
    const kinds: RawSeedData['sensitiveColumns'][number]['kind'][] = ['card', 'iban', 'secret'];
    for (const kind of kinds) {
      const [finding] = runRule(
        seedDataSensitive,
        project([
          seedCsv('db/data/X.csv', {
            sensitiveColumns: [{ columnIndex: 1, kind, rowsMatching: 1 }],
          }),
        ]),
      );
      expect(finding!.severity).toBe('high');
      expect(finding!.evidence).toMatchObject({ impact: 'significant', easeOfAttack: 'advanced' });
    }
  });

  describe('does not fire', () => {
    const none = (seeds: RawSeedData[]) =>
      expect(runRule(seedDataSensitive, project(seeds))).toEqual([]);

    it('for a sensitive-looking column whose values never match', () => {
      none([cardSeed(CUSTOMERS, 0)]);
      none([
        seedCsv('db/data/Users.csv', {
          sensitiveColumns: [
            { columnIndex: 2, kind: 'secret', rowsMatching: 0 },
            { columnIndex: 3, kind: 'iban', rowsMatching: 0 },
          ],
        }),
      ]);
    });

    it('for a file without sensitive columns', () => {
      none([seedCsv('db/data/Status.csv', { columnCount: 2, rowsChecked: 5 })]);
    });

    it('for a file whose header was rejected, so no values were checked', () => {
      none([
        seedCsv('test/data/export.csv', { headerRejected: true, columnCount: 0, rowsChecked: 0 }),
      ]);
    });

    it('for a file without data rows', () => {
      none([
        seedCsv('db/data/Empty.csv', {
          rowsChecked: 0,
          sensitiveColumns: [{ columnIndex: 6, kind: 'card', rowsMatching: 0 }],
        }),
      ]);
    });

    it('when the project has no seed data at all', () => {
      none([]);
      expect(
        runRule(seedDataSensitive, rawProject({ packageJson: packageJson(['@sap/cds']) })),
      ).toEqual([]);
    });
  });

  it('emits one finding per column of a file, sorted by column position', () => {
    const findings = runRule(
      seedDataSensitive,
      project([
        seedCsv(CUSTOMERS, {
          sensitiveColumns: [
            { columnIndex: 6, kind: 'card', rowsMatching: 3 },
            { columnIndex: 4, kind: 'iban', rowsMatching: 2 },
            { columnIndex: 2, kind: 'secret', rowsMatching: 0 },
          ],
        }),
      ]),
    );
    expect(subjects(findings)).toEqual([
      [`${CUSTOMERS}#4`, 'high'],
      [`${CUSTOMERS}#6`, 'high'],
    ]);
  });

  it('emits one finding per file for the same column position, sorted by file', () => {
    const findings = runRule(
      seedDataSensitive,
      project([cardSeed('test/data/Customers.csv', 1), cardSeed('db/data/Customers.csv', 2)]),
    );
    expect(subjects(findings)).toEqual([
      ['db/data/Customers.csv#6', 'high'],
      ['test/data/Customers.csv#6', 'high'],
    ]);
    expect(findings.map((f) => f.location?.file)).toEqual([
      'db/data/Customers.csv',
      'test/data/Customers.csv',
    ]);
    expect(findings.map((f) => f.evidence.rowsMatching)).toEqual([2, 1]);
  });

  it('emits one finding per subject when a snapshot lists a column position twice, keeping the larger count', () => {
    const findings = runRule(
      seedDataSensitive,
      project([
        seedCsv(CUSTOMERS, {
          sensitiveColumns: [
            { columnIndex: 6, kind: 'card', rowsMatching: 1 },
            { columnIndex: 6, kind: 'card', rowsMatching: 4 },
          ],
        }),
      ]),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]!.evidence).toMatchObject({ rowsMatching: 4 });
  });

  it('picks the same entry for a repeated subject whatever the order, when the counts tie', () => {
    // A snapshot edited by hand may list one subject twice with equal counts;
    // the collector itself gives one kind per column position.
    const secret = { columnIndex: 2, kind: 'secret' as const, rowsMatching: 2 };
    const card = { columnIndex: 2, kind: 'card' as const, rowsMatching: 2 };
    const forward = runRule(
      seedDataSensitive,
      project([seedCsv('db/data/X.csv', { sensitiveColumns: [secret, card] })]),
    );
    const backward = runRule(
      seedDataSensitive,
      project([seedCsv('db/data/X.csv', { sensitiveColumns: [card, secret] })]),
    );
    expect(forward).toHaveLength(1);
    expect(forward[0]!.evidence).toMatchObject({ kind: 'card', rowsMatching: 2 });
    expect(forward[0]!.title).toBe('Seed data column 2 contains payment card numbers');
    expect(backward).toEqual(forward);
  });

  it('reports the larger row count for a file listed twice, whatever the order', () => {
    const fewer = seedCsv(CUSTOMERS, {
      rowsChecked: 5,
      sensitiveColumns: [{ columnIndex: 4, kind: 'iban', rowsMatching: 1 }],
    });
    const more = seedCsv(CUSTOMERS, {
      rowsChecked: 9,
      sensitiveColumns: [{ columnIndex: 4, kind: 'iban', rowsMatching: 1 }],
    });
    const forward = runRule(seedDataSensitive, project([fewer, more]));
    const backward = runRule(seedDataSensitive, project([more, fewer]));
    expect(forward).toHaveLength(1);
    expect(forward[0]!.evidence).toMatchObject({ rowsChecked: 9, rowsMatching: 1 });
    expect(backward).toEqual(forward);
  });

  it('orders findings the same whatever the collector order', () => {
    const a = seedCsv('db/data/B.csv', {
      sensitiveColumns: [
        { columnIndex: 3, kind: 'secret', rowsMatching: 1 },
        { columnIndex: 2, kind: 'iban', rowsMatching: 1 },
      ],
    });
    const b = cardSeed('db/data/A.csv');
    const forward = subjects(runRule(seedDataSensitive, project([a, b])));
    const backward = subjects(runRule(seedDataSensitive, project([b, a])));
    expect(forward).toEqual([
      ['db/data/A.csv#6', 'high'],
      ['db/data/B.csv#2', 'high'],
      ['db/data/B.csv#3', 'high'],
    ]);
    expect(backward).toEqual(forward);
  });

  it('reports each project on its own', () => {
    const findings = runRule(
      seedDataSensitive,
      project([cardSeed()]),
      rawProject({ id: 'other', seedData: [cardSeed(CUSTOMERS, 0)] }),
      rawProject({ id: 'third', seedData: [cardSeed('db/data/Cards.csv', 1)] }),
    );
    expect(findings.map((f) => [f.app.name, f.evidence.subject])).toEqual([
      ['acme', `${CUSTOMERS}#6`],
      ['third', 'db/data/Cards.csv#6'],
    ]);
  });

  it('links the CAP initial-data guide, the OWASP secrets cheat sheet and OWASP A04:2025', () => {
    const finding = runRule(seedDataSensitive, project([cardSeed()]))[0]!;
    expect(finding.references).toEqual([
      'https://cap.cloud.sap/docs/guides/databases/initial-data',
      'https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html',
      owaspUrl('A04:2025'),
    ]);
    expect(finding.remediation).toContain('db/data');
    expect(finding.remediation).toContain('test/data');
    expect(finding.remediation).toContain('repository history');
  });

  it('is deterministic', () => {
    expectDeterministic(
      seedDataSensitive,
      project([
        seedCsv('db/data/B.csv', {
          sensitiveColumns: [
            { columnIndex: 3, kind: 'secret', rowsMatching: 1 },
            { columnIndex: 2, kind: 'iban', rowsMatching: 1 },
          ],
        }),
        cardSeed('db/data/A.csv'),
        cardSeed('db/data/A.csv', 5),
      ]),
    );
  });

  it('copies nothing from the project but the file name, the column position and counts', () => {
    const poisoned = rawProject({
      sourcesRead: ['.cdsrc.json', 'package.json'],
      files: POISON,
      unreadable: POISON.map((file) => ({ file, kind: 'csv' as const })),
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
          scopes: [value, { name: value, grantedToApps: true }],
          roleTemplates: [[value, [value]]],
          attributes: [value],
        }),
      ),
      xsApps: POISON.map((value) => xsApp(value, [{ source: value }])),
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
      seedData: [
        // The one file that fires: its other columns never match a value.
        seedCsv(CUSTOMERS, {
          columnCount: POISON.length + 7,
          rowsChecked: POISON.length,
          sensitiveColumns: [
            { columnIndex: 6, kind: 'card', rowsMatching: 2 },
            ...POISON.map((_, i) => ({
              columnIndex: 7 + i,
              kind: 'secret' as const,
              rowsMatching: 0,
            })),
          ],
        }),
        // Poisoned files whose columns never match a value, so none of them fires.
        ...POISON.map((value) =>
          seedCsv(value, {
            sensitiveColumns: [
              { columnIndex: 1, kind: 'card', rowsMatching: 0 },
              { columnIndex: 2, kind: 'iban', rowsMatching: 0 },
              { columnIndex: 3, kind: 'secret', rowsMatching: 0 },
            ],
          }),
        ),
        ...POISON.map((value) =>
          seedCsv(value, { headerRejected: true, columnCount: 0, rowsChecked: 0 }),
        ),
      ],
      archives: POISON.map((value) => archive(value)),
      html: POISON.map((value) => htmlBootstrap(value, value)),
    });
    const findings = runRule(seedDataSensitive, poisoned);
    expect(findings).toHaveLength(1);
    expectNoValueLeak(findings, POISON);
    expect(findings[0]!.evidence).toEqual({
      subject: `${CUSTOMERS}#6`,
      columnIndex: 6,
      kind: 'card',
      rowsChecked: POISON.length,
      rowsMatching: 2,
      impact: 'significant',
      easeOfAttack: 'advanced',
    });
    expect(findings[0]!.location).toEqual({ file: CUSTOMERS });
  });
});
