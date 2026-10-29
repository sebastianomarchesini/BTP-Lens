import { describe, expect, it } from 'vitest';
import {
  RULE_ID,
  TITLE_ENTITY_NAME,
  TITLE_LINKED_ENTITY,
  TITLE_STRONG_FIELDS,
  capPersonalDataUnannotated,
} from '../../../src/analyzers/project/capPersonalDataUnannotated.js';
import { FindingSchema } from '../../../src/model/finding.js';
import { owaspUrl } from '../../../src/model/owasp.js';
import type { RawCdsFile, RawProject } from '../../../src/model/raw.js';
import {
  POISON,
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

function project(...cdsFiles: RawCdsFile[]): RawProject {
  return rawProject({ cdsFiles });
}

function schema(...entities: ReturnType<typeof entity>[]): RawCdsFile {
  return cdsFile('db/schema.cds', { entities });
}

const toCustomers = { associations: [{ field: 'customer', target: 'Customers' }] };

describe('CAP_PERSONAL_DATA_UNANNOTATED', () => {
  it('has the rule id', () => {
    expect(RULE_ID).toBe('CAP_PERSONAL_DATA_UNANNOTATED');
    expect(capPersonalDataUnannotated.rule.owasp).toEqual(['A04:2025', 'A09:2025']);
  });

  it('fires, medium, on an entity with strong personal fields and no annotation', () => {
    const findings = runRule(
      capPersonalDataUnannotated,
      project(schema(entity('Customers', ['ID', 'firstName', 'email', 'city'], { line: 7 }))),
    );
    expect(findings).toHaveLength(1);
    const finding = findings[0]!;
    expect(finding.id).toBe(RULE_ID);
    expect(finding.severity).toBe('medium');
    expect(finding.title).toBe(TITLE_STRONG_FIELDS);
    expect(finding.app).toEqual({
      guid: 'project:acme',
      name: 'acme',
      space: 'project',
      org: 'local',
    });
    expect(finding.evidence).toEqual({
      subject: 'Customers',
      reason: 'strong-fields',
      strongFields: ['firstName', 'email'],
      weakFields: ['city'],
      linkedTo: null,
      impact: 'moderate',
      easeOfAttack: 'advanced',
    });
    expect(finding.location).toEqual({ file: 'db/schema.cds', line: 7 });
    expect(finding.remediation).toContain('@PersonalData');
    // The plugin is CAP_AUDITLOG_MISSING's business; this rule only points there.
    expect(finding.remediation).toContain('cap-js/audit-logging');
    expect(finding.remediation).toContain('CAP_AUDITLOG_MISSING');
    expect(finding.remediation).not.toMatch(/then add/i);
    expect(finding.remediation).toContain('inferred from element and entity names');
    expect(FindingSchema.safeParse(finding).success).toBe(true);
  });

  it('fires on weak fields when an association targets an entity with strong fields', () => {
    const findings = runRule(
      capPersonalDataUnannotated,
      project(
        schema(
          entity('Customers', ['ID', 'email'], { personalData: true }),
          entity('Addresses', ['ID', 'city', 'postCode'], { line: 12, ...toCustomers }),
        ),
      ),
    );
    expect(findings.map((f) => [f.evidence.subject, f.title])).toEqual([
      ['Addresses', TITLE_LINKED_ENTITY],
    ]);
    expect(findings[0]!.severity).toBe('medium');
    expect(findings[0]!.evidence).toEqual({
      subject: 'Addresses',
      reason: 'linked-entity',
      strongFields: [],
      weakFields: ['city', 'postCode'],
      linkedTo: 'Customers',
      impact: 'moderate',
      easeOfAttack: 'advanced',
    });
    expect(findings[0]!.location).toEqual({ file: 'db/schema.cds', line: 12 });
  });

  it('fires on weak fields when the association target is personal through @PersonalData only', () => {
    const findings = runRule(
      capPersonalDataUnannotated,
      project(
        schema(
          entity('Subjects', ['ID', 'code'], { personalData: true }),
          entity('Locations', ['ID', 'city'], {
            associations: [{ field: 'subject', target: 'Subjects' }],
          }),
        ),
      ),
    );
    expect(findings.map((f) => [f.evidence.subject, f.evidence.linkedTo])).toEqual([
      ['Locations', 'Subjects'],
    ]);
  });

  it('fires on weak fields when the entity is named like a person', () => {
    const findings = runRule(
      capPersonalDataUnannotated,
      project(schema(entity('acme.incidents.Contacts', ['ID', 'street', 'country'], { line: 3 }))),
    );
    expect(findings).toHaveLength(1);
    const finding = findings[0]!;
    expect(finding.title).toBe(TITLE_ENTITY_NAME);
    expect(finding.severity).toBe('medium');
    expect(finding.evidence).toEqual({
      subject: 'acme.incidents.Contacts',
      reason: 'entity-name',
      strongFields: [],
      weakFields: ['street', 'country'],
      linkedTo: null,
      impact: 'moderate',
      easeOfAttack: 'advanced',
    });
    expect(finding.location).toEqual({ file: 'db/schema.cds', line: 3 });
  });

  it('names the branch after the name pattern, which also matches Addresses and UserSettings', () => {
    const findings = runRule(
      capPersonalDataUnannotated,
      project(
        schema(entity('Addresses', ['ID', 'street', 'city']), entity('UserSettings', ['country'])),
      ),
    );
    expect(findings.map((f) => [f.evidence.subject, f.title])).toEqual([
      ['Addresses', TITLE_ENTITY_NAME],
      ['UserSettings', TITLE_ENTITY_NAME],
    ]);
    expect(TITLE_ENTITY_NAME).toContain('name suggests personal data');
    expect(TITLE_ENTITY_NAME).not.toMatch(/like a person/);
  });

  it('resolves a using alias on the association target', () => {
    const findings = runRule(
      capPersonalDataUnannotated,
      project(
        cdsFile('db/schema.cds', {
          entities: [entity('acme.Customers', ['ID', 'phone'], { personalData: true })],
        }),
        cdsFile('db/extra.cds', {
          usings: [{ alias: 'base', target: 'acme' }],
          entities: [
            entity('Addresses', ['ID', 'zipCode'], {
              associations: [{ field: 'customer', target: 'base.Customers' }],
            }),
          ],
        }),
      ),
    );
    expect(findings.map((f) => [f.evidence.subject, f.evidence.linkedTo])).toEqual([
      ['Addresses', 'acme.Customers'],
    ]);
  });

  describe('does not fire', () => {
    it('when the model has no entities', () => {
      expect(runRule(capPersonalDataUnannotated, rawProject())).toEqual([]);
      expect(runRule(capPersonalDataUnannotated, project(cdsFile('db/schema.cds')))).toEqual([]);
    });

    it('on an entity with no personal fields at all', () => {
      const model = schema(entity('Incidents', ['ID', 'title', 'status'], toCustomers));
      expect(runRule(capPersonalDataUnannotated, project(model))).toEqual([]);
    });

    it('on weak fields alone, neither linked to a personal entity nor named like one', () => {
      const model = schema(
        entity('Warehouses', ['ID', 'city', 'postCode', 'country']),
        entity('Plants', ['ID', 'latitude', 'longitude'], {
          associations: [{ field: 'warehouse', target: 'Warehouses' }],
        }),
      );
      expect(runRule(capPersonalDataUnannotated, project(model))).toEqual([]);
    });

    it('on weak fields linked to an entity that is not personal', () => {
      const model = schema(
        entity('Incidents', ['ID', 'title']),
        entity('Sites', ['ID', 'city'], {
          associations: [{ field: 'incident', target: 'Incidents' }],
        }),
      );
      expect(runRule(capPersonalDataUnannotated, project(model))).toEqual([]);
    });

    it('on a weak-field entity whose only association points to itself', () => {
      const model = schema(
        entity('Regions', ['ID', 'city', 'country'], {
          associations: [{ field: 'parent', target: 'Regions' }],
        }),
      );
      expect(runRule(capPersonalDataUnannotated, project(model))).toEqual([]);
    });

    it('on weak fields linked to an entity that is personal by its name only', () => {
      const model = schema(
        entity('Contacts', ['ID', 'city']),
        entity('Sites', ['ID', 'country'], {
          associations: [{ field: 'contact', target: 'Contacts' }],
        }),
      );
      // Contacts fires by name; Sites does not, because its target has no strong field.
      expect(
        runRule(capPersonalDataUnannotated, project(model)).map((f) => f.evidence.subject),
      ).toEqual(['Contacts']);
    });

    it('when @PersonalData is declared inline on the entity', () => {
      const model = schema(entity('Customers', ['ID', 'email'], { personalData: true }));
      expect(runRule(capPersonalDataUnannotated, project(model))).toEqual([]);
    });

    it('when @PersonalData comes from an annotate on the entity', () => {
      const findings = runRule(
        capPersonalDataUnannotated,
        project(
          schema(entity('Customers', ['ID', 'email'])),
          cdsFile('db/data-privacy.cds', {
            annotates: [annotate('Customers', { personalData: true })],
          }),
        ),
      );
      expect(findings).toEqual([]);
    });

    it('when the annotate addresses the entity through a using alias or namespace', () => {
      const findings = runRule(
        capPersonalDataUnannotated,
        project(
          cdsFile('db/schema.cds', {
            entities: [
              entity('acme.Customers', ['ID', 'email']),
              entity('acme.Employees', ['ID', 'salary']),
            ],
          }),
          cdsFile('db/data-privacy.cds', {
            usings: [{ alias: 'my', target: 'acme' }],
            annotates: [
              annotate('my.Customers', { personalData: true }),
              annotate('Employees', { personalData: true }),
            ],
          }),
        ),
      );
      expect(findings).toEqual([]);
    });

    it('when @PersonalData is annotated on a service projection of the entity', () => {
      const findings = runRule(
        capPersonalDataUnannotated,
        project(
          schema(entity('Customers', ['ID', 'email'])),
          cdsFile('srv/services.cds', {
            services: [
              service('AdminService', {
                entities: [serviceEntity('Customers', { projectionOf: 'Customers' })],
              }),
            ],
            annotates: [annotate('AdminService.Customers', { personalData: true })],
          }),
        ),
      );
      expect(findings).toEqual([]);
    });

    it('on an annotated entity even when another entity links to it', () => {
      const model = schema(
        entity('Customers', ['ID', 'email'], { personalData: true }),
        entity('Addresses', ['ID', 'city'], { personalData: true, ...toCustomers }),
      );
      expect(runRule(capPersonalDataUnannotated, project(model))).toEqual([]);
    });
  });

  it('still fires when the annotate is on a service projection that has no projectionOf', () => {
    const findings = runRule(
      capPersonalDataUnannotated,
      project(
        schema(entity('Customers', ['ID', 'email'])),
        cdsFile('srv/services.cds', {
          services: [service('AdminService', { entities: [serviceEntity('Customers')] })],
          annotates: [annotate('AdminService.Customers', { personalData: true })],
        }),
      ),
    );
    expect(findings.map((f) => f.evidence.subject)).toEqual(['Customers']);
  });

  it('prefers the strong-fields reason over a link or a personal name', () => {
    const findings = runRule(
      capPersonalDataUnannotated,
      project(
        schema(
          entity('Employees', ['ID', 'salary'], { personalData: true }),
          entity('Contacts', ['ID', 'email', 'city'], {
            associations: [{ field: 'employee', target: 'Employees' }],
          }),
        ),
      ),
    );
    expect(findings.map((f) => [f.evidence.reason, f.evidence.linkedTo])).toEqual([
      ['strong-fields', null],
    ]);
  });

  it('emits one finding per entity, in file and line order whatever the input order', () => {
    const findings = runRule(
      capPersonalDataUnannotated,
      project(
        schema(
          entity('Vendors', ['ID', 'taxId'], { line: 30 }),
          entity('Customers', ['ID', 'email'], { line: 10 }),
          entity('Addresses', ['ID', 'city'], { line: 20, ...toCustomers }),
        ),
      ),
    );
    expect(findings.map((f) => [f.evidence.subject, f.location?.line])).toEqual([
      ['Customers', 10],
      ['Addresses', 20],
      ['Vendors', 30],
    ]);
  });

  it('emits the same findings whatever the order of files and entities', () => {
    const files = [
      cdsFile('db/z.cds', {
        entities: [
          entity('Vendors', ['taxId'], { line: 2 }),
          entity('Buyers', ['phone'], { line: 1 }),
        ],
      }),
      cdsFile('db/a.cds', {
        entities: [
          entity('Members', ['city'], { line: 9 }),
          entity('Addresses', ['street'], { line: 4, ...toCustomers }),
          entity('Customers', ['email'], { line: 1 }),
        ],
      }),
    ];
    const reversed = files.map((file) => ({ ...file, entities: [...file.entities].reverse() }));
    const expected = runRule(capPersonalDataUnannotated, project(...files));
    expect(runRule(capPersonalDataUnannotated, project(...reversed.reverse()))).toEqual(expected);
    expect(expected.map((f) => [f.location?.file, f.location?.line, f.evidence.subject])).toEqual([
      ['db/a.cds', 1, 'Customers'],
      ['db/a.cds', 4, 'Addresses'],
      ['db/a.cds', 9, 'Members'],
      ['db/z.cds', 1, 'Buyers'],
      ['db/z.cds', 2, 'Vendors'],
    ]);
  });

  it('produces a schema-valid finding for every reason', () => {
    const findings = runRule(
      capPersonalDataUnannotated,
      project(
        schema(
          entity('Customers', ['ID', 'email']),
          entity('Addresses', ['ID', 'city'], toCustomers),
          entity('Contacts', ['ID', 'street']),
        ),
      ),
    );
    expect(findings.map((f) => f.evidence.reason).sort()).toEqual([
      'entity-name',
      'linked-entity',
      'strong-fields',
    ]);
    for (const finding of findings) {
      expect(FindingSchema.safeParse(finding).success).toBe(true);
      expect(finding.severity).toBe('medium');
      expect(typeof finding.evidence.subject).toBe('string');
      expect(finding.location?.file).toBe('db/schema.cds');
    }
  });

  it('emits one finding per subject when two files declare the same entity name', () => {
    const findings = runRule(
      capPersonalDataUnannotated,
      project(
        cdsFile('db/second.cds', { entities: [entity('Customers', ['ID', 'phone'], { line: 5 })] }),
        cdsFile('db/first.cds', { entities: [entity('Customers', ['ID', 'email'], { line: 9 })] }),
      ),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]!.location).toEqual({ file: 'db/first.cds', line: 9 });
  });

  it('emits findings per project, keeping the project order', () => {
    const findings = runRule(
      capPersonalDataUnannotated,
      project(schema(entity('Customers', ['ID', 'email']))),
      rawProject({ id: 'clean', cdsFiles: [schema(entity('Warehouses', ['ID', 'city']))] }),
      rawProject({ id: 'other', cdsFiles: [schema(entity('Members', ['ID', 'street']))] }),
    );
    expect(findings.map((f) => [f.app.name, f.evidence.subject])).toEqual([
      ['acme', 'Customers'],
      ['other', 'Members'],
    ]);
  });

  it('links the CAP data-privacy guides and OWASP A04:2025 and A09:2025', () => {
    const finding = runRule(
      capPersonalDataUnannotated,
      project(schema(entity('Customers', ['ID', 'email']))),
    )[0]!;
    expect(finding.references).toEqual([
      'https://cap.cloud.sap/docs/guides/security/dpp-annotations',
      'https://cap.cloud.sap/docs/guides/security/dpp-audit-logging',
      owaspUrl('A04:2025'),
      owaspUrl('A09:2025'),
    ]);
  });

  it('is deterministic', () => {
    expectDeterministic(
      capPersonalDataUnannotated,
      project(
        schema(
          entity('Vendors', ['ID', 'taxId']),
          entity('Customers', ['ID', 'email'], { personalData: true }),
          entity('Addresses', ['ID', 'city'], toCustomers),
          entity('Contacts', ['ID', 'street']),
        ),
      ),
    );
  });

  it('copies nothing from the project but entity and field identifiers, counts and booleans', () => {
    const identifiers = POISON.filter((value) => /^[A-Za-z_$][\w.$:-]{0,127}$/.test(value));
    expect(identifiers.length).toBeGreaterThan(10);
    const poisoned = rawProject({
      sourcesRead: ['.cdsrc.json', 'package.json'],
      files: POISON,
      unreadable: POISON.map((file) => ({ file, kind: 'cds' as const })),
      packageJson: {
        ...packageJson(
          { '@sap/cds': POISON[0]!, ...Object.fromEntries(POISON.map((v) => [v, v])) },
          POISON,
          POISON[1],
        ),
        name: POISON[2]!,
      },
      cds: cdsEffective('production', {
        authKind: 'mocked',
        mockedUsers: POISON.length,
        mockedUsersWithPassword: POISON.length,
      }),
      mta: mta({
        id: null,
        modules: POISON.map((value) => ({ name: value, buildpack: value, requires: [value] })),
        resources: POISON.map((value) => ({ name: value, service: value, plan: value })),
      }),
      xsSecurity: POISON.map((value) =>
        xsSecurity({
          file: value,
          scopes: [value],
          roleTemplates: [[value, [value]]],
          attributes: [value],
        }),
      ),
      xsApps: POISON.map((value) => xsApp(value, [{ source: value }])),
      cdsFiles: [
        // The reported entities live in a clean file; everything else is poison,
        // including their non-personal fields and association names.
        schema(
          entity('Customers', ['ID', 'email', ...identifiers], {
            associations: identifiers.map((value) => ({ field: value, target: value })),
          }),
          entity('Addresses', ['ID', 'city', ...identifiers], {
            associations: [
              ...identifiers.map((value) => ({ field: value, target: 'Incidents' })),
              ...toCustomers.associations,
            ],
          }),
          entity('Incidents', ['ID', ...identifiers]),
        ),
        ...POISON.map((value) =>
          cdsFile(value, {
            usings: [{ alias: value, target: value }],
            services: [
              service(value, {
                requires: [value],
                restrictTo: [value],
                entities: [serviceEntity(value, { projectionOf: value })],
              }),
            ],
            entities: [
              // Annotated: never reported, even with strong fields and a poison name.
              entity(value, [value, 'email'], {
                personalData: true,
                associations: [{ field: value, target: value }],
              }),
              // No personal field at all: never reported, whatever the name.
              entity(`${value}Customer`, [value], {
                associations: [{ field: value, target: 'Customers' }],
              }),
            ],
            annotates: [annotate(value, { personalData: true, requires: [value] })],
          }),
        ),
      ],
      seedData: POISON.map((value) =>
        seedCsv(value, {
          sensitiveColumns: [{ column: value, kind: 'secret', rowsMatching: 1 }],
        }),
      ),
      archives: POISON.map((value) => archive(value)),
      html: POISON.map((value) => htmlBootstrap(value, value)),
    });
    const findings = runRule(capPersonalDataUnannotated, poisoned);
    expect(findings.map((f) => f.evidence.subject)).toEqual(['Addresses', 'Customers']);
    expectNoValueLeak(findings, POISON);
    for (const finding of findings) {
      expect(finding.location?.file).toBe('db/schema.cds');
    }
  });
});
