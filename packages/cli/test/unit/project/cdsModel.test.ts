import { describe, expect, it } from 'vitest';
import {
  effectiveEntities,
  effectiveServices,
  hasPersonalDataDeclared,
  namesMatch,
  personalEntities,
  referencedRoles,
  resolveTarget,
} from '../../../src/analyzers/project/cdsModel.js';
import {
  action,
  annotate,
  cdsFile,
  entity,
  rawProject,
  service,
  serviceEntity,
} from '../../support/project.js';

const schema = cdsFile('db/schema.cds', {
  entities: [
    entity('Customers', ['ID', 'firstName', 'email'], {
      associations: [{ field: 'addresses', target: 'Addresses' }],
    }),
    entity('Addresses', ['ID', 'city', 'postCode'], {
      associations: [{ field: 'customer', target: 'Customers' }],
    }),
    entity('Warehouses', ['ID', 'city', 'postCode']),
    entity('Incidents', ['ID', 'title'], {
      associations: [{ field: 'customer', target: 'Customers' }],
    }),
  ],
});

const services = cdsFile('srv/services.cds', {
  usings: [{ alias: 'db', target: 'acme.incidents' }],
  services: [
    service('AdminService', {
      line: 3,
      entities: [
        serviceEntity('Customers', { projectionOf: 'db.Customers' }),
        serviceEntity('Incidents', { projectionOf: 'db.Incidents', readonly: true }),
      ],
      actions: [action('close')],
    }),
    service('ProcessorService', {
      line: 20,
      requires: ['support'],
      entities: [serviceEntity('Incidents', { restrictTo: ['auditor', '$user.role'] })],
    }),
  ],
});

describe('resolveTarget', () => {
  it('resolves `using … as` aliases, including qualified members', () => {
    expect(resolveTarget(services, 'db')).toBe('acme.incidents');
    expect(resolveTarget(services, 'db.Customers')).toBe('acme.incidents.Customers');
    expect(resolveTarget(services, 'dbx.Customers')).toBe('dbx.Customers');
    expect(resolveTarget(services, 'Customers')).toBe('Customers');
  });
});

describe('namesMatch', () => {
  it('matches exact names and namespace-qualified forms', () => {
    expect(namesMatch('Customers', 'Customers')).toBe(true);
    expect(namesMatch('acme.incidents.Customers', 'Customers')).toBe(true);
    expect(namesMatch('Customers', 'acme.incidents.Customers')).toBe(true);
    expect(namesMatch('MyCustomers', 'Customers')).toBe(false);
    expect(namesMatch('Customers', 'Addresses')).toBe(false);
  });
});

describe('effectiveServices', () => {
  it('merges restrictions from the service, its members and annotates in any file', () => {
    const project = rawProject({
      cdsFiles: [
        services,
        cdsFile('srv/annotations.cds', {
          usings: [{ alias: 'Admin', target: 'AdminService' }],
          annotates: [
            annotate('Admin', { requires: ['admin'] }),
            annotate('Admin.Customers', { restrictTo: ['sales'] }),
            annotate('AdminService.close', { requires: ['closer'] }),
            annotate('Customers', { requires: ['db-only'] }),
          ],
        }),
      ],
    });
    const [admin, processor] = effectiveServices(project);
    expect(admin).toMatchObject({
      file: 'srv/services.cds',
      name: 'AdminService',
      line: 3,
      requires: ['admin', 'closer'],
      restrictTo: ['sales'],
    });
    expect(admin?.entities).toHaveLength(2);
    expect(admin?.actions).toHaveLength(1);
    expect(processor).toMatchObject({
      name: 'ProcessorService',
      requires: ['support'],
      restrictTo: ['$user.role', 'auditor'],
    });
  });

  it('matches namespace-qualified annotate targets by suffix', () => {
    const project = rawProject({
      cdsFiles: [
        services,
        cdsFile('srv/x.cds', {
          annotates: [annotate('acme.srv.AdminService.Incidents', { requires: ['viewer'] })],
        }),
      ],
    });
    expect(effectiveServices(project)[0]?.requires).toEqual(['viewer']);
  });

  it('keeps unrestricted services empty and carries protocolNone / external', () => {
    const project = rawProject({
      cdsFiles: [
        cdsFile('srv/internal.cds', {
          services: [service('InternalService', { protocolNone: true })],
        }),
        cdsFile('srv/external/External.cds', {
          services: [service('External', { external: true })],
        }),
      ],
    });
    expect(effectiveServices(project)).toMatchObject([
      { name: 'InternalService', protocolNone: true, requires: [], restrictTo: [] },
      { name: 'External', external: true },
    ]);
  });
});

describe('effectiveEntities', () => {
  it('merges @PersonalData from annotates by exact, alias-resolved and qualified names', () => {
    const project = rawProject({
      cdsFiles: [
        schema,
        cdsFile('db/annotations.cds', {
          usings: [{ alias: 'db', target: 'acme.incidents' }],
          annotates: [
            annotate('db.Customers', { personalData: true }),
            annotate('acme.incidents.Addresses', { personalData: true }),
            annotate('Warehouses', { personalData: false }),
          ],
        }),
      ],
    });
    const byName = Object.fromEntries(effectiveEntities(project).map((e) => [e.name, e]));
    expect(byName.Customers?.personalData).toBe(true);
    expect(byName.Addresses?.personalData).toBe(true);
    expect(byName.Warehouses?.personalData).toBe(false);
    expect(byName.Customers?.linkTargets).toEqual(['Addresses']);
  });

  it('counts an annotate on a service projection only through projectionOf', () => {
    const project = rawProject({
      cdsFiles: [
        schema,
        services,
        cdsFile('srv/annotations.cds', {
          annotates: [
            annotate('AdminService.Customers', { personalData: true }),
            annotate('ProcessorService.Incidents', { personalData: true }),
          ],
        }),
      ],
    });
    const byName = Object.fromEntries(effectiveEntities(project).map((e) => [e.name, e]));
    // AdminService.Customers is a projection on db.Customers: the db entity counts as annotated.
    expect(byName.Customers?.personalData).toBe(true);
    // ProcessorService.Incidents has no projectionOf: the db entity stays unannotated.
    expect(byName.Incidents?.personalData).toBe(false);
  });

  it('keeps inline @PersonalData', () => {
    const project = rawProject({
      cdsFiles: [
        cdsFile('db/a.cds', { entities: [entity('P', ['email'], { personalData: true })] }),
      ],
    });
    expect(effectiveEntities(project)[0]?.personalData).toBe(true);
    expect(hasPersonalDataDeclared(project)).toBe(true);
  });
});

describe('referencedRoles', () => {
  it('collects roles from every level, removes pseudo-roles and $/: names, sorted unique', () => {
    const project = rawProject({
      cdsFiles: [
        services,
        cdsFile('srv/more.cds', {
          services: [
            service('S', {
              requires: ['authenticated-user', 'any', 'zeta'],
              restrictTo: ['system-user'],
              entities: [serviceEntity('E', { requires: ['admin', 'support'] })],
              actions: [action('a', { restrictTo: ['ops:write', 'auditor'] })],
            }),
          ],
          annotates: [annotate('S', { requires: ['Annotated'] })],
        }),
      ],
    });
    expect(referencedRoles(project)).toEqual(['admin', 'Annotated', 'auditor', 'support', 'zeta']);
  });

  it('is empty without restrictions', () => {
    expect(referencedRoles(rawProject())).toEqual([]);
  });
});

describe('hasPersonalDataDeclared', () => {
  it('is true for an annotate anywhere, false otherwise', () => {
    expect(hasPersonalDataDeclared(rawProject({ cdsFiles: [schema] }))).toBe(false);
    expect(
      hasPersonalDataDeclared(
        rawProject({
          cdsFiles: [cdsFile('x.cds', { annotates: [annotate('Y', { personalData: true })] })],
        }),
      ),
    ).toBe(true);
  });
});

describe('personalEntities', () => {
  it('applies the two tiers: strong fields, or weak fields with a personal link or name', () => {
    const result = personalEntities(rawProject({ cdsFiles: [schema] }));
    expect(result.map((e) => [e.name, e.strongFields, e.weakFields, e.linkedTo])).toEqual([
      ['Customers', ['firstName', 'email'], [], null],
      ['Addresses', [], ['city', 'postCode'], 'Customers'],
    ]);
    expect(result.every((e) => e.personalData === false)).toBe(true);
  });

  it('names an entity with weak fields when its name says it is about people', () => {
    const result = personalEntities(
      rawProject({
        cdsFiles: [
          cdsFile('db/a.cds', {
            entities: [
              entity('acme.Contacts', ['ID', 'city']),
              entity('CustomerSites', ['ID', 'street']),
              entity('Depots', ['ID', 'street']),
            ],
          }),
        ],
      }),
    );
    expect(result.map((e) => [e.name, e.linkedTo])).toEqual([
      ['acme.Contacts', null],
      ['CustomerSites', null],
    ]);
  });

  it('links through a using alias to an entity declared personal by annotation', () => {
    const result = personalEntities(
      rawProject({
        cdsFiles: [
          cdsFile('db/people.cds', {
            entities: [entity('People', ['ID', 'name'], { personalData: true })],
          }),
          cdsFile('db/sites.cds', {
            usings: [{ alias: 'p', target: 'acme.people' }],
            entities: [
              entity('Sites', ['ID', 'city'], {
                associations: [{ field: 'owner', target: 'p.People' }],
              }),
            ],
          }),
        ],
      }),
    );
    expect(result.map((e) => [e.name, e.linkedTo])).toEqual([['Sites', 'People']]);
  });

  it('keeps already annotated entities, flagged, so a rule can skip them', () => {
    const result = personalEntities(
      rawProject({
        cdsFiles: [
          cdsFile('db/a.cds', {
            entities: [entity('Customers', ['email'], { personalData: true })],
          }),
        ],
      }),
    );
    expect(result).toMatchObject([{ name: 'Customers', personalData: true }]);
  });
});
