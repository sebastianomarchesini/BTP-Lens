import { describe, expect, it } from 'vitest';
import { CDS_LIMITS, maskCds, scanCds } from '../../../../src/collectors/project/cdsFiles.js';

const scan = (text: string) => scanCds(text, 'srv/test.cds');

describe('maskCds', () => {
  it('blanks comments and string contents but keeps every position and newline', () => {
    const text = '// c1\nentity A { x : String default \'POISON\'; } /* multi\nline */ @t: "q"';
    const masked = maskCds(text);
    expect(masked).toHaveLength(text.length);
    expect(masked.split('\n')).toHaveLength(text.split('\n').length);
    expect(masked).not.toContain('POISON');
    expect(masked).not.toContain('c1');
    expect(masked).not.toContain('multi');
    expect(masked).toContain("default '      '");
    expect(masked).toContain('@t: " "');
  });

  it('treats a doubled quote inside a string as an escape', () => {
    const masked = maskCds("where: '$user.email = ''poison.where@example.com''' entity B {}");
    expect(masked).not.toContain('poison');
    expect(masked).toContain('entity B {}');
  });
});

describe('scanCds: services, entities and actions', () => {
  it('reads a typical service file with aliases, projections, actions and restrictions', () => {
    const file = scan(`using { acme.incidents as db } from '../db/schema';
using { sap.common.CodeList, cuid as Keyed } from '@sap/cds/common';

/** Full access for administrators. */
service AdminService {
  entity Customers as projection on db.Customers;
  entity Incidents as projection on db.Incidents;
  function fetchCustomer(email : String) returns Customers;
}

service ProcessorService @(requires: 'support') {
  @restrict: [{ grant: 'READ', to: 'auditor', where: '$user.email = ''poison.where@example.com''' }]
  entity Incidents as projection on db.Incidents;
  @readonly entity Customers as projection on db.Customers;
  @requires: ['admin', 'support'] action close(ID : UUID);
}

service InternalService @protocol: 'none' {
  entity Warehouses as projection on db.Warehouses;
}

annotate AdminService.Incidents with @odata.draft.enabled;
annotate AdminService with @(requires: 'admin');
annotate ProcessorService.Customers with @requires: 'support';
`);
    expect(file.usings).toEqual([
      { alias: 'db', target: 'acme.incidents' },
      { alias: 'CodeList', target: 'sap.common.CodeList' },
      { alias: 'Keyed', target: 'cuid' },
    ]);
    expect(file.services).toHaveLength(3);
    const [admin, processor, internal] = file.services;
    expect(admin).toEqual({
      name: 'AdminService',
      line: 5,
      requires: [],
      restrictTo: [],
      protocolNone: false,
      external: false,
      entities: [
        {
          name: 'Customers',
          line: 6,
          requires: [],
          restrictTo: [],
          readonly: false,
          projectionOf: 'db.Customers',
        },
        {
          name: 'Incidents',
          line: 7,
          requires: [],
          restrictTo: [],
          readonly: false,
          projectionOf: 'db.Incidents',
        },
      ],
      actions: [{ name: 'fetchCustomer', line: 8, requires: [], restrictTo: [] }],
    });
    expect(processor).toMatchObject({
      name: 'ProcessorService',
      line: 11,
      requires: ['support'],
      restrictTo: [],
      entities: [
        { name: 'Incidents', line: 13, requires: [], restrictTo: ['auditor'], readonly: false },
        { name: 'Customers', line: 14, requires: [], restrictTo: [], readonly: true },
      ],
      actions: [{ name: 'close', line: 15, requires: ['admin', 'support'], restrictTo: [] }],
    });
    expect(internal).toMatchObject({ name: 'InternalService', line: 18, protocolNone: true });
    expect(file.entities).toEqual([]);
    expect(file.annotates).toEqual([
      {
        target: 'AdminService.Incidents',
        line: 22,
        personalData: false,
        requires: [],
        restrictTo: [],
      },
      {
        target: 'AdminService',
        line: 23,
        personalData: false,
        requires: ['admin'],
        restrictTo: [],
      },
      {
        target: 'ProcessorService.Customers',
        line: 24,
        personalData: false,
        requires: ['support'],
        restrictTo: [],
      },
    ]);
    expect(JSON.stringify(file)).not.toContain('poison');
    expect(JSON.stringify(file)).not.toContain('@example.com');
  });

  it('reads annotations before the keyword, between the name and the body, bare or grouped', () => {
    const file = scan(`@requires: 'a'
service S1 {}
service S2 @requires: 'b' {}
@(requires: ['c', 'd'], restrict: [{ grant: 'READ', to: 'e' }, { grant: 'WRITE', to: ['f', 'g'] }])
service S3 {}
service S4 @(restrict: [{ to: 'h' }]) {
  @(requires: 'i') entity E1 as projection on X;
  entity E2 @requires: 'j' as projection on X;
  entity E3 @(requires: 'k') { key ID : UUID; }
  @requires: 'l'
  entity E4 as projection on X;
}
`);
    const byName = Object.fromEntries(file.services.map((s) => [s.name, s]));
    expect(byName.S1).toMatchObject({ requires: ['a'] });
    expect(byName.S2).toMatchObject({ requires: ['b'] });
    expect(byName.S3).toMatchObject({ requires: ['c', 'd'], restrictTo: ['e', 'f', 'g'] });
    expect(byName.S4).toMatchObject({ requires: [], restrictTo: ['h'] });
    expect(byName.S4?.entities).toEqual([
      { name: 'E1', line: 7, requires: ['i'], restrictTo: [], readonly: false, projectionOf: 'X' },
      { name: 'E2', line: 8, requires: ['j'], restrictTo: [], readonly: false, projectionOf: 'X' },
      { name: 'E3', line: 9, requires: ['k'], restrictTo: [], readonly: false, projectionOf: null },
      { name: 'E4', line: 11, requires: ['l'], restrictTo: [], readonly: false, projectionOf: 'X' },
    ]);
  });

  it('keeps only role-shaped values and never where, grant or other annotation values', () => {
    const file = scan(`@requires: 'has space'
@(restrict: [{ grant: 'POISON_grant', to: 'ok.role', where: 'POISON_where' }], title: 'POISON_title')
@requires: '${'x'.repeat(70)}'
@requires: 'any'
service S {}
`);
    expect(file.services[0]).toMatchObject({ requires: ['any'], restrictTo: ['ok.role'] });
    expect(JSON.stringify(file)).not.toContain('POISON');
  });

  it('recognises @protocol none in every spelling, @cds.external and @readonly', () => {
    const file = scan(`service A @protocol: 'none' {}
service B @protocol: none {}
service C @(protocol: ['none']) {}
service D @protocol: 'odata' {}
@protocol: 'none'
service E {}
@cds.external service F { entity X { key ID : String; } }
service G { @readonly entity Y as projection on Z; entity W as projection on Z; }
`);
    const byName = Object.fromEntries(file.services.map((s) => [s.name, s]));
    expect(byName.A?.protocolNone).toBe(true);
    expect(byName.B?.protocolNone).toBe(true);
    expect(byName.C?.protocolNone).toBe(true);
    expect(byName.D?.protocolNone).toBe(false);
    expect(byName.E?.protocolNone).toBe(true);
    expect(byName.F).toMatchObject({ external: true, entities: [{ name: 'X' }] });
    expect(byName.A?.external).toBe(false);
    expect(byName.G?.entities.map((e) => [e.name, e.readonly])).toEqual([
      ['Y', true],
      ['W', false],
    ]);
  });

  it('records bound actions under the service and select-from views as projections', () => {
    const file = scan(`service S {
  entity Orders as projection on db.Orders actions {
    @requires: 'clerk' action ship();
    function total() returns Decimal;
  };
  entity View as select from db.Orders { ID };
  action unbound();
}`);
    expect(file.services[0]?.entities.map((e) => [e.name, e.projectionOf])).toEqual([
      ['Orders', 'db.Orders'],
      ['View', 'db.Orders'],
    ]);
    expect(file.services[0]?.actions).toEqual([
      { name: 'ship', line: 3, requires: ['clerk'], restrictTo: [] },
      { name: 'total', line: 4, requires: [], restrictTo: [] },
      { name: 'unbound', line: 7, requires: [], restrictTo: [] },
    ]);
  });

  it('reads the Fiori-tools `using X as service from` line as an alias, not a service', () => {
    const file = scan(`using ProcessorService as service from '../../srv/services';
using from '../../db/schema';
using { acme.incidents as entity } from '../../db/schema';

annotate service.Incidents with @(UI.HeaderInfo: { TypeName: 'POISON_title' });
annotate service.Incidents with @(restrict: [{ grant: 'READ', to: 'auditor' }]);
annotate service with @(requires: 'admin');
`);
    expect(file.usings).toEqual([
      { alias: 'service', target: 'ProcessorService' },
      { alias: 'entity', target: 'acme.incidents' },
    ]);
    expect(file.services).toEqual([]);
    expect(file.entities).toEqual([]);
    expect(file.annotates.map((a) => [a.target, a.line, a.requires, a.restrictTo])).toEqual([
      ['service.Incidents', 5, [], []],
      ['service.Incidents', 6, [], ['auditor']],
      ['service', 7, ['admin'], []],
    ]);
    expect(JSON.stringify(file)).not.toContain('POISON');
  });

  it('still ends a statement without `;` at the next keyword', () => {
    const file = scan(`using db.Books as Titles from '../db/schema'
service S { entity Titles as projection on Titles }
entity E { key ID : UUID; }`);
    expect(file.usings).toEqual([{ alias: 'Titles', target: 'db.Books' }]);
    expect(file.services.map((s) => [s.name, s.entities.map((e) => e.name)])).toEqual([
      ['S', ['Titles']],
    ]);
    expect(file.entities.map((e) => e.name)).toEqual(['E']);
  });
});

describe('scanCds: model entities', () => {
  it('reads fields, associations and nested compositions of top-level entities', () => {
    const file = scan(`namespace acme.incidents;
using { cuid, managed } from '@sap/cds/common';

entity Customers : cuid, managed {
  firstName    : String(100);
  email        : String(255) @title: 'POISON_title';
  creditCardNo : String(19) @assert.format: 'POISON_format';
  remarks      : String(500) default 'POISON_default';
  addresses    : Composition of many Addresses on addresses.customer = $self;
  incidents    : Association to many Incidents on incidents.customer = $self;
  status       : Association to Status default 'N';
  urgency      : String(1) enum { high = 'H'; medium = 'M'; } default 'M';
  conversation : Composition of many {
    key ID    : UUID;
    timestamp : DateTime;
    author    : String(100);
  };
  virtual flag : Boolean;
}

context nested {
  entity Inside { key ID : UUID; owner : Association to one db.Users; }
}

type Name : String(80);
aspect tracked { tracer : String; }
`);
    expect(file.entities).toHaveLength(2);
    const [customers, inside] = file.entities;
    expect(customers).toEqual({
      name: 'Customers',
      line: 4,
      fields: [
        'firstName',
        'email',
        'creditCardNo',
        'remarks',
        'addresses',
        'incidents',
        'status',
        'urgency',
        'conversation',
        'ID',
        'timestamp',
        'author',
        'flag',
      ],
      personalData: false,
      associations: [
        { field: 'addresses', target: 'Addresses' },
        { field: 'incidents', target: 'Incidents' },
        { field: 'status', target: 'Status' },
      ],
    });
    expect(inside).toEqual({
      name: 'Inside',
      line: 22,
      fields: ['ID', 'owner'],
      personalData: false,
      associations: [{ field: 'owner', target: 'db.Users' }],
    });
    expect(JSON.stringify(file)).not.toContain('POISON');
    expect(JSON.stringify(file)).not.toContain('tracer');
  });

  it('detects @PersonalData on the header, in a group, on an element and in annotate blocks', () => {
    const file = scan(`@PersonalData.EntitySemantics: 'DataSubject'
entity A { key ID : UUID; }
entity B @(PersonalData.EntitySemantics: 'Other') { key ID : UUID; }
entity C {
  @PersonalData.FieldSemantics: 'DataSubjectID'
  email : String;
}
entity D { phone : String @PersonalData.IsPotentiallyPersonal; }
entity E { name : String; }
annotate E with @PersonalData.EntitySemantics: 'DataSubject';
annotate F with { phone @PersonalData.IsPotentiallyPersonal; };
annotate G with @(PersonalData: { EntitySemantics: 'DataSubject' });
annotate H with @title: 'PersonalData';
annotate I with @requires: 'admin' @restrict: [{ grant: 'READ', to: 'x' }];
`);
    expect(file.entities.map((e) => [e.name, e.personalData])).toEqual([
      ['A', true],
      ['B', true],
      ['C', true],
      ['D', true],
      ['E', false],
    ]);
    expect(file.annotates).toEqual([
      { target: 'E', line: 10, personalData: true, requires: [], restrictTo: [] },
      { target: 'F', line: 11, personalData: true, requires: [], restrictTo: [] },
      { target: 'G', line: 12, personalData: true, requires: [], restrictTo: [] },
      { target: 'H', line: 13, personalData: false, requires: [], restrictTo: [] },
      { target: 'I', line: 14, personalData: false, requires: ['admin'], restrictTo: ['x'] },
    ]);
  });

  it('ignores comments and strings and keeps line numbers across them', () => {
    const file = scan(`// @requires: 'commented'
/* service Fake {}
   @requires: 'blocked' */
@title: 'service Quoted { @requires: ''q'' }'
service Real {}
`);
    expect(file.services).toEqual([
      {
        name: 'Real',
        line: 5,
        requires: [],
        restrictTo: [],
        protocolNone: false,
        external: false,
        entities: [],
        actions: [],
      },
    ]);
  });

  it('drops definitions without an identifier-shaped name and handles an empty file', () => {
    expect(scan('')).toEqual({
      file: 'srv/test.cds',
      usings: [],
      services: [],
      entities: [],
      annotates: [],
    });
    const file = scan('entity ![odd name] { key ID : UUID; } service { } entity Ok {}');
    expect(file.entities.map((e) => e.name)).toEqual(['Ok']);
    expect(file.services).toEqual([]);
  });

  it('caps every list', () => {
    const services = Array.from({ length: CDS_LIMITS.services + 5 }, (_, i) => `service S${i} {}`);
    expect(scan(services.join('\n')).services).toHaveLength(CDS_LIMITS.services);
    const entities = Array.from({ length: CDS_LIMITS.entities + 5 }, (_, i) => `entity E${i} {}`);
    expect(scan(entities.join('\n')).entities).toHaveLength(CDS_LIMITS.entities);
    const fields = Array.from({ length: CDS_LIMITS.fields + 5 }, (_, i) => `f${i} : String;`);
    expect(scan(`entity E { ${fields.join(' ')} }`).entities[0]?.fields).toHaveLength(
      CDS_LIMITS.fields,
    );
    const annotates = Array.from(
      { length: CDS_LIMITS.annotates + 5 },
      (_, i) => `annotate A${i} with @x;`,
    );
    expect(scan(annotates.join('\n')).annotates).toHaveLength(CDS_LIMITS.annotates);
    const roles = Array.from({ length: CDS_LIMITS.roles + 5 }, (_, i) => `'r${i}'`);
    expect(
      scan(`@requires: [${roles.join(', ')}] service S {}`).services[0]?.requires,
    ).toHaveLength(CDS_LIMITS.roles);
  });

  it('finishes hostile input in linear time (no nested quantifiers)', () => {
    const repeated = "@requires:'".repeat((2 * 1024 * 1024) / 11);
    const nested = '{'.repeat(50_000);
    const started = Date.now();
    expect(() => scan(repeated)).not.toThrow();
    expect(() => scan(`service S ${nested}`)).not.toThrow();
    expect(() => scan(`entity E ${nested}`)).not.toThrow();
    expect(() => scan(`${repeated}${nested}`)).not.toThrow();
    // Sub-second on a developer machine; a super-linear regression takes minutes, so a
    // wide budget keeps a slow, fully loaded CI runner out of the noise band.
    expect(Date.now() - started).toBeLessThan(10_000);
  }, 30_000);

  it('scans a generated model of 20 000 entities in time linear to its size', () => {
    // A `cds import` model: many entities, each with a few annotated elements.
    const entities = Array.from(
      { length: 20_000 },
      (_, i) => `@cds.persistence.skip
entity E${i} {
  key ID : UUID;
  @title: 'Name' name : String(100);
  city : String(100);
  owner : Association to E${i};
}`,
    );
    const text = entities.join('\n');
    expect(text.length).toBeGreaterThan(1_400_000);
    const started = Date.now();
    const file = scan(text);
    const elapsed = Date.now() - started;
    expect(file.entities).toHaveLength(CDS_LIMITS.entities);
    expect(file.entities[CDS_LIMITS.entities - 1]).toMatchObject({
      fields: ['ID', 'name', 'city', 'owner'],
      associations: [{ field: 'owner', target: `E${CDS_LIMITS.entities - 1}` }],
    });
    // Well under 2 s on a developer machine; the budget only guards against a regression
    // back to a scan that rereads the file once per definition (80 s for this input).
    expect(elapsed).toBeLessThan(20_000);
  }, 60_000);
});
