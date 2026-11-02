import { describe, expect, it } from 'vitest';
import {
  RULE_ID,
  XSAPPNAME_PREFIX,
  xsuaaScopeUnused,
} from '../../../src/analyzers/project/xsuaaScopeUnused.js';
import { FindingSchema } from '../../../src/model/finding.js';
import { owaspUrl } from '../../../src/model/owasp.js';
import type { RawProject, RawXsSecurity } from '../../../src/model/raw.js';
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

function project(descriptors: RawXsSecurity[], overrides: Partial<RawProject> = {}): RawProject {
  return rawProject({ xsSecurity: descriptors, ...overrides });
}

/** `admin` referenced by a template, `unused` not. */
function descriptor(opts: Partial<Parameters<typeof xsSecurity>[0]> = {}): RawXsSecurity {
  return xsSecurity({
    scopes: ['$XSAPPNAME.admin', '$XSAPPNAME.unused'],
    roleTemplates: [['Admin', ['$XSAPPNAME.admin']]],
    ...opts,
  });
}

const subjects = (findings: ReturnType<typeof runRule>) =>
  findings.map((f) => [f.evidence.subject, f.severity]);

describe('XSUAA_SCOPE_UNUSED', () => {
  it('declares the local scope prefix', () => {
    expect(RULE_ID).toBe('XSUAA_SCOPE_UNUSED');
    expect(XSAPPNAME_PREFIX).toBe('$XSAPPNAME.');
  });

  it('fires low for a scope no role template references', () => {
    const findings = runRule(xsuaaScopeUnused, project([descriptor()]));
    expect(findings).toHaveLength(1);
    const finding = findings[0]!;
    expect(finding.id).toBe(RULE_ID);
    expect(finding.severity).toBe('low');
    expect(finding.title).toBe('Scope is defined but no role template references it');
    expect(finding.app).toEqual({
      guid: 'project:acme',
      name: 'acme',
      space: 'project',
      org: 'local',
    });
    expect(finding.evidence).toEqual({
      subject: '$XSAPPNAME.unused',
      source: 'xs-security.json',
      roleTemplates: 1,
      descriptors: 1,
      impact: 'minor',
      easeOfAttack: 'complex',
    });
    expect(finding.location).toEqual({ file: 'xs-security.json' });
    expect(FindingSchema.safeParse(finding).success).toBe(true);
  });

  it('fires for a descriptor without any role template at all', () => {
    const findings = runRule(
      xsuaaScopeUnused,
      project([xsSecurity({ scopes: ['$XSAPPNAME.read'] })]),
    );
    expect(subjects(findings)).toEqual([['$XSAPPNAME.read', 'low']]);
    expect(findings[0]!.evidence).toMatchObject({ roleTemplates: 0, descriptors: 1 });
  });

  it('fires for the inline config of an xsuaa resource in mta.yaml', () => {
    const findings = runRule(
      xsuaaScopeUnused,
      project([descriptor({ file: 'mta.yaml', source: 'mta.yaml' })]),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]!.evidence).toMatchObject({ source: 'mta.yaml' });
    expect(findings[0]!.location).toEqual({ file: 'mta.yaml' });
  });

  it('fires for a scope written without the $XSAPPNAME prefix', () => {
    const findings = runRule(
      xsuaaScopeUnused,
      project([xsSecurity({ scopes: ['read', 'write'], roleTemplates: [['Reader', ['read']]] })]),
    );
    expect(subjects(findings)).toEqual([['write', 'low']]);
  });

  it('is always low: minor impact, complex to exploit', () => {
    const [finding] = runRule(xsuaaScopeUnused, project([descriptor()]));
    expect(finding!.severity).toBe('low');
    expect(finding!.evidence).toMatchObject({ impact: 'minor', easeOfAttack: 'complex' });
  });

  describe('does not fire', () => {
    const none = (descriptors: RawXsSecurity[]) =>
      expect(runRule(xsuaaScopeUnused, project(descriptors))).toEqual([]);

    it('for a scope a role template references by its exact name', () => {
      none([
        xsSecurity({
          scopes: ['$XSAPPNAME.admin'],
          roleTemplates: [['Admin', ['$XSAPPNAME.admin']]],
        }),
      ]);
    });

    it('for a scope referenced with or without the $XSAPPNAME prefix', () => {
      none([xsSecurity({ scopes: ['$XSAPPNAME.admin'], roleTemplates: [['Admin', ['admin']]] })]);
      none([xsSecurity({ scopes: ['admin'], roleTemplates: [['Admin', ['$XSAPPNAME.admin']]] })]);
    });

    it('for a scope referenced by one of several templates, among foreign references', () => {
      none([
        xsSecurity({
          scopes: ['$XSAPPNAME.admin', '$XSAPPNAME.support'],
          roleTemplates: [
            ['Token_Exchange', ['uaa.user']],
            ['Admin', ['$XSAPPNAME.admin', '$XSAPPNAME.support']],
          ],
        }),
      ]);
    });

    it('for a scope granted to other applications', () => {
      none([
        xsSecurity({
          scopes: [{ name: '$XSAPPNAME.callback', grantedToApps: true }],
          roleTemplates: [],
        }),
      ]);
    });

    it('for a scope referenced by a template in another descriptor of the project', () => {
      none([
        xsSecurity({ file: 'xs-security.json', scopes: ['$XSAPPNAME.admin'] }),
        xsSecurity({
          file: 'mta.yaml',
          source: 'mta.yaml',
          scopes: [],
          roleTemplates: [['Admin', ['$XSAPPNAME.admin']]],
        }),
      ]);
    });

    it('when the project has no XSUAA descriptor or no scopes', () => {
      none([]);
      none([xsSecurity({ scopes: [], roleTemplates: [['Token_Exchange', ['uaa.user']]] })]);
      none([xsSecurity({ scopes: [], attributes: ['Country'] })]);
    });

    it('for a scope that differs from the reference only by a prefix other than $XSAPPNAME', () => {
      expect(
        subjects(
          runRule(
            xsuaaScopeUnused,
            project([
              xsSecurity({
                scopes: ['$XSAPPNAME.admin', 'other.admin'],
                roleTemplates: [['Admin', ['$XSAPPNAME.admin']]],
              }),
            ]),
          ),
        ),
      ).toEqual([['other.admin', 'low']]);
    });
  });

  it('emits one finding per scope, sorted by name, whatever the descriptor order', () => {
    const findings = runRule(
      xsuaaScopeUnused,
      project([
        xsSecurity({
          file: 'app/b/xs-security.json',
          scopes: ['$XSAPPNAME.zeta', '$XSAPPNAME.beta'],
        }),
        xsSecurity({
          file: 'app/a/xs-security.json',
          scopes: ['$XSAPPNAME.alpha', '$XSAPPNAME.used'],
          roleTemplates: [['User', ['$XSAPPNAME.used']]],
        }),
      ]),
    );
    expect(subjects(findings)).toEqual([
      ['$XSAPPNAME.alpha', 'low'],
      ['$XSAPPNAME.beta', 'low'],
      ['$XSAPPNAME.zeta', 'low'],
    ]);
    expect(findings.map((f) => f.location?.file)).toEqual([
      'app/a/xs-security.json',
      'app/b/xs-security.json',
      'app/b/xs-security.json',
    ]);
    expect(findings.map((f) => f.evidence.descriptors)).toEqual([2, 2, 2]);
  });

  it('emits one finding per subject when two descriptors define the same unused scope', () => {
    const findings = runRule(
      xsuaaScopeUnused,
      project([
        xsSecurity({ file: 'xs-security.json', scopes: ['$XSAPPNAME.unused'] }),
        xsSecurity({ file: 'mta.yaml', source: 'mta.yaml', scopes: ['$XSAPPNAME.unused'] }),
      ]),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]!.location).toEqual({ file: 'mta.yaml' });
    expect(findings[0]!.evidence).toMatchObject({ source: 'mta.yaml', descriptors: 2 });
  });

  it('treats a scope spelt with and without the prefix in two descriptors as one scope', () => {
    const findings = runRule(
      xsuaaScopeUnused,
      project([
        xsSecurity({ file: 'xs-security.json', scopes: ['$XSAPPNAME.unused'] }),
        xsSecurity({ file: 'mta.yaml', source: 'mta.yaml', scopes: ['unused'] }),
      ]),
    );
    expect(subjects(findings)).toEqual([['unused', 'low']]);
    expect(findings[0]!.location).toEqual({ file: 'mta.yaml' });
  });

  it('does not depend on the order of descriptors that share a file and source', () => {
    // Two xsuaa resources in one mta.yaml both define the scope; the richer one is the location.
    const sparse = xsSecurity({ file: 'mta.yaml', source: 'mta.yaml', scopes: ['$XSAPPNAME.x'] });
    const rich = xsSecurity({
      file: 'mta.yaml',
      source: 'mta.yaml',
      scopes: ['$XSAPPNAME.x', '$XSAPPNAME.y'],
      roleTemplates: [['Y', ['$XSAPPNAME.y']]],
    });
    const forward = runRule(xsuaaScopeUnused, project([sparse, rich]));
    const reversed = runRule(xsuaaScopeUnused, project([rich, sparse]));
    expect(reversed).toEqual(forward);
    expect(subjects(forward)).toEqual([['$XSAPPNAME.x', 'low']]);
    expect(forward[0]!.evidence).toMatchObject({ roleTemplates: 1, descriptors: 2 });
  });

  it('reports each project on its own', () => {
    const findings = runRule(
      xsuaaScopeUnused,
      project([descriptor()]),
      rawProject({
        id: 'other',
        xsSecurity: [
          xsSecurity({ scopes: ['$XSAPPNAME.a'], roleTemplates: [['A', ['$XSAPPNAME.a']]] }),
        ],
      }),
      rawProject({ id: 'third', xsSecurity: [xsSecurity({ scopes: ['$XSAPPNAME.a'] })] }),
    );
    expect(findings.map((f) => [f.app.name, f.evidence.subject])).toEqual([
      ['acme', '$XSAPPNAME.unused'],
      ['third', '$XSAPPNAME.a'],
    ]);
  });

  it('links the SAP Help descriptor and role topics, the CAP users guide and OWASP A02:2025', () => {
    const finding = runRule(xsuaaScopeUnused, project([descriptor()]))[0]!;
    expect(finding.references).toEqual([
      'https://help.sap.com/docs/btp/sap-business-technology-platform/application-security-descriptor-configuration-syntax',
      'https://help.sap.com/docs/btp/sap-business-technology-platform/building-roles-and-role-collections-for-applications',
      'https://cap.cloud.sap/docs/guides/security/cap-users',
      owaspUrl('A02:2025'),
    ]);
    expect(finding.remediation).toContain('scope-references');
    expect(finding.remediation).toContain('granted-apps');
    expect(finding.remediation).toContain('cds compile srv --to xsuaa');
  });

  it('is deterministic', () => {
    expectDeterministic(
      xsuaaScopeUnused,
      project([
        xsSecurity({
          file: 'app/b/xs-security.json',
          scopes: ['$XSAPPNAME.zeta', '$XSAPPNAME.beta'],
        }),
        descriptor({ file: 'mta.yaml', source: 'mta.yaml' }),
        descriptor(),
      ]),
    );
  });

  it('copies nothing from the project but the scope name and the descriptor file', () => {
    const poisoned = rawProject({
      sourcesRead: ['.cdsrc.json', 'package.json'],
      files: POISON,
      unreadable: POISON.map((file) => ({ file, kind: 'json' as const })),
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
      xsSecurity: [
        // The one descriptor that fires: its other scopes, templates and attributes are poisoned.
        xsSecurity({
          file: 'xs-security.json',
          scopes: [
            '$XSAPPNAME.unused',
            ...POISON.map((value) => ({ name: value, grantedToApps: true })),
          ],
          roleTemplates: POISON.map((value) => [value, [value, `$XSAPPNAME.${value}`]]),
          attributes: POISON,
        }),
        // Poisoned descriptors whose scopes are all referenced, so none of them fires.
        ...POISON.map((value) =>
          xsSecurity({
            file: value,
            source: 'mta.yaml',
            scopes: [value, `$XSAPPNAME.${value}`],
            roleTemplates: [[value, [value]]],
            attributes: [value],
          }),
        ),
      ],
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
      seedData: POISON.map((value) =>
        seedCsv(value, {
          sensitiveColumns: [{ columnIndex: 1, kind: 'secret', rowsMatching: 1 }],
        }),
      ),
      archives: POISON.map((value) => archive(value)),
      html: POISON.map((value) => htmlBootstrap(value, value)),
    });
    const findings = runRule(xsuaaScopeUnused, poisoned);
    expect(findings).toHaveLength(1);
    expectNoValueLeak(findings, POISON);
    expect(findings[0]!.evidence).toEqual({
      subject: '$XSAPPNAME.unused',
      source: 'xs-security.json',
      roleTemplates: POISON.length,
      descriptors: POISON.length + 1,
      impact: 'minor',
      easeOfAttack: 'complex',
    });
    expect(findings[0]!.location).toEqual({ file: 'xs-security.json' });
  });
});
