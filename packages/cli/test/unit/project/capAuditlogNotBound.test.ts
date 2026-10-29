import { describe, expect, it } from 'vitest';
import {
  ALSNG_BINDING_NAME,
  AUDIT_LOGGING_PLUGIN,
  AUDIT_LOG_SERVICE,
  BOUND_RESOURCE_TYPES,
  RULE_ID,
  capAuditlogNotBound,
} from '../../../src/analyzers/project/capAuditlogNotBound.js';
import { FindingSchema } from '../../../src/model/finding.js';
import { owaspUrl } from '../../../src/model/owasp.js';
import type { CdsAuditLogKind, RawMta, RawProject } from '../../../src/model/raw.js';
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

/** The srv module requiring xsuaa and hana, no audit log resource. */
function unboundMta(overrides: Parameters<typeof mta>[0] = {}): RawMta {
  return mta({
    modules: [{ name: 'acme-srv', type: 'nodejs', requires: ['acme-auth', 'acme-db'] }],
    resources: [
      { name: 'acme-auth', type: 'org.cloudfoundry.managed-service', service: 'xsuaa' },
      { name: 'acme-db', type: 'org.cloudfoundry.managed-service', service: 'hana' },
    ],
    ...overrides,
  });
}

function pluginProject(
  overrides: Parameters<typeof rawProject>[0] = {},
  deps: string[] = ['@sap/cds', AUDIT_LOGGING_PLUGIN],
): RawProject {
  return rawProject({ packageJson: packageJson(deps), mta: unboundMta(), ...overrides });
}

function productionKind(kind: CdsAuditLogKind | null): RawProject['cds'] {
  return cdsEffective('production', { auditLogKind: kind, auditLogConfigured: kind !== null });
}

describe('CAP_AUDITLOG_NOT_BOUND', () => {
  it('names the plugin, service and binding it looks for', () => {
    expect(RULE_ID).toBe('CAP_AUDITLOG_NOT_BOUND');
    expect(AUDIT_LOGGING_PLUGIN).toBe('@cap-js/audit-logging');
    expect(AUDIT_LOG_SERVICE).toBe('auditlog');
    expect(ALSNG_BINDING_NAME).toBe('auditlog-ng');
    expect(BOUND_RESOURCE_TYPES).toEqual([
      'org.cloudfoundry.existing-service',
      'org.cloudfoundry.user-provided-service',
    ]);
  });

  it('fires once, medium, when the plugin is installed and mta.yaml binds no audit log service', () => {
    const findings = runRule(capAuditlogNotBound, pluginProject());
    expect(findings).toHaveLength(1);
    const finding = findings[0]!;
    expect(finding.id).toBe(RULE_ID);
    expect(finding.severity).toBe('medium');
    expect(finding.title).toBe('Audit logging is installed but no audit log service is bound');
    expect(finding.app).toEqual({
      guid: 'project:acme',
      name: 'acme',
      space: 'project',
      org: 'local',
    });
    expect(finding.evidence).toEqual({
      subject: 'auditlog',
      auditLogKind: null,
      auditLogConfigured: false,
      modules: 1,
      resources: 2,
      impact: 'moderate',
      easeOfAttack: 'advanced',
    });
    expect(finding.location).toEqual({ file: 'mta.yaml' });
    expect(finding.remediation).toContain('service: auditlog');
    expect(finding.remediation).toContain('auditlog-ng');
    expect(FindingSchema.safeParse(finding).success).toBe(true);
  });

  it.each(['audit-log-to-restv2', 'audit-log-to-alsng'] as const)(
    'fires when production uses the service-backed kind %s',
    (kind) => {
      const findings = runRule(capAuditlogNotBound, pluginProject({ cds: productionKind(kind) }));
      expect(findings).toHaveLength(1);
      expect(findings[0]!.evidence.auditLogKind).toBe(kind);
      expect(findings[0]!.evidence.auditLogConfigured).toBe(true);
    },
  );

  it('fires when the production kind is unset even though development logs to the console', () => {
    const project = pluginProject({
      cds: cdsEffective('development', {
        auditLogKind: 'audit-log-to-console',
        auditLogConfigured: true,
      }),
    });
    expect(runRule(capAuditlogNotBound, project)).toHaveLength(1);
  });

  /* `audit-log: true`, or an object with `impl` but no `kind`, leaves the plugin's production default (restv2) in force. */
  it('fires when audit-log is configured for production without a kind', () => {
    const project = pluginProject({
      cds: cdsEffective('production', { auditLogKind: null, auditLogConfigured: true }),
    });
    const findings = runRule(capAuditlogNotBound, project);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.evidence.auditLogKind).toBeNull();
    expect(findings[0]!.evidence.auditLogConfigured).toBe(true);
  });

  it('counts the plugin in devDependencies as installed', () => {
    const project = rawProject({
      packageJson: packageJson(['@sap/cds'], [AUDIT_LOGGING_PLUGIN]),
      mta: unboundMta(),
    });
    expect(runRule(capAuditlogNotBound, project)).toHaveLength(1);
  });

  it('points at mta.yml when the descriptor has that name', () => {
    const project = pluginProject({ mta: unboundMta({ file: 'mta.yml' }) });
    expect(runRule(capAuditlogNotBound, project)[0]!.location).toEqual({ file: 'mta.yml' });
  });

  it('does not count a managed-service resource that only has audit in its name', () => {
    const project = pluginProject({
      mta: unboundMta({
        resources: [
          { name: 'acme-auditlog', type: 'org.cloudfoundry.managed-service', service: 'xsuaa' },
        ],
      }),
    });
    expect(runRule(capAuditlogNotBound, project)).toHaveLength(1);
  });

  it('does not count a module requiring an unrelated resource named after audit', () => {
    const project = pluginProject({
      mta: unboundMta({
        modules: [{ name: 'acme-srv', requires: ['auditlog-ng-but-not'] }],
        resources: [{ name: 'auditlog-ng-but-not', type: 'org.cloudfoundry.managed-service' }],
      }),
    });
    expect(runRule(capAuditlogNotBound, project)).toHaveLength(1);
  });

  describe('does not fire', () => {
    it('when @cap-js/audit-logging is not a dependency', () => {
      expect(runRule(capAuditlogNotBound, pluginProject({}, ['@sap/cds']))).toEqual([]);
      expect(
        runRule(capAuditlogNotBound, pluginProject({}, ['@sap/cds', '@sap/audit-logging'])),
      ).toEqual([]);
      expect(runRule(capAuditlogNotBound, rawProject({ mta: unboundMta() }))).toEqual([]);
    });

    it('when there is no MTA descriptor', () => {
      expect(runRule(capAuditlogNotBound, pluginProject({ mta: null }))).toEqual([]);
    });

    it.each(['audit-log-to-console', 'audit-log-to-library', 'other'] as const)(
      'when the production kind %s needs no service binding',
      (kind) => {
        const project = pluginProject({ cds: productionKind(kind) });
        expect(runRule(capAuditlogNotBound, project)).toEqual([]);
      },
    );

    it.each([
      'org.cloudfoundry.managed-service',
      'org.cloudfoundry.existing-service',
      null,
    ] as const)('when a resource of type %s has service auditlog', (type) => {
      const project = pluginProject({
        mta: unboundMta({
          resources: [{ name: 'acme-logs', type, service: AUDIT_LOG_SERVICE, plan: 'premium' }],
        }),
      });
      expect(runRule(capAuditlogNotBound, project)).toEqual([]);
    });

    /* Documented limits: neither the plan nor the module's `requires` list is checked. */
    it('when the auditlog resource has another plan and no module requires it', () => {
      const project = pluginProject({
        mta: unboundMta({
          modules: [{ name: 'acme-srv', requires: ['acme-auth'] }],
          resources: [
            {
              name: 'acme-auditlog',
              type: 'org.cloudfoundry.managed-service',
              service: AUDIT_LOG_SERVICE,
              plan: 'oauth2',
            },
          ],
        }),
      });
      expect(runRule(capAuditlogNotBound, project)).toEqual([]);
    });

    it.each(BOUND_RESOURCE_TYPES)(
      'when a resource of type %s is named after an audit log instance',
      (type) => {
        for (const name of ['my-auditlog-service', 'AuditLog', 'audit']) {
          const project = pluginProject({ mta: unboundMta({ resources: [{ name, type }] }) });
          expect(runRule(capAuditlogNotBound, project), name).toEqual([]);
        }
      },
    );

    it('when a module requires the auditlog-ng binding', () => {
      const project = pluginProject({
        mta: unboundMta({
          modules: [{ name: 'acme-srv', requires: ['acme-auth', ALSNG_BINDING_NAME] }],
        }),
      });
      expect(runRule(capAuditlogNotBound, project)).toEqual([]);
    });
  });

  it('links the CAP guide, the plugin, the SAP Help page and OWASP A09:2025', () => {
    const finding = runRule(capAuditlogNotBound, pluginProject())[0]!;
    expect(finding.references).toEqual([
      'https://cap.cloud.sap/docs/guides/security/dpp-audit-logging',
      'https://github.com/cap-js/audit-logging',
      'https://help.sap.com/docs/btp/sap-business-technology-platform/audit-log-write-api-for-customers',
      owaspUrl('A09:2025'),
    ]);
  });

  it('emits one finding per project, sorted by project name whatever the input order', () => {
    const projects = [
      pluginProject({ id: 'zeta', cds: productionKind('audit-log-to-alsng') }),
      pluginProject({ id: 'mid', mta: null }),
      pluginProject(),
    ];
    const expected = [
      ['acme', null],
      ['zeta', 'audit-log-to-alsng'],
    ];
    const names = (findings: ReturnType<typeof runRule>) =>
      findings.map((f) => [f.app.name, f.evidence.auditLogKind]);
    expect(names(runRule(capAuditlogNotBound, ...projects))).toEqual(expected);
    expect(names(runRule(capAuditlogNotBound, ...projects.reverse()))).toEqual(expected);
  });

  it('is deterministic', () => {
    expectDeterministic(
      capAuditlogNotBound,
      pluginProject({ cds: productionKind('audit-log-to-restv2') }),
    );
  });

  it('copies nothing from the project but counts, booleans, the kind and the fixed subject', () => {
    const poisoned = rawProject({
      sourcesRead: ['.cdsrc.json', 'package.json'],
      files: POISON,
      unreadable: POISON.map((file) => ({ file, kind: 'yaml' as const })),
      packageJson: {
        ...packageJson(
          {
            [AUDIT_LOGGING_PLUGIN]: POISON[0]!,
            ...Object.fromEntries(POISON.map((v) => [v, v])),
          },
          POISON,
          POISON[1],
        ),
        name: POISON[2]!,
      },
      cds: cdsEffective('production', {
        authKind: 'mocked',
        mockedUsers: POISON.length,
        mockedUsersWithPassword: POISON.length,
        auditLogKind: 'audit-log-to-restv2',
        auditLogConfigured: true,
      }),
      mta: mta({
        id: null,
        file: 'mta.yml',
        modules: POISON.map((value) => ({
          name: value,
          type: value,
          buildpack: value,
          requires: [value],
        })),
        resources: POISON.map((value) => ({
          name: value,
          type: 'org.cloudfoundry.managed-service',
          service: value,
          plan: value,
        })),
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
      cdsFiles: POISON.map((value) =>
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
            entity(value, [value, 'email'], {
              personalData: true,
              associations: [{ field: value, target: value }],
            }),
          ],
          annotates: [annotate(value, { personalData: true, requires: [value] })],
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
    const findings = runRule(capAuditlogNotBound, poisoned);
    expect(findings).toHaveLength(1);
    expectNoValueLeak(findings, POISON);
    expect(findings[0]!.location).toEqual({ file: 'mta.yml' });
    expect(findings[0]!.evidence.modules).toBe(POISON.length);
    expect(findings[0]!.evidence.resources).toBe(POISON.length);
  });
});
