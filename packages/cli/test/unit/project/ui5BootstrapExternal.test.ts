import { describe, expect, it } from 'vitest';
import {
  RULE_ID,
  bootstrapHost,
  ui5BootstrapExternal,
} from '../../../src/analyzers/project/ui5BootstrapExternal.js';
import { ruleHelpUri } from '../../../src/analyzers/types.js';
import { FindingSchema } from '../../../src/model/finding.js';
import { owaspUrl } from '../../../src/model/owasp.js';
import type { RawHtmlBootstrap, RawProject } from '../../../src/model/raw.js';
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

const INDEX = 'app/incidents/webapp/index.html';
const SANDBOX = 'app/incidents/webapp/test/flpSandbox.html';
const LATEST = 'https://ui5.example.com/resources/sap-ui-core.js';
const SPECIFIC = 'https://ui5.example.com/1.120.3/resources/sap-ui-core.js';
const EVERGREEN = 'https://ui5.example.com/1.120/resources/sap-ui-core.js';
const RELATIVE = 'resources/sap-ui-core.js';

function project(html: RawHtmlBootstrap[], overrides: Partial<RawProject> = {}): RawProject {
  return rawProject({ html, ...overrides });
}

const subjects = (findings: ReturnType<typeof runRule>) =>
  findings.map((f) => [f.evidence.subject, f.severity]);

describe('UI5_BOOTSTRAP_EXTERNAL', () => {
  it('declares the rule metadata from the spec', () => {
    expect(RULE_ID).toBe('UI5_BOOTSTRAP_EXTERNAL');
    expect(ui5BootstrapExternal.rule).toMatchObject({
      id: RULE_ID,
      title: 'SAPUI5 loaded from an external CDN without integrity protection',
      roles: [],
      owasp: ['A08:2025'],
      helpUri: ruleHelpUri(RULE_ID),
    });
    expect(ui5BootstrapExternal.requires).toEqual(['collect.project']);
  });

  it('fires medium for an unversioned CDN bootstrap without integrity on a real page', () => {
    const findings = runRule(
      ui5BootstrapExternal,
      project([htmlBootstrap(INDEX, LATEST, { line: 12, versionForm: 'latest' })]),
    );
    expect(findings).toHaveLength(1);
    const finding = findings[0]!;
    expect(finding.id).toBe(RULE_ID);
    expect(finding.severity).toBe('medium');
    expect(finding.title).toBe('SAPUI5 loaded from an external CDN without integrity protection');
    expect(finding.app).toEqual({
      guid: 'project:acme',
      name: 'acme',
      space: 'project',
      org: 'local',
    });
    expect(finding.evidence).toEqual({
      subject: INDEX,
      host: 'ui5.example.com',
      versionForm: 'latest',
      testPage: false,
      impact: 'moderate',
      easeOfAttack: 'advanced',
    });
    expect(finding.location).toEqual({ file: INDEX, line: 12 });
    expect(FindingSchema.safeParse(finding).success).toBe(true);
  });

  it('fires low for a bootstrap pinned to a specific version', () => {
    const findings = runRule(
      ui5BootstrapExternal,
      project([htmlBootstrap(INDEX, SPECIFIC, { line: 7, versionForm: 'specific' })]),
    );
    expect(subjects(findings)).toEqual([[INDEX, 'low']]);
    expect(findings[0]!.evidence).toEqual({
      subject: INDEX,
      host: 'ui5.example.com',
      versionForm: 'specific',
      testPage: false,
      impact: 'minor',
      easeOfAttack: 'complex',
    });
    expect(findings[0]!.location).toEqual({ file: INDEX, line: 7 });
  });

  it('fires low for an evergreen version', () => {
    const findings = runRule(
      ui5BootstrapExternal,
      project([htmlBootstrap('app/launchpage.html', EVERGREEN, { versionForm: 'evergreen' })]),
    );
    expect(subjects(findings)).toEqual([['app/launchpage.html', 'low']]);
    expect(findings[0]!.evidence).toMatchObject({ versionForm: 'evergreen', testPage: false });
  });

  it('fires low for an unversioned bootstrap on a test page', () => {
    const findings = runRule(
      ui5BootstrapExternal,
      project([htmlBootstrap(SANDBOX, LATEST, { versionForm: 'latest', testPage: true })]),
    );
    expect(subjects(findings)).toEqual([[SANDBOX, 'low']]);
    expect(findings[0]!.evidence).toEqual({
      subject: SANDBOX,
      host: 'ui5.example.com',
      versionForm: 'latest',
      testPage: true,
      impact: 'minor',
      easeOfAttack: 'complex',
    });
  });

  it('fires low for a pinned version on a test page', () => {
    const findings = runRule(
      ui5BootstrapExternal,
      project([htmlBootstrap(SANDBOX, SPECIFIC, { versionForm: 'specific', testPage: true })]),
    );
    expect(subjects(findings)).toEqual([[SANDBOX, 'low']]);
  });

  it('fires for a plain http host as well', () => {
    const findings = runRule(
      ui5BootstrapExternal,
      project([htmlBootstrap(INDEX, 'http://cdn.example.com/resources/sap-ui-core.js')]),
    );
    expect(subjects(findings)).toEqual([[INDEX, 'medium']]);
    expect(findings[0]!.evidence.host).toBe('cdn.example.com');
  });

  describe('does not fire', () => {
    const none = (html: RawHtmlBootstrap[]) =>
      expect(runRule(ui5BootstrapExternal, project(html))).toEqual([]);

    it('for a bootstrap served relative to the app (approuter or HTML5 repository)', () => {
      none([htmlBootstrap(INDEX, RELATIVE)]);
      none([htmlBootstrap(INDEX, '/resources/sap-ui-core.js', { versionForm: 'none' })]);
    });

    it('for a relative bootstrap even when its path carries a version segment', () => {
      none([htmlBootstrap(INDEX, 'resources/1.120.3/sap-ui-core.js', { versionForm: 'specific' })]);
    });

    it('for a bootstrap with a non-http scheme', () => {
      none([htmlBootstrap(INDEX, '[non-http]', { external: false, versionForm: 'none' })]);
    });

    it('for an external bootstrap that carries an integrity attribute', () => {
      none([htmlBootstrap(INDEX, LATEST, { integrity: true, versionForm: 'latest' })]);
      none([htmlBootstrap(INDEX, SPECIFIC, { integrity: true, versionForm: 'specific' })]);
      none([htmlBootstrap(INDEX, EVERGREEN, { integrity: true, versionForm: 'evergreen' })]);
    });

    it('for a test page whose external bootstrap carries an integrity attribute', () => {
      none([htmlBootstrap(SANDBOX, LATEST, { integrity: true, testPage: true })]);
    });

    it('when the project has no HTML bootstrap at all', () => {
      none([]);
    });

    it('for a project whose pages are all relative or protected', () => {
      none([
        htmlBootstrap(INDEX, RELATIVE),
        htmlBootstrap(SANDBOX, SPECIFIC, { integrity: true, testPage: true }),
        htmlBootstrap('app/launchpage.html', 'resources/sap-ui-core.js', { versionForm: 'none' }),
      ]);
    });
  });

  describe('host', () => {
    it('is the host name of the src, without path, port, userinfo, query or fragment', () => {
      expect(bootstrapHost(LATEST)).toBe('ui5.example.com');
      expect(bootstrapHost('https://cdn.example.com:8443/1.120/resources/sap-ui-core.js')).toBe(
        'cdn.example.com',
      );
      expect(
        bootstrapHost('https://user:secret@cdn.example.com/resources/sap-ui-core.js?t=1#f'),
      ).toBe('cdn.example.com');
      expect(bootstrapHost('http://10.0.0.1/resources/sap-ui-core.js')).toBe('10.0.0.1');
    });

    it('is null when the src is not an absolute URL with a host name', () => {
      expect(bootstrapHost(RELATIVE)).toBeNull();
      expect(bootstrapHost('[non-http]')).toBeNull();
      expect(bootstrapHost('')).toBeNull();
      expect(bootstrapHost('not a url')).toBeNull();
      expect(bootstrapHost('C:\\Users\\someone\\sap-ui-core.js')).toBeNull();
      expect(bootstrapHost('https://[::1]/resources/sap-ui-core.js')).toBeNull();
      expect(bootstrapHost(`https://${'a'.repeat(64)}.example.com/x.js`)).toBeNull();
    });

    it('is recorded as null in the evidence when the src cannot be parsed', () => {
      const findings = runRule(
        ui5BootstrapExternal,
        project([htmlBootstrap(INDEX, 'not a url', { external: true, versionForm: 'latest' })]),
      );
      expect(findings).toHaveLength(1);
      expect(findings[0]!.evidence).toMatchObject({ host: null, versionForm: 'latest' });
    });
  });

  it('emits one finding per file, keeping the unpinned bootstrap over a pinned one', () => {
    const findings = runRule(
      ui5BootstrapExternal,
      project([
        htmlBootstrap(INDEX, SPECIFIC, { line: 5, versionForm: 'specific' }),
        htmlBootstrap(INDEX, LATEST, { line: 40, versionForm: 'latest' }),
      ]),
    );
    expect(subjects(findings)).toEqual([[INDEX, 'medium']]);
    expect(findings[0]!.location).toEqual({ file: INDEX, line: 40 });
    expect(findings[0]!.evidence.versionForm).toBe('latest');
  });

  it('keeps the first bootstrap of a file when both are equally severe', () => {
    const findings = runRule(
      ui5BootstrapExternal,
      project([
        htmlBootstrap(INDEX, LATEST, { line: 30 }),
        htmlBootstrap(INDEX, LATEST, { line: 9 }),
      ]),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]!.location).toEqual({ file: INDEX, line: 9 });
  });

  it('picks the lower src when two equal bootstraps share a line, whatever the collected order', () => {
    const a = htmlBootstrap(INDEX, 'https://a.example.com/resources/sap-ui-core.js', { line: 1 });
    const b = htmlBootstrap(INDEX, 'https://b.example.com/resources/sap-ui-core.js', { line: 1 });
    const forward = runRule(ui5BootstrapExternal, project([a, b]));
    const backward = runRule(ui5BootstrapExternal, project([b, a]));
    expect(forward).toHaveLength(1);
    expect(forward[0]!.evidence.host).toBe('a.example.com');
    expect(backward).toEqual(forward);
  });

  it('ignores a protected bootstrap in a file whose other bootstrap is unprotected', () => {
    const findings = runRule(
      ui5BootstrapExternal,
      project([
        htmlBootstrap(INDEX, LATEST, { line: 3, integrity: true }),
        htmlBootstrap(INDEX, SPECIFIC, { line: 8, versionForm: 'specific' }),
      ]),
    );
    expect(subjects(findings)).toEqual([[INDEX, 'low']]);
    expect(findings[0]!.location).toEqual({ file: INDEX, line: 8 });
  });

  it('sorts findings by severity, then by file, whatever the collected order', () => {
    const findings = runRule(
      ui5BootstrapExternal,
      project([
        htmlBootstrap('app/z/index.html', LATEST),
        htmlBootstrap(SANDBOX, SPECIFIC, { versionForm: 'specific', testPage: true }),
        htmlBootstrap('app/a/index.html', EVERGREEN, { versionForm: 'evergreen' }),
        htmlBootstrap(INDEX, RELATIVE),
      ]),
    );
    expect(subjects(findings)).toEqual([
      ['app/z/index.html', 'medium'],
      ['app/a/index.html', 'low'],
      [SANDBOX, 'low'],
    ]);
    expect(findings.map((f) => f.location?.file)).toEqual([
      'app/z/index.html',
      'app/a/index.html',
      SANDBOX,
    ]);
  });

  it('reports each project on its own', () => {
    const findings = runRule(
      ui5BootstrapExternal,
      project([htmlBootstrap(INDEX, LATEST)]),
      rawProject({ id: 'other', html: [htmlBootstrap(INDEX, RELATIVE)] }),
      rawProject({
        id: 'third',
        html: [htmlBootstrap('index.html', SPECIFIC, { versionForm: 'specific' })],
      }),
    );
    expect(findings.map((f) => [f.app.name, f.evidence.subject, f.severity])).toEqual([
      ['acme', INDEX, 'medium'],
      ['third', 'index.html', 'low'],
    ]);
  });

  it('links the SAPUI5 CDN topic, SAP Note 3001696 and OWASP A08:2025', () => {
    const finding = runRule(ui5BootstrapExternal, project([htmlBootstrap(INDEX, LATEST)]))[0]!;
    expect(finding.references).toEqual([
      'https://ui5.sap.com/#/topic/2d3eb2f322ea4a82983c1c62a33ec4ae',
      'https://me.sap.com/notes/3001696',
      owaspUrl('A08:2025'),
    ]);
    expect(finding.remediation).toContain('`ui5` destination');
    expect(finding.remediation).toContain('HTML5 Application Repository');
    expect(finding.remediation).toContain('integrity=');
    expect(finding.remediation).toContain('crossorigin="anonymous"');
    expect(finding.remediation).toContain('only the loader');
  });

  it('is deterministic', () => {
    const html = [
      htmlBootstrap('app/z/index.html', LATEST, { line: 20 }),
      htmlBootstrap('app/z/index.html', SPECIFIC, { line: 4, versionForm: 'specific' }),
      htmlBootstrap(SANDBOX, LATEST, { testPage: true }),
      htmlBootstrap(INDEX, RELATIVE),
      htmlBootstrap('app/a/index.html', EVERGREEN, { versionForm: 'evergreen' }),
    ];
    expectDeterministic(ui5BootstrapExternal, project(html));
    expect(runRule(ui5BootstrapExternal, project([...html].reverse()))).toEqual(
      runRule(ui5BootstrapExternal, project(html)),
    );
  });

  it('never derives a host from a value that is not an absolute URL', () => {
    for (const value of POISON) expect(bootstrapHost(value), value).toBeNull();
  });

  it('copies nothing from the project but the file name and the CDN host', () => {
    const poisoned = rawProject({
      repository: true,
      gitIgnore: { present: true },
      sourcesRead: ['.cdsrc.yaml', '.cdsrc.json', 'package.json'],
      files: POISON,
      unreadable: POISON.map((file) => ({ file, kind: 'html' as const })),
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
        modules: POISON.map((value) => ({
          name: value,
          type: value,
          path: value,
          buildpack: value,
          requires: [value],
        })),
        resources: POISON.map((value) => ({
          name: value,
          type: value,
          service: value,
          plan: value,
        })),
      }),
      xsSecurity: POISON.map((value) =>
        xsSecurity({
          file: value,
          scopes: [value, { name: `$XSAPPNAME.${value}`, grantedToApps: true }],
          roleTemplates: [[value, [value]]],
          attributes: [value],
        }),
      ),
      xsApps: POISON.map((value) =>
        xsApp(value, [{ source: value, authenticationType: 'none', csrfProtection: false }]),
      ),
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
          sensitiveColumns: [{ column: value, kind: 'secret', rowsMatching: 1 }],
        }),
      ),
      archives: POISON.map((value) => archive(value, { bytes: POISON.length })),
      html: [
        // The one bootstrap that fires: userinfo, query and fragment must not reach the host.
        htmlBootstrap(
          INDEX,
          'https://POISON_user:POISON_pw@cdn.example.com/resources/sap-ui-core.js?sap-ui-token=POISON_query#POISON_fragment',
          { line: 3, versionForm: 'latest' },
        ),
        // A poison src that fires on a clean file: the host cannot be parsed and stays null.
        ...POISON.map((value) =>
          htmlBootstrap('app/other/index.html', value, { external: true, versionForm: 'latest' }),
        ),
        // Poison-named files and srcs with nothing to report.
        ...POISON.map((value) => htmlBootstrap(value, value)),
        ...POISON.map((value) => htmlBootstrap(value, value, { external: true, integrity: true })),
        ...POISON.map((value) => htmlBootstrap(value, LATEST, { integrity: true, testPage: true })),
      ],
    });
    const findings = runRule(ui5BootstrapExternal, poisoned);
    expect(findings).toHaveLength(2);
    expectNoValueLeak(findings, POISON);
    expect(findings.map((f) => f.evidence.subject)).toEqual([INDEX, 'app/other/index.html']);
    expect(findings[0]!.evidence).toEqual({
      subject: INDEX,
      host: 'cdn.example.com',
      versionForm: 'latest',
      testPage: false,
      impact: 'moderate',
      easeOfAttack: 'advanced',
    });
    expect(findings[0]!.location).toEqual({ file: INDEX, line: 3 });
    expect(findings[1]!.evidence.host).toBeNull();
  });
});
