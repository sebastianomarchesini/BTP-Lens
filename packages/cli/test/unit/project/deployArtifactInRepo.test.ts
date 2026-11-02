import { describe, expect, it } from 'vitest';
import {
  RULE_ID,
  deployArtifactInRepo,
} from '../../../src/analyzers/project/deployArtifactInRepo.js';
import { ruleHelpUri } from '../../../src/analyzers/types.js';
import { FindingSchema } from '../../../src/model/finding.js';
import { owaspUrl } from '../../../src/model/owasp.js';
import type { RawArchive, RawProject } from '../../../src/model/raw.js';
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

const ARCHIVE = 'mta_archives/acme_1.0.0.mtar';

function project(archives: RawArchive[], overrides: Partial<RawProject> = {}): RawProject {
  return rawProject({ archives, ...overrides });
}

const subjects = (findings: ReturnType<typeof runRule>) =>
  findings.map((f) => [f.evidence.subject, f.severity]);

describe('DEPLOY_ARTIFACT_IN_REPO', () => {
  it('declares the rule metadata from the spec', () => {
    expect(RULE_ID).toBe('DEPLOY_ARTIFACT_IN_REPO');
    expect(deployArtifactInRepo.rule).toMatchObject({
      id: RULE_ID,
      title: 'Deployment archive (.mtar) is not ignored by git',
      roles: [],
      owasp: ['A03:2025'],
      helpUri: ruleHelpUri(RULE_ID),
    });
    expect(deployArtifactInRepo.requires).toEqual(['collect.project']);
  });

  it('fires medium for an unignored archive in a git repository', () => {
    const findings = runRule(
      deployArtifactInRepo,
      project([archive(ARCHIVE, { bytes: 4096 })], { repository: true }),
    );
    expect(findings).toHaveLength(1);
    const finding = findings[0]!;
    expect(finding.id).toBe(RULE_ID);
    expect(finding.severity).toBe('medium');
    expect(finding.title).toBe('Deployment archive (.mtar) is not ignored by git');
    expect(finding.app).toEqual({
      guid: 'project:acme',
      name: 'acme',
      space: 'project',
      org: 'local',
    });
    expect(finding.evidence).toEqual({
      subject: ARCHIVE,
      bytes: 4096,
      ignored: false,
      repository: true,
      tracked: 'unknown',
      impact: 'moderate',
      easeOfAttack: 'advanced',
    });
    expect(finding.location).toEqual({ file: ARCHIVE });
    expect(FindingSchema.safeParse(finding).success).toBe(true);
  });

  it('fires low for an unignored archive in a folder that is not a git repository', () => {
    const findings = runRule(
      deployArtifactInRepo,
      project([archive(ARCHIVE, { bytes: 64 })], { repository: false }),
    );
    expect(subjects(findings)).toEqual([[ARCHIVE, 'low']]);
    expect(findings[0]!.evidence).toEqual({
      subject: ARCHIVE,
      bytes: 64,
      ignored: false,
      repository: false,
      tracked: 'unknown',
      impact: 'minor',
      easeOfAttack: 'complex',
    });
    expect(findings[0]!.location).toEqual({ file: ARCHIVE });
  });

  it('fires when a .gitignore exists but none of its patterns covers the archive', () => {
    const findings = runRule(
      deployArtifactInRepo,
      project([archive(ARCHIVE)], { repository: true, gitIgnore: { present: true } }),
    );
    expect(subjects(findings)).toEqual([[ARCHIVE, 'medium']]);
  });

  it('fires for an archive at the project root as well as in a subfolder', () => {
    const findings = runRule(
      deployArtifactInRepo,
      project([archive('acme.mtar'), archive('build/out/acme.mtar')]),
    );
    expect(subjects(findings)).toEqual([
      ['acme.mtar', 'low'],
      ['build/out/acme.mtar', 'low'],
    ]);
  });

  it('reports no line: the archive is never opened', () => {
    const [finding] = runRule(deployArtifactInRepo, project([archive(ARCHIVE)]));
    expect(finding!.location).toEqual({ file: ARCHIVE });
    expect(finding!.location?.line).toBeUndefined();
  });

  describe('does not fire', () => {
    const none = (archives: RawArchive[], overrides: Partial<RawProject> = {}) =>
      expect(runRule(deployArtifactInRepo, project(archives, overrides))).toEqual([]);

    it('for an archive a .gitignore pattern ignores', () => {
      none([archive(ARCHIVE, { ignored: true })], {
        repository: true,
        gitIgnore: { present: true },
      });
    });

    it('for an ignored archive even when the folder is not a repository', () => {
      none([archive(ARCHIVE, { ignored: true })], { repository: false });
    });

    it('when the project has no archive at all', () => {
      none([]);
      none([], { repository: true, gitIgnore: { present: false } });
    });

    it('for a repository without .gitignore that holds no archive', () => {
      none([], { repository: true, gitIgnore: { present: false }, mta: mta() });
    });

    it('when every archive is ignored', () => {
      none([archive('a.mtar', { ignored: true }), archive('b/c.mtar', { ignored: true })], {
        repository: true,
      });
    });
  });

  it('emits one finding per archive, sorted by file, whatever the collected order', () => {
    const findings = runRule(
      deployArtifactInRepo,
      project(
        [
          archive('mta_archives/zeta_1.0.0.mtar', { bytes: 3 }),
          archive('alpha.mtar', { bytes: 1, ignored: true }),
          archive('mta_archives/beta_1.0.0.mtar', { bytes: 2 }),
          archive('archive.mtar', { bytes: 4 }),
        ],
        { repository: true },
      ),
    );
    expect(subjects(findings)).toEqual([
      ['archive.mtar', 'medium'],
      ['mta_archives/beta_1.0.0.mtar', 'medium'],
      ['mta_archives/zeta_1.0.0.mtar', 'medium'],
    ]);
    expect(findings.map((f) => f.evidence.bytes)).toEqual([4, 2, 3]);
    expect(findings.map((f) => f.location?.file)).toEqual([
      'archive.mtar',
      'mta_archives/beta_1.0.0.mtar',
      'mta_archives/zeta_1.0.0.mtar',
    ]);
  });

  it('emits one finding per subject when the same file is listed twice', () => {
    const findings = runRule(
      deployArtifactInRepo,
      project([archive(ARCHIVE, { bytes: 1 }), archive(ARCHIVE, { bytes: 2 })]),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]!.evidence).toMatchObject({ subject: ARCHIVE, bytes: 1 });
  });

  it('still fires once when an ignored entry for the same file comes first', () => {
    const findings = runRule(
      deployArtifactInRepo,
      project([archive(ARCHIVE, { bytes: 1, ignored: true }), archive(ARCHIVE, { bytes: 2 })]),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]!.evidence).toMatchObject({ subject: ARCHIVE, bytes: 2, ignored: false });
  });

  it('yields the same findings when archives and projects arrive in reverse order', () => {
    const archives = [
      archive('mta_archives/zeta_1.0.0.mtar', { bytes: 3 }),
      archive('alpha.mtar', { bytes: 1, ignored: true }),
      archive('mta_archives/beta_1.0.0.mtar', { bytes: 2 }),
    ];
    const projects = [
      project(archives, { repository: true }),
      rawProject({ id: 'other', repository: false, archives }),
    ];
    const expected = runRule(deployArtifactInRepo, ...projects);
    expect(expected).toHaveLength(4);
    const reversed = projects.map((p) => ({ ...p, archives: [...p.archives].reverse() })).reverse();
    expect(runRule(deployArtifactInRepo, ...reversed)).toEqual(expected);
  });

  it('produces schema-valid findings in both severity branches', () => {
    const findings = runRule(
      deployArtifactInRepo,
      project([archive(ARCHIVE)], { repository: true }),
      rawProject({ id: 'other', repository: false, archives: [archive('other.mtar')] }),
    );
    expect(findings.map((f) => f.severity)).toEqual(['medium', 'low']);
    for (const finding of findings) {
      expect(FindingSchema.safeParse(finding).success).toBe(true);
      expect(Object.keys(finding.evidence).sort()).toEqual([
        'bytes',
        'easeOfAttack',
        'ignored',
        'impact',
        'repository',
        'subject',
        'tracked',
      ]);
    }
  });

  it('reports each project on its own, with the severity of its own repository flag', () => {
    const findings = runRule(
      deployArtifactInRepo,
      project([archive(ARCHIVE)], { repository: true }),
      rawProject({
        id: 'other',
        repository: true,
        archives: [archive('x.mtar', { ignored: true })],
      }),
      rawProject({ id: 'third', repository: false, archives: [archive('y.mtar')] }),
    );
    expect(findings.map((f) => [f.app.name, f.evidence.subject, f.severity])).toEqual([
      ['acme', ARCHIVE, 'medium'],
      ['third', 'y.mtar', 'low'],
    ]);
  });

  it('links git, the MTA build tool, SAP Help and OWASP A03:2025', () => {
    const finding = runRule(deployArtifactInRepo, project([archive(ARCHIVE)]))[0]!;
    expect(finding.references).toEqual([
      'https://git-scm.com/docs/gitignore',
      'https://sap.github.io/cloud-mta-build-tool/usage/',
      'https://help.sap.com/docs/btp/sap-business-technology-platform/multitarget-applications-in-the-cloud-foundry-environment',
      owaspUrl('A03:2025'),
    ]);
    expect(finding.remediation).toContain('*.mtar');
    expect(finding.remediation).toContain('git rm --cached');
    expect(finding.remediation).toContain('mbt build');
  });

  it('is deterministic', () => {
    expectDeterministic(
      deployArtifactInRepo,
      project(
        [
          archive('mta_archives/zeta_1.0.0.mtar'),
          archive('alpha.mtar', { ignored: true }),
          archive('mta_archives/beta_1.0.0.mtar'),
        ],
        { repository: true, gitIgnore: { present: true } },
      ),
    );
  });

  it('copies nothing from the project but the archive file name', () => {
    const poisoned = rawProject({
      repository: true,
      gitIgnore: { present: true },
      sourcesRead: ['.cdsrc.yaml', '.cdsrc.json', 'package.json'],
      files: POISON,
      unreadable: POISON.map((file) => ({ file, kind: 'binary' as const })),
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
          sensitiveColumns: [{ columnIndex: 1, kind: 'secret', rowsMatching: 1 }],
        }),
      ),
      archives: [
        // The one archive that fires; every poison-named archive is ignored and must stay silent.
        archive(ARCHIVE, { bytes: 64 }),
        ...POISON.map((value) => archive(value, { bytes: POISON.length, ignored: true })),
      ],
      html: POISON.map((value) => htmlBootstrap(value, value)),
    });
    const findings = runRule(deployArtifactInRepo, poisoned);
    expect(findings).toHaveLength(1);
    expectNoValueLeak(findings, POISON);
    expect(findings[0]!.evidence).toEqual({
      subject: ARCHIVE,
      bytes: 64,
      ignored: false,
      repository: true,
      tracked: 'unknown',
      impact: 'moderate',
      easeOfAttack: 'advanced',
    });
    expect(findings[0]!.location).toEqual({ file: ARCHIVE });
  });
});
