import type { Finding } from '../../model/finding.js';
import { owaspUrl } from '../../model/owasp.js';
import type { RawArchive, RawProject } from '../../model/raw.js';
import { type Analyzer, type AnalyzerContext, ruleHelpUri } from '../types.js';
import { type MatrixSeverity, projectFinding } from './support.js';

export const RULE_ID = 'DEPLOY_ARTIFACT_IN_REPO';

/** With a `.git` directory the archive is one `git add .` away from the history. */
const IN_REPOSITORY: MatrixSeverity = { impact: 'moderate', easeOfAttack: 'advanced' };
/*
 * Without one the archive only lingers on disk until the folder is put under
 * version control or shared, an extra step for anyone to get at it. The
 * design table wrote this cell as `low = ('minor', 'advanced')`, but that
 * pair is `medium` in the matrix; `complex` is the pair that yields `low`.
 */
const NO_REPOSITORY: MatrixSeverity = { impact: 'minor', easeOfAttack: 'complex' };

const REMEDIATION =
  'Add `*.mtar` (or the build output folder, usually `mta_archives/`) to the root `.gitignore`. ' +
  'If the archive was already committed, stop tracking it with `git rm --cached <file>` and commit; ' +
  'if it reached a shared remote, treat every credential in its configuration files as exposed and ' +
  'rotate it, since removing the file does not remove it from the history. Build the archive in the ' +
  'pipeline with `mbt build` and deploy from there instead of keeping it next to the sources.';

const REFERENCES = [
  'https://git-scm.com/docs/gitignore',
  'https://sap.github.io/cloud-mta-build-tool/usage/',
  'https://help.sap.com/docs/btp/sap-business-technology-platform/multitarget-applications-in-the-cloud-foundry-environment',
  owaspUrl('A03:2025'),
];

/** Archives no .gitignore pattern covers, one per file, sorted by file. */
function unignoredArchives(project: RawProject): RawArchive[] {
  const byFile = new Map<string, RawArchive>();
  for (const archive of project.archives) {
    if (archive.ignored || byFile.has(archive.file)) continue;
    byFile.set(archive.file, archive);
  }
  return [...byFile.values()].sort((a, b) => a.file.localeCompare(b.file));
}

function findingFor(context: AnalyzerContext, project: RawProject, archive: RawArchive): Finding {
  return projectFinding(context, project, {
    id: RULE_ID,
    title: deployArtifactInRepo.rule.title,
    subject: archive.file,
    severity: project.repository ? IN_REPOSITORY : NO_REPOSITORY,
    evidence: {
      bytes: archive.bytes,
      ignored: archive.ignored,
      repository: project.repository,
      // The collector never runs git, so whether the file is already committed is not known.
      tracked: 'unknown',
    },
    location: { file: archive.file },
    remediation: REMEDIATION,
    references: [...REFERENCES],
  });
}

/**
 * DEPLOY_ARTIFACT_IN_REPO: a built MTA archive lies in the project and no
 * .gitignore pattern excludes it, so it is about to be, or already is, part
 * of the repository history with its resolved dependencies and generated
 * configuration. See docs/rules.md.
 */
export const deployArtifactInRepo: Analyzer = {
  rule: {
    id: RULE_ID,
    title: 'Deployment archive (.mtar) is not ignored by git',
    description:
      'A built MTA archive lies in the project and no .gitignore pattern excludes it. Archives carry resolved dependencies and generated configuration, and they end up in the repository history.',
    roles: [],
    owasp: ['A03:2025'],
    helpUri: ruleHelpUri(RULE_ID),
  },
  requires: ['collect.project'],
  analyze(context): Finding[] {
    return context.raw.projects.flatMap((project) =>
      unignoredArchives(project).map((archive) => findingFor(context, project, archive)),
    );
  },
};
