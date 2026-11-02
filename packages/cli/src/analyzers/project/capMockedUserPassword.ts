import type { Finding } from '../../model/finding.js';
import { owaspUrl } from '../../model/owasp.js';
import type { CdsSource, CdsView, RawProject } from '../../model/raw.js';
import { type Analyzer, type AnalyzerContext, ruleHelpUri } from '../types.js';
import { DEVELOPMENT_AUTH_KINDS } from './capMockedAuthInProd.js';
import { type MatrixSeverity, projectFinding } from './support.js';

export const RULE_ID = 'CAP_MOCKED_USER_PASSWORD';

/** The configuration key the finding is about, as `cds env get requires.auth.users` prints it. */
export const SUBJECT = 'requires.auth.users';

type View = keyof RawProject['cds']['effective'];

/** The cds env sources the collector reads, lowest priority first (docs/data-sources.md). */
const SOURCE_PRIORITY: readonly CdsSource[] = ['.cdsrc.yaml', '.cdsrc.json', 'package.json'];

const TITLES: Record<View, string> = {
  development: 'Mocked users carry passwords in the development configuration',
  production: 'Mocked users carry passwords in the production configuration',
};

/** The source cds applies last among those read: where a reader should look first. */
function highestPrioritySource(sourcesRead: readonly CdsSource[]): CdsSource | undefined {
  return [...SOURCE_PRIORITY].reverse().find((source) => sourcesRead.includes(source));
}

/**
 * Production users outrank development users: they are reachable from the
 * deployed app, so one finding reports the production view when both carry
 * passwords.
 */
function affectedView(project: RawProject): View | undefined {
  const { development, production } = project.cds.effective;
  if (production.mockedUsersWithPassword > 0) return 'production';
  if (development.mockedUsersWithPassword > 0) return 'development';
  return undefined;
}

/**
 * Medium only when the passwords are usable in production and nothing else
 * reports that configuration. When CAP_MOCKED_AUTH_IN_PROD fires, the
 * critical finding already covers the impersonation risk, and development
 * passwords are reachable only locally; both are a low-severity hygiene issue.
 */
function severityFor(view: View, production: CdsView): MatrixSeverity {
  const mockedAuthInProd =
    production.authKind !== null && DEVELOPMENT_AUTH_KINDS.includes(production.authKind);
  return view === 'production' && !mockedAuthInProd
    ? { impact: 'moderate', easeOfAttack: 'complex' }
    : { impact: 'minor', easeOfAttack: 'complex' };
}

function findingFor(context: AnalyzerContext, project: RawProject): Finding | undefined {
  const view = affectedView(project);
  if (view === undefined) return undefined;
  const effective = project.cds.effective[view];
  const file = highestPrioritySource(project.sourcesRead);
  return projectFinding(context, project, {
    id: RULE_ID,
    title: TITLES[view],
    subject: SUBJECT,
    severity: severityFor(view, project.cds.effective.production),
    evidence: {
      view,
      usersWithPassword: effective.mockedUsersWithPassword,
      mockedUsers: effective.mockedUsers,
      authKind: effective.authKind,
    },
    ...(file ? { location: { file } } : {}),
    remediation:
      'Delete the `password` values from the mocked users in `cds.requires.auth.users` and keep the ' +
      '`users` block under `[development]` only, so it never applies to production. A developer who ' +
      'needs a password-protected local login can define it in `.cdsrc-private.json`, which cds reads ' +
      'but which must stay out of version control. If any of these passwords was ever reused on ' +
      'another system, change it there.',
    references: [
      'https://cap.cloud.sap/docs/node.js/authentication#mocked',
      'https://cap.cloud.sap/docs/node.js/cds-env',
      owaspUrl('A07:2025'),
    ],
  });
}

/**
 * CAP_MOCKED_USER_PASSWORD: the effective configuration defines mocked users
 * with a `password` key, in the development or the production view. The
 * collector counts the keys only; no user name or password is ever read.
 * See docs/rules.md.
 */
export const capMockedUserPassword: Analyzer = {
  rule: {
    id: RULE_ID,
    title: 'Mocked users carry passwords in the project configuration',
    description:
      'Mocked CAP users are defined with a password in a project configuration file (package.json or .cdsrc). Passwords in source files travel with every clone and are easy to reuse against other systems.',
    roles: [],
    owasp: ['A07:2025'],
    helpUri: ruleHelpUri(RULE_ID),
  },
  requires: ['collect.project'],
  analyze(context): Finding[] {
    return context.raw.projects.flatMap((project) => findingFor(context, project) ?? []);
  },
};
