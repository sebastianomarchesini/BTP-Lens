import type { Finding } from '../../model/finding.js';
import { owaspUrl } from '../../model/owasp.js';
import type { CdsAuthKind, CdsSource, RawProject } from '../../model/raw.js';
import { type Analyzer, type AnalyzerContext, ruleHelpUri } from '../types.js';
import { projectFinding } from './support.js';

export const RULE_ID = 'CAP_MOCKED_AUTH_IN_PROD';

/** The strategies CAP documents for development; production defaults to `jwt`. */
const DEVELOPMENT_AUTH_KIND_LIST = [
  'mocked',
  'dummy',
  'basic',
] as const satisfies readonly CdsAuthKind[];
type DevelopmentAuthKind = (typeof DEVELOPMENT_AUTH_KIND_LIST)[number];

/** Widened for callers that hold any `CdsAuthKind` (CAP_MOCKED_USER_PASSWORD). */
export const DEVELOPMENT_AUTH_KINDS: readonly CdsAuthKind[] = DEVELOPMENT_AUTH_KIND_LIST;

/**
 * The cds env sources the collector reads, lowest priority first, as the
 * "Sources for cds.env" table of the cds-env page orders them.
 */
const SOURCE_PRIORITY: readonly CdsSource[] = ['.cdsrc.yaml', '.cdsrc.json', 'package.json'];

/**
 * Sources cds also reads but the collector never opens, because they hold
 * credentials. `.cdsrc.js` sits in the same tier as `.cdsrc.yaml`/`.cdsrc.json`;
 * the others outrank `package.json#cds`. Any of them can still change the
 * strategy at runtime, so the finding names them as its limit.
 */
export const SOURCES_NOT_READ: readonly string[] = [
  '.cdsrc-private.json',
  '.cdsrc.js',
  '.env',
  'CDS_* environment variables',
];

/** The configuration key the finding is about, as `cds env get requires.auth` prints it. */
const SUBJECT = 'requires.auth';

const TITLES: Record<DevelopmentAuthKind, string> = {
  mocked: 'Mocked authentication is configured for production',
  dummy: 'Dummy authentication is configured for production',
  basic: 'Basic authentication with mocked users is configured for production',
};

function isDevelopmentAuth(kind: CdsAuthKind | null): kind is DevelopmentAuthKind {
  return kind !== null && DEVELOPMENT_AUTH_KINDS.includes(kind);
}

/** The source cds applies last among those read: where a reader should look first. */
function highestPrioritySource(sourcesRead: readonly CdsSource[]): CdsSource | undefined {
  return [...SOURCE_PRIORITY].reverse().find((source) => sourcesRead.includes(source));
}

function sourcesInPriorityOrder(sourcesRead: readonly CdsSource[]): CdsSource[] {
  return SOURCE_PRIORITY.filter((source) => sourcesRead.includes(source));
}

function findingFor(context: AnalyzerContext, project: RawProject): Finding | undefined {
  const authKind = project.cds.effective.production.authKind;
  if (!isDevelopmentAuth(authKind)) return undefined;
  const file = highestPrioritySource(project.sourcesRead);
  return projectFinding(context, project, {
    id: RULE_ID,
    title: TITLES[authKind],
    subject: SUBJECT,
    severity: { impact: 'severe', easeOfAttack: 'easy' },
    evidence: {
      authKind,
      sourcesRead: sourcesInPriorityOrder(project.sourcesRead),
      sourcesNotRead: [...SOURCES_NOT_READ],
    },
    ...(file ? { location: { file } } : {}),
    remediation:
      'Configure a production authentication strategy, for example in package.json: ' +
      '`"cds": { "requires": { "[production]": { "auth": "xsuaa" } } }` (or `"ias"`), bind the app ' +
      'to an XSUAA or IAS instance, and keep `mocked` and its users under `[development]` only. ' +
      'Verify the result with `cds env get requires.auth --profile production`.',
    references: [
      'https://cap.cloud.sap/docs/node.js/authentication',
      'https://cap.cloud.sap/docs/node.js/cds-env',
      owaspUrl('A07:2025'),
    ],
  });
}

/**
 * CAP_MOCKED_AUTH_IN_PROD: the effective production configuration selects a
 * development authentication strategy. Mocked and basic auth accept the users
 * listed in the project files, dummy auth accepts everyone and disables
 * `@requires`/`@restrict`. See docs/rules.md.
 */
export const capMockedAuthInProd: Analyzer = {
  rule: {
    id: RULE_ID,
    title: 'Mocked authentication is configured for production',
    description:
      'The effective CAP configuration for the production profile uses a development authentication strategy (mocked, dummy or basic). Anyone who knows a mocked user name can act as that user, and dummy authentication accepts every request.',
    roles: [],
    owasp: ['A07:2025'],
    helpUri: ruleHelpUri(RULE_ID),
  },
  requires: ['collect.project'],
  analyze(context): Finding[] {
    return context.raw.projects.flatMap((project) => findingFor(context, project) ?? []);
  },
};
