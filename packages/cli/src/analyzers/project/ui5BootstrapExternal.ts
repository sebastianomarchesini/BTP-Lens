import type { Finding } from '../../model/finding.js';
import { owaspUrl } from '../../model/owasp.js';
import type { RawHtmlBootstrap, RawProject } from '../../model/raw.js';
import { type Analyzer, type AnalyzerContext, ruleHelpUri } from '../types.js';
import { type MatrixSeverity, projectFinding } from './support.js';

export const RULE_ID = 'UI5_BOOTSTRAP_EXTERNAL';

/*
 * An unversioned CDN URL serves whatever the host publishes next, so the page
 * changes without a deploy and nobody can say which code ran when.
 */
const UNPINNED: MatrixSeverity = { impact: 'moderate', easeOfAttack: 'advanced' };
/*
 * A pinned version still trusts the host, but a swap would have to target one
 * fixed artifact; a test page is not what end users open. The design table
 * wrote this cell as `low = ('minor', 'advanced')`, but that pair is `medium`
 * in the matrix; `complex` is the pair that yields `low`.
 */
const PINNED_OR_TEST: MatrixSeverity = { impact: 'minor', easeOfAttack: 'complex' };

/** A DNS host name (or dotted IPv4 address); anything else is not recorded. */
const HOSTNAME = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/i;
const MAX_HOSTNAME_LENGTH = 253;

const REMEDIATION =
  'Serve SAPUI5 through the approuter instead of a public CDN: route `resources/` to the `ui5` ' +
  'destination or to the HTML5 Application Repository, so the version is controlled by the ' +
  'landscape and does not change behind a deployed app. Where the CDN must stay, pin a specific ' +
  'version (`https://ui5.sap.com/1.120.3/resources/sap-ui-core.js`) rather than the evergreen or ' +
  'unversioned form, and add `integrity="sha384-…"` with `crossorigin="anonymous"` to the ' +
  'bootstrap script, knowing that they protect only the loader: the libraries it fetches at run ' +
  'time are still trusted blindly. Keep the pinned version inside maintenance, since the CDN ' +
  'removes versions one year after their end of maintenance.';

const REFERENCES = [
  'https://ui5.sap.com/#/topic/2d3eb2f322ea4a82983c1c62a33ec4ae',
  'https://me.sap.com/notes/3001696',
  owaspUrl('A08:2025'),
];

/** The host of an external bootstrap, or null when the src carries none that looks like one. */
export function bootstrapHost(src: string): string | null {
  let hostname: string;
  try {
    hostname = new URL(src).hostname;
  } catch {
    return null;
  }
  if (hostname.length === 0 || hostname.length > MAX_HOSTNAME_LENGTH) return null;
  return HOSTNAME.test(hostname) ? hostname : null;
}

function triggers(bootstrap: RawHtmlBootstrap): boolean {
  return bootstrap.external && !bootstrap.integrity;
}

function isUnpinned(bootstrap: RawHtmlBootstrap): boolean {
  return bootstrap.versionForm === 'latest' && !bootstrap.testPage;
}

/**
 * The unpinned one wins; among equals the first in the file, and on one line
 * the lower src, so the pick never depends on the order the collector emitted.
 */
function moreSevere(a: RawHtmlBootstrap, b: RawHtmlBootstrap): boolean {
  if (isUnpinned(a) !== isUnpinned(b)) return isUnpinned(a);
  if (a.line !== b.line) return a.line < b.line;
  return a.src.localeCompare(b.src) < 0;
}

/** One bootstrap per file: the worst of those loaded externally without integrity, sorted by file. */
function unprotectedBootstraps(project: RawProject): RawHtmlBootstrap[] {
  const byFile = new Map<string, RawHtmlBootstrap>();
  for (const bootstrap of project.html) {
    if (!triggers(bootstrap)) continue;
    const current = byFile.get(bootstrap.file);
    if (current === undefined || moreSevere(bootstrap, current))
      byFile.set(bootstrap.file, bootstrap);
  }
  return [...byFile.values()].sort((a, b) => a.file.localeCompare(b.file));
}

function findingFor(
  context: AnalyzerContext,
  project: RawProject,
  bootstrap: RawHtmlBootstrap,
): Finding {
  return projectFinding(context, project, {
    id: RULE_ID,
    title: ui5BootstrapExternal.rule.title,
    subject: bootstrap.file,
    severity: isUnpinned(bootstrap) ? UNPINNED : PINNED_OR_TEST,
    evidence: {
      host: bootstrapHost(bootstrap.src),
      versionForm: bootstrap.versionForm,
      testPage: bootstrap.testPage,
    },
    location: { file: bootstrap.file, line: bootstrap.line },
    remediation: REMEDIATION,
    references: [...REFERENCES],
  });
}

/**
 * UI5_BOOTSTRAP_EXTERNAL: an HTML page bootstraps SAPUI5 from another host
 * without an `integrity` attribute, so whatever that host serves runs with
 * the application's session. See docs/rules.md.
 */
export const ui5BootstrapExternal: Analyzer = {
  rule: {
    id: RULE_ID,
    title: 'SAPUI5 loaded from an external CDN without integrity protection',
    description:
      'An HTML page bootstraps SAPUI5 from an external host without an integrity attribute, so the application trusts whatever that host serves, including an unpinned latest version.',
    roles: [],
    owasp: ['A08:2025'],
    helpUri: ruleHelpUri(RULE_ID),
  },
  requires: ['collect.project'],
  analyze(context): Finding[] {
    return context.raw.projects.flatMap((project) =>
      unprotectedBootstraps(project).map((bootstrap) => findingFor(context, project, bootstrap)),
    );
  },
};
