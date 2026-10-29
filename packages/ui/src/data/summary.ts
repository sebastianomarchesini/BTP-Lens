import type { ReportData } from '@btp-lens/model';
import { formatDate } from './format';

/**
 * Plain-language phrases per rule, for readers who are not developers.
 * `n` is the number of apps affected for a Cloud Foundry rule and the number
 * of findings for a project rule, where one project yields many findings
 * (one per service, entity, route, ...).
 */
const RULE_PHRASES: Record<string, (n: number) => string> = {
  RUNTIME_NODE_EOL: (n) =>
    `${n} ${run(n)} a Node.js version that no longer receives security fixes`,
  RUNTIME_JAVA_EOL: (n) => `${n} ${run(n)} a Java version that no longer receives security fixes`,
  BUILDPACK_OUTDATED: (n) => `${n} ${were(n)} built with an outdated buildpack`,
  STACK_DEPRECATED: (n) => `${n} ${run(n)} on a deprecated operating system stack`,
  APP_IDLE: (n) => `${n} ${look(n)} unused`,
  APP_NO_RECENT_DEPLOY: (n) => `${n} ${have(n)} not been deployed in over a year`,
  UI5_OUT_OF_MAINTENANCE: (n) => `${n} ${use(n)} a SAPUI5 version that is out of maintenance`,
  SAP_PKG_OUTDATED: (n) => `${n} ${use(n)} outdated SAP libraries`,
  DEP_KNOWN_CVE: (n) => `${n} ${use(n)} a library with a known vulnerability`,
  ENV_SECRET_PLAINTEXT: (n) => `${n} ${have(n)} environment variable names that look like secrets`,
  CAP_MOCKED_AUTH_IN_PROD: (n) =>
    `mocked authentication is configured for production${inProjects(n)}`,
  CAP_MOCKED_USER_PASSWORD: (n) =>
    `mocked users carry passwords in the project configuration${inProjects(n)}`,
  CAP_AUDITLOG_MISSING: (n) =>
    `personal data is modelled but audit logging is not set up${inProjects(n)}`,
  CAP_AUDITLOG_NOT_BOUND: (n) =>
    `audit logging is installed but no audit log service is bound${inProjects(n)}`,
  CAP_PERSONAL_DATA_UNANNOTATED: (n) =>
    `${count(n, 'entity', 'entities')} ${hold(n)} personal data without @PersonalData annotations`,
  CAP_SERVICE_NO_RESTRICTION: (n) =>
    `${count(n, 'service')} ${is(n)} open to every authenticated user`,
  CAP_ROLE_NOT_IN_XSUAA: (n) =>
    `${count(n, 'role')} used in the CDS model ${have(n)} no scope in the XSUAA descriptor`,
  XSUAA_SCOPE_UNUSED: (n) =>
    `${count(n, 'scope')} ${is(n)} defined but not referenced by any role template`,
  APPROUTER_ROUTE_NO_AUTH: (n) =>
    `${count(n, 'approuter route')} ${forward(n)} requests without authentication`,
  APPROUTER_CSRF_DISABLED: (n) =>
    `${count(n, 'authenticated approuter route')} ${have(n)} CSRF protection disabled`,
  DEPLOY_ARTIFACT_IN_REPO: (n) =>
    `${count(n, 'deployment archive')} (.mtar) ${is(n)} not ignored by git`,
  SEED_DATA_SENSITIVE: (n) =>
    `${count(n, 'seed data column')} ${contain(n)} card numbers, IBANs or secrets`,
  UI5_BOOTSTRAP_EXTERNAL: (n) =>
    `${count(n, 'page')} ${load(n)} SAPUI5 from an external CDN without integrity protection`,
};

const run = (n: number) => (n === 1 ? 'runs' : 'run');
const were = (n: number) => (n === 1 ? 'was' : 'were');
const look = (n: number) => (n === 1 ? 'looks' : 'look');
const have = (n: number) => (n === 1 ? 'has' : 'have');
const use = (n: number) => (n === 1 ? 'uses' : 'use');
const is = (n: number) => (n === 1 ? 'is' : 'are');
const hold = (n: number) => (n === 1 ? 'holds' : 'hold');
const forward = (n: number) => (n === 1 ? 'forwards' : 'forward');
const contain = (n: number) => (n === 1 ? 'contains' : 'contain');
const load = (n: number) => (n === 1 ? 'loads' : 'load');
const count = (n: number, noun: string, plural = `${noun}s`) => `${n} ${n === 1 ? noun : plural}`;
const apps = (n: number) => count(n, 'app');
const findings = (n: number) => count(n, 'finding');
/** Rules that fire once per project read as a statement; the count matters only across projects. */
const inProjects = (n: number) => (n === 1 ? '' : ` in ${n} projects`);

type Scope = ReportData['scope'];

/** A scan of local project files (`btp-lens project`) rather than of a CF org. */
export function isProjectScope(scope: Scope): boolean {
  return scope.orgs.length === 0 && (scope.projects?.length ?? 0) > 0;
}

/** Every inventory row is a local project, so app-only columns and grouping make no sense. */
export function isProjectInventory(apps: ReportData['apps']): boolean {
  return apps.length > 0 && apps.every((app) => app.kind === 'project');
}

/** "acme-prod", "acme-prod / prod" when the scan was limited to spaces, or "acme-incidents" for a project. */
export function scopeLabel(scope: Scope): string {
  if (isProjectScope(scope)) return (scope.projects ?? []).join(', ');
  const orgs = scope.orgs.join(', ');
  return scope.spaces?.length ? `${orgs} / ${scope.spaces.join(', ')}` : orgs;
}

/** "acme-prod", "space prod of acme-prod" or "project acme-incidents" for a sentence. */
export function scopePhrase(scope: Scope): string {
  if (isProjectScope(scope)) {
    const projects = scope.projects ?? [];
    return `project${projects.length === 1 ? '' : 's'} ${projects.join(', ')}`;
  }
  const orgs = scope.orgs.join(', ');
  if (!scope.spaces?.length) return orgs;
  return `space${scope.spaces.length === 1 ? '' : 's'} ${scope.spaces.join(', ')} of ${orgs}`;
}

/** The three rules with the most affected apps (CF) or findings (project), as phrases. */
function topRulePhrases(data: ReportData, perFinding: boolean): string[] {
  const byRule = new Map<string, Set<string>>();
  data.findings.forEach((f, index) => {
    const key = perFinding ? String(index) : f.app.guid;
    (byRule.get(f.id) ?? byRule.set(f.id, new Set()).get(f.id))?.add(key);
  });
  return [...byRule.entries()]
    .sort((a, b) => b[1].size - a[1].size)
    .slice(0, 3)
    .map(([id, keys]) => {
      const phrase = RULE_PHRASES[id];
      const rule = data.rules.find((r) => r.id === id);
      return phrase ? phrase(keys.size) : `${keys.size} ${have(keys.size)} "${rule?.title ?? id}"`;
    });
}

/**
 * Three to four sentences a manager can read without knowing Cloud Foundry.
 * Everything is computed from the report data, so it is always true of the
 * scan being shown.
 */
export function startHereSentences(data: ReportData): string[] {
  const sentences: string[] = [];
  const project = isProjectScope(data.scope);
  const where = scopePhrase(data.scope);
  const when = formatDate(data.scannedAt);
  if (project) {
    const n = data.scope.projects?.length ?? 0;
    sentences.push(`The ${where} ${were(n)} scanned on ${when}.`);
  } else {
    sentences.push(
      `${apps(data.summary.apps)} in ${where} ${were(data.summary.apps)} scanned on ${when}.`,
    );
  }

  const affected = project
    ? data.findings.length
    : new Set(data.findings.map((f) => f.app.guid)).size;
  if (affected === 0) {
    sentences.push('No rule found a problem in the checks that ran.');
  } else {
    const subject = project ? findings(affected) : apps(affected);
    sentences.push(
      `${subject} need${affected === 1 ? 's' : ''} attention: ${topRulePhrases(data, project).join('; ')}.`,
    );
  }

  const skipped = data.summary.checksSkipped;
  if (skipped > 0) {
    const checks = `${skipped} check${skipped === 1 ? '' : 's'}`;
    sentences.push(
      project
        ? `${checks} could not run, so some things were not looked at. That is not a problem with your project.`
        : `${checks} could not run with your role, so some things were not looked at. That is not a problem with your apps.`,
    );
  }
  sentences.push(
    project
      ? 'Nothing in your project was changed: this scan only read files in the project folder.'
      : 'Nothing in your account was changed: this scan only read information.',
  );
  return sentences;
}
