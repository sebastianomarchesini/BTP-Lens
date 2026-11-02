import type { CheckResult } from '../model/check.js';
import type { AppRef, Finding } from '../model/finding.js';
import type { RawData, RawProject } from '../model/raw.js';
import { type Severity, emptySeverityCounts, severityRank } from '../model/severity.js';
import type { AppInventoryItem, Snapshot } from '../model/snapshot.js';
import { noRecentDeploy } from './noRecentDeploy.js';
import { PROJECT_ANALYZERS } from './project/index.js';
import {
  type Analyzer,
  type AnalyzerContext,
  PROJECT_GUID_PREFIX,
  findingSubject,
  projectRef,
  ruleCheck,
} from './types.js';

/** Every rule, in report order: Cloud Foundry rules first, then project rules. */
export const ANALYZERS: readonly Analyzer[] = [noRecentDeploy, ...PROJECT_ANALYZERS];

/** Weights used to rank apps by risk (docs/rules.md). */
export const RISK_WEIGHTS: Record<Severity, number> = {
  critical: 100,
  high: 25,
  medium: 5,
  low: 1,
  info: 0,
};

export interface AnalysisResult {
  apps: AppInventoryItem[];
  findings: Finding[];
  /** One result per rule that applies to this scan: ran, or skipped because a collector was skipped. */
  ruleChecks: CheckResult[];
}

function appRefResolver(raw: RawData): (appGuid: string) => AppRef | undefined {
  const spaces = new Map(raw.spaces.map((s) => [s.guid, s]));
  const orgs = new Map(raw.orgs.map((o) => [o.guid, o]));
  const apps = new Map(raw.apps.map((a) => [a.guid, a]));
  const projects = new Map(raw.projects.map((p) => [`${PROJECT_GUID_PREFIX}${p.id}`, p]));
  return (appGuid) => {
    const project = projects.get(appGuid);
    if (project !== undefined) return projectRef(project);
    const app = apps.get(appGuid);
    if (app === undefined) return undefined;
    const space = spaces.get(app.spaceGuid);
    const org = space ? orgs.get(space.orgGuid) : undefined;
    return {
      guid: app.guid,
      name: app.name,
      space: space?.name ?? '(unknown)',
      org: org?.name ?? '(unknown)',
    };
  };
}

/** Sorts a missing value after every present one. */
function compareOptional<T extends string | number>(a: T | undefined, b: T | undefined): number {
  if (a === undefined) return b === undefined ? 0 : 1;
  if (b === undefined) return -1;
  return typeof a === 'number' && typeof b === 'number'
    ? a - b
    : String(a).localeCompare(String(b));
}

/**
 * Report order: worst first, then by rule, app and location. Every key a
 * project rule can vary is included, so two findings of one rule on one
 * project sort the same whatever order the rule emitted them in.
 */
export function compareFindings(a: Finding, b: Finding): number {
  return (
    severityRank(b.severity) - severityRank(a.severity) ||
    a.id.localeCompare(b.id) ||
    a.app.org.localeCompare(b.app.org) ||
    a.app.space.localeCompare(b.app.space) ||
    a.app.name.localeCompare(b.app.name) ||
    compareOptional(a.location?.file, b.location?.file) ||
    compareOptional(a.location?.line, b.location?.line) ||
    findingSubject(a).localeCompare(findingSubject(b)) ||
    a.title.localeCompare(b.title)
  );
}

interface Counted {
  findingCounts: AppInventoryItem['findingCounts'];
  highestSeverity: Severity | null;
  riskScore: number;
}

function countFindings(findings: Finding[]): Counted {
  const findingCounts = emptySeverityCounts();
  for (const finding of findings) findingCounts[finding.severity] += 1;
  const highestSeverity = findings.reduce<Severity | null>(
    (top, f) => (top === null || severityRank(f.severity) > severityRank(top) ? f.severity : top),
    null,
  );
  return {
    findingCounts,
    highestSeverity,
    riskScore: findings.reduce((sum, f) => sum + RISK_WEIGHTS[f.severity], 0),
  };
}

/** Buildpack names only: a buildpack given as a URL is not an inventory fact. */
const BUILDPACK_NAME = /^[A-Za-z0-9_.-]+$/;

function projectBuildpacks(project: RawProject): AppInventoryItem['buildpacks'] {
  const names = new Set<string>();
  for (const module of project.mta?.modules ?? []) {
    if (module.buildpack !== null && BUILDPACK_NAME.test(module.buildpack))
      names.add(module.buildpack);
  }
  return [...names].map((name) => ({ name, version: null }));
}

export function buildInventory(
  raw: RawData,
  findings: Finding[],
  appRef: (guid: string) => AppRef | undefined,
): AppInventoryItem[] {
  const droplets = new Map(raw.droplets.map((d) => [d.appGuid, d]));
  const byApp = new Map<string, Finding[]>();
  for (const finding of findings) {
    const list = byApp.get(finding.app.guid) ?? [];
    list.push(finding);
    byApp.set(finding.app.guid, list);
  }
  const apps = raw.apps.map((app): AppInventoryItem => {
    const ref = appRef(app.guid);
    const droplet = droplets.get(app.guid);
    return {
      guid: app.guid,
      name: app.name,
      org: ref?.org ?? '(unknown)',
      space: ref?.space ?? '(unknown)',
      kind: 'app',
      state: app.state,
      lifecycleType: droplet?.lifecycleType ?? app.lifecycleType,
      stack: droplet?.stack ?? app.stack,
      buildpacks: droplet
        ? droplet.buildpacks.map((bp) => ({
            name: bp.buildpackName ?? bp.name,
            version: bp.version,
          }))
        : app.buildpacks.map((name) => ({ name, version: null })),
      createdAt: app.createdAt,
      updatedAt: app.updatedAt,
      lastDeployAt: droplet?.createdAt ?? null,
      ...countFindings(byApp.get(app.guid) ?? []),
    };
  });
  const projects = raw.projects.map((project): AppInventoryItem => {
    const ref = projectRef(project);
    return {
      guid: ref.guid,
      name: ref.name,
      org: ref.org,
      space: ref.space,
      kind: 'project',
      state: null,
      lifecycleType: 'unknown',
      stack: null,
      buildpacks: projectBuildpacks(project),
      createdAt: null,
      updatedAt: null,
      lastDeployAt: null,
      ...countFindings(byApp.get(ref.guid) ?? []),
    };
  });
  return [...apps, ...projects].sort(
    (a, b) => b.riskScore - a.riskScore || a.name.localeCompare(b.name),
  );
}

/**
 * Pure analysis of collected data. `report --from snapshot.json` calls this
 * again offline, so it must not read the clock or the network.
 *
 * A rule whose collector was not part of the scan at all (a project rule in
 * a CF scan, or the reverse) is omitted: it is not a check of this scan. A
 * rule whose collector was part of the scan but skipped is recorded as
 * skipped, so the reader knows what was not looked at.
 */
export function analyze(
  raw: RawData,
  scannedAt: string,
  collectorChecks: readonly CheckResult[],
  analyzers: readonly Analyzer[] = ANALYZERS,
): AnalysisResult {
  const appRef = appRefResolver(raw);
  const context: AnalyzerContext = { now: new Date(scannedAt), raw, appRef, projectRef };
  const status = new Map(collectorChecks.map((c) => [c.id, c.status]));
  const findings: Finding[] = [];
  const ruleChecks: CheckResult[] = [];

  for (const analyzer of analyzers) {
    if (analyzer.requires.some((id) => !status.has(id))) continue;
    const check = ruleCheck(analyzer.rule);
    const missing = analyzer.requires.filter((id) => status.get(id) !== 'ran');
    if (missing.length > 0) {
      ruleChecks.push({
        id: check.id,
        title: check.title,
        roles: [...check.roles],
        status: 'skipped',
        reasonCode: 'dependency_skipped',
        reason: `needs ${missing.join(', ')}, which did not run`,
      });
      continue;
    }
    findings.push(...analyzer.analyze(context));
    ruleChecks.push({ id: check.id, title: check.title, roles: [...check.roles], status: 'ran' });
  }

  findings.sort(compareFindings);
  return { apps: buildInventory(raw, findings, appRef), findings, ruleChecks };
}

/**
 * Re-runs every rule on a stored snapshot (e.g. after upgrading btp-lens).
 * Collector results are kept; rule results and findings are recomputed.
 */
export function reanalyze(snapshot: Snapshot): Snapshot {
  const collectorChecks = snapshot.checks.filter((c) => c.id.startsWith('collect.'));
  const analysis = analyze(snapshot.raw, snapshot.scannedAt, collectorChecks);
  return {
    ...snapshot,
    checks: [...collectorChecks, ...analysis.ruleChecks],
    apps: analysis.apps,
    findings: analysis.findings,
  };
}
