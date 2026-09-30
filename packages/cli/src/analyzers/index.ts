import type { CheckResult } from '../model/check.js';
import type { AppRef, Finding } from '../model/finding.js';
import type { RawData } from '../model/raw.js';
import { type Severity, emptySeverityCounts, severityRank } from '../model/severity.js';
import type { AppInventoryItem, Snapshot } from '../model/snapshot.js';
import { noRecentDeploy } from './noRecentDeploy.js';
import { type Analyzer, type AnalyzerContext, ruleCheck } from './types.js';

/** Every rule, in report order. */
export const ANALYZERS: readonly Analyzer[] = [noRecentDeploy];

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
  /** One result per rule: ran, or skipped because a collector was skipped. */
  ruleChecks: CheckResult[];
}

function appRefResolver(raw: RawData): (appGuid: string) => AppRef | undefined {
  const spaces = new Map(raw.spaces.map((s) => [s.guid, s]));
  const orgs = new Map(raw.orgs.map((o) => [o.guid, o]));
  const apps = new Map(raw.apps.map((a) => [a.guid, a]));
  return (appGuid) => {
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

function compareFindings(a: Finding, b: Finding): number {
  return (
    severityRank(b.severity) - severityRank(a.severity) ||
    a.id.localeCompare(b.id) ||
    a.app.org.localeCompare(b.app.org) ||
    a.app.space.localeCompare(b.app.space) ||
    a.app.name.localeCompare(b.app.name)
  );
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
  const items = raw.apps.map((app): AppInventoryItem => {
    const ref = appRef(app.guid);
    const droplet = droplets.get(app.guid);
    const appFindings = byApp.get(app.guid) ?? [];
    const findingCounts = emptySeverityCounts();
    for (const finding of appFindings) findingCounts[finding.severity] += 1;
    const highest = appFindings.reduce<Severity | null>(
      (top, f) => (top === null || severityRank(f.severity) > severityRank(top) ? f.severity : top),
      null,
    );
    return {
      guid: app.guid,
      name: app.name,
      org: ref?.org ?? '(unknown)',
      space: ref?.space ?? '(unknown)',
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
      findingCounts,
      highestSeverity: highest,
      riskScore: appFindings.reduce((sum, f) => sum + RISK_WEIGHTS[f.severity], 0),
    };
  });
  return items.sort((a, b) => b.riskScore - a.riskScore || a.name.localeCompare(b.name));
}

/**
 * Pure analysis of collected data. `report --from snapshot.json` calls this
 * again offline, so it must not read the clock or the network.
 */
export function analyze(
  raw: RawData,
  scannedAt: string,
  collectorChecks: readonly CheckResult[],
  analyzers: readonly Analyzer[] = ANALYZERS,
): AnalysisResult {
  const appRef = appRefResolver(raw);
  const context: AnalyzerContext = { now: new Date(scannedAt), raw, appRef };
  const status = new Map(collectorChecks.map((c) => [c.id, c.status]));
  const findings: Finding[] = [];
  const ruleChecks: CheckResult[] = [];

  for (const analyzer of analyzers) {
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
