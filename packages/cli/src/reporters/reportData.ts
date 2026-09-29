import { ANALYZERS } from '../analyzers/index.js';
import { emptySeverityCounts } from '../model/severity.js';
import type { ReportData, Snapshot } from '../model/snapshot.js';

/** The report view of a snapshot: no raw data, plus summary and rule metadata. */
export function toReportData(snapshot: Snapshot): ReportData {
  const findingsBySeverity = emptySeverityCounts();
  for (const finding of snapshot.findings) findingsBySeverity[finding.severity] += 1;
  return {
    schemaVersion: snapshot.schemaVersion,
    tool: snapshot.tool,
    scannedAt: snapshot.scannedAt,
    scope: snapshot.scope,
    options: snapshot.options,
    checks: snapshot.checks,
    apps: snapshot.apps,
    findings: snapshot.findings,
    rules: ANALYZERS.map((a) => a.rule),
    summary: {
      apps: snapshot.apps.length,
      findings: snapshot.findings.length,
      findingsBySeverity,
      checksSkipped: snapshot.checks.filter((c) => c.status === 'skipped').length,
    },
  };
}
