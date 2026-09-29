import type { ReportData } from '../model/snapshot.js';

/**
 * RFC 4180 cell. Cells that a spreadsheet would treat as a formula
 * (=, +, -, @, tab, CR) get a leading apostrophe (OWASP CSV injection).
 */
export function csvCell(value: unknown): string {
  let text =
    value === null || value === undefined
      ? ''
      : typeof value === 'string'
        ? value
        : typeof value === 'number' || typeof value === 'boolean'
          ? String(value)
          : JSON.stringify(value);
  if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`;
  return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

function toCsv(header: string[], rows: unknown[][]): string {
  return [header, ...rows].map((row) => row.map(csvCell).join(',')).join('\r\n') + '\r\n';
}

export function renderFindingsCsv(data: ReportData): string {
  return toCsv(
    [
      'rule_id',
      'severity',
      'title',
      'org',
      'space',
      'app',
      'app_guid',
      'remediation',
      'references',
      'evidence',
    ],
    data.findings.map((f) => [
      f.id,
      f.severity,
      f.title,
      f.app.org,
      f.app.space,
      f.app.name,
      f.app.guid,
      f.remediation,
      f.references.join(' '),
      f.evidence,
    ]),
  );
}

export function renderAppsCsv(data: ReportData): string {
  return toCsv(
    [
      'org',
      'space',
      'app',
      'app_guid',
      'state',
      'lifecycle',
      'stack',
      'buildpacks',
      'last_deploy_at',
      'risk_score',
      'highest_severity',
      'critical',
      'high',
      'medium',
      'low',
      'info',
    ],
    data.apps.map((a) => [
      a.org,
      a.space,
      a.name,
      a.guid,
      a.state,
      a.lifecycleType,
      a.stack,
      a.buildpacks.map((b) => (b.version ? `${b.name}@${b.version}` : b.name)).join(' '),
      a.lastDeployAt,
      a.riskScore,
      a.highestSeverity,
      a.findingCounts.critical,
      a.findingCounts.high,
      a.findingCounts.medium,
      a.findingCounts.low,
      a.findingCounts.info,
    ]),
  );
}
