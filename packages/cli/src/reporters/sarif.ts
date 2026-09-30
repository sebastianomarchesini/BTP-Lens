import { createHash } from 'node:crypto';
import type { Finding } from '../model/finding.js';
import type { Severity } from '../model/severity.js';
import type { ReportData } from '../model/snapshot.js';

export const PROJECT_URL = 'https://github.com/sebastianomarchesini/BTP-Lens';

const LEVEL: Record<Severity, 'error' | 'warning' | 'note'> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
  info: 'note',
};

/** GitHub code scanning reads this property (0.0-10.0) to rank alerts. */
const SECURITY_SEVERITY: Record<Severity, string> = {
  critical: '9.5',
  high: '8.0',
  medium: '5.5',
  low: '3.0',
  info: '0.0',
};

/** Cloud resources have no file; this stable pseudo-path locates the app. */
function appUri(finding: Finding): string {
  const part = (s: string) => encodeURIComponent(s);
  return `cf/${part(finding.app.org)}/${part(finding.app.space)}/${part(finding.app.name)}`;
}

function fingerprint(finding: Finding): string {
  return createHash('sha256').update(`${finding.id}:${finding.app.guid}`).digest('hex');
}

/** SARIF 2.1.0 log with one run. */
export function renderSarif(data: ReportData): string {
  const ruleIds = data.rules.map((r) => r.id);
  const worst = new Map<string, Severity>();
  for (const f of data.findings) if (!worst.has(f.id)) worst.set(f.id, f.severity);

  const log = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: data.tool.name,
            version: data.tool.version,
            informationUri: PROJECT_URL,
            rules: data.rules.map((rule) => ({
              id: rule.id,
              name: rule.id,
              shortDescription: { text: rule.title },
              fullDescription: { text: rule.description },
              helpUri: rule.helpUri,
              help: { text: `${rule.description} See ${rule.helpUri}` },
              defaultConfiguration: { level: LEVEL[worst.get(rule.id) ?? 'low'] },
              properties: { tags: ['cloud-foundry', 'btp'] },
            })),
          },
        },
        invocations: [
          {
            executionSuccessful: true,
            endTimeUtc: data.scannedAt,
            toolExecutionNotifications: data.checks
              .filter((c) => c.status === 'skipped')
              .map((c) => ({
                level: 'warning',
                message: { text: `Check ${c.id} skipped: ${c.reason ?? 'no reason given'}` },
              })),
          },
        ],
        results: data.findings.map((finding) => ({
          ruleId: finding.id,
          ruleIndex: ruleIds.indexOf(finding.id),
          level: LEVEL[finding.severity],
          message: {
            text: `${finding.title} (${finding.app.org}/${finding.app.space}/${finding.app.name}). ${finding.remediation}`,
          },
          locations: [
            {
              physicalLocation: { artifactLocation: { uri: appUri(finding) } },
              logicalLocations: [
                {
                  name: finding.app.name,
                  fullyQualifiedName: `${finding.app.org}/${finding.app.space}/${finding.app.name}`,
                  kind: 'resource',
                },
              ],
            },
          ],
          partialFingerprints: { 'btpLensFinding/v1': fingerprint(finding) },
          properties: {
            'security-severity': SECURITY_SEVERITY[finding.severity],
            severity: finding.severity,
            appGuid: finding.app.guid,
            evidence: finding.evidence,
            references: finding.references,
          },
        })),
        properties: { scope: data.scope },
      },
    ],
  };
  return `${JSON.stringify(log, null, 2)}\n`;
}
