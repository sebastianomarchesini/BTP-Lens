import type { Finding, ReportData, Severity } from '@btp-lens/model';
import {
  Label,
  Link,
  List,
  ListItemCustom,
  MessageStrip,
  Panel,
  SegmentedButton,
  SegmentedButtonItem,
  Text,
  Title,
} from '@ui5/webcomponents-react';
import { useMemo } from 'react';
import { useOutletContext, useSearchParams } from 'react-router';
import { EmptyState } from '../components/EmptyState';
import { SeverityStatus } from '../components/SeverityStatus';
import { formatEvidenceValue } from '../data/format';
import { owaspLabel, owaspTooltip } from '../data/owasp';
import { SEVERITY_LABEL, SEVERITY_ORDER, isSeverity } from '../data/severity';

/** Only http(s) references become clickable; anything else is shown as text. */
export function isWebLink(href: string): boolean {
  return /^https?:\/\//i.test(href);
}

/** "srv/services.cds:3", or just the file when the line is unknown. */
export function formatLocation(location: NonNullable<Finding['location']>): string {
  return location.line === undefined ? location.file : `${location.file}:${location.line}`;
}

/** One project yields many findings per rule, so the key needs where and what. */
function findingKey(finding: Finding): string {
  const where = finding.location ? formatLocation(finding.location) : '';
  return `${finding.id}:${finding.app.guid}:${where}:${formatEvidenceValue(finding.evidence.subject)}`;
}

function FindingItem({ finding }: { finding: Finding }) {
  const location = finding.location ? formatLocation(finding.location) : undefined;
  return (
    <ListItemCustom
      accessibleName={[
        `${SEVERITY_LABEL[finding.severity]}: ${finding.title}, ${finding.app.name}`,
        location,
      ]
        .filter(Boolean)
        .join(', ')}
    >
      <article className="finding">
        <header className="finding-header">
          <SeverityStatus severity={finding.severity} />
          <Title level="H5" wrappingType="Normal">
            {finding.title}
          </Title>
        </header>
        <Text className="finding-app">
          {finding.app.org} / {finding.app.space} / <strong>{finding.app.name}</strong>
        </Text>
        {location && <code className="finding-location">{location}</code>}
        <div>
          <Label showColon>Remediation</Label> <Text>{finding.remediation}</Text>
        </div>
        <dl className="evidence">
          {Object.entries(finding.evidence).map(([key, value]) => (
            <div key={key}>
              <dt>{key}</dt>
              <dd>{formatEvidenceValue(value)}</dd>
            </div>
          ))}
        </dl>
        {finding.references.length > 0 && (
          <div className="references">
            {finding.references.map((href) =>
              isWebLink(href) ? (
                <Link key={href} href={href} target="_blank" wrappingType="Normal">
                  {href}
                </Link>
              ) : (
                <Text key={href}>{href}</Text>
              ),
            )}
          </div>
        )}
      </article>
    </ListItemCustom>
  );
}

/** "acme-prod / dev / docs-static" for a CF app, "project acme-incidents" for a local project. */
function describeApp(app: ReportData['apps'][number] | undefined): string {
  if (!app) return 'an unknown app';
  return app.kind === 'project' ? `project ${app.name}` : `${app.org} / ${app.space} / ${app.name}`;
}

function parseSeverities(value: string | null): Severity[] {
  if (value === null) return [...SEVERITY_ORDER];
  return value.split(',').filter(isSeverity);
}

export function Findings() {
  const data = useOutletContext<ReportData>();
  const [params, setParams] = useSearchParams();
  const appGuid = params.get('app');
  const selected = parseSeverities(params.get('severity'));
  const app = appGuid ? data.apps.find((a) => a.guid === appGuid) : undefined;

  const visible = useMemo(
    () =>
      data.findings.filter(
        (f) => selected.includes(f.severity) && (appGuid === null || f.app.guid === appGuid),
      ),
    [data.findings, selected, appGuid],
  );

  const update = (key: string, value: string | null) => {
    const next = new URLSearchParams(params);
    if (value === null) next.delete(key);
    else next.set(key, value);
    setParams(next, { replace: true });
  };

  if (data.findings.length === 0) {
    return (
      <EmptyState
        name="NoEntries"
        title="No findings"
        subtitle="No rule matched in this scan. Check the Overview for rules that were skipped."
      />
    );
  }

  const countBy = (severity: Severity) =>
    data.findings.filter(
      (f) => f.severity === severity && (appGuid === null || f.app.guid === appGuid),
    ).length;

  return (
    <div className="stack">
      <div className="toolbar">
        <Label id="severity-filter-label">Severity</Label>
        <SegmentedButton
          selectionMode="Multiple"
          accessibleNameRef="severity-filter-label"
          onSelectionChange={(event) => {
            const chosen = event.detail.selectedItems
              .map((item) => item.getAttribute('data-severity') ?? '')
              .filter(isSeverity);
            update('severity', chosen.length === SEVERITY_ORDER.length ? null : chosen.join(','));
          }}
        >
          {SEVERITY_ORDER.map((severity) => (
            <SegmentedButtonItem
              key={severity}
              data-severity={severity}
              selected={selected.includes(severity)}
            >
              {`${SEVERITY_LABEL[severity]} (${countBy(severity)})`}
            </SegmentedButtonItem>
          ))}
        </SegmentedButton>
      </div>

      {appGuid !== null && (
        <MessageStrip design="Information" onClose={() => update('app', null)}>
          Showing findings for {describeApp(app)}. Close to show all{' '}
          {app?.kind === 'project' ? 'projects' : 'apps'}.
        </MessageStrip>
      )}

      {visible.length === 0 ? (
        <EmptyState
          name="NoFilterResults"
          title="No findings match the filters"
          subtitle="Select more severities or show all apps."
        />
      ) : (
        data.rules.map((rule) => {
          const findings = visible.filter((f) => f.id === rule.id);
          if (findings.length === 0) return null;
          const owasp = rule.owasp.length > 0 ? ` · OWASP ${rule.owasp.join(', ')}` : '';
          return (
            <Panel
              key={rule.id}
              headerText={`${rule.title} (${findings.length})${owasp}`}
              headerLevel="H3"
              title={rule.owasp.length > 0 ? owaspTooltip(rule.owasp) : undefined}
            >
              <Text className="rule-description">
                {rule.description}{' '}
                {isWebLink(rule.helpUri) && (
                  <Link href={rule.helpUri} target="_blank">
                    About this rule
                  </Link>
                )}
              </Text>
              {rule.owasp.length > 0 && (
                // The category names in text, for readers who cannot hover the header.
                <Text className="rule-owasp">
                  OWASP Top 10 (2025): {rule.owasp.map(owaspLabel).join('; ')}
                </Text>
              )}
              <List accessibleName={`${rule.title} findings`}>
                {findings.map((finding) => (
                  <FindingItem key={findingKey(finding)} finding={finding} />
                ))}
              </List>
            </Panel>
          );
        })
      )}
    </div>
  );
}
