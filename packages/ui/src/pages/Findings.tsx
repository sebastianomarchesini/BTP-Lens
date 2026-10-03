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
import { SEVERITY_LABEL, SEVERITY_ORDER, isSeverity } from '../data/severity';

/** Only http(s) references become clickable; anything else is shown as text. */
export function isWebLink(href: string): boolean {
  return /^https?:\/\//i.test(href);
}

function FindingItem({ finding }: { finding: Finding }) {
  return (
    <ListItemCustom
      accessibleName={`${SEVERITY_LABEL[finding.severity]}: ${finding.title}, ${finding.app.name}`}
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
          Showing findings for {app ? `${app.org} / ${app.space} / ${app.name}` : 'an unknown app'}.
          Close to show all apps.
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
          return (
            <Panel key={rule.id} headerText={`${rule.title} (${findings.length})`} headerLevel="H3">
              <Text className="rule-description">
                {rule.description}{' '}
                {isWebLink(rule.helpUri) && (
                  <Link href={rule.helpUri} target="_blank">
                    About this rule
                  </Link>
                )}
              </Text>
              <List accessibleName={`${rule.title} findings`}>
                {findings.map((finding) => (
                  <FindingItem key={`${finding.id}:${finding.app.guid}`} finding={finding} />
                ))}
              </List>
            </Panel>
          );
        })
      )}
    </div>
  );
}
