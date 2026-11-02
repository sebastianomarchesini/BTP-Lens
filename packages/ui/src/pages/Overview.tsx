import type { ReportData } from '@btp-lens/model';
import { Card, CardHeader, List, ListItemStandard, MessageStrip } from '@ui5/webcomponents-react';
import { useNavigate, useOutletContext } from 'react-router';
import { EmptyState } from '../components/EmptyState';
import { SeverityChart } from '../components/SeverityChart';
import { formatEvidenceValue } from '../data/format';
import { SEVERITY_LABEL, SEVERITY_STATE } from '../data/severity';
import { scopeLabel, startHereSentences } from '../data/summary';

interface Kpi {
  label: string;
  value: string;
  hint: string;
}

/**
 * Counts what the rules affected; "Not checked" when none of them ran. A CF
 * rule yields one finding per app, a project rule one per subject (service,
 * entity, ...) within a project, so the subject is part of the key.
 */
function ruleKpi(data: ReportData, label: string, ruleIds: string[], unit: string): Kpi {
  const ran = ruleIds.some((id) =>
    data.checks.some((c) => c.id === `rule.${id}` && c.status === 'ran'),
  );
  if (!ran) return { label, value: '—', hint: 'Not checked in this scan' };
  const affected = new Set(
    data.findings
      .filter((f) => ruleIds.includes(f.id))
      .map((f) => `${f.app.guid}:${formatEvidenceValue(f.evidence.subject)}`),
  );
  return { label, value: String(affected.size), hint: unit };
}

/** The two rule KPIs depend on what was scanned: a CF landscape or local projects. */
function kpiRow(data: ReportData): Kpi[] {
  const s = data.summary.findingsBySeverity;
  const project = data.summary.projects > 0;
  const findings = {
    label: 'Critical and high findings',
    value: String(s.critical + s.high),
    hint: `of ${data.summary.findings} findings`,
  };
  if (project) {
    return [
      {
        label: 'Projects scanned',
        value: String(data.summary.projects),
        hint: scopeLabel(data.scope),
      },
      findings,
      ruleKpi(
        data,
        'Services open to all users',
        ['CAP_SERVICE_NO_RESTRICTION'],
        'services affected',
      ),
      ruleKpi(
        data,
        'Personal data without annotations',
        ['CAP_PERSONAL_DATA_UNANNOTATED'],
        'entities affected',
      ),
    ];
  }
  return [
    { label: 'Apps scanned', value: String(data.summary.apps), hint: scopeLabel(data.scope) },
    findings,
    ruleKpi(data, 'Idle apps', ['APP_IDLE'], 'apps with no activity'),
    ruleKpi(
      data,
      'End-of-life runtimes',
      ['RUNTIME_NODE_EOL', 'RUNTIME_JAVA_EOL'],
      'apps affected',
    ),
  ];
}

export function Overview() {
  const data = useOutletContext<ReportData>();
  const navigate = useNavigate();
  const s = data.summary.findingsBySeverity;
  const kpis = kpiRow(data);
  const riskTitle = data.summary.projects > 0 ? 'Top risks' : 'Top risky apps';
  const skipped = data.checks.filter((c) => c.status === 'skipped');
  const risky = data.apps.filter((a) => a.riskScore > 0).slice(0, 5);

  return (
    <div className="stack">
      <Card
        header={
          <CardHeader titleText="Start here" subtitleText="What this report says, in plain words" />
        }
      >
        <section className="start-here" aria-label="Summary in plain words">
          {startHereSentences(data).map((sentence) => (
            <p key={sentence}>{sentence}</p>
          ))}
        </section>
      </Card>

      <section className="kpi-row" aria-label="Key figures">
        {kpis.map((kpi) => (
          <Card
            key={kpi.label}
            accessibleName={`${kpi.label}: ${kpi.value}`}
            header={<CardHeader titleText={kpi.label} subtitleText={kpi.hint} />}
          >
            <p className="kpi-value">{kpi.value}</p>
          </Card>
        ))}
      </section>

      {skipped.length > 0 && (
        <MessageStrip design="Critical" hideCloseButton>
          {skipped.length} check{skipped.length === 1 ? ' was' : 's were'} skipped, so results may
          be incomplete:{' '}
          {skipped.map((c) => `${c.title} (${c.reason ?? 'no reason given'})`).join('; ')}.
        </MessageStrip>
      )}

      <div className="card-grid">
        <Card
          header={
            <CardHeader
              titleText="Findings by severity"
              subtitleText={`${data.summary.findings} findings`}
            />
          }
        >
          <div className="card-body">
            <SeverityChart counts={s} />
          </div>
        </Card>
        <Card
          header={<CardHeader titleText={riskTitle} subtitleText="Ranked by weighted findings" />}
        >
          {risky.length === 0 ? (
            <EmptyState
              name="NoEntries"
              design="Spot"
              title={data.summary.projects > 0 ? 'No risks found' : 'No risky apps'}
              subtitle={
                data.summary.projects > 0
                  ? 'No rule matched in this scan.'
                  : 'No rule matched an app in this scan.'
              }
            />
          ) : (
            <List accessibleName={riskTitle}>
              {risky.map((app) => {
                const severity = app.highestSeverity;
                return (
                  <ListItemStandard
                    key={app.guid}
                    type="Navigation"
                    text={app.name}
                    description={`${app.org} / ${app.space}`}
                    additionalText={severity ? SEVERITY_LABEL[severity] : undefined}
                    additionalTextState={severity ? SEVERITY_STATE[severity].state : undefined}
                    onClick={() => void navigate(`/findings?app=${encodeURIComponent(app.guid)}`)}
                  />
                );
              })}
            </List>
          )}
        </Card>
      </div>
    </div>
  );
}
