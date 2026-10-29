import type { AppInventoryItem, ReportData } from '@btp-lens/model';
import {
  AnalyticalTable,
  type AnalyticalTableCellInstance,
  type AnalyticalTableColumnDefinition,
  Label,
  SegmentedButton,
  SegmentedButtonItem,
} from '@ui5/webcomponents-react';
import { useMemo, useState } from 'react';
import { useNavigate, useOutletContext } from 'react-router';
import { EmptyState } from '../components/EmptyState';
import { SeverityStatus } from '../components/SeverityStatus';
import { lastDeploySortValue, lastDeployText, stateText } from '../data/inventory';
import { severityRank } from '../data/severity';
import { isProjectInventory } from '../data/summary';

type GroupBy = 'none' | 'org' | 'space';

/** Table rows are our own inventory items; the table types them loosely. */
const asApp = (row: Record<string, unknown>) => row as unknown as AppInventoryItem;
/** Grouped (aggregate) rows have no original item, so renderers must cope with undefined. */
const cellApp = ({ cell }: AnalyticalTableCellInstance): AppInventoryItem | undefined =>
  cell.row.original ? asApp(cell.row.original as Record<string, unknown>) : undefined;

const total = (row: Record<string, unknown>) =>
  Object.values(asApp(row).findingCounts).reduce((sum, n) => sum + n, 0);

const buildpacks = (row: Record<string, unknown>) => {
  const app = asApp(row);
  return (
    app.buildpacks.map((b) => (b.version ? `${b.name} ${b.version}` : b.name)).join(', ') ||
    (app.lifecycleType === 'docker' ? 'Docker image' : '—')
  );
};

const state = (row: Record<string, unknown>) => stateText(asApp(row));
const lastDeployAt = (row: Record<string, unknown>) => lastDeploySortValue(asApp(row));

const rank = (row: { original?: Record<string, unknown> }) =>
  row.original ? severityRank(asApp(row.original).highestSeverity) : -1;
const byRank = (
  a: { original?: Record<string, unknown> },
  b: { original?: Record<string, unknown> },
) => rank(a) - rank(b);

export function Apps() {
  const data = useOutletContext<ReportData>();
  const navigate = useNavigate();
  const [groupBy, setGroupBy] = useState<GroupBy>('none');
  const projects = isProjectInventory(data.apps);
  const noun = projects ? 'Projects' : 'Apps';

  const columns = useMemo<AnalyticalTableColumnDefinition[]>(
    () => [
      { Header: projects ? 'Project' : 'App', accessor: 'name', minWidth: 160 },
      {
        Header: 'Highest severity',
        id: 'severity',
        accessor: (row: Record<string, unknown>) => asApp(row).highestSeverity ?? 'none',
        Cell: (props: AnalyticalTableCellInstance) => {
          const app = cellApp(props);
          return app ? <SeverityStatus severity={app.highestSeverity} /> : null;
        },
        sortType: byRank,
        minWidth: 150,
      },
      { Header: 'Findings', id: 'findings', accessor: total, hAlign: 'End', width: 100 },
      { Header: 'Org', accessor: 'org', responsiveMinWidth: 700, responsivePopIn: true },
      { Header: 'Space', accessor: 'space', responsiveMinWidth: 700, responsivePopIn: true },
      { Header: 'State', id: 'state', accessor: state, width: 110, responsiveMinWidth: 900 },
      { Header: 'Buildpacks', id: 'buildpacks', accessor: buildpacks, responsiveMinWidth: 1000 },
      {
        Header: 'Stack',
        id: 'stack',
        accessor: (row: Record<string, unknown>) => asApp(row).stack ?? '—',
        width: 120,
        responsiveMinWidth: 1100,
      },
      {
        Header: 'Last deploy',
        id: 'lastDeployAt',
        accessor: lastDeployAt,
        Cell: (props: AnalyticalTableCellInstance) => {
          const app = cellApp(props);
          return app ? lastDeployText(app) : '';
        },
        width: 130,
        responsiveMinWidth: 800,
        responsivePopIn: true,
      },
      {
        Header: 'Risk score',
        accessor: 'riskScore',
        hAlign: 'End',
        width: 110,
        responsiveMinWidth: 900,
      },
    ],
    [projects],
  );
  // Projects all share org "local" and space "project", so grouping is hidden for them.
  const grouping = useMemo(
    () => (groupBy === 'none' || projects ? [] : [groupBy]),
    [groupBy, projects],
  );

  if (data.apps.length === 0) {
    return (
      <EmptyState
        name="NoEntries"
        title="No apps in this scan"
        subtitle="The user has no visible apps in the scanned org, or the app inventory check was skipped."
      />
    );
  }

  return (
    <div className="stack">
      {!projects && (
        <div className="toolbar">
          <Label id="group-by-label">Group by</Label>
          <SegmentedButton
            accessibleNameRef="group-by-label"
            onSelectionChange={(event) => {
              const next = event.detail.selectedItems[0]?.getAttribute('data-group');
              if (next === 'none' || next === 'org' || next === 'space') setGroupBy(next);
            }}
          >
            <SegmentedButtonItem data-group="none" selected={groupBy === 'none'}>
              None
            </SegmentedButtonItem>
            <SegmentedButtonItem data-group="org" selected={groupBy === 'org'}>
              Org
            </SegmentedButtonItem>
            <SegmentedButtonItem data-group="space" selected={groupBy === 'space'}>
              Space
            </SegmentedButtonItem>
          </SegmentedButton>
        </div>
      )}
      <AnalyticalTable
        header={`${noun} (${data.apps.length})`}
        accessibleName={`${noun} sorted by risk`}
        data={data.apps}
        columns={columns}
        filterable
        sortable
        groupable={!projects}
        groupBy={grouping}
        scaleWidthMode="Smart"
        visibleRows={Math.min(data.apps.length, 15)}
        onRowClick={(event) => {
          const app = event.detail.row.original as AppInventoryItem | undefined;
          if (app?.guid) void navigate(`/findings?app=${encodeURIComponent(app.guid)}`);
        }}
      />
    </div>
  );
}
