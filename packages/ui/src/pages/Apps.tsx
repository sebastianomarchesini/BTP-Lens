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
import { formatDate } from '../data/format';
import { severityRank } from '../data/severity';

type GroupBy = 'none' | 'org' | 'space';

/** Table rows are our own inventory items; the table types them loosely. */
const asApp = (row: Record<string, unknown>) => row as unknown as AppInventoryItem;
const cellApp = ({ cell }: AnalyticalTableCellInstance) =>
  asApp(cell.row.original as Record<string, unknown>);

const total = (row: Record<string, unknown>) =>
  Object.values(asApp(row).findingCounts).reduce((sum, n) => sum + n, 0);

const buildpacks = (row: Record<string, unknown>) => {
  const app = asApp(row);
  return (
    app.buildpacks.map((b) => (b.version ? `${b.name} ${b.version}` : b.name)).join(', ') ||
    (app.lifecycleType === 'docker' ? 'Docker image' : '—')
  );
};

const byRank = (
  a: { original: Record<string, unknown> },
  b: { original: Record<string, unknown> },
) =>
  severityRank(asApp(a.original).highestSeverity) - severityRank(asApp(b.original).highestSeverity);

export function Apps() {
  const data = useOutletContext<ReportData>();
  const navigate = useNavigate();
  const [groupBy, setGroupBy] = useState<GroupBy>('none');

  const columns = useMemo<AnalyticalTableColumnDefinition[]>(
    () => [
      { Header: 'App', accessor: 'name', minWidth: 160 },
      {
        Header: 'Highest severity',
        id: 'severity',
        accessor: (row: Record<string, unknown>) => asApp(row).highestSeverity ?? 'none',
        Cell: (props: AnalyticalTableCellInstance) => (
          <SeverityStatus severity={cellApp(props).highestSeverity} />
        ),
        sortType: byRank,
        minWidth: 150,
      },
      { Header: 'Findings', id: 'findings', accessor: total, hAlign: 'End', width: 100 },
      { Header: 'Org', accessor: 'org', responsiveMinWidth: 700, responsivePopIn: true },
      { Header: 'Space', accessor: 'space', responsiveMinWidth: 700, responsivePopIn: true },
      { Header: 'State', accessor: 'state', width: 110, responsiveMinWidth: 900 },
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
        accessor: 'lastDeployAt',
        Cell: (props: AnalyticalTableCellInstance) => formatDate(cellApp(props).lastDeployAt),
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
    [],
  );
  const grouping = useMemo(() => (groupBy === 'none' ? [] : [groupBy]), [groupBy]);

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
      <AnalyticalTable
        header={`Apps (${data.apps.length})`}
        accessibleName="Apps sorted by risk"
        data={data.apps}
        columns={columns}
        filterable
        sortable
        groupable
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
