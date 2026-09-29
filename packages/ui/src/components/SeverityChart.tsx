import '@ui5/webcomponents-icons/dist/horizontal-bar-chart.js';
import '@ui5/webcomponents-icons/dist/table-view.js';
import type { ReportData, Severity } from '@btp-lens/model';
import { BarChart } from '@ui5/webcomponents-react-charts';
import { SegmentedButton, SegmentedButtonItem } from '@ui5/webcomponents-react';
import { useState } from 'react';
import { SEVERITY_COLOR, SEVERITY_LABEL, SEVERITY_ORDER } from '../data/severity';
import { SeverityStatus } from './SeverityStatus';

type Row = {
  key: Severity;
  label: string;
  count: number;
};

type View = 'chart' | 'table';

interface BarLabelProps {
  value?: number | string;
  viewBox?: { x?: number; y?: number; width?: number; height?: number };
}

/**
 * The value just past the bar end, in the text color. The chart's default
 * label is meant for text inside a bar (contrast color) and disappears on
 * short bars; a label outside the bar must wear a text token instead.
 */
function BarValueLabel({ value, viewBox = {} }: BarLabelProps) {
  const { x = 0, y = 0, width = 0, height = 0 } = viewBox;
  return (
    <text
      x={x + Math.max(width, 0) + 6}
      y={y + height / 2}
      dominantBaseline="central"
      style={{ fill: 'var(--sapTextColor)', fontSize: 'var(--sapFontSmallSize)' }}
    >
      {value}
    </text>
  );
}

/**
 * Findings by severity: one bar per severity in a fixed order, colored with
 * the theme's status colors and labeled on the axis, so identity never
 * depends on color. A table view carries the same numbers.
 */
export function SeverityChart({ counts }: { counts: ReportData['summary']['findingsBySeverity'] }) {
  const [view, setView] = useState<View>('chart');
  const rows: Row[] = SEVERITY_ORDER.map((key) => ({
    key,
    label: SEVERITY_LABEL[key],
    count: counts[key],
  }));

  return (
    <div className="severity-chart">
      <SegmentedButton
        accessibleName="Show findings by severity as"
        onSelectionChange={(event) => {
          const next = event.detail.selectedItems[0]?.getAttribute('data-view');
          if (next === 'chart' || next === 'table') setView(next);
        }}
      >
        <SegmentedButtonItem
          icon="horizontal-bar-chart"
          data-view="chart"
          selected={view === 'chart'}
          tooltip="Chart"
        >
          Chart
        </SegmentedButtonItem>
        <SegmentedButtonItem
          icon="table-view"
          data-view="table"
          selected={view === 'table'}
          tooltip="Table"
        >
          Table
        </SegmentedButtonItem>
      </SegmentedButton>
      {view === 'chart' ? (
        <BarChart
          style={{ height: '15rem', width: '100%' }}
          dataset={rows}
          dimensions={[{ accessor: 'label' }]}
          measures={[
            {
              accessor: 'count',
              label: 'Findings',
              width: 20,
              formatter: (value: number) => String(value),
              DataLabel: BarValueLabel,
              highlightColor: (_value, _measure, row) =>
                SEVERITY_COLOR[(row as unknown as Row).key],
            },
          ]}
          noLegend
          chartConfig={{
            gridVertical: false,
            gridHorizontal: false,
            // Keep the numeric axis for scaling but do not draw it: without an
            // x-axis the chart falls back to a category scale and drops bars.
            xAxisVisible: true,
            xAxisConfig: { hide: true },
            margin: { right: 32 },
          }}
        />
      ) : (
        <table className="data-table">
          <caption className="visually-hidden">Findings by severity</caption>
          <thead>
            <tr>
              <th scope="col">Severity</th>
              <th scope="col" className="numeric">
                Findings
              </th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.key}>
                <td>
                  <SeverityStatus severity={row.key} />
                </td>
                <td className="numeric">{row.count}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
