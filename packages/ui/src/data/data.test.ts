import type { ReportData } from '@btp-lens/model';
import { describe, expect, it } from 'vitest';
import sample from '../test/fixtures/report.json';
import { resolveTheme } from '../ui5/theme';
import { formatDate, formatEvidenceValue } from './format';
import { DATA_ELEMENT_ID, readEmbeddedReport } from './report';
import { SEVERITY_ORDER, SEVERITY_STATE, severityRank } from './severity';

function docWith(content: string): Document {
  const doc = document.implementation.createHTMLDocument('t');
  const script = doc.createElement('script');
  script.type = 'application/json';
  script.id = DATA_ELEMENT_ID;
  script.textContent = content;
  doc.body.append(script);
  return doc;
}

describe('readEmbeddedReport', () => {
  it('returns null while the build placeholder is still in place', () => {
    expect(readEmbeddedReport(docWith('<!--BTP_LENS_DATA-->'))).toBeNull();
    expect(readEmbeddedReport(document.implementation.createHTMLDocument('empty'))).toBeNull();
  });

  it('reads report data injected by the CLI', () => {
    const data = readEmbeddedReport(docWith(JSON.stringify(sample)));
    expect(data?.summary.apps).toBe(8);
  });

  it('rejects data from an incompatible version', () => {
    expect(() => readEmbeddedReport(docWith('{"schemaVersion": 99}'))).toThrow(
      /incompatible version/,
    );
  });
});

describe('severity semantics', () => {
  it('maps severities to Fiori value states', () => {
    expect(SEVERITY_STATE.critical).toEqual({ state: 'Negative', inverted: true });
    expect(SEVERITY_STATE.high.state).toBe('Negative');
    expect(SEVERITY_STATE.medium.state).toBe('Critical');
    expect(SEVERITY_STATE.low.state).toBe('Information');
    expect(SEVERITY_STATE.info.state).toBe('None');
  });

  it('ranks severities, with no findings lowest', () => {
    const ranks = SEVERITY_ORDER.map(severityRank);
    expect([...ranks].sort((a, b) => b - a)).toEqual(ranks);
    expect(severityRank(null)).toBeLessThan(severityRank('info'));
  });
});

describe('theme', () => {
  it('follows the OS in auto mode and honours an explicit choice', () => {
    expect(resolveTheme('auto', true)).toBe('sap_horizon_dark');
    expect(resolveTheme('auto', false)).toBe('sap_horizon');
    expect(resolveTheme('light', true)).toBe('sap_horizon');
    expect(resolveTheme('dark', false)).toBe('sap_horizon_dark');
  });
});

describe('format', () => {
  it('formats dates in UTC and handles missing values', () => {
    expect(formatDate('2024-03-15T08:00:00Z')).toBe('Mar 15, 2024');
    expect(formatDate(null)).toBe('Never');
    expect(formatEvidenceValue(null)).toBe('—');
    expect(formatEvidenceValue({ a: 1 })).toBe('{"a":1}');
  });
});

// Keeps the fixture honest against the model's type.
const typed: ReportData = sample as unknown as ReportData;
void typed;
