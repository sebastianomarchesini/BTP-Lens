import type { ReportData } from '@btp-lens/model';
import { useQuery } from '@tanstack/react-query';

export const DATA_ELEMENT_ID = 'btp-lens-data';

function isReportData(value: unknown): value is ReportData {
  if (typeof value !== 'object' || value === null) return false;
  const v = value as Record<string, unknown>;
  return (
    v.schemaVersion === 1 &&
    Array.isArray(v.apps) &&
    Array.isArray(v.findings) &&
    Array.isArray(v.checks) &&
    Array.isArray(v.rules) &&
    typeof v.summary === 'object' &&
    typeof v.scope === 'object'
  );
}

/**
 * Report mode: the CLI injects the scan data into a JSON script element.
 * Returns null while it still holds the build placeholder.
 */
export function readEmbeddedReport(doc: Document = document): ReportData | null {
  const text = doc.getElementById(DATA_ELEMENT_ID)?.textContent?.trim() ?? '';
  if (!text.startsWith('{')) return null;
  const data: unknown = JSON.parse(text);
  if (!isReportData(data)) {
    throw new Error('The report data was written by an incompatible version of btp-lens.');
  }
  return data;
}

async function loadReport(): Promise<ReportData | null> {
  const embedded = readEmbeddedReport();
  if (embedded !== null) return embedded;
  if (import.meta.env.DEV) {
    // `npm run dev` without a scan: show the synthetic sample.
    const sample = await import('../test/fixtures/report.json');
    return sample.default as unknown as ReportData;
  }
  return null;
}

export function useReport() {
  return useQuery({ queryKey: ['report'], queryFn: loadReport, staleTime: Infinity, retry: false });
}
