import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { ConfigError } from '../http/errors.js';
import type { ReportData } from '../model/snapshot.js';
import { renderAppsCsv, renderFindingsCsv } from './csv.js';
import { loadReportTemplate, renderHtml } from './html.js';
import { renderJson } from './json.js';
import { renderSarif } from './sarif.js';

export const REPORT_FORMATS = ['html', 'json', 'csv', 'sarif'] as const;
export type ReportFormat = (typeof REPORT_FORMATS)[number];

export function parseFormats(value: string): ReportFormat[] {
  const formats = value
    .split(',')
    .map((f) => f.trim().toLowerCase())
    .filter((f) => f !== '');
  const unknown = formats.filter((f) => !(REPORT_FORMATS as readonly string[]).includes(f));
  if (unknown.length > 0 || formats.length === 0) {
    throw new ConfigError(
      `Unknown report format "${unknown.join(', ') || value}". Use any of: ${REPORT_FORMATS.join(', ')}.`,
    );
  }
  return [...new Set(formats)] as ReportFormat[];
}

export interface WriteReportsOptions {
  /** Overrides the UI template (tests). */
  htmlTemplate?: string;
}

/** Writes every requested format into outDir and returns the file paths. */
export async function writeReports(
  data: ReportData,
  formats: readonly ReportFormat[],
  outDir: string,
  options: WriteReportsOptions = {},
): Promise<string[]> {
  await mkdir(outDir, { recursive: true });
  const files: [string, string][] = [];
  for (const format of formats) {
    switch (format) {
      case 'html':
        files.push([
          'btp-lens-report.html',
          renderHtml(data, options.htmlTemplate ?? (await loadReportTemplate())),
        ]);
        break;
      case 'json':
        files.push(['btp-lens-report.json', renderJson(data)]);
        break;
      case 'csv':
        files.push(['btp-lens-findings.csv', renderFindingsCsv(data)]);
        files.push(['btp-lens-apps.csv', renderAppsCsv(data)]);
        break;
      case 'sarif':
        files.push(['btp-lens-report.sarif', renderSarif(data)]);
        break;
    }
  }
  const written: string[] = [];
  for (const [name, content] of files) {
    const path = join(outDir, name);
    await writeFile(path, content, 'utf8');
    written.push(path);
  }
  return written;
}
