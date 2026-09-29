import { readFile } from 'node:fs/promises';
import { ConfigError } from '../http/errors.js';
import type { ReportData } from '../model/snapshot.js';

/** The placeholder the UI's report build leaves for the data (packages/ui/index.html). */
export const DATA_PLACEHOLDER =
  '<script type="application/json" id="btp-lens-data"><!--BTP_LENS_DATA--></script>';

/** Matches the placeholder however a formatter has wrapped it. */
const DATA_PLACEHOLDER_PATTERN =
  /<script type="application\/json" id="btp-lens-data">\s*<!--BTP_LENS_DATA-->\s*<\/script>/g;

/**
 * JSON that is safe inside a <script> element: no "<", ">" or "&" that could
 * close the tag or open a comment, and no JS line separators.
 */
export function scriptSafeJson(data: unknown): string {
  return JSON.stringify(data)
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e')
    .replace(/&/g, '\\u0026')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029');
}

export function renderHtml(data: ReportData, template: string): string {
  const occurrences = template.match(DATA_PLACEHOLDER_PATTERN)?.length ?? 0;
  if (occurrences !== 1) {
    throw new ConfigError(
      `The HTML report template must contain the data placeholder exactly once (found ${occurrences}).`,
    );
  }
  const tag = `<script type="application/json" id="btp-lens-data">${scriptSafeJson(data)}</script>`;
  // A callback, so "$&" and friends in the data are never interpreted.
  return template.replace(DATA_PLACEHOLDER_PATTERN, () => tag);
}

/**
 * The UI's single-file build. Published packages ship it as
 * dist/report-template.html; in the monorepo it is read from packages/ui.
 */
const TEMPLATE_CANDIDATES = [
  new URL('../report-template.html', import.meta.url),
  new URL('../../../ui/dist-report/index.html', import.meta.url),
];

export async function loadReportTemplate(): Promise<string> {
  for (const candidate of TEMPLATE_CANDIDATES) {
    try {
      return await readFile(candidate, 'utf8');
    } catch {
      // Try the next location.
    }
  }
  throw new ConfigError(
    'The HTML report template is missing. Build the UI first (`npm run build`), or choose other formats.',
  );
}
