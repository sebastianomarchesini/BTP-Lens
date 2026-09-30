import type { ReportData } from '../model/snapshot.js';

export function renderJson(data: ReportData): string {
  return `${JSON.stringify(data, null, 2)}\n`;
}
