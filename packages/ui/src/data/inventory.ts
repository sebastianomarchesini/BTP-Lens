import type { AppInventoryItem } from '@btp-lens/model';
import { formatDate } from './format';

/** A local project is neither started nor stopped. */
export function stateText(app: AppInventoryItem): string {
  return app.kind === 'project' ? '—' : (app.state ?? '—');
}

/** Sort value: the ISO timestamp keeps the order chronological; a project has no deploy. */
export function lastDeploySortValue(app: AppInventoryItem): string {
  return app.kind === 'project' ? '—' : (app.lastDeployAt ?? '');
}

/** What the cell shows: a date, "Never" for an app, "—" for a project. */
export function lastDeployText(app: AppInventoryItem): string {
  return app.kind === 'project' ? '—' : formatDate(app.lastDeployAt);
}
