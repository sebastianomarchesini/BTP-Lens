const DATE = new Intl.DateTimeFormat('en', { dateStyle: 'medium', timeZone: 'UTC' });
const DATE_TIME = new Intl.DateTimeFormat('en', {
  dateStyle: 'medium',
  timeStyle: 'short',
  timeZone: 'UTC',
});

export function formatDate(iso: string | null | undefined): string {
  if (!iso) return 'Never';
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? iso : DATE.format(date);
}

export function formatDateTime(iso: string): string {
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? iso : `${DATE_TIME.format(date)} UTC`;
}

/** Renders evidence values: primitives as-is, anything else as compact JSON. */
export function formatEvidenceValue(value: unknown): string {
  if (value === null || value === undefined) return '—';
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
    return String(value);
  }
  return JSON.stringify(value);
}
