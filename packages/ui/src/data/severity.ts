import type { Severity } from '@btp-lens/model';

export const SEVERITY_ORDER: readonly Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
};

type ValueStateName = 'Negative' | 'Critical' | 'Information' | 'None';

/** Fiori severity semantics for ObjectStatus (critical is inverted for emphasis). */
export const SEVERITY_STATE: Record<Severity, { state: ValueStateName; inverted: boolean }> = {
  critical: { state: 'Negative', inverted: true },
  high: { state: 'Negative', inverted: false },
  medium: { state: 'Critical', inverted: false },
  low: { state: 'Information', inverted: false },
  info: { state: 'None', inverted: false },
};

/**
 * Status colors for chart marks: theme parameters only, so light and dark
 * themes each get their own values. Severity is status, never categorical.
 */
export const SEVERITY_COLOR: Record<Severity, string> = {
  critical: 'var(--sapIndicationColor_1)',
  high: 'var(--sapNegativeElementColor)',
  medium: 'var(--sapCriticalElementColor)',
  low: 'var(--sapInformativeElementColor)',
  info: 'var(--sapNeutralElementColor)',
};

export function severityRank(severity: Severity | null): number {
  return severity === null ? -1 : SEVERITY_ORDER.length - SEVERITY_ORDER.indexOf(severity);
}

export function isSeverity(value: string): value is Severity {
  return (SEVERITY_ORDER as readonly string[]).includes(value);
}
