import { z } from 'zod';

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;

export const SeveritySchema = z.enum(SEVERITIES);
export type Severity = z.infer<typeof SeveritySchema>;

const RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

export function severityRank(severity: Severity): number {
  return RANK[severity];
}

/** True when `severity` is at or above `threshold`. */
export function meetsThreshold(severity: Severity, threshold: Severity): boolean {
  return RANK[severity] >= RANK[threshold];
}

export function emptySeverityCounts(): Record<Severity, number> {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
}
