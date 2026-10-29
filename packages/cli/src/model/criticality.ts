import type { Severity } from './severity.js';

/*
 * Criticality matrix: impact × ease of attack → severity. Rules that use it
 * record both inputs in the finding evidence, so a reader can see why a
 * finding got its severity. The matrix is the one from the SAP TechEd 2026
 * XP261 workshop material (docs/rules.md, "Criticality").
 */

export const IMPACTS = ['minor', 'moderate', 'significant', 'severe'] as const;
export type Impact = (typeof IMPACTS)[number];

export const EASES = ['very-complex', 'complex', 'advanced', 'easy'] as const;
export type EaseOfAttack = (typeof EASES)[number];

const MATRIX: Record<Impact, Record<EaseOfAttack, Severity>> = {
  severe: { 'very-complex': 'high', complex: 'high', advanced: 'critical', easy: 'critical' },
  significant: { 'very-complex': 'medium', complex: 'medium', advanced: 'high', easy: 'critical' },
  moderate: { 'very-complex': 'low', complex: 'medium', advanced: 'medium', easy: 'high' },
  minor: { 'very-complex': 'low', complex: 'low', advanced: 'medium', easy: 'medium' },
};

export function criticality(impact: Impact, ease: EaseOfAttack): Severity {
  return MATRIX[impact][ease];
}
