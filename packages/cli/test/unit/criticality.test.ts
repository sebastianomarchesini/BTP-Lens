import { describe, expect, it } from 'vitest';
import { EASES, IMPACTS, criticality } from '../../src/model/criticality.js';
import {
  OWASP_2025,
  OWASP_2025_IDS,
  OwaspCategorySchema,
  owaspUrl,
} from '../../src/model/owasp.js';
import type { Severity } from '../../src/model/severity.js';

describe('criticality matrix', () => {
  const expected: Record<string, Severity> = {
    'severe/very-complex': 'high',
    'severe/complex': 'high',
    'severe/advanced': 'critical',
    'severe/easy': 'critical',
    'significant/very-complex': 'medium',
    'significant/complex': 'medium',
    'significant/advanced': 'high',
    'significant/easy': 'critical',
    'moderate/very-complex': 'low',
    'moderate/complex': 'medium',
    'moderate/advanced': 'medium',
    'moderate/easy': 'high',
    'minor/very-complex': 'low',
    'minor/complex': 'low',
    'minor/advanced': 'medium',
    'minor/easy': 'medium',
  };

  it.each(IMPACTS.flatMap((impact) => EASES.map((ease) => [impact, ease] as const)))(
    'maps %s × %s',
    (impact, ease) => {
      expect(criticality(impact, ease)).toBe(expected[`${impact}/${ease}`]);
    },
  );

  it('covers all 16 cells', () => {
    expect(Object.keys(expected)).toHaveLength(16);
  });
});

describe('OWASP Top 10 (2025)', () => {
  it('has ten categories with the published URL pattern', () => {
    expect(OWASP_2025_IDS).toHaveLength(10);
    expect(OwaspCategorySchema.safeParse('A01:2025').success).toBe(true);
    expect(OwaspCategorySchema.safeParse('A01:2021').success).toBe(false);
    expect(owaspUrl('A01:2025')).toBe(
      'https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/',
    );
    expect(owaspUrl('A10:2025')).toBe(
      'https://owasp.org/Top10/2025/A10_2025-Mishandling_of_Exceptional_Conditions/',
    );
    expect(OWASP_2025['A03:2025']).toBe('Software Supply Chain Failures');
  });
});
