import type { OwaspCategory } from '@btp-lens/model';

/**
 * OWASP Top 10 (2025) titles by id. Duplicated from the CLI model
 * (packages/cli/src/model/owasp.ts) because the UI may import only types
 * from it: `@btp-lens/model` is a TypeScript paths alias that Vite does not
 * resolve. `owasp.test.ts` keeps the two copies in step.
 */
export const OWASP_2025: Readonly<Record<OwaspCategory, string>> = {
  'A01:2025': 'Broken Access Control',
  'A02:2025': 'Security Misconfiguration',
  'A03:2025': 'Software Supply Chain Failures',
  'A04:2025': 'Cryptographic Failures',
  'A05:2025': 'Injection',
  'A06:2025': 'Insecure Design',
  'A07:2025': 'Authentication Failures',
  'A08:2025': 'Software or Data Integrity Failures',
  'A09:2025': 'Security Logging and Alerting Failures',
  'A10:2025': 'Mishandling of Exceptional Conditions',
};

function isOwaspCategory(id: string): id is OwaspCategory {
  return Object.hasOwn(OWASP_2025, id);
}

/** "A01:2025 Broken Access Control"; an unknown id (newer CLI) is shown as is. */
export function owaspLabel(id: string): string {
  return isOwaspCategory(id) ? `${id} ${OWASP_2025[id]}` : id;
}

/** One line naming every category of a rule, for a tooltip. */
export function owaspTooltip(ids: readonly string[]): string {
  return `OWASP Top 10 (2025): ${ids.map(owaspLabel).join('; ')}`;
}
