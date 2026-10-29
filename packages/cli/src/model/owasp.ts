import { z } from 'zod';

/** OWASP Top 10 (2025) categories, id → title, as published in OWASP/Top10 `2025/mkdocs.yml`. */
export const OWASP_2025 = {
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
} as const;

export const OWASP_2025_IDS = Object.keys(OWASP_2025) as [OwaspCategory, ...OwaspCategory[]];

export const OwaspCategorySchema = z.enum(OWASP_2025_IDS);
export type OwaspCategory = keyof typeof OWASP_2025;

export const OWASP_2025_URL = 'https://owasp.org/Top10/2025/';

/** `https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/` */
export function owaspUrl(id: OwaspCategory): string {
  return `${OWASP_2025_URL}${id.replace(':', '_')}-${OWASP_2025[id].replace(/ /g, '_')}/`;
}
