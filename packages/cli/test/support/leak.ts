import { expect } from 'vitest';

/** Patterns that look like secrets or personal data, whatever the value. */
export const SUSPICIOUS = [
  // Domain must end in an alphabetic TLD, so "nodejs@1.8.40" is not an email.
  { name: 'email address', pattern: /[\w.+-]+@(?:[a-z0-9-]+\.)+[a-z]{2,}\b/i },
  { name: 'JWT', pattern: /eyJ[\w-]{10,}\.[\w-]{10,}/ },
  { name: 'bearer token', pattern: /bearer\s+[\w.-]{8,}/i },
  { name: 'URL with credentials', pattern: /[a-z]+:\/\/[^\s/"@]+:[^\s/"@]+@/i },
];

/** An absolute POSIX path under a user or system directory, or a Windows drive path. */
export const ABSOLUTE_PATH = /(^|["'\s(=])(\/(home|Users|tmp|var|opt|etc|private)\/|[A-Za-z]:\\)/;

/**
 * Asserts that none of the texts (keyed by a label, e.g. a file name) contains
 * a poison value, a suspicious pattern or any of the extra patterns.
 */
export function expectNoLeaks(
  texts: Record<string, string>,
  poison: string[],
  extra: RegExp[] = [],
): void {
  for (const [label, content] of Object.entries(texts)) {
    for (const value of poison) {
      expect(content, `${label} contains "${value}"`).not.toContain(value);
    }
    for (const { name, pattern } of SUSPICIOUS) {
      expect(pattern.test(content), `${label} contains a ${name}`).toBe(false);
    }
    for (const pattern of extra) {
      expect(pattern.test(content), `${label} matches ${pattern}`).toBe(false);
    }
  }
}
