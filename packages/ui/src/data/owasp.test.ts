import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { OWASP_2025, owaspLabel, owaspTooltip } from './owasp';

// Under jsdom import.meta.url is an http: URL, so the path is built from __dirname.
const CLI_MODEL = resolve(__dirname, '../../../cli/src/model/owasp.ts');

describe('OWASP_2025', () => {
  it('is a copy of the CLI model map', () => {
    // The UI may import only types from the CLI model, so the map is duplicated
    // and this test is what keeps the copy honest.
    const source = readFileSync(CLI_MODEL, 'utf8');
    const entries = Object.entries(OWASP_2025);
    expect(entries).toHaveLength(10);
    for (const [id, title] of entries) {
      expect(source).toContain(`'${id}': '${title}'`);
    }
  });

  it('labels known ids and passes unknown ones through', () => {
    expect(owaspLabel('A01:2025')).toBe('A01:2025 Broken Access Control');
    expect(owaspLabel('A11:2029')).toBe('A11:2029');
    expect(owaspTooltip(['A04:2025', 'A09:2025'])).toBe(
      'OWASP Top 10 (2025): A04:2025 Cryptographic Failures; A09:2025 Security Logging and Alerting Failures',
    );
  });
});
