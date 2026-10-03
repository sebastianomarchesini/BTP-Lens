import type { ReportData } from '@btp-lens/model';
import { describe, expect, it } from 'vitest';
import sample from '../test/fixtures/report.json';
import { startHereSentences } from './summary';

const data = sample as unknown as ReportData;

describe('startHereSentences', () => {
  it('summarises the sample scan in plain language', () => {
    const s = startHereSentences(data);
    expect(s[0]).toBe('8 apps in acme-prod were scanned on Sep 29, 2026.');
    expect(s[1]).toBe('3 apps need attention: 3 have not been deployed in over a year.');
    expect(s.at(-1)).toBe('Nothing in your account was changed: this scan only read information.');
  });

  it('says when nothing was found and when checks were skipped', () => {
    const s = startHereSentences({
      ...data,
      findings: [],
      summary: { ...data.summary, findings: 0, checksSkipped: 2 },
    });
    expect(s).toEqual([
      '8 apps in acme-prod were scanned on Sep 29, 2026.',
      'No rule found a problem in the checks that ran.',
      '2 checks could not run with your role, so some things were not looked at. That is not a problem with your apps.',
      'Nothing in your account was changed: this scan only read information.',
    ]);
  });

  it('falls back to the rule title for rules without a phrase', () => {
    const finding = { ...data.findings[0]!, id: 'SOMETHING_NEW' };
    const s = startHereSentences({
      ...data,
      findings: [finding],
      rules: [...data.rules, { ...data.rules[0]!, id: 'SOMETHING_NEW', title: 'Something new' }],
    });
    expect(s[1]).toBe('1 app needs attention: 1 has "Something new".');
  });
});
