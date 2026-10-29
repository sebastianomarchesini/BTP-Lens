import type { ReportData } from '@btp-lens/model';
import { describe, expect, it } from 'vitest';
import projectSample from '../test/fixtures/report-project.json';
import sample from '../test/fixtures/report.json';
import {
  isProjectInventory,
  isProjectScope,
  scopeLabel,
  scopePhrase,
  startHereSentences,
} from './summary';

const data = sample as unknown as ReportData;
const project = projectSample as unknown as ReportData;

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

  it('names the space when the scan was limited to one', () => {
    const scope = { ...data.scope, spaces: ['prod'] };
    expect(startHereSentences({ ...data, scope })[0]).toBe(
      '8 apps in space prod of acme-prod were scanned on Sep 29, 2026.',
    );
    expect(scopeLabel(scope)).toBe('acme-prod / prod');
    expect(scopePhrase({ ...scope, spaces: ['dev', 'qa'] })).toBe('spaces dev, qa of acme-prod');
    expect(scopeLabel(data.scope)).toBe('acme-prod');
  });

  it('describes a project scan by its findings', () => {
    const s = startHereSentences(project);
    expect(s).toEqual([
      'The project acme-incidents was scanned on Sep 29, 2026.',
      '16 findings need attention: 3 pages load SAPUI5 from an external CDN without integrity protection; 2 entities hold personal data without @PersonalData annotations; mocked authentication is configured for production.',
      'Nothing in your project was changed: this scan only read files in the project folder.',
    ]);
  });

  it('counts findings, not projects, per project rule', () => {
    const open = project.findings.find((f) => f.id === 'CAP_SERVICE_NO_RESTRICTION')!;
    const twice = [open, { ...open, location: { file: 'srv/other.cds' } }];
    const s = startHereSentences({
      ...project,
      findings: twice,
      summary: { ...project.summary, findings: 2, checksSkipped: 1 },
    });
    expect(s[1]).toBe(
      '2 findings need attention: 2 services are open to every authenticated user.',
    );
    expect(s[2]).toBe(
      '1 check could not run, so some things were not looked at. That is not a problem with your project.',
    );
  });

  it('has a phrase for every project rule', () => {
    const projectRules = project.rules.filter(
      (r) => r.roles.length === 0 && r.id !== 'APP_NO_RECENT_DEPLOY',
    );
    expect(projectRules).toHaveLength(13);
    for (const rule of projectRules) {
      const finding = { ...project.findings[0]!, id: rule.id };
      const s = startHereSentences({ ...project, findings: [finding, finding] });
      // The fallback wording quotes the rule title; a phrase never does.
      expect(s[1]).not.toContain(`"${rule.title}"`);
    }
  });

  it('labels the scope of a project scan', () => {
    expect(isProjectScope(project.scope)).toBe(true);
    expect(isProjectScope(data.scope)).toBe(false);
    expect(scopeLabel(project.scope)).toBe('acme-incidents');
    expect(scopePhrase(project.scope)).toBe('project acme-incidents');
    expect(scopePhrase({ orgs: [], projects: ['a', 'b'] })).toBe('projects a, b');
    expect(isProjectInventory(project.apps)).toBe(true);
    expect(isProjectInventory(data.apps)).toBe(false);
    expect(isProjectInventory([])).toBe(false);
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
