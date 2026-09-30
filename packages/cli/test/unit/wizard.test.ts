import { mkdtemp, readdir, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { ScriptedPrompter } from '../../src/guided/prompt.js';
import { REGIONS } from '../../src/guided/regions.js';
import { explainConnectionError, reportDirName, runWizard } from '../../src/guided/wizard.js';
import { ACME, acmeFetch } from '../support/acme.js';
import { FakeFetch, jsonResponse } from '../support/fakeFetch.js';

const HOST = ACME.api.host;

/** acme-prod plus the calls only guided mode makes: org listing and the passcode exchange. */
function guidedFetch(): FakeFetch {
  return acmeFetch()
    .on('GET', `${HOST}/v3/organizations?per_page=5000`, () =>
      jsonResponse({
        pagination: { next: null },
        resources: [{ guid: ACME.orgGuid, name: ACME.org }],
      }),
    )
    .on('POST', 'uaa.cf.example.org/oauth/token', (call) => {
      const form = new URLSearchParams(call.body);
      if (form.get('grant_type') === 'password' && form.get('passcode') === 'K7Q2ZX') {
        return jsonResponse({ access_token: 'guided-access-token-POISON', refresh_token: 'r1' });
      }
      return jsonResponse({ error: 'unauthorized' }, 401);
    });
}

const tmp = () => mkdtemp(join(tmpdir(), 'btp-lens-wizard-'));

describe('guided mode', () => {
  it('scans with four questions, pastes the endpoint and signs in with a one-time code', async () => {
    const cwd = await tmp();
    const opened: string[] = [];
    const prompter = new ScriptedPrompter([
      '1', // paste the endpoint
      'https://api.cf.example.org',
      '1', // browser + one-time code (no cf CLI session in this env)
      'K7Q2ZX',
      '', // confirm (default yes)
    ]);
    const code = await runWizard({
      prompter,
      env: { CF_HOME: cwd }, // no ~/.cf/config.json here
      cwd,
      open: (path) => {
        opened.push(path);
        return Promise.resolve(true);
      },
      fetch: guidedFetch().fetch,
      now: () => ACME.now,
    });
    expect(code).toBe(0);
    const dir = join(cwd, 'btp-lens-reports', reportDirName(ACME.now));
    expect((await readdir(dir)).sort()).toEqual([
      'btp-lens-apps.csv',
      'btp-lens-findings.csv',
      'btp-lens-report.html',
      'btp-lens-report.json',
      'btp-lens-report.sarif',
      'snapshot-20260929T000000Z.json',
    ]);
    // The passcode page was opened, then the finished report.
    expect(opened).toEqual([
      'https://login.cf.example.org/passcode',
      join(dir, 'btp-lens-report.html'),
    ]);
    const text = prompter.transcript.join('\n');
    expect(text).toContain('You have access to one org: acme-prod.');
    expect(text).toContain('8 apps scanned, 3 findings');
    expect(text).toContain('Nothing in your account was changed.');
    // Neither the passcode nor the token is ever printed or stored.
    expect(text).not.toContain('K7Q2ZX');
    expect(text).not.toContain('POISON');
    const snapshot = await readFile(join(dir, 'snapshot-20260929T000000Z.json'), 'utf8');
    expect(snapshot).not.toContain('POISON');
  }, 20_000);

  it('picks a region from the list and uses BTP_LENS_ACCESS_TOKEN silently', async () => {
    const cwd = await tmp();
    const trial = REGIONS.findIndex((r) => r.id === 'us10-001');
    const host = 'api.cf.us10-001.hana.ondemand.com';
    const fake = new FakeFetch()
      .on('GET', `${host}/`, () =>
        jsonResponse({ links: { uaa: { href: `https://uaa.cf.us10-001.hana.ondemand.com` } } }),
      )
      .on('GET', `${host}/v3/organizations?per_page=5000`, () =>
        jsonResponse({ pagination: { next: null }, resources: [] }),
      );
    const prompter = new ScriptedPrompter([String(trial + 2)]);
    await expect(
      runWizard({
        prompter,
        env: { BTP_LENS_ACCESS_TOKEN: 'abc', CF_HOME: cwd },
        cwd,
        open: null,
        fetch: fake.fetch,
        now: () => ACME.now,
      }),
    ).rejects.toThrow(/no role in any Cloud Foundry org/);
    expect(prompter.transcript.join('\n')).toContain('Using the token from BTP_LENS_ACCESS_TOKEN');
    expect(fake.calls.map((c) => c.url.pathname)).toEqual(['/', '/v3/organizations']);
  });

  it('exits 0 and writes nothing when the user declines to start', async () => {
    const cwd = await tmp();
    const prompter = new ScriptedPrompter(['1', 'https://api.cf.example.org', '1', 'K7Q2ZX', 'n']);
    const code = await runWizard({
      prompter,
      env: { CF_HOME: cwd },
      cwd,
      open: null,
      fetch: guidedFetch().fetch,
      now: () => ACME.now,
    });
    expect(code).toBe(0);
    expect(prompter.transcript.at(-1)).toBe('Cancelled. Nothing was written.');
    await expect(readdir(join(cwd, 'btp-lens-reports'))).rejects.toThrow();
  });

  it('retries a wrong one-time code and never echoes it', async () => {
    const cwd = await tmp();
    const prompter = new ScriptedPrompter([
      '1',
      'https://api.cf.example.org',
      '1',
      'WRONG1',
      'K7Q2ZX',
      'n',
    ]);
    const code = await runWizard({
      prompter,
      env: { CF_HOME: cwd },
      cwd,
      open: null,
      fetch: guidedFetch().fetch,
      now: () => ACME.now,
    });
    expect(code).toBe(0);
    const text = prompter.transcript.join('\n');
    expect(text).toContain('Sign-in failed');
    expect(text).toContain('Signed in.');
    expect(text).not.toContain('WRONG1');
  });

  it('explains a mistyped endpoint and gives up after three attempts', async () => {
    const cwd = await tmp();
    const prompter = new ScriptedPrompter(['1', 'not a url', 'http://plain.example', 'ftp://x']);
    await expect(
      runWizard({ prompter, env: {}, cwd, open: null, fetch: new FakeFetch().fetch }),
    ).rejects.toThrow(/three attempts/);
    expect(prompter.transcript.join('\n')).toContain('--api must use https');
  });
});

describe('explainConnectionError', () => {
  const api = new URL('https://api.cf.example.org');
  it('turns TLS, DNS and connection errors into one problem line and one action line', () => {
    expect(
      explainConnectionError(new Error('unable to verify the first certificate'), api),
    ).toMatch(/NODE_EXTRA_CA_CERTS/);
    expect(
      explainConnectionError(new Error('getaddrinfo ENOTFOUND api.cf.example.org'), api),
    ).toMatch(/could not be found/);
    expect(explainConnectionError(new Error('fetch failed'), api)).toMatch(/HTTPS_PROXY/);
    expect(explainConnectionError(new Error('CF API 500'), api)).toMatch(/btp-lens doctor/);
  });
});

describe('reportDirName', () => {
  it('is a sortable local timestamp', () => {
    const d = new Date(2026, 8, 30, 14, 5);
    expect(reportDirName(d)).toBe('2026-09-30-1405');
  });
});
