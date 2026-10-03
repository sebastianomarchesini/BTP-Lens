import { mkdtemp, readFile, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { type CliIo, EXIT, main } from '../../src/main.js';
import { TOOL_VERSION } from '../../src/version.js';
import { jsonResponse } from '../support/fakeFetch.js';
import { ACME, acmeFetch } from '../support/acme.js';

interface Captured {
  io: CliIo;
  out: () => string;
  err: () => string;
}

function capture(fake = acmeFetch()): Captured {
  let out = '';
  let err = '';
  return {
    io: {
      stdout: (t) => (out += t),
      stderr: (t) => (err += t),
      env: { BTP_LENS_ACCESS_TOKEN: ACME.token },
      fetch: fake.fetch,
      now: () => ACME.now,
    },
    out: () => out,
    err: () => err,
  };
}

const tmp = () => mkdtemp(join(tmpdir(), 'btp-lens-cli-'));
const scanArgs = (out: string, ...extra: string[]) => [
  'scan',
  '--api',
  'https://api.cf.example.org',
  '--org',
  'acme-prod',
  '--out',
  out,
  '--format',
  'json,csv,sarif',
  ...extra,
];

describe('btp-lens CLI', () => {
  it('scans and writes a snapshot plus the requested reports', async () => {
    const out = await tmp();
    const c = capture();
    expect(await main(scanArgs(out), c.io)).toBe(EXIT.ok);
    expect((await readdir(out)).sort()).toEqual([
      'btp-lens-apps.csv',
      'btp-lens-findings.csv',
      'btp-lens-report.json',
      'btp-lens-report.sarif',
      'snapshot-20260929T000000Z.json',
    ]);
    expect(c.out()).toContain(
      'Scanned 8 app(s) in acme-prod: 3 finding(s) (0 critical, 0 high, 1 medium, 2 low, 0 info)',
    );
    expect(c.err()).toContain('Authenticated with the BTP_LENS_ACCESS_TOKEN');
    // SEC-22: the sharing warning is printed once per scan.
    expect(c.out().match(/do not commit them/g)).toHaveLength(1);
  });

  it('exits 1 when findings meet --fail-on', async () => {
    const out = await tmp();
    expect(await main(scanArgs(out, '--fail-on', 'medium'), capture().io)).toBe(EXIT.findings);
    expect(await main(scanArgs(out, '--fail-on', 'high'), capture().io)).toBe(EXIT.ok);
  });

  it('exits 2 on invalid options', async () => {
    const c = capture();
    expect(await main(scanArgs(await tmp(), '--fail-on', 'severe'), c.io)).toBe(EXIT.error);
    expect(c.err()).toContain('--fail-on must be one of');
    const d = capture();
    expect(await main(['scan', '--api', 'http://api.cf.example.org', '--org', 'x'], d.io)).toBe(
      EXIT.error,
    );
    expect(d.err()).toContain('--api must use https');
  });

  it('exits 2 when a required option is missing', async () => {
    const c = capture();
    expect(await main(['scan', '--api', 'https://api.cf.example.org'], c.io)).toBe(EXIT.error);
    expect(c.err()).toContain("required option '--org <name>' not specified");
  });

  it('exits 2 with a clear message when the org is not visible', async () => {
    const fake = acmeFetch().on(
      'GET',
      'api.cf.example.org/v3/organizations?names=nope&per_page=5000',
      () => jsonResponse({ pagination: { next: null }, resources: [] }),
    );
    const c = capture(fake);
    const args = [
      'scan',
      '--api',
      'https://api.cf.example.org',
      '--org',
      'nope',
      '--out',
      await tmp(),
    ];
    expect(await main(args, c.io)).toBe(EXIT.error);
    expect(c.err()).toContain('Organization "nope" was not found, or your user has no role in it.');
  });

  it('re-analyzes a snapshot offline with `report --from`', async () => {
    const scanOut = await tmp();
    await main(scanArgs(scanOut), capture().io);
    const reportOut = await tmp();
    const noNetwork = capture();
    noNetwork.io.fetch = () => Promise.reject(new Error('network must not be used'));
    const code = await main(
      [
        'report',
        '--from',
        join(scanOut, 'snapshot-20260929T000000Z.json'),
        '--format',
        'json',
        '--out',
        reportOut,
        '--fail-on',
        'low',
      ],
      noNetwork.io,
    );
    expect(code).toBe(EXIT.findings);
    const report = JSON.parse(await readFile(join(reportOut, 'btp-lens-report.json'), 'utf8')) as {
      findings: unknown[];
    };
    expect(report.findings).toHaveLength(3);
  });

  it('exits 2 for an unreadable snapshot', async () => {
    const c = capture();
    expect(await main(['report', '--from', '/nonexistent/snapshot.json'], c.io)).toBe(EXIT.error);
    expect(c.err()).toContain('Could not read snapshot');
  });

  it('without arguments in a script prints help and exits 2, and starts guided mode on a TTY', async () => {
    const script = capture();
    script.io.isTTY = false;
    expect(await main([], script.io)).toBe(EXIT.error);
    expect(script.err()).toContain('guided mode starts when a person is at the terminal');
    expect(script.err()).toContain('Usage:');

    const { ScriptedPrompter } = await import('../../src/guided/prompt.js');
    const tty = capture();
    tty.io.isTTY = true;
    tty.io.cwd = await tmp();
    tty.io.open = null;
    tty.io.env = { CF_HOME: tty.io.cwd, BTP_LENS_ACCESS_TOKEN: ACME.token };
    tty.io.fetch = acmeFetch().on('GET', 'api.cf.example.org/v3/organizations?per_page=5000', () =>
      jsonResponse({
        pagination: { next: null },
        resources: [{ guid: ACME.orgGuid, name: ACME.org }],
      }),
    ).fetch;
    const prompter = new ScriptedPrompter(['1', 'https://api.cf.example.org', 'n']);
    tty.io.prompter = prompter;
    expect(await main([], tty.io)).toBe(EXIT.ok);
    expect(prompter.transcript.join('\n')).toContain('Cancelled. Nothing was written.');
  });

  it('strips terminal escape sequences and token shapes from everything it prints', async () => {
    const fake = acmeFetch().on('GET', /\/v3\/organizations\?.*names=evil/, () =>
      jsonResponse({ pagination: { next: null }, resources: [] }),
    );
    const c = capture(fake);
    const org = 'evil\u001b]0;pwned\u0007';
    expect(await main(['scan', '--api', 'https://api.cf.example.org', '--org', org], c.io)).toBe(
      EXIT.error,
    );
    expect(c.err()).not.toContain('\u001b');
    expect(c.err()).toContain('Organization "evil" was not found');
  });

  it('runs doctor against the fixture API', async () => {
    const c = capture();
    c.io.cwd = await tmp();
    c.io.env = { CF_HOME: c.io.cwd };
    expect(await main(['doctor', '--api', 'https://api.cf.example.org'], c.io)).toBe(EXIT.ok);
    expect(c.out()).toContain('OK   Cloud Foundry API: api.cf.example.org answered');
    expect(c.out()).toContain('Everything looks fine.');
  });

  it('prints the version', async () => {
    const c = capture();
    expect(await main(['version'], c.io)).toBe(EXIT.ok);
    expect(c.out()).toBe(`btp-lens ${TOOL_VERSION}\n`);
    const v = capture();
    expect(await main(['--version'], v.io)).toBe(EXIT.ok);
    expect(v.out()).toContain(TOOL_VERSION);
  });
});
