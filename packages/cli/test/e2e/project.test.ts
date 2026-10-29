import { mkdtemp, readFile, readdir, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve, sep } from 'node:path';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import type * as ChildProcess from 'node:child_process';
import type * as HtmlReporter from '../../src/reporters/html.js';
import { type CliIo, EXIT, main } from '../../src/main.js';
import { isSafeRelativePath } from '../../src/model/paths.js';
import type { RawProject } from '../../src/model/raw.js';
import type { Snapshot } from '../../src/model/snapshot.js';
import { ABSOLUTE_PATH, expectNoLeaks } from '../support/leak.js';
import { POISON } from '../support/project.js';
import { type MaterializedFixture, materializeFixture } from '../support/projectFixture.js';

/*
 * The project scan must never spawn a process. The fixture helper itself
 * creates a FIFO with mkfifo, which is the one call let through; everything
 * else throws, as the collector would if it ever tried.
 */
vi.mock('node:child_process', async (importOriginal) => {
  const actual = await importOriginal<typeof ChildProcess>();
  const refuse = (): never => {
    throw new Error('child processes must not be used');
  };
  const execFileSync = ((
    file: string,
    args?: readonly string[],
    options?: ChildProcess.ExecFileSyncOptions,
  ) =>
    file === 'mkfifo'
      ? actual.execFileSync(file, args, options)
      : refuse()) as typeof actual.execFileSync;
  return {
    ...actual,
    default: { ...actual, execFileSync, exec: refuse, execFile: refuse, spawn: refuse },
    execFileSync,
    exec: refuse,
    execFile: refuse,
    execSync: refuse,
    spawn: refuse,
    spawnSync: refuse,
    fork: refuse,
  };
});

/* The real UI bundle is not under test here; a tiny template keeps the leak checks about our data. */
vi.mock('../../src/reporters/html.js', async (importOriginal) => {
  const actual = await importOriginal<typeof HtmlReporter>();
  return {
    ...actual,
    loadReportTemplate: () =>
      Promise.resolve(`<html><body>${actual.DATA_PLACEHOLDER}</body></html>`),
  };
});

const NOW = new Date('2026-09-29T00:00:00.000Z');
const SNAPSHOT_FILE = 'snapshot-20260929T000000Z.json';
const REPORT_FILES = [
  'btp-lens-apps.csv',
  'btp-lens-findings.csv',
  'btp-lens-report.html',
  'btp-lens-report.json',
  'btp-lens-report.sarif',
];

interface Captured {
  io: CliIo;
  out: () => string;
  err: () => string;
}

function capture(): Captured {
  let out = '';
  let err = '';
  return {
    io: {
      stdout: (t) => (out += t),
      stderr: (t) => (err += t),
      env: {},
      fetch: () => Promise.reject(new Error('network must not be used')),
      now: () => NOW,
    },
    out: () => out,
    err: () => err,
  };
}

const tmp = () => mkdtemp(join(tmpdir(), 'btp-lens-project-out-'));

/** Terminal output without the `Wrote:` block, whose lines are the output paths. */
function terminalText(c: Captured, out: string): string {
  const lines = `${c.out()}\n${c.err()}`.split('\n');
  return lines.filter((line) => line !== 'Wrote:' && !line.trim().startsWith(out)).join('\n');
}

async function readOutputs(out: string): Promise<Record<string, string>> {
  const texts: Record<string, string> = {};
  for (const file of await readdir(out)) texts[file] = await readFile(join(out, file), 'utf8');
  return texts;
}

/** Every string value in a JSON-like structure, with its key path. */
function stringValues(value: unknown, path = '$'): [string, string][] {
  if (typeof value === 'string') return [[path, value]];
  if (Array.isArray(value)) return value.flatMap((item, i) => stringValues(item, `${path}[${i}]`));
  if (value !== null && typeof value === 'object') {
    return Object.entries(value).flatMap(([key, item]) => stringValues(item, `${path}.${key}`));
  }
  return [];
}

function pathFields(project: RawProject): string[] {
  return stringValues(project)
    .filter(([path]) => /\.(file|path)$/.test(path))
    .map(([, value]) => value);
}

async function scanFixture(
  fixture: MaterializedFixture,
  ...extra: string[]
): Promise<{ code: number; out: string; c: Captured; snapshot: Snapshot }> {
  const out = await tmp();
  const c = capture();
  const args = ['project', '--path', fixture.root, '--out', out, '--format', 'html,json,csv,sarif'];
  const code = await main([...args, ...extra], c.io);
  const snapshotText = await readFile(join(out, SNAPSHOT_FILE), 'utf8').catch(() => '{}');
  return { code, out, c, snapshot: JSON.parse(snapshotText) as Snapshot };
}

function expectCleanOutputs(
  texts: Record<string, string>,
  terminal: string,
  fixture: MaterializedFixture,
): void {
  const forbidden = [...POISON, fixture.root, tmpdir()];
  expectNoLeaks({ ...texts, terminal }, forbidden, [ABSOLUTE_PATH]);
}

describe('btp-lens project on the acme-incidents fixture', () => {
  let fixture: MaterializedFixture;
  let out: string;
  let c: Captured;
  let code: number;
  let snapshot: Snapshot;
  let texts: Record<string, string>;
  let project: RawProject;

  beforeAll(async () => {
    fixture = await materializeFixture('acme-incidents');
    ({ code, out, c, snapshot } = await scanFixture(fixture));
    texts = await readOutputs(out);
    project = snapshot.raw.projects[0]!;
  });
  afterAll(() => fixture.cleanup());

  it('writes the snapshot and every report format', () => {
    expect(code).toBe(EXIT.ok);
    expect(Object.keys(texts).sort()).toEqual([...REPORT_FILES, SNAPSHOT_FILE]);
    expect(c.out()).toMatch(/^Scanned project acme-incidents: \d+ finding\(s\)/);
    expect(c.err()).toMatch(
      /^Read \d+ project file\(s\), \d+ unreadable in project acme-incidents\n/,
    );
  });

  it('(1) leaks no poison value, personal data, secret or absolute path into any output', () => {
    expectCleanOutputs(texts, terminalText(c, out), fixture);
  });

  it('(2) stores only safe relative paths that resolve inside the project', () => {
    const paths = pathFields(project);
    expect(paths.length).toBeGreaterThan(10);
    for (const file of paths) {
      expect(isSafeRelativePath(file), file).toBe(true);
      expect(resolve(fixture.root, file).startsWith(fixture.root + sep), file).toBe(true);
    }
  });

  it('(3) never opens a deny-listed, linked, special or oversized file', () => {
    const listed = JSON.stringify(project.files);
    for (const name of [
      '.md',
      '.pem',
      '.env',
      '.mtaext',
      '.cdsrc-private.json',
      'default-env.json',
      '.http',
      'link-out',
      'link.cds',
      'pipe.cds',
      'big.cds',
      '.git',
    ]) {
      expect(listed, name).not.toContain(name);
    }
    expect(project.unreadable).toEqual([{ file: 'db/big.cds', kind: 'too-large' }]);
    expect(project.files).toEqual([
      '.cdsrc.json',
      '.cdsrc.yaml',
      'app/incidents/webapp/index.html',
      'app/incidents/webapp/test/flpSandbox.html',
      'app/incidents/xs-app.json',
      'app/launchpage.html',
      'db/data/acme.incidents-Customers.csv',
      'db/data/acme.incidents-Status.csv',
      'db/schema.cds',
      'mta.yaml',
      'package.json',
      'srv/external/ExternalService.cds',
      'srv/services.cds',
      'test/data/POISON-export.csv',
      'xs-security.json',
    ]);
    expect(project.archives).toEqual([
      { file: 'mta_archives/acme-incidents_1.0.0.mtar', bytes: 64, ignored: false },
    ]);
    expect(project.repository).toBe(true);
  });

  it('(4) keeps every string short and every unreadable entry to file and kind', () => {
    for (const [path, value] of stringValues(snapshot.raw.projects)) {
      expect(value.length, path).toBeLessThanOrEqual(256);
    }
    for (const entry of project.unreadable)
      expect(Object.keys(entry).sort()).toEqual(['file', 'kind']);
  });

  it('(5) check reasons carry neither a rooted path nor a parser position', () => {
    for (const check of snapshot.checks) {
      expect(check.reason ?? '').not.toMatch(/(^|[\s"'(=])\//);
      expect(check.reason ?? '').not.toContain('at line');
    }
    expect(snapshot.checks.find((check) => check.id === 'collect.project')?.status).toBe('ran');
  });

  it('(6) stores bootstrap sources without query, fragment or userinfo', () => {
    expect(project.html).toHaveLength(3);
    for (const bootstrap of project.html) expect(bootstrap.src).not.toMatch(/[?#@]/);
    expect(
      project.html.map((h) => [h.file, h.versionForm, h.external, h.integrity, h.testPage]),
    ).toEqual([
      ['app/incidents/webapp/index.html', 'latest', true, false, false],
      ['app/incidents/webapp/test/flpSandbox.html', 'specific', true, false, true],
      ['app/launchpage.html', 'evergreen', true, false, false],
    ]);
  });

  it('(7) names the project with a safe id', () => {
    expect(snapshot.scope.projects?.[0]).toMatch(/^[A-Za-z0-9._-]+$/);
    expect(snapshot.scope.projects).toEqual(['acme-incidents']);
    for (const app of snapshot.apps) expect(app.guid).toMatch(/^(project:)?[A-Za-z0-9._-]+$/);
  });

  it('(8) counts one project and no app', () => {
    const report = JSON.parse(texts['btp-lens-report.json']!) as {
      summary: { projects: number; apps: number };
    };
    expect(report.summary.projects).toBe(1);
    expect(report.summary.apps).toBe(0);
  });

  it('(9) reports findings with a subject each', () => {
    // TODO(integrator): once all 13 project rules have landed, replace this
    // with the exact sorted list of (id, severity, evidence.subject) for the
    // acme-incidents fixture (spec §9, assertion 9), e.g.
    //   expect(snapshot.findings.map((f) => [f.id, f.severity, f.evidence.subject])).toEqual([...]);
    expect(snapshot.findings.length).toBeGreaterThan(0);
    for (const finding of snapshot.findings) {
      expect(typeof finding.evidence.subject, finding.id).toBe('string');
    }
  });

  it('(10) honours --fail-on', async () => {
    expect((await scanFixture(fixture, '--fail-on', 'high')).code).toBe(EXIT.findings);
    expect((await scanFixture(fixture, '--fail-on', 'none')).code).toBe(EXIT.ok);
  });

  it('(11) report --from reproduces the same findings offline', async () => {
    const again = await tmp();
    const d = capture();
    const args = ['report', '--from', join(out, SNAPSHOT_FILE), '--out', again, '--format', 'json'];
    expect(await main(args, d.io)).toBe(EXIT.ok);
    const first = JSON.parse(texts['btp-lens-report.json']!) as { findings: unknown };
    const second = JSON.parse(await readFile(join(again, 'btp-lens-report.json'), 'utf8')) as {
      findings: unknown;
    };
    expect(second.findings).toEqual(first.findings);
    expect(d.out()).toContain('Scanned project acme-incidents');
  });

  it('collects the structural facts the rules need', () => {
    expect(project.id).toBe('acme-incidents');
    expect(project.sourcesRead).toEqual(['.cdsrc.yaml', '.cdsrc.json', 'package.json']);
    expect(project.cds.effective.production).toMatchObject({
      authKind: 'mocked',
      mockedUsers: 0,
      mockedUsersWithPassword: 0,
      restrictAllServices: true,
      auditLogConfigured: false,
    });
    expect(project.cds.effective.development).toMatchObject({
      authKind: 'mocked',
      mockedUsers: 2,
      mockedUsersWithPassword: 1,
    });
    expect(project.packageJson.dependencies.map((d) => d.name)).toEqual([
      '@sap/cds',
      '@sap/xssec',
      'express',
      'poison-git',
      'poison-file',
      'poison-alias',
    ]);
    expect(project.mta?.modules.map((m) => m.buildpack)).toEqual([
      'nodejs_buildpack',
      'https://github.com/acme/buildpack.git',
      'nodejs_buildpack',
    ]);
    expect(project.mta?.resources.map((r) => r.service)).toEqual(['xsuaa', 'hana', 'destination']);
    expect(project.xsSecurity.map((x) => [x.file, x.source])).toEqual([
      ['mta.yaml', 'mta.yaml'],
      ['xs-security.json', 'xs-security.json'],
    ]);
    expect(
      project.xsApps[0]?.routes.map((r) => [
        r.target,
        r.targetHint,
        r.authenticationType,
        r.isLogoutPage,
      ]),
    ).toEqual([
      ['destination', 'api', 'xsuaa', false],
      ['destination', 'other', 'none', false],
      ['destination', 'ui5-cdn', 'none', false],
      ['destination', 'api', 'none', false],
      ['localDir', 'other', 'none', true],
      ['service', 'html5-repo', 'xsuaa', false],
    ]);
    const services = project.cdsFiles.find((f) => f.file === 'srv/services.cds')?.services;
    expect(services?.map((s) => [s.name, s.requires, s.protocolNone])).toEqual([
      ['AdminService', [], false],
      ['ProcessorService', ['support'], false],
      ['InternalService', [], true],
    ]);
    expect(services?.[1]?.entities[0]?.restrictTo).toEqual(['auditor']);
    const external = project.cdsFiles.find((f) => f.file === 'srv/external/ExternalService.cds');
    expect(external?.services[0]?.external).toBe(true);
    const schema = project.cdsFiles.find((f) => f.file === 'db/schema.cds');
    expect(schema?.entities.map((e) => e.name)).toEqual([
      'Customers',
      'Addresses',
      'Warehouses',
      'Incidents',
      'Status',
    ]);
    expect(project.seedData.map((s) => [s.file, s.headerRejected, s.sensitiveColumns])).toEqual([
      [
        'db/data/acme.incidents-Customers.csv',
        false,
        [{ column: 'creditCardNo', kind: 'card', rowsMatching: 1 }],
      ],
      ['db/data/acme.incidents-Status.csv', false, []],
      ['test/data/POISON-export.csv', true, []],
    ]);
  });
});

describe('btp-lens project on the clean-cap fixture', () => {
  it('(12) finds nothing and leaks nothing', async () => {
    const fixture = await materializeFixture('clean-cap');
    try {
      const { code, out, c, snapshot } = await scanFixture(fixture);
      expect(code).toBe(EXIT.ok);
      expect(snapshot.findings).toEqual([]);
      expect(snapshot.raw.projects[0]?.archives).toEqual([
        { file: 'mta_archives/clean-cap_1.0.0.mtar', bytes: 64, ignored: true },
      ]);
      expect(snapshot.raw.projects[0]?.unreadable).toEqual([]);
      expectCleanOutputs(await readOutputs(out), terminalText(c, out), fixture);
    } finally {
      await fixture.cleanup();
    }
  });
});

describe('btp-lens project root errors', () => {
  it('(13) exits 2 and echoes the --path the user gave, never its real path', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'btp-lens-project-roots-'));
    await writeFile(join(dir, 'real-file.txt'), 'x');
    await symlink(join(dir, 'real-file.txt'), join(dir, 'file-link'));
    await symlink(dir, join(dir, 'dir-link'));
    const cases: [string, string][] = [
      [join(dir, 'file-link'), 'is not a folder'],
      [join(dir, 'missing'), 'does not exist'],
      [join(dir, 'dir-link'), 'does not look like a CAP or MTA project'],
    ];
    for (const [path, reason] of cases) {
      const c = capture();
      const code = await main(['project', '--path', path, '--out', await tmp()], c.io);
      expect(code, path).toBe(EXIT.error);
      expect(c.err()).toContain(`Project path "${path}" ${reason}`);
      expect(c.err()).not.toContain('real-file');
      expect(c.err()).not.toContain('btp-lens-project-roots-/');
      expect(c.out()).toBe('');
    }
  });
});
