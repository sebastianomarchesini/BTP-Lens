import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { formatDoctor, runDoctor } from '../../src/doctor.js';
import { FakeFetch, jsonResponse } from '../support/fakeFetch.js';

const api = new URL('https://api.cf.example.org');
const NOW = 1_800_000_000_000;

function jwt(expSeconds: number): string {
  const enc = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');
  return `${enc({ alg: 'none' })}.${enc({ exp: expSeconds })}.sig`;
}

async function cfHome(config: object): Promise<string> {
  const home = await mkdtemp(join(tmpdir(), 'btp-lens-doctor-'));
  await mkdir(join(home, '.cf'));
  await writeFile(join(home, '.cf', 'config.json'), JSON.stringify(config));
  return home;
}

describe('btp-lens doctor', () => {
  it('passes on a healthy setup and says so in one line per check', async () => {
    const home = await cfHome({
      Target: 'https://api.cf.example.org',
      AccessToken: `bearer ${jwt(NOW / 1000 + 5 * 3600)}`,
      RefreshToken: 'r',
    });
    const fake = new FakeFetch().on('GET', 'api.cf.example.org/', () =>
      jsonResponse({ links: {} }),
    );
    const checks = await runDoctor({
      api,
      env: { CF_HOME: home },
      cwd: home,
      fetch: fake.fetch,
      nodeVersion: '22.12.0',
      now: () => NOW,
    });
    expect(checks.map((c) => [c.name, c.ok])).toEqual([
      ['Node.js', true],
      ['Cloud Foundry API', true],
      ['cf CLI login', true],
      ['Output folder', true],
    ]);
    expect(checks[2]?.detail).toBe('Logged in, token valid for about 5 h');
    expect(formatDoctor(checks)).toContain('Everything looks fine.');
  });

  it('names the fix for old Node, TLS interception and a wrong cf target', async () => {
    const home = await cfHome({
      Target: 'https://api.cf.other.org',
      AccessToken: `bearer ${jwt(NOW / 1000 + 60)}`,
      RefreshToken: 'r',
    });
    const fake = new FakeFetch().on('GET', 'api.cf.example.org/', () => {
      throw new Error('unable to verify the first certificate');
    });
    const checks = await runDoctor({
      api,
      env: { CF_HOME: home },
      cwd: home,
      fetch: fake.fetch,
      nodeVersion: '20.19.0',
      now: () => NOW,
    });
    const text = formatDoctor(checks);
    expect(text).toContain('FAIL Node.js');
    expect(text).toContain('nodejs.org');
    expect(text).toContain('NODE_EXTRA_CA_CERTS');
    expect(text).toContain('cf CLI targets https://api.cf.other.org');
    expect(text).toContain('3 checks need attention');
    expect(formatDoctor([checks[0]!])).toContain('1 check needs attention');
    // No stack traces, request objects or tokens.
    expect(text).not.toMatch(/at .*\.ts:\d+/);
    expect(text).not.toContain('eyJ');
  });

  it('explains a proxy 403 and never tells people to run doctor again', async () => {
    const home = await mkdtemp(join(tmpdir(), 'btp-lens-doctor-'));
    const fake = new FakeFetch().on('GET', 'api.cf.example.org/', () =>
      jsonResponse({ errors: [] }, 403),
    );
    const checks = await runDoctor({
      api,
      env: { CF_HOME: home },
      cwd: home,
      fetch: fake.fetch,
      nodeVersion: '22.12.0',
      now: () => NOW,
    });
    const text = formatDoctor(checks);
    expect(text).toContain('FAIL Cloud Foundry API');
    expect(text).toContain('proxy or firewall');
    expect(text).not.toMatch(/Run `btp-lens doctor`/);
  });

  it('recognises TLS interception hidden behind "fetch failed" and fits proxy advice to Node', async () => {
    const home = await mkdtemp(join(tmpdir(), 'btp-lens-doctor-'));
    const failWith = (message: string, code: string) =>
      new FakeFetch().on('GET', 'api.cf.example.org/', () => {
        throw new TypeError('fetch failed', { cause: Object.assign(new Error(message), { code }) });
      });
    const run = (fake: FakeFetch, nodeVersion: string) =>
      runDoctor({
        api,
        env: { CF_HOME: home },
        cwd: home,
        fetch: fake.fetch,
        nodeVersion,
        now: () => NOW,
      });

    const tls = formatDoctor(
      await run(failWith('self-signed certificate', 'DEPTH_ZERO_SELF_SIGNED_CERT'), '24.9.0'),
    );
    expect(tls).toContain('is not trusted');
    expect(tls).toContain('NODE_EXTRA_CA_CERTS');
    expect(tls).not.toContain('HTTPS_PROXY');

    const oldNode = formatDoctor(
      await run(failWith('connect ECONNREFUSED 10.0.0.1:443', 'ECONNREFUSED'), '22.12.0'),
    );
    expect(oldNode).toContain('could not be reached');
    expect(oldNode).toContain('upgrade Node.js to 24');
  });

  it('treats a missing cf CLI login as fine, because guided mode signs in itself', async () => {
    const home = await mkdtemp(join(tmpdir(), 'btp-lens-doctor-'));
    const checks = await runDoctor({ env: { CF_HOME: home }, cwd: home, nodeVersion: '24.0.0' });
    expect(checks.find((c) => c.name === 'cf CLI login')?.ok).toBe(true);
    expect(checks.find((c) => c.name === 'Cloud Foundry API')?.detail).toContain('Not tested');
  });
});
