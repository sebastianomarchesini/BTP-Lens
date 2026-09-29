import { mkdtemp, mkdir, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  CfCliTokenProvider,
  jwtExpiryMs,
  resolveTokenProvider,
  sameEndpoint,
} from '../../src/http/auth.js';
import { CfAuthError, ConfigError } from '../../src/http/errors.js';
import { HttpClient } from '../../src/http/httpClient.js';
import { EgressPolicy, uaaRule } from '../../src/net/allowlist.js';
import { FakeFetch, jsonResponse, noSleep } from '../support/fakeFetch.js';

const api = new URL('https://api.cf.example.org');
const tokenUrl = new URL('https://uaa.cf.example.org/oauth/token');
const NOW = 1_800_000_000_000;

function jwt(expSeconds: number): string {
  const enc = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');
  return `${enc({ alg: 'none' })}.${enc({ exp: expSeconds })}.sig`;
}

function http(fake: FakeFetch): HttpClient {
  const policy = new EgressPolicy();
  policy.add(uaaRule(new URL('https://uaa.cf.example.org')));
  return new HttpClient({ policy, userAgent: 't', fetch: fake.fetch, sleep: noSleep });
}

async function cfHomeWith(config: object): Promise<string> {
  const home = await mkdtemp(join(tmpdir(), 'btp-lens-cf-'));
  await mkdir(join(home, '.cf'));
  await writeFile(join(home, '.cf', 'config.json'), JSON.stringify(config));
  return home;
}

describe('jwtExpiryMs', () => {
  it('reads exp from a JWT', () => {
    expect(jwtExpiryMs(jwt(1234))).toBe(1_234_000);
  });
  it('returns undefined for opaque tokens', () => {
    expect(jwtExpiryMs('opaque')).toBeUndefined();
    expect(jwtExpiryMs('a.@@@.c')).toBeUndefined();
  });
});

describe('sameEndpoint', () => {
  it('ignores trailing slashes and host case', () => {
    expect(sameEndpoint('https://API.cf.example.org/', api)).toBe(true);
    expect(sameEndpoint('https://api.cf.other.org', api)).toBe(false);
    expect(sameEndpoint('not a url', api)).toBe(false);
  });
});

describe('resolveTokenProvider', () => {
  it('prefers BTP_LENS_ACCESS_TOKEN and strips the bearer prefix', async () => {
    const provider = await resolveTokenProvider({
      env: { BTP_LENS_ACCESS_TOKEN: 'bearer abc' },
      http: http(new FakeFetch()),
      apiUrl: api,
      tokenUrl,
    });
    await expect(provider.getToken()).resolves.toBe('abc');
    provider.invalidate();
    await expect(provider.getToken()).rejects.toBeInstanceOf(CfAuthError);
  });

  it('uses client credentials with HTTP basic auth', async () => {
    const fake = new FakeFetch().on(
      'POST',
      'uaa.cf.example.org/oauth/token',
      jsonResponse({ access_token: 'cc-token', token_type: 'bearer' }),
    );
    const provider = await resolveTokenProvider({
      env: { BTP_LENS_CLIENT_ID: 'scanner', BTP_LENS_CLIENT_SECRET: 's3cr3t' },
      http: http(fake),
      apiUrl: api,
      tokenUrl,
    });
    await expect(provider.getToken()).resolves.toBe('cc-token');
    const call = fake.calls[0];
    expect(call?.headers.authorization).toBe(
      `Basic ${Buffer.from('scanner:s3cr3t').toString('base64')}`,
    );
    expect(call?.body).toBe('grant_type=client_credentials');
  });

  it('requires both client id and secret', async () => {
    await expect(
      resolveTokenProvider({
        env: { BTP_LENS_CLIENT_ID: 'scanner' },
        http: http(new FakeFetch()),
        apiUrl: api,
        tokenUrl,
      }),
    ).rejects.toBeInstanceOf(ConfigError);
  });

  it('explains how to log in when there is no cf CLI config', async () => {
    const home = await mkdtemp(join(tmpdir(), 'btp-lens-empty-'));
    await expect(
      resolveTokenProvider({
        env: { CF_HOME: home },
        http: http(new FakeFetch()),
        apiUrl: api,
        tokenUrl,
      }),
    ).rejects.toThrow(/cf login -a https:\/\/api\.cf\.example\.org/);
  });

  it('refuses a cf CLI session for a different API', async () => {
    const home = await cfHomeWith({ AccessToken: 'bearer x', Target: 'https://api.cf.other.org' });
    await expect(
      resolveTokenProvider({
        env: { CF_HOME: home },
        http: http(new FakeFetch()),
        apiUrl: api,
        tokenUrl,
      }),
    ).rejects.toThrow(/targeting https:\/\/api\.cf\.other\.org/);
  });

  it('reuses a valid cf CLI token without network calls', async () => {
    const token = jwt(NOW / 1000 + 3600);
    const home = await cfHomeWith({
      AccessToken: `bearer ${token}`,
      Target: 'https://api.cf.example.org',
    });
    const fake = new FakeFetch();
    const provider = await resolveTokenProvider({
      env: { CF_HOME: home },
      http: http(fake),
      apiUrl: api,
      tokenUrl,
      now: () => NOW,
    });
    await expect(provider.getToken()).resolves.toBe(token);
    expect(fake.calls).toHaveLength(0);
  });

  it('refreshes an expired cf CLI token in memory and never writes the config', async () => {
    const config = {
      AccessToken: `bearer ${jwt(NOW / 1000 - 10)}`,
      RefreshToken: 'refresh-1',
      Target: 'https://api.cf.example.org',
      UAAOAuthClient: 'cf',
      UAAOAuthClientSecret: '',
    };
    const home = await cfHomeWith(config);
    const before = await readFile(join(home, '.cf', 'config.json'), 'utf8');
    const fresh = jwt(NOW / 1000 + 3600);
    const fake = new FakeFetch().on(
      'POST',
      'uaa.cf.example.org/oauth/token',
      jsonResponse({ access_token: fresh, refresh_token: 'refresh-2' }),
    );
    const provider = await resolveTokenProvider({
      env: { CF_HOME: home },
      http: http(fake),
      apiUrl: api,
      tokenUrl,
      now: () => NOW,
    });
    await expect(provider.getToken()).resolves.toBe(fresh);
    expect(fake.calls[0]?.body).toBe('grant_type=refresh_token&refresh_token=refresh-1');
    expect(fake.calls[0]?.headers.authorization).toBe(
      `Basic ${Buffer.from('cf:').toString('base64')}`,
    );
    expect(await readFile(join(home, '.cf', 'config.json'), 'utf8')).toBe(before);
  });

  it('refreshes only once for concurrent callers', async () => {
    const fake = new FakeFetch().on(
      'POST',
      'uaa.cf.example.org/oauth/token',
      jsonResponse({ access_token: jwt(NOW / 1000 + 3600) }),
    );
    const provider = new CfCliTokenProvider(
      http(fake),
      tokenUrl,
      {
        AccessToken: '',
        RefreshToken: 'r',
        Target: api.href,
        UAAOAuthClient: '',
        UAAOAuthClientSecret: '',
      },
      () => NOW,
    );
    await Promise.all([provider.getToken(), provider.getToken(), provider.getToken()]);
    expect(fake.calls).toHaveLength(1);
  });

  it('reports a failed refresh with the OAuth error code only', async () => {
    const fake = new FakeFetch().on(
      'POST',
      'uaa.cf.example.org/oauth/token',
      jsonResponse({ error: 'invalid_token', error_description: 'details' }, 401),
    );
    const provider = new CfCliTokenProvider(
      http(fake),
      tokenUrl,
      {
        AccessToken: '',
        RefreshToken: 'r',
        Target: api.href,
        UAAOAuthClient: '',
        UAAOAuthClientSecret: '',
      },
      () => NOW,
    );
    await expect(provider.getToken()).rejects.toThrow(/HTTP 401 \(invalid_token\)/);
  });
});
