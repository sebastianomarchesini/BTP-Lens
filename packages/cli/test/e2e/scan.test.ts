import { describe, expect, it } from 'vitest';
import { scan } from '../../src/scan.js';
import { ACME, acmeFetch } from '../support/acme.js';

function scanAcme(fake = acmeFetch(), overrides: { deep?: boolean } = {}) {
  return scan({
    apiUrl: ACME.api,
    org: ACME.org,
    deep: overrides.deep ?? false,
    probeRoutes: true,
    concurrency: 5,
    env: { BTP_LENS_ACCESS_TOKEN: ACME.token },
    fetch: fake.fetch,
    now: () => ACME.now,
  });
}

describe('scan against the acme fixture landscape', () => {
  it('collects the full inventory across paginated responses', async () => {
    const snapshot = await scanAcme();
    expect(snapshot.apps).toHaveLength(8);
    expect(snapshot.raw.droplets).toHaveLength(7);
    expect(snapshot.scope).toEqual({
      apiEndpoint: 'https://api.cf.example.org/',
      orgs: ['acme-prod'],
    });
    const orders = snapshot.apps.find((a) => a.name === 'orders-srv');
    expect(orders).toMatchObject({
      org: 'acme-prod',
      space: 'prod',
      state: 'STARTED',
      stack: 'cflinuxfs4',
      buildpacks: [{ name: 'nodejs', version: '1.8.40' }],
      lastDeployAt: '2026-07-20T10:00:00Z',
    });
    const neverStaged = snapshot.apps.find((a) => a.name === 'never-staged');
    expect(neverStaged?.lastDeployAt).toBeNull();
  });

  it('issues only GET requests to the CF API and sends the token nowhere else', async () => {
    const fake = acmeFetch();
    await scanAcme(fake);
    expect(fake.calls.length).toBeGreaterThan(0);
    for (const call of fake.calls) {
      expect(call.method).toBe('GET');
      expect(call.url.host).toBe('api.cf.example.org');
      expect(call.redirect).toBe('manual');
    }
    const authenticated = fake.calls.filter((c) => c.headers.authorization !== undefined);
    expect(authenticated.every((c) => c.headers.authorization === `bearer ${ACME.token}`)).toBe(
      true,
    );
    // The unauthenticated root call is the only one without a token.
    expect(
      fake.calls.filter((c) => c.headers.authorization === undefined).map((c) => c.url.pathname),
    ).toEqual(['/']);
  });

  it('finds apps without a deploy in the last 12 months', async () => {
    const snapshot = await scanAcme();
    const stale = snapshot.findings.filter((f) => f.id === 'APP_NO_RECENT_DEPLOY');
    expect(stale.map((f) => [f.app.name, f.severity])).toEqual([
      ['legacy-reporting', 'medium'],
      ['docs-static', 'low'],
      ['orders-approuter', 'low'],
    ]);
    expect(snapshot.apps[0]?.name).toBe('legacy-reporting'); // highest risk first
  });

  it('strips credentials from buildpack URLs', async () => {
    const snapshot = await scanAcme();
    const custom = snapshot.raw.apps.find((a) => a.name === 'custom-bp-app');
    expect(custom?.buildpacks).toEqual(['https://github.com/acme/custom-buildpack.git']);
  });

  it('records a 403 as a skipped check and keeps going', async () => {
    const snapshot = await scanAcme(acmeFetch({ dropletsForbidden: true }));
    expect(snapshot.apps).toHaveLength(8);
    expect(snapshot.checks.find((c) => c.id === 'collect.droplets')).toMatchObject({
      status: 'skipped',
      reasonCode: 'insufficient_role',
      reason: 'insufficient role: needs SpaceAuditor',
    });
    expect(snapshot.checks.find((c) => c.id === 'rule.APP_NO_RECENT_DEPLOY')).toMatchObject({
      status: 'skipped',
      reasonCode: 'dependency_skipped',
    });
    expect(snapshot.findings).toHaveLength(0);
  });
});
