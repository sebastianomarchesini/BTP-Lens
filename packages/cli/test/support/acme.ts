import { readFileSync } from 'node:fs';
import { FakeFetch, jsonResponse } from './fakeFetch.js';

/**
 * "acme-prod": a synthetic landscape built from the documented CF v3 shapes
 * (test/fixtures/cf/acme). It contains poison values — credentials in a
 * buildpack URL, a password in a start command, an owner email in
 * annotations — that must never reach any output.
 */
export const ACME = {
  api: new URL('https://api.cf.example.org'),
  org: 'acme-prod',
  orgGuid: '0a1b2c3d-0000-4000-8000-000000000001',
  now: new Date('2026-09-29T00:00:00Z'),
  token: 'test-access-token-POISON',
  /** Strings that must not appear in any report or snapshot. */
  poison: [
    'test-access-token-POISON',
    'FAKE-POISON-TOKEN-123',
    'deploy-bot',
    'POISON_hunter2',
    'POISON-execution-metadata',
    'POISON-annotation-contact',
    'jane.doe@example.com',
    'platform-team@example.com',
  ],
} as const;

function fixture(name: string): unknown {
  return JSON.parse(
    readFileSync(new URL(`../fixtures/cf/acme/${name}.json`, import.meta.url), 'utf8'),
  );
}

export interface AcmeOptions {
  /** Simulate a user who may not read droplets (403). */
  dropletsForbidden?: boolean;
}

export function acmeFetch(options: AcmeOptions = {}): FakeFetch {
  const host = ACME.api.host;
  const org = ACME.orgGuid;
  return new FakeFetch()
    .on('GET', `${host}/`, () => jsonResponse(fixture('root')))
    .on('GET', `${host}/v3/organizations?names=acme-prod&per_page=5000`, () =>
      jsonResponse(fixture('organizations')),
    )
    .on('GET', `${host}/v3/spaces?organization_guids=${org}&per_page=5000`, () =>
      jsonResponse(fixture('spaces')),
    )
    .on('GET', `${host}/v3/apps?organization_guids=${org}&per_page=5000`, () =>
      jsonResponse(fixture('apps-page1')),
    )
    .on('GET', `${host}/v3/apps?organization_guids=${org}&page=2&per_page=5000`, () =>
      jsonResponse(fixture('apps-page2')),
    )
    .on('GET', `${host}/v3/droplets?current=true&organization_guids=${org}&per_page=5000`, () =>
      options.dropletsForbidden
        ? jsonResponse(fixture('forbidden'), 403)
        : jsonResponse(fixture('droplets')),
    );
}
