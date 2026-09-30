import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import type { TokenProvider } from '../../src/http/auth.js';
import { CfClient } from '../../src/http/cfClient.js';
import {
  CfApiError,
  CfAuthError,
  CfForbiddenError,
  CfNotFoundError,
} from '../../src/http/errors.js';
import { HttpClient } from '../../src/http/httpClient.js';
import { EgressPolicy, cfApiRule } from '../../src/net/allowlist.js';
import { FakeFetch, jsonResponse, noSleep } from '../support/fakeFetch.js';

const api = new URL('https://api.cf.example.org');
const Item = z.object({ guid: z.string(), name: z.string() });

class CountingTokens implements TokenProvider {
  readonly source = 'test';
  issued = 0;
  async getToken(): Promise<string> {
    return Promise.resolve(`token-${this.issued}`);
  }
  invalidate(): void {
    this.issued += 1;
  }
}

function setup(fake: FakeFetch) {
  const policy = new EgressPolicy();
  policy.add(cfApiRule(api));
  const http = new HttpClient({ policy, userAgent: 't', fetch: fake.fetch, sleep: noSleep });
  const cf = new CfClient(http, api);
  const tokens = new CountingTokens();
  cf.setTokenProvider(tokens);
  return { cf, tokens };
}

const page = (resources: unknown[], next: string | null, included?: Record<string, unknown[]>) => ({
  pagination: { total_results: 3, next: next ? { href: next } : null },
  resources,
  ...(included ? { included } : {}),
});

describe('CfClient', () => {
  it('follows pagination.next and merges included resources', async () => {
    const fake = new FakeFetch()
      .on(
        'GET',
        'api.cf.example.org/v3/apps?include=space&per_page=5000',
        jsonResponse(
          page(
            [
              { guid: 'a', name: 'one' },
              { guid: 'b', name: 'two' },
            ],
            'https://api.cf.example.org/v3/apps?include=space&page=2&per_page=5000',
            { spaces: [{ guid: 's1' }] },
          ),
        ),
      )
      .on(
        'GET',
        'api.cf.example.org/v3/apps?include=space&page=2&per_page=5000',
        jsonResponse(page([{ guid: 'c', name: 'three' }], null, { spaces: [{ guid: 's2' }] })),
      );
    const { cf } = setup(fake);
    const result = await cf.list('/v3/apps', Item, { include: 'space' });
    expect(result.resources.map((r) => r.guid)).toEqual(['a', 'b', 'c']);
    expect(result.included.spaces).toHaveLength(2);
    expect(fake.calls.every((c) => c.method === 'GET')).toBe(true);
    expect(fake.calls[0]?.headers.authorization).toBe('bearer token-0');
  });

  it('counts and drops resources that do not match the schema', async () => {
    const fake = new FakeFetch().on(
      'GET',
      'api.cf.example.org/v3/apps?per_page=5000',
      jsonResponse(page([{ guid: 'a', name: 'ok' }, { guid: 42 }], null)),
    );
    const result = await setup(fake).cf.list('/v3/apps', Item);
    expect(result.resources).toHaveLength(1);
    expect(result.invalid).toBe(1);
  });

  it('refuses a pagination link to another host', async () => {
    const fake = new FakeFetch().on(
      'GET',
      'api.cf.example.org/v3/apps?per_page=5000',
      jsonResponse(page([], 'https://attacker.example.com/v3/apps?page=2')),
    );
    await expect(setup(fake).cf.list('/v3/apps', Item)).rejects.toThrow(
      /pagination link leaves the CF API/,
    );
    expect(fake.calls).toHaveLength(1);
  });

  it('refuses a pagination loop', async () => {
    const fake = new FakeFetch().on(
      'GET',
      'api.cf.example.org/v3/apps?per_page=5000',
      jsonResponse(page([], 'https://api.cf.example.org/v3/apps?per_page=5000')),
    );
    await expect(setup(fake).cf.list('/v3/apps', Item)).rejects.toThrow(/pagination loop/);
  });

  it('maps 403 to CfForbiddenError with the CF error title', async () => {
    const fake = new FakeFetch().on(
      'GET',
      'api.cf.example.org/v3/apps/x/environment_variables',
      jsonResponse(
        { errors: [{ code: 10003, title: 'CF-NotAuthorized', detail: 'You are not authorized' }] },
        403,
      ),
    );
    const error = await setup(fake)
      .cf.get('/v3/apps/x/environment_variables', z.unknown())
      .catch((e: unknown) => e);
    expect(error).toBeInstanceOf(CfForbiddenError);
    expect(String(error)).toContain('CF-NotAuthorized (10003)');
  });

  it('maps 404 to CfNotFoundError', async () => {
    const fake = new FakeFetch().on(
      'GET',
      'api.cf.example.org/v3/apps/missing',
      jsonResponse({ errors: [{ code: 10010, title: 'CF-ResourceNotFound' }] }, 404),
    );
    await expect(setup(fake).cf.get('/v3/apps/missing', z.unknown())).rejects.toBeInstanceOf(
      CfNotFoundError,
    );
  });

  it('treats a redirect as an error and does not follow it', async () => {
    const fake = new FakeFetch().on(
      'GET',
      'api.cf.example.org/v3/apps/x',
      new Response(null, { status: 302, headers: { location: 'https://elsewhere.example.com' } }),
    );
    await expect(setup(fake).cf.get('/v3/apps/x', z.unknown())).rejects.toThrow(
      /redirect not followed/,
    );
    expect(fake.calls).toHaveLength(1);
  });

  it('refreshes the token once after a 401', async () => {
    const fake = new FakeFetch()
      .on('GET', 'api.cf.example.org/v3/apps/x', jsonResponse({}, 401), 1)
      .on('GET', 'api.cf.example.org/v3/apps/x', jsonResponse({ guid: 'x', name: 'n' }));
    const { cf, tokens } = setup(fake);
    await expect(cf.get('/v3/apps/x', Item)).resolves.toEqual({ guid: 'x', name: 'n' });
    expect(tokens.issued).toBe(1);
    expect(fake.calls[1]?.headers.authorization).toBe('bearer token-1');
  });

  it('gives up with CfAuthError after a second 401', async () => {
    const fake = new FakeFetch().on('GET', 'api.cf.example.org/v3/apps/x', () =>
      jsonResponse({}, 401),
    );
    await expect(setup(fake).cf.get('/v3/apps/x', Item)).rejects.toBeInstanceOf(CfAuthError);
    expect(fake.calls).toHaveLength(2);
  });

  it('reads the root without credentials', async () => {
    const fake = new FakeFetch().on(
      'GET',
      'api.cf.example.org/',
      jsonResponse({ links: { uaa: { href: 'https://uaa.cf.example.org' } } }),
    );
    const root = await setup(fake).cf.root();
    expect(root.links.uaa?.href).toBe('https://uaa.cf.example.org');
    expect(fake.calls[0]?.headers.authorization).toBeUndefined();
  });

  it('reports an unexpected body shape', async () => {
    const fake = new FakeFetch().on(
      'GET',
      'api.cf.example.org/v3/apps?per_page=5000',
      jsonResponse({ nope: true }),
    );
    await expect(setup(fake).cf.list('/v3/apps', Item)).rejects.toBeInstanceOf(CfApiError);
  });
});
