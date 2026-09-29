import { describe, expect, it, vi } from 'vitest';
import { HttpBodyTooLargeError, HttpNetworkError } from '../../src/http/errors.js';
import { HttpClient } from '../../src/http/httpClient.js';
import { EgressPolicy, cfApiRule, type HttpMethod } from '../../src/net/allowlist.js';
import { EgressDeniedError } from '../../src/net/errors.js';
import { FakeFetch, jsonResponse, noSleep } from '../support/fakeFetch.js';

const api = new URL('https://api.cf.example.org');

function client(fake: FakeFetch, extra: Partial<ConstructorParameters<typeof HttpClient>[0]> = {}) {
  const policy = new EgressPolicy();
  policy.add(cfApiRule(api));
  return new HttpClient({
    policy,
    userAgent: 'btp-lens/test',
    fetch: fake.fetch,
    sleep: noSleep,
    random: () => 0.5,
    ...extra,
  });
}

describe('HttpClient', () => {
  describe('read-only guarantee for the CF API', () => {
    it.each(['POST', 'PUT', 'PATCH', 'DELETE'])(
      'refuses %s before anything is sent',
      async (method) => {
        const fake = new FakeFetch();
        const http = client(fake);
        await expect(
          http.request({
            url: new URL('/v3/apps/guid', api),
            method: method as HttpMethod,
            headers: { authorization: 'bearer t' },
          }),
        ).rejects.toBeInstanceOf(EgressDeniedError);
        expect(fake.calls).toHaveLength(0);
      },
    );

    it('refuses hosts that are not on the allow-list', async () => {
      const fake = new FakeFetch();
      await expect(
        client(fake).request({ url: new URL('https://attacker.example.com/v3/apps') }),
      ).rejects.toBeInstanceOf(EgressDeniedError);
      expect(fake.calls).toHaveLength(0);
    });
  });

  it('sends GET with a user agent and never follows redirects', async () => {
    const fake = new FakeFetch().on(
      'GET',
      'api.cf.example.org/v3/apps',
      new Response(null, { status: 302, headers: { location: 'https://elsewhere.example.com/' } }),
    );
    const res = await client(fake).request({ url: new URL('/v3/apps', api) });
    expect(res.status).toBe(302);
    expect(fake.calls).toHaveLength(1);
    expect(fake.calls[0]?.redirect).toBe('manual');
    expect(fake.calls[0]?.headers['user-agent']).toBe('btp-lens/test');
  });

  it('retries 503 with backoff and then succeeds', async () => {
    const sleep = vi.fn(noSleep);
    const fake = new FakeFetch()
      .on('GET', 'api.cf.example.org/v3/apps', jsonResponse({}, 503), 1)
      .on('GET', 'api.cf.example.org/v3/apps', jsonResponse({ ok: true }));
    const res = await client(fake, { sleep }).request({ url: new URL('/v3/apps', api) });
    expect(res.status).toBe(200);
    expect(fake.calls).toHaveLength(2);
    expect(sleep).toHaveBeenCalledWith(375); // 500ms * (0.5 + 0.5/2)
  });

  it('honours Retry-After on 429', async () => {
    const sleep = vi.fn(noSleep);
    const fake = new FakeFetch()
      .on('GET', 'api.cf.example.org/v3/apps', jsonResponse({}, 429, { 'retry-after': '7' }), 1)
      .on('GET', 'api.cf.example.org/v3/apps', jsonResponse({}));
    await client(fake, { sleep }).request({ url: new URL('/v3/apps', api) });
    expect(sleep).toHaveBeenCalledWith(7000);
  });

  it('caps a very long Retry-After', async () => {
    const sleep = vi.fn(noSleep);
    const fake = new FakeFetch()
      .on('GET', 'api.cf.example.org/v3/apps', jsonResponse({}, 429, { 'retry-after': '99999' }), 1)
      .on('GET', 'api.cf.example.org/v3/apps', jsonResponse({}));
    await client(fake, { sleep }).request({ url: new URL('/v3/apps', api) });
    expect(sleep).toHaveBeenCalledWith(120_000);
  });

  it('returns the last response when retries are exhausted', async () => {
    const fake = new FakeFetch().on('GET', 'api.cf.example.org/v3/apps', () =>
      jsonResponse({}, 503),
    );
    const res = await client(fake, { maxRetries: 2 }).request({ url: new URL('/v3/apps', api) });
    expect(res.status).toBe(503);
    expect(fake.calls).toHaveLength(3);
  });

  it('retries network errors, then reports them without the query string', async () => {
    const fake = new FakeFetch().on('GET', /api\.cf\.example\.org/, () => {
      throw new TypeError('fetch failed');
    });
    const request = client(fake, { maxRetries: 1 }).request({
      url: new URL('/v3/apps?names=secret-app', api),
    });
    await expect(request).rejects.toBeInstanceOf(HttpNetworkError);
    await expect(request).rejects.not.toThrow(/secret-app/);
    expect(fake.calls).toHaveLength(2);
  });

  it('does not retry when retry is false', async () => {
    const fake = new FakeFetch().on('GET', 'api.cf.example.org/v3/apps', () =>
      jsonResponse({}, 503),
    );
    await client(fake).request({ url: new URL('/v3/apps', api), retry: false });
    expect(fake.calls).toHaveLength(1);
  });

  it('cuts off bodies above the size limit', async () => {
    const fake = new FakeFetch().on(
      'GET',
      'api.cf.example.org/v3/apps',
      new Response('x'.repeat(2048)),
    );
    await expect(
      client(fake).request({ url: new URL('/v3/apps', api), maxBytes: 1024 }),
    ).rejects.toBeInstanceOf(HttpBodyTooLargeError);
  });

  it('rejects a declared content-length above the limit without reading', async () => {
    const fake = new FakeFetch().on(
      'GET',
      'api.cf.example.org/v3/apps',
      new Response('small', { headers: { 'content-length': '999999' } }),
    );
    await expect(
      client(fake).request({ url: new URL('/v3/apps', api), maxBytes: 1024 }),
    ).rejects.toBeInstanceOf(HttpBodyTooLargeError);
  });

  it('limits concurrency', async () => {
    let inFlight = 0;
    let peak = 0;
    const fake = new FakeFetch().on('GET', /api\.cf\.example\.org/, async () => {
      inFlight += 1;
      peak = Math.max(peak, inFlight);
      await new Promise((resolve) => setTimeout(resolve, 5));
      inFlight -= 1;
      return jsonResponse({});
    });
    const http = client(fake, { concurrency: 2 });
    await Promise.all(
      Array.from({ length: 6 }, (_, i) => http.request({ url: new URL(`/v3/apps/${i}`, api) })),
    );
    expect(peak).toBe(2);
    expect(fake.calls).toHaveLength(6);
  });

  it('paces requests once the rate-limit budget runs low', async () => {
    const now = 1_000_000_000_000;
    const sleep = vi.fn(noSleep);
    const fake = new FakeFetch().on('GET', /api\.cf\.example\.org/, () =>
      jsonResponse({}, 200, {
        'x-ratelimit-limit': '1000',
        'x-ratelimit-remaining': '10',
        'x-ratelimit-reset': String(now / 1000 + 40),
      }),
    );
    const http = client(fake, { sleep, now: () => now });
    await http.request({ url: new URL('/v3/a', api) });
    expect(sleep).not.toHaveBeenCalled();
    await http.request({ url: new URL('/v3/b', api) });
    expect(sleep).toHaveBeenCalledWith(4000); // 40s window / 10 remaining
  });
});
