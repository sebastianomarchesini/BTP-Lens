import { describe, expect, it } from 'vitest';
import { EgressPolicy, cfApiRule, logCacheRule, uaaRule } from '../../src/net/allowlist.js';
import { EgressDeniedError } from '../../src/net/errors.js';

const api = new URL('https://api.cf.example.org');
const uaa = new URL('https://uaa.cf.example.org');

function policy(): EgressPolicy {
  const p = new EgressPolicy();
  p.add(cfApiRule(api));
  p.add(uaaRule(uaa));
  p.add(logCacheRule(new URL('https://log-cache.cf.example.org')));
  return p;
}

const allowed = (method: string, url: string, auth = false): boolean => {
  try {
    policy().authorize(new URL(url), method, auth);
    return true;
  } catch (error) {
    expect(error).toBeInstanceOf(EgressDeniedError);
    return false;
  }
};

describe('egress allow-list', () => {
  describe('CF API', () => {
    it('allows GET on / and /v3/**', () => {
      expect(allowed('GET', 'https://api.cf.example.org/')).toBe(true);
      expect(allowed('GET', 'https://api.cf.example.org/v3/apps?per_page=5000')).toBe(true);
      expect(allowed('GET', 'https://api.cf.example.org/v3/apps/abc/droplets/current')).toBe(true);
    });

    it.each(['POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'])('denies %s', (method) => {
      expect(allowed(method, 'https://api.cf.example.org/v3/apps', true)).toBe(false);
    });

    it('denies the v2 API and other paths', () => {
      expect(allowed('GET', 'https://api.cf.example.org/v2/apps')).toBe(false);
      expect(allowed('GET', 'https://api.cf.example.org/v3apps')).toBe(false);
      expect(allowed('GET', 'https://api.cf.example.org/networking/v1/external')).toBe(false);
    });

    it('honours a path prefix in the API URL', () => {
      const p = new EgressPolicy([cfApiRule(new URL('https://example.org/cf/'))]);
      expect(() =>
        p.authorize(new URL('https://example.org/cf/v3/apps'), 'GET', true),
      ).not.toThrow();
      expect(() => p.authorize(new URL('https://example.org/v3/apps'), 'GET', true)).toThrow(
        EgressDeniedError,
      );
    });

    it('allows sending the bearer token', () => {
      expect(allowed('GET', 'https://api.cf.example.org/v3/apps', true)).toBe(true);
    });
  });

  describe('UAA', () => {
    it('allows only POST /oauth/token', () => {
      expect(allowed('POST', 'https://uaa.cf.example.org/oauth/token', true)).toBe(true);
      expect(allowed('GET', 'https://uaa.cf.example.org/oauth/token')).toBe(false);
      expect(allowed('POST', 'https://uaa.cf.example.org/oauth/authorize')).toBe(false);
      expect(allowed('DELETE', 'https://uaa.cf.example.org/oauth/token')).toBe(false);
    });
  });

  describe('public data sources', () => {
    it('allows OSV batch queries and vulnerability details', () => {
      expect(allowed('POST', 'https://api.osv.dev/v1/querybatch')).toBe(true);
      expect(allowed('GET', 'https://api.osv.dev/v1/vulns/GHSA-xxxx-yyyy-zzzz')).toBe(true);
      expect(allowed('GET', 'https://api.osv.dev/v1/query')).toBe(false);
    });

    it('allows endoflife.date product lookups only', () => {
      expect(allowed('GET', 'https://endoflife.date/api/v1/products/nodejs')).toBe(true);
      expect(allowed('GET', 'https://endoflife.date/api/v1/products/sapmachine/')).toBe(true);
      expect(allowed('GET', 'https://endoflife.date/api/v1/categories')).toBe(false);
      expect(allowed('POST', 'https://endoflife.date/api/v1/products/nodejs')).toBe(false);
    });

    it('allows the UI5 version overview only', () => {
      expect(allowed('GET', 'https://ui5.sap.com/versionoverview.json')).toBe(true);
      expect(allowed('GET', 'https://ui5.sap.com/1.120.0/resources/sap-ui-core.js')).toBe(false);
    });

    it('allows the four @sap packages on the npm registry only', () => {
      expect(allowed('GET', 'https://registry.npmjs.org/@sap%2Fcds')).toBe(true);
      expect(allowed('GET', 'https://registry.npmjs.org/@sap/approuter')).toBe(true);
      expect(allowed('GET', 'https://registry.npmjs.org/@sap/xssec')).toBe(true);
      expect(allowed('GET', 'https://registry.npmjs.org/@sap/xsenv')).toBe(true);
      expect(allowed('GET', 'https://registry.npmjs.org/lodash')).toBe(false);
      expect(allowed('GET', 'https://registry.npmjs.org/@sap/cds-dk')).toBe(false);
    });

    it('never allows credentials to public hosts', () => {
      expect(allowed('POST', 'https://api.osv.dev/v1/querybatch', true)).toBe(false);
      expect(allowed('GET', 'https://endoflife.date/api/v1/products/nodejs', true)).toBe(false);
      expect(allowed('GET', 'https://ui5.sap.com/versionoverview.json', true)).toBe(false);
    });
  });

  describe('general rules', () => {
    it('denies unknown hosts', () => {
      expect(allowed('GET', 'https://example.com/')).toBe(false);
      expect(allowed('GET', 'https://evil.api.cf.example.org/v3/apps')).toBe(false);
    });

    it('denies plain http and other schemes', () => {
      expect(allowed('GET', 'http://api.cf.example.org/v3/apps')).toBe(false);
      expect(allowed('GET', 'file:///etc/passwd')).toBe(false);
    });

    it('denies credentials embedded in the URL', () => {
      expect(allowed('GET', 'https://user:pass@api.cf.example.org/v3/apps')).toBe(false);
    });

    it('denies a different port', () => {
      expect(allowed('GET', 'https://api.cf.example.org:8443/v3/apps')).toBe(false);
    });

    it('names the reason in the error without the query string', () => {
      expect(() =>
        policy().authorize(new URL('https://example.com/x?token=secret'), 'GET', false),
      ).toThrow(/Egress denied: GET https:\/\/example\.com\/x \(host is not on the allow-list\)/);
      try {
        policy().authorize(new URL('https://example.com/x?token=secret'), 'GET', false);
      } catch (error) {
        expect(String(error)).not.toContain('secret');
      }
    });
  });
});
