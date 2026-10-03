/**
 * The egress allow-list: the ONLY place that decides which hosts BTP Lens may
 * contact, with which HTTP methods and paths, and whether credentials may be
 * sent. Every request goes through `EgressPolicy.authorize` before `fetch`
 * runs. See docs/data-sources.md §6.
 */
import { EgressDeniedError } from './errors.js';

/** The only methods the HTTP layer can issue at all. */
export type HttpMethod = 'GET' | 'POST';

export interface EgressRule {
  host: string;
  /** Explicit port, when the rule's base URL had one. */
  port?: string;
  /** Allowed path pattern per method. A method with no entry is denied. */
  allow: Partial<Record<HttpMethod, RegExp>>;
  /**
   * Paths denied for every method even when `allow` matches, tested against
   * the raw and the percent-decoded path. Used for endpoints that return
   * credentials, so that no future collector can reach them by accident.
   */
  deny?: RegExp;
  /** Whether an Authorization header may be sent to this host. */
  allowAuthorization: boolean;
  /** Why the host is allowed; shown in errors and docs. */
  purpose: string;
}

/** Fixed public data sources. No customer data is ever sent to them. */
export const STATIC_EGRESS_RULES: readonly EgressRule[] = [
  {
    host: 'api.osv.dev',
    allow: { POST: /^\/v1\/querybatch$/, GET: /^\/v1\/vulns\/[A-Za-z0-9._:-]+$/ },
    allowAuthorization: false,
    purpose: 'Known-vulnerability lookups for SBOM packages (DEP_KNOWN_CVE)',
  },
  {
    host: 'endoflife.date',
    allow: { GET: /^\/api\/v1\/products\/[a-z0-9-]+\/?$/ },
    allowAuthorization: false,
    purpose: 'Runtime end-of-life dates (RUNTIME_NODE_EOL, RUNTIME_JAVA_EOL)',
  },
  {
    host: 'ui5.sap.com',
    allow: { GET: /^\/versionoverview\.json$/ },
    allowAuthorization: false,
    purpose: 'SAPUI5 maintenance status (UI5_OUT_OF_MAINTENANCE)',
  },
  {
    host: 'registry.npmjs.org',
    allow: { GET: /^\/@sap(?:\/|%2[fF])(?:cds|approuter|xssec|xsenv)$/ },
    allowAuthorization: false,
    purpose: 'Current major versions of @sap/* packages (SAP_PKG_OUTDATED)',
  },
];

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Path prefix of a base URL without trailing slash ("" for the root). */
function basePath(base: URL): string {
  return base.pathname.replace(/\/+$/, '');
}

function ruleFor(base: URL, rule: Omit<EgressRule, 'host' | 'port'>): EgressRule {
  return { ...rule, host: base.hostname.toLowerCase(), port: base.port || undefined };
}

/**
 * CF v3 endpoints that return secrets. BTP Lens never needs them: `/env`
 * includes VCAP_SERVICES credentials and `/details` is the binding's
 * credentials. Environment variable *names* come from
 * `/environment_variables`, which stays allowed for `--deep`.
 */
const CREDENTIAL_ENDPOINTS = [
  'apps/[^/]+/env',
  'service_credential_bindings/[^/]+/details',
  'service_credential_bindings/[^/]+/parameters',
  'service_instances/[^/]+/credentials',
  'service_instances/[^/]+/parameters',
].join('|');

/** The customer's Cloud Foundry API: GET only, `/` and `/v3/**`, minus credential endpoints. */
export function cfApiRule(apiUrl: URL): EgressRule {
  const prefix = escapeRegExp(basePath(apiUrl));
  return ruleFor(apiUrl, {
    allow: { GET: new RegExp(`^${prefix}(?:/|/v3(?:/.*)?)?$`) },
    deny: new RegExp(`^${prefix}/v3/(?:${CREDENTIAL_ENDPOINTS})/*$`, 'i'),
    allowAuthorization: true,
    purpose: 'Cloud Foundry API (read-only)',
  });
}

/** UAA or login server discovered from the CF root: token endpoint only. */
export function uaaRule(uaaUrl: URL): EgressRule {
  const prefix = escapeRegExp(basePath(uaaUrl));
  return ruleFor(uaaUrl, {
    allow: { POST: new RegExp(`^${prefix}/oauth/token$`) },
    allowAuthorization: true,
    purpose: 'OAuth token endpoint (UAA)',
  });
}

/** Log cache discovered from the CF root (used from v0.2). */
export function logCacheRule(logCacheUrl: URL): EgressRule {
  const prefix = escapeRegExp(basePath(logCacheUrl));
  return ruleFor(logCacheUrl, {
    allow: { GET: new RegExp(`^${prefix}/api/v1/.*$`) },
    allowAuthorization: true,
    purpose: 'Log cache (read-only)',
  });
}

/** The path as sent plus its percent-decoded form, so encoding cannot bypass `deny`. */
function pathVariants(pathname: string): string[] {
  try {
    const decoded = decodeURIComponent(pathname);
    return decoded === pathname ? [pathname] : [pathname, decoded];
  } catch {
    return [pathname];
  }
}

export class EgressPolicy {
  private readonly rules: EgressRule[];

  constructor(rules: readonly EgressRule[] = STATIC_EGRESS_RULES) {
    this.rules = [...rules];
  }

  add(rule: EgressRule): void {
    this.rules.push(rule);
  }

  list(): readonly EgressRule[] {
    return this.rules;
  }

  /**
   * Returns the matching rule, or throws EgressDeniedError. Checks, in order:
   * https only, no userinfo, known host and port, allowed method and path,
   * and no Authorization header unless the rule allows it.
   */
  authorize(url: URL, method: string, hasAuthorization: boolean): EgressRule {
    const deny = (reason: string): never => {
      throw new EgressDeniedError(method, url, reason);
    };
    if (url.protocol !== 'https:') deny('only https is allowed');
    if (url.username !== '' || url.password !== '') deny('credentials in URL are not allowed');

    const host = url.hostname.toLowerCase();
    const candidates = this.rules.filter(
      (rule) => rule.host === host && (rule.port ?? '') === url.port,
    );
    if (candidates.length === 0) deny('host is not on the allow-list');

    const methodRules = candidates.filter((rule) => rule.allow[method as HttpMethod] !== undefined);
    if (methodRules.length === 0) deny(`method ${method} is not allowed for this host`);

    const match = methodRules.find((rule) => rule.allow[method as HttpMethod]?.test(url.pathname));
    if (match === undefined) return deny(`path is not allowed for ${method}`);

    if (match.deny !== undefined) {
      for (const path of pathVariants(url.pathname)) {
        if (match.deny.test(path)) deny('endpoint returns credentials and is never read');
      }
    }

    if (hasAuthorization && !match.allowAuthorization) {
      deny('credentials may not be sent to this host');
    }
    return match;
  }
}
