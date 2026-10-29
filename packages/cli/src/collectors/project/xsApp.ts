import {
  type RawXsApp,
  type RawXsAppRoute,
  type XsAppAuthenticationType,
  XsAppAuthenticationTypeSchema,
  type XsAppTargetHint,
} from '../../model/raw.js';
import { isPlainObject, objectItems, parseJson, stringValue } from './read.js';

/*
 * xs-app.json (approuter): the authentication method, each route's source
 * regex, authentication type, CSRF setting, and which kind of target it
 * has. The destination, service and localDir names are not stored; a hint is
 * computed from them. The logout page is used only to flag the logout route.
 */

const MAX_ROUTES = 200;
const MAX_SOURCE_LENGTH = 200;

function authenticationMethodOf(value: unknown): RawXsApp['authenticationMethod'] {
  if (typeof value !== 'string') return null;
  return value === 'route' || value === 'none' ? value : 'other';
}

function authenticationTypeOf(value: unknown): XsAppAuthenticationType | null {
  if (typeof value !== 'string') return null;
  const parsed = XsAppAuthenticationTypeSchema.safeParse(value);
  return parsed.success && parsed.data !== 'other' ? parsed.data : 'other';
}

/** Computed from the destination or service name, which is not stored. */
export function targetHintOf(name: string): XsAppTargetHint {
  if (/^ui5$|sapui5|cdn/i.test(name)) return 'ui5-cdn';
  if (name === 'html5-apps-repo-rt') return 'html5-repo';
  if (/srv|api|backend/i.test(name)) return 'api';
  return 'other';
}

function targetOf(route: Record<string, unknown>): Pick<RawXsAppRoute, 'target' | 'targetHint'> {
  const destination = stringValue(route.destination);
  if (destination !== undefined) {
    return { target: 'destination', targetHint: targetHintOf(destination) };
  }
  const service = stringValue(route.service);
  if (service !== undefined) return { target: 'service', targetHint: targetHintOf(service) };
  if (stringValue(route.localDir) !== undefined) return { target: 'localDir', targetHint: 'other' };
  return { target: 'unknown', targetHint: 'other' };
}

/**
 * The route source is a regex written by the project; it is compared
 * literally (after `^`, `$` and backslash escapes) rather than compiled, so
 * a hostile pattern cannot stall the scan.
 */
export function isLogoutRoute(source: string, logoutPage: string | undefined): boolean {
  if (logoutPage === undefined || logoutPage === '') return false;
  const literal = source.replace(/^\^/, '').replace(/\$$/, '').replace(/\\(.)/g, '$1');
  return source === logoutPage || literal === logoutPage;
}

function routeOf(
  route: Record<string, unknown>,
  logoutPage: string | undefined,
): RawXsAppRoute | null {
  const source = stringValue(route.source);
  if (source === undefined) return null;
  return {
    source: source.slice(0, MAX_SOURCE_LENGTH),
    authenticationType: authenticationTypeOf(route.authenticationType),
    csrfProtection: typeof route.csrfProtection === 'boolean' ? route.csrfProtection : null,
    ...targetOf(route),
    isLogoutPage: isLogoutRoute(source, logoutPage),
  };
}

/** Reads an xs-app.json; null when it is not a JSON object. */
export function parseXsApp(text: string, file: string): RawXsApp | null {
  const json = parseJson(text);
  if (!isPlainObject(json)) return null;
  const logout = isPlainObject(json.logout) ? json.logout : {};
  const logoutPage = stringValue(logout.logoutPage);
  return {
    file,
    authenticationMethod: authenticationMethodOf(json.authenticationMethod),
    routes: objectItems(json.routes, MAX_ROUTES)
      .map((route) => routeOf(route, logoutPage))
      .filter((route) => route !== null),
  };
}
