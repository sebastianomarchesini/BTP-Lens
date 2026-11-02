import type { RawXsSecurity } from '../../model/raw.js';
import { identifiers, isIdentifier, isPlainObject, objectItems, parseJson } from './read.js';

/*
 * An XSUAA descriptor: xs-security.json, or the `config` of an xsuaa
 * resource in mta.yaml. Only scope and role-template names, scope references
 * and attribute names are kept. `description`, `oauth2-configuration`,
 * `foreign-scope-references`, `authorities`, `xsappname` and `tenant-mode`
 * are never read.
 */

const MAX_SCOPES = 500;
const MAX_ROLE_TEMPLATES = 500;
const MAX_ATTRIBUTES = 500;

/** `granted-apps` or `grant-as-authority-to-apps` with at least one entry. */
function grantedToApps(scope: Record<string, unknown>): boolean {
  return ['granted-apps', 'grant-as-authority-to-apps'].some((key) => {
    const value = scope[key];
    return Array.isArray(value) ? value.length > 0 : value !== undefined && value !== null;
  });
}

export interface XsSecurityOptions {
  /** mta.yaml resources carry no attribute list we read. */
  attributes: boolean;
}

export function xsSecurityFromConfig(
  config: Record<string, unknown>,
  file: string,
  source: RawXsSecurity['source'],
  options: XsSecurityOptions,
): RawXsSecurity {
  return {
    file,
    source,
    scopes: objectItems(config.scopes, MAX_SCOPES)
      .filter((scope) => isIdentifier(scope.name))
      .map((scope) => ({ name: scope.name as string, grantedToApps: grantedToApps(scope) })),
    roleTemplates: objectItems(config['role-templates'], MAX_ROLE_TEMPLATES)
      .filter((template) => isIdentifier(template.name))
      .map((template) => ({
        name: template.name as string,
        scopeReferences: identifiers(template['scope-references'], MAX_SCOPES),
      })),
    attributes: options.attributes
      ? objectItems(config.attributes, MAX_ATTRIBUTES)
          .map((attribute) => attribute.name)
          .filter(isIdentifier)
      : [],
  };
}

/** Reads an xs-security.json; null when it is not a JSON object. */
export function parseXsSecurity(text: string, file: string): RawXsSecurity | null {
  const json = parseJson(text);
  if (!isPlainObject(json)) return null;
  return xsSecurityFromConfig(json, file, 'xs-security.json', { attributes: true });
}
