import { isSafeRelativePath } from '../../model/paths.js';
import {
  PROJECT_ID_PATTERN,
  type RawMta,
  type RawMtaModule,
  type RawMtaResource,
  type RawXsSecurity,
} from '../../model/raw.js';
import {
  identifierOrNull,
  identifiers,
  isIdentifier,
  isPlainObject,
  objectItems,
  parseYaml,
} from './read.js';
import { xsSecurityFromConfig } from './xsSecurity.js';

/*
 * mta.yaml: the ID, module names, types, paths, buildpacks and required
 * resource names, resource names, types, services and plans, and the XSUAA
 * scopes and role templates of xsuaa resources. `properties`,
 * `build-parameters`, `hooks`, `provides`, `service-key`, destinations and
 * every other `config` key are never read.
 */

const MAX_MODULES = 200;
const MAX_RESOURCES = 200;
const MAX_REQUIRES = 50;
const MAX_BUILDPACK_LENGTH = 200;
const BUILDPACK_NAME = /^[A-Za-z0-9_.-]{1,100}$/;
const BUILDPACK_URL = /^(https?|git|git\+https?):\/\//i;

export interface MtaResult {
  mta: RawMta;
  xsSecurity: RawXsSecurity[];
}

/**
 * A buildpack name, or an http(s)/git buildpack URL reduced to scheme, host
 * and path (no userinfo, query or fragment). Anything else, such as a local
 * path, is null: it could carry a user name or a directory layout.
 */
export function buildpackOf(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  if (BUILDPACK_NAME.test(value)) return value;
  if (!BUILDPACK_URL.test(value)) return null;
  try {
    const url = new URL(value);
    return `${url.protocol}//${url.host}${url.pathname}`.slice(0, MAX_BUILDPACK_LENGTH);
  } catch {
    return null;
  }
}

/** A module path as a safe relative path (`./srv` counts as `srv`), else null. */
export function modulePathOf(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const path = value.replace(/^\.\//, '').replace(/\/+$/, '');
  return isSafeRelativePath(path) ? path : null;
}

function moduleOf(module: Record<string, unknown>): RawMtaModule | null {
  if (!isIdentifier(module.name)) return null;
  const parameters = isPlainObject(module.parameters) ? module.parameters : {};
  return {
    name: module.name,
    type: identifierOrNull(module.type),
    path: modulePathOf(module.path),
    buildpack: buildpackOf(parameters.buildpack),
    requires: identifiers(
      objectItems(module.requires, MAX_REQUIRES).map((entry) => entry.name),
      MAX_REQUIRES,
    ),
  };
}

function resourceOf(resource: Record<string, unknown>): RawMtaResource | null {
  if (!isIdentifier(resource.name)) return null;
  const parameters = isPlainObject(resource.parameters) ? resource.parameters : {};
  return {
    name: resource.name,
    type: identifierOrNull(resource.type),
    service: identifierOrNull(parameters.service),
    plan: identifierOrNull(parameters['service-plan']),
  };
}

function xsuaaConfigOf(resource: Record<string, unknown>): Record<string, unknown> | null {
  const parameters = isPlainObject(resource.parameters) ? resource.parameters : {};
  if (parameters.service !== 'xsuaa' || !isPlainObject(parameters.config)) return null;
  return parameters.config;
}

/** Reads an mta.yaml; null when it is not a YAML mapping. */
export function parseMta(text: string, file: RawMta['file']): MtaResult | null {
  const yaml = parseYaml(text);
  if (!isPlainObject(yaml)) return null;
  const modules = objectItems(yaml.modules, MAX_MODULES);
  const resources = objectItems(yaml.resources, MAX_RESOURCES);
  const id = typeof yaml.ID === 'string' && PROJECT_ID_PATTERN.test(yaml.ID) ? yaml.ID : null;
  return {
    mta: {
      file,
      id,
      modules: modules.map(moduleOf).filter((module) => module !== null),
      resources: resources.map(resourceOf).filter((resource) => resource !== null),
    },
    xsSecurity: resources
      .map(xsuaaConfigOf)
      .filter((config) => config !== null)
      .map((config) => xsSecurityFromConfig(config, file, 'mta.yaml', { attributes: false })),
  };
}
