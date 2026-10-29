import {
  NON_REGISTRY_RANGE,
  PACKAGE_NAME_PATTERN,
  RANGE_PATTERN,
  type RawDependency,
  type RawPackageJson,
} from '../../model/raw.js';
import { isPlainObject, parseJson } from './read.js';

const MAX_DEPENDENCIES = 500;

export interface PackageJsonResult {
  packageJson: RawPackageJson;
  /** The `cds` section, merged by cdsConfig.ts; nothing else of the file is kept. */
  cds: unknown;
}

/** A registry range as written; a git URL, file path or alias becomes the placeholder. */
export function rangeOf(value: unknown): string {
  return typeof value === 'string' && RANGE_PATTERN.test(value) ? value : NON_REGISTRY_RANGE;
}

function dependenciesOf(value: unknown): RawDependency[] {
  if (!isPlainObject(value)) return [];
  return Object.entries(value)
    .filter(([name]) => PACKAGE_NAME_PATTERN.test(name))
    .slice(0, MAX_DEPENDENCIES)
    .map(([name, range]) => ({ name, range: rangeOf(range) }));
}

export function emptyPackageJson(): RawPackageJson {
  return { present: false, name: null, dependencies: [], devDependencies: [], nodeEngine: null };
}

/** Reads the allow-listed facts of a package.json; null when it is not a JSON object. */
export function parsePackageJson(text: string): PackageJsonResult | null {
  const json = parseJson(text);
  if (!isPlainObject(json)) return null;
  const engines = isPlainObject(json.engines) ? json.engines : {};
  return {
    packageJson: {
      present: true,
      name:
        typeof json.name === 'string' && PACKAGE_NAME_PATTERN.test(json.name) ? json.name : null,
      dependencies: dependenciesOf(json.dependencies),
      devDependencies: dependenciesOf(json.devDependencies),
      nodeEngine: engines.node === undefined ? null : rangeOf(engines.node),
    },
    cds: json.cds,
  };
}
