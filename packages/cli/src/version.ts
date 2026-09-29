import { readFileSync } from 'node:fs';

export const TOOL_NAME = 'btp-lens';

/** Reads the version from packages/cli/package.json (works from src and dist). */
function readVersion(): string {
  try {
    const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as {
      version?: unknown;
    };
    return typeof pkg.version === 'string' ? pkg.version : '0.0.0';
  } catch {
    return '0.0.0';
  }
}

export const TOOL_VERSION = readVersion();
