import {
  type CdsAuditLogKind,
  CdsAuditLogKindSchema,
  type CdsAuthKind,
  CdsAuthKindSchema,
  type CdsSource,
  type CdsView,
} from '../../model/raw.js';
import { isPlainObject } from './read.js';

/*
 * The effective cds configuration per profile. Sources are merged in the
 * order cds uses for the files we read (.cdsrc.yaml, .cdsrc.json,
 * package.json#cds; later wins, plain objects merge deeply). Profile blocks
 * `[name]` apply at any nesting level, `[name!]` last (verified in the design
 * review, docs/data-sources.md). `.cdsrc-private.json`, `.cdsrc.js`, `.env`
 * and the process environment are never read: they hold credentials.
 */

export type CdsProfile = 'development' | 'production';

export interface CdsSourceValue {
  source: CdsSource;
  value: unknown;
}

const PROFILE_KEY = /^\[([A-Za-z0-9_-]+)(!?)\]$/;

/**
 * Objects nested deeper than this are dropped by the merge and the profile
 * resolution, and a source that deep is rejected before either runs: both
 * recurse one level per object, and a planted configuration thousands of
 * levels deep would otherwise exhaust the stack. Real cds configuration is a
 * handful of levels deep.
 */
export const MAX_CONFIG_DEPTH = 32;

/** Whether a value nests objects or arrays deeper than `max` levels (iterative). */
export function exceedsConfigDepth(value: unknown, max = MAX_CONFIG_DEPTH): boolean {
  const pending: { value: unknown; depth: number }[] = [{ value, depth: 0 }];
  while (pending.length > 0) {
    const item = pending.pop();
    if (item === undefined) break;
    const children = Array.isArray(item.value)
      ? item.value
      : isPlainObject(item.value)
        ? Object.values(item.value)
        : [];
    if (children.length === 0) continue;
    if (item.depth >= max) return true;
    for (const child of children) pending.push({ value: child, depth: item.depth + 1 });
  }
  return false;
}

/** Keys that would change the prototype of the merged object are dropped. */
function isSafeKey(key: string): boolean {
  return key !== '__proto__' && key !== 'constructor' && key !== 'prototype';
}

/**
 * Objects merge key by key; arrays and primitives replace. A string under
 * `requires` is the cds shorthand for `{ kind }`, so a string and an object
 * merge as objects (`auth: 'mocked'` plus `auth: { users }` keeps the kind).
 * Beyond MAX_CONFIG_DEPTH levels the subtree is dropped.
 */
export function deepMerge(base: unknown, override: unknown, depth = 0): unknown {
  if (depth >= MAX_CONFIG_DEPTH) return undefined;
  if (typeof base === 'string' && isPlainObject(override)) {
    return deepMerge({ kind: base }, override, depth);
  }
  if (isPlainObject(base) && typeof override === 'string') {
    return { ...base, kind: override };
  }
  if (!isPlainObject(base) || !isPlainObject(override)) return override;
  const result: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(base)) if (isSafeKey(key)) result[key] = value;
  for (const [key, value] of Object.entries(override)) {
    if (!isSafeKey(key)) continue;
    result[key] = key in result ? deepMerge(result[key], value, depth + 1) : value;
  }
  return result;
}

export function mergeCdsSources(sources: CdsSourceValue[]): unknown {
  let merged: unknown = {};
  for (const { value } of sources) {
    if (isPlainObject(value)) merged = deepMerge(merged, value);
  }
  return merged;
}

/**
 * Applies the profile blocks of one profile recursively: at every object
 * level the plain keys come first, then `[profile]`, then `[profile!]`;
 * blocks of other profiles are dropped, as are objects nested beyond
 * MAX_CONFIG_DEPTH.
 */
export function resolveProfile(value: unknown, profile: CdsProfile, depth = 0): unknown {
  if (!isPlainObject(value)) return value;
  if (depth >= MAX_CONFIG_DEPTH) return undefined;
  let result: Record<string, unknown> = {};
  const blocks: unknown[] = [];
  const importantBlocks: unknown[] = [];
  for (const [key, child] of Object.entries(value)) {
    if (!isSafeKey(key)) continue;
    const match = PROFILE_KEY.exec(key);
    if (match === null) {
      const resolved = resolveProfile(child, profile, depth + 1);
      if (resolved !== undefined) result[key] = resolved;
    } else if (match[1] === profile) {
      (match[2] === '!' ? importantBlocks : blocks).push(child);
    }
  }
  for (const block of [...blocks, ...importantBlocks]) {
    const merged = deepMerge(result, resolveProfile(block, profile, depth + 1), depth);
    result = isPlainObject(merged) ? merged : result;
  }
  return result;
}

function authKindOf(value: unknown): CdsAuthKind | null {
  const kind = typeof value === 'string' ? value : isPlainObject(value) ? value.kind : undefined;
  if (typeof kind !== 'string') return null;
  // Older configurations spell the strategies `mocked-auth`, `basic-auth`, ...
  const normalized = kind.replace(/-auth$/, '');
  const parsed = CdsAuthKindSchema.safeParse(normalized);
  return parsed.success ? parsed.data : 'other';
}

function auditLogKindOf(value: unknown): CdsAuditLogKind | null {
  const kind = typeof value === 'string' ? value : isPlainObject(value) ? value.kind : undefined;
  if (typeof kind !== 'string') return null;
  const parsed = CdsAuditLogKindSchema.safeParse(kind);
  return parsed.success ? parsed.data : 'other';
}

/** Counts of `requires.auth.users`; neither names nor passwords are read. */
function mockedUsersOf(auth: unknown): { mockedUsers: number; mockedUsersWithPassword: number } {
  const users = isPlainObject(auth) ? auth.users : undefined;
  if (!isPlainObject(users)) return { mockedUsers: 0, mockedUsersWithPassword: 0 };
  const entries = Object.values(users);
  return {
    mockedUsers: entries.length,
    mockedUsersWithPassword: entries.filter((user) => isPlainObject(user) && 'password' in user)
      .length,
  };
}

/** The allow-listed facts of one resolved configuration. */
export function cdsViewOf(effective: unknown): CdsView {
  const requires =
    isPlainObject(effective) && isPlainObject(effective.requires) ? effective.requires : {};
  const auth = requires.auth;
  const auditLog = requires['audit-log'];
  const restrict = isPlainObject(auth) ? auth.restrict_all_services : undefined;
  return {
    authKind: authKindOf(auth),
    ...mockedUsersOf(auth),
    restrictAllServices: typeof restrict === 'boolean' ? restrict : null,
    auditLogKind: auditLogKindOf(auditLog),
    auditLogConfigured: auditLog !== undefined && auditLog !== null && auditLog !== false,
  };
}

export function effectiveCdsViews(sources: CdsSourceValue[]): Record<CdsProfile, CdsView> {
  const merged = mergeCdsSources(sources);
  return {
    development: cdsViewOf(resolveProfile(merged, 'development')),
    production: cdsViewOf(resolveProfile(merged, 'production')),
  };
}
