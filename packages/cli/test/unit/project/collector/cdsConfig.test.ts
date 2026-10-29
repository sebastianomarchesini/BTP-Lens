import { describe, expect, it } from 'vitest';
import {
  type CdsSourceValue,
  MAX_CONFIG_DEPTH,
  cdsViewOf,
  deepMerge,
  effectiveCdsViews,
  exceedsConfigDepth,
  mergeCdsSources,
  resolveProfile,
} from '../../../../src/collectors/project/cdsConfig.js';

/** `{ a: { a: { … value } } }` with `depth` objects. */
function nested(depth: number, leaf: unknown = 1): unknown {
  let value = leaf;
  for (let i = 0; i < depth; i += 1) value = { a: value };
  return value;
}

const sources = (...values: [CdsSourceValue['source'], unknown][]): CdsSourceValue[] =>
  values.map(([source, value]) => ({ source, value }));

describe('cds source merge', () => {
  it('merges .cdsrc.yaml, then .cdsrc.json, then package.json#cds, later wins, objects deep', () => {
    const merged = mergeCdsSources(
      sources(
        ['.cdsrc.yaml', { requires: { auth: { kind: 'basic', users: { a: {} } }, db: 'sqlite' } }],
        ['.cdsrc.json', { requires: { auth: { kind: 'xsuaa' } } }],
        ['package.json', { requires: { db: { kind: 'hana' } } }],
      ),
    );
    expect(merged).toEqual({
      requires: { auth: { kind: 'xsuaa', users: { a: {} } }, db: { kind: 'hana' } },
    });
  });

  it('treats a string under requires as the { kind } shorthand when merged with an object', () => {
    expect(deepMerge('mocked', { users: { a: {} } })).toEqual({ kind: 'mocked', users: { a: {} } });
    expect(deepMerge({ kind: 'mocked', users: {} }, 'xsuaa')).toEqual({ kind: 'xsuaa', users: {} });
    expect(deepMerge([1], [2])).toEqual([2]);
    expect(deepMerge({ a: 1 }, null)).toBeNull();
  });

  it('ignores non-object sources and prototype keys', () => {
    const merged = mergeCdsSources(
      sources(['.cdsrc.json', 'not an object'], ['package.json', { a: 1 }]),
    );
    expect(merged).toEqual({ a: 1 });
    const poisoned: unknown = JSON.parse(
      '{"__proto__": {"polluted": true}, "constructor": {}, "b": 2}',
    );
    const result = deepMerge({}, poisoned) as Record<string, unknown>;
    expect(Object.keys(result)).toEqual(['b']);
    expect(({} as { polluted?: boolean }).polluted).toBeUndefined();
  });
});

describe('profile resolution (verified cds behaviour)', () => {
  it('applies [profile] blocks at any nesting level and drops other profiles', () => {
    const config = {
      requires: {
        auth: {
          '[production]': { kind: 'xsuaa' },
          '[development]': { kind: 'mocked', users: { alice: {} } },
          '[hybrid]': { kind: 'ias' },
        },
      },
    };
    expect(resolveProfile(config, 'production')).toEqual({
      requires: { auth: { kind: 'xsuaa' } },
    });
    expect(resolveProfile(config, 'development')).toEqual({
      requires: { auth: { kind: 'mocked', users: { alice: {} } } },
    });
  });

  it('applies top-level profile blocks over plain keys', () => {
    const config = {
      requires: { auth: 'mocked' },
      '[production]': { requires: { auth: 'xsuaa' } },
    };
    expect(cdsViewOf(resolveProfile(config, 'production')).authKind).toBe('xsuaa');
    expect(cdsViewOf(resolveProfile(config, 'development')).authKind).toBe('mocked');
  });

  it('applies [profile!] after [profile], whatever the key order', () => {
    const config = {
      requires: {
        '[production!]': { auth: { kind: 'ias' } },
        auth: { kind: 'mocked' },
        '[production]': { auth: { kind: 'xsuaa' } },
      },
    };
    expect(cdsViewOf(resolveProfile(config, 'production')).authKind).toBe('ias');
  });

  it('keeps the kind of a string shorthand when a profile block adds users', () => {
    const config = {
      requires: {
        auth: 'mocked',
        '[development]': { auth: { users: { alice: { password: 'x' }, bob: {} } } },
      },
    };
    const views = effectiveCdsViews(sources(['package.json', config]));
    expect(views.development).toMatchObject({
      authKind: 'mocked',
      mockedUsers: 2,
      mockedUsersWithPassword: 1,
    });
    expect(views.production).toMatchObject({
      authKind: 'mocked',
      mockedUsers: 0,
      mockedUsersWithPassword: 0,
    });
  });

  it('resolves profiles inside a profile block', () => {
    const config = {
      '[production]': { requires: { auth: { '[production]': { kind: 'xsuaa' } } } },
    };
    expect(cdsViewOf(resolveProfile(config, 'production')).authKind).toBe('xsuaa');
    expect(cdsViewOf(resolveProfile(config, 'development')).authKind).toBeNull();
  });
});

describe('cdsViewOf', () => {
  it('reads only the allow-listed facts', () => {
    const view = cdsViewOf({
      requires: {
        auth: {
          kind: 'mocked-auth',
          restrict_all_services: false,
          users: {
            'poison.user@example.com': { password: 'POISON_hunter2', roles: ['admin'] },
            alice: { roles: [] },
            bob: 'POISON_plain',
          },
          credentials: { clientsecret: 'POISON_clientsecret' },
        },
        'audit-log': { kind: 'audit-log-to-restv2', credentials: { secret: 'POISON' } },
      },
    });
    expect(view).toEqual({
      authKind: 'mocked',
      mockedUsers: 3,
      mockedUsersWithPassword: 1,
      restrictAllServices: false,
      auditLogKind: 'audit-log-to-restv2',
      auditLogConfigured: true,
    });
    expect(JSON.stringify(view)).not.toContain('POISON');
    expect(JSON.stringify(view)).not.toContain('alice');
  });

  it('maps unknown strategies to other, absent ones to null, and any audit-log shape to configured', () => {
    expect(cdsViewOf({ requires: { auth: 'my-custom-auth-impl' } }).authKind).toBe('other');
    expect(cdsViewOf({ requires: { auth: { kind: 'jwt' } } }).authKind).toBe('jwt');
    expect(cdsViewOf({ requires: { auth: { impl: 'x' } } }).authKind).toBeNull();
    expect(cdsViewOf({ requires: { 'audit-log': true } })).toMatchObject({
      auditLogKind: null,
      auditLogConfigured: true,
    });
    expect(cdsViewOf({ requires: { 'audit-log': 'audit-log-to-console' } })).toMatchObject({
      auditLogKind: 'audit-log-to-console',
      auditLogConfigured: true,
    });
    expect(cdsViewOf({ requires: { 'audit-log': 'something-else' } }).auditLogKind).toBe('other');
    expect(cdsViewOf({ requires: { 'audit-log': false } }).auditLogConfigured).toBe(false);
    expect(cdsViewOf(null)).toEqual({
      authKind: null,
      mockedUsers: 0,
      mockedUsersWithPassword: 0,
      restrictAllServices: null,
      auditLogKind: null,
      auditLogConfigured: false,
    });
    expect(
      cdsViewOf({ requires: { auth: { restrict_all_services: 'no' } } }).restrictAllServices,
    ).toBeNull();
  });
});

describe('nesting depth', () => {
  it('measures depth without recursion', () => {
    expect(exceedsConfigDepth(nested(MAX_CONFIG_DEPTH - 1))).toBe(false);
    expect(exceedsConfigDepth(nested(MAX_CONFIG_DEPTH))).toBe(false);
    expect(exceedsConfigDepth(nested(MAX_CONFIG_DEPTH + 1))).toBe(true);
    expect(exceedsConfigDepth(nested(100_000))).toBe(true);
    expect(exceedsConfigDepth({ a: [[1]] }, 3)).toBe(false);
    expect(exceedsConfigDepth({ a: [[[1]]] }, 3)).toBe(true);
    expect(exceedsConfigDepth('x')).toBe(false);
    expect(exceedsConfigDepth(null)).toBe(false);
  });

  it('merges and resolves a hostile depth without exhausting the stack, dropping what lies beyond', () => {
    const deep = nested(100_000);
    expect(() => deepMerge(deep, deep)).not.toThrow();
    expect(() => resolveProfile(deep, 'production')).not.toThrow();
    expect(() => effectiveCdsViews(sources(['.cdsrc.json', deep]))).not.toThrow();
    expect(() =>
      effectiveCdsViews(sources(['.cdsrc.json', deep], ['package.json', deep])),
    ).not.toThrow();
    expect(resolveProfile(nested(MAX_CONFIG_DEPTH - 1), 'production')).toEqual(
      nested(MAX_CONFIG_DEPTH - 1),
    );
    expect(resolveProfile(nested(MAX_CONFIG_DEPTH + 5), 'production')).toEqual(
      nested(MAX_CONFIG_DEPTH - 1, {}),
    );
    expect(deepMerge(nested(MAX_CONFIG_DEPTH - 1), nested(MAX_CONFIG_DEPTH - 1, 2))).toEqual(
      nested(MAX_CONFIG_DEPTH - 1, 2),
    );
    expect(deepMerge(nested(MAX_CONFIG_DEPTH + 5), nested(MAX_CONFIG_DEPTH + 5, 2))).toEqual(
      nested(MAX_CONFIG_DEPTH - 1, { a: undefined }),
    );
  });

  it('still reads the facts of a realistic configuration next to a deep subtree', () => {
    const config = { requires: { auth: { kind: 'xsuaa' } }, junk: nested(50_000) };
    expect(effectiveCdsViews(sources(['.cdsrc.json', config])).production.authKind).toBe('xsuaa');
  });
});
