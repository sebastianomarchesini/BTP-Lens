import { z } from 'zod';
import type { CfClient, ListResult } from '../http/cfClient.js';
import type { LifecycleType, RawApp } from '../model/raw.js';
import { redactUrlCredentials } from './sanitize.js';

/** Fields confirmed in docs/data-sources.md §2 (the app object). */
const CfAppSchema = z.object({
  guid: z.string(),
  name: z.string(),
  state: z.enum(['STARTED', 'STOPPED']),
  created_at: z.string(),
  updated_at: z.string(),
  lifecycle: z
    .object({
      type: z.string(),
      data: z
        .object({
          buildpacks: z.array(z.string().nullable()).nullish(),
          stack: z.string().nullish(),
        })
        .nullish(),
    })
    .nullish(),
  relationships: z.object({
    space: z.object({ data: z.object({ guid: z.string() }) }),
  }),
});

export function toLifecycleType(type: string | undefined): LifecycleType {
  return type === 'buildpack' || type === 'cnb' || type === 'docker' ? type : 'unknown';
}

export interface Scope {
  orgGuid: string;
  /** Set when scanning a single space. */
  spaceGuids?: string[];
}

export function scopeQuery(scope: Scope): Record<string, string> {
  return scope.spaceGuids
    ? { space_guids: scope.spaceGuids.join(',') }
    : { organization_guids: scope.orgGuid };
}

export interface Collected<T> {
  items: T[];
  invalid: number;
}

function collected<T, U>(result: ListResult<T>, map: (item: T) => U): Collected<U> {
  return { items: result.resources.map(map), invalid: result.invalid };
}

/** GET /v3/apps filtered by org (or space). Any role; results are visibility-filtered. */
export async function collectApps(cf: CfClient, scope: Scope): Promise<Collected<RawApp>> {
  const result = await cf.list('/v3/apps', CfAppSchema, scopeQuery(scope));
  return collected(result, (app) => ({
    guid: app.guid,
    name: app.name,
    spaceGuid: app.relationships.space.data.guid,
    state: app.state,
    createdAt: app.created_at,
    updatedAt: app.updated_at,
    lifecycleType: toLifecycleType(app.lifecycle?.type),
    buildpacks: (app.lifecycle?.data?.buildpacks ?? [])
      .filter((bp): bp is string => typeof bp === 'string')
      .map(redactUrlCredentials),
    stack: app.lifecycle?.data?.stack ?? null,
  }));
}
