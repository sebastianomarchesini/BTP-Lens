import { z } from 'zod';
import type { CfClient } from '../http/cfClient.js';
import type { RawDroplet } from '../model/raw.js';
import { type Collected, type Scope, scopeQuery, toLifecycleType } from './apps.js';
import { redactUrlCredentials, truncate } from './sanitize.js';

/**
 * Fields confirmed in docs/data-sources.md §2 (the droplet object). The docs
 * say some fields are redacted for auditors without naming them, so nothing
 * here is required beyond guid, state, timestamps and the app relationship.
 */
const CfDropletSchema = z.object({
  guid: z.string(),
  state: z.string(),
  created_at: z.string(),
  updated_at: z.string(),
  lifecycle: z.object({ type: z.string() }).nullish(),
  stack: z.string().nullish(),
  image: z.string().nullish(),
  buildpacks: z
    .array(
      z.object({
        name: z.string().nullish(),
        buildpack_name: z.string().nullish(),
        version: z.string().nullish(),
        detect_output: z.string().nullish(),
      }),
    )
    .nullish(),
  relationships: z.object({
    app: z.object({ data: z.object({ guid: z.string() }) }),
  }),
});

/** GET /v3/droplets?current=true — one call for the current droplet of every app. */
export async function collectCurrentDroplets(
  cf: CfClient,
  scope: Scope,
): Promise<Collected<RawDroplet>> {
  const result = await cf.list('/v3/droplets', CfDropletSchema, {
    ...scopeQuery(scope),
    current: 'true',
  });
  return {
    invalid: result.invalid,
    items: result.resources.map((droplet) => ({
      guid: droplet.guid,
      appGuid: droplet.relationships.app.data.guid,
      state: droplet.state,
      createdAt: droplet.created_at,
      updatedAt: droplet.updated_at,
      lifecycleType: toLifecycleType(droplet.lifecycle?.type),
      stack: droplet.stack ?? null,
      image: droplet.image ? redactUrlCredentials(droplet.image) : null,
      buildpacks: (droplet.buildpacks ?? []).map((bp) => ({
        name: redactUrlCredentials(bp.name ?? bp.buildpack_name ?? 'unknown'),
        buildpackName: truncate(bp.buildpack_name, 100),
        version: truncate(bp.version, 50),
        detectOutput: truncate(bp.detect_output),
      })),
    })),
  };
}
