import { z } from 'zod';

/*
 * Normalized, sanitized raw data collected from the CF API. This is what the
 * analyzers read, and what `report --from snapshot.json` re-analyzes offline.
 * Only allow-listed fields are kept: zod strips every unknown key, so user
 * identities, env values and credentials cannot slip into a snapshot.
 */

const Timestamp = z.iso.datetime({ offset: true });

export const LifecycleTypeSchema = z.enum(['buildpack', 'cnb', 'docker', 'unknown']);
export type LifecycleType = z.infer<typeof LifecycleTypeSchema>;

export const RawOrgSchema = z.object({
  guid: z.string(),
  name: z.string(),
});
export type RawOrg = z.infer<typeof RawOrgSchema>;

export const RawSpaceSchema = z.object({
  guid: z.string(),
  name: z.string(),
  orgGuid: z.string(),
});
export type RawSpace = z.infer<typeof RawSpaceSchema>;

export const RawAppSchema = z.object({
  guid: z.string(),
  name: z.string(),
  spaceGuid: z.string(),
  state: z.enum(['STARTED', 'STOPPED']),
  createdAt: Timestamp,
  updatedAt: Timestamp,
  lifecycleType: LifecycleTypeSchema,
  /** Buildpacks requested for the app (names, or URLs with credentials removed). */
  buildpacks: z.array(z.string()),
  stack: z.string().nullable(),
});
export type RawApp = z.infer<typeof RawAppSchema>;

export const RawDetectedBuildpackSchema = z.object({
  name: z.string(),
  buildpackName: z.string().nullable(),
  version: z.string().nullable(),
  detectOutput: z.string().nullable(),
});
export type RawDetectedBuildpack = z.infer<typeof RawDetectedBuildpackSchema>;

export const RawDropletSchema = z.object({
  guid: z.string(),
  appGuid: z.string(),
  state: z.string(),
  createdAt: Timestamp,
  updatedAt: Timestamp,
  lifecycleType: LifecycleTypeSchema,
  stack: z.string().nullable(),
  buildpacks: z.array(RawDetectedBuildpackSchema),
  /** Docker image reference for docker droplets (credentials removed). */
  image: z.string().nullable(),
});
export type RawDroplet = z.infer<typeof RawDropletSchema>;

export const RawDataSchema = z.object({
  orgs: z.array(RawOrgSchema),
  spaces: z.array(RawSpaceSchema),
  apps: z.array(RawAppSchema),
  /** Current droplet per app; absent when the droplet collector was skipped. */
  droplets: z.array(RawDropletSchema),
});
export type RawData = z.infer<typeof RawDataSchema>;
