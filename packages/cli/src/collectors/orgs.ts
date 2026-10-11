import { z } from 'zod';
import type { CfClient } from '../http/cfClient.js';
import { ConfigError } from '../http/errors.js';
import type { RawOrg, RawSpace } from '../model/raw.js';

const CfOrgSchema = z.object({ guid: z.string(), name: z.string() });

const CfSpaceSchema = z.object({
  guid: z.string(),
  name: z.string(),
  relationships: z.object({
    organization: z.object({ data: z.object({ guid: z.string() }) }),
  }),
});

/** GET /v3/organizations?names=<org>. Any role; zero results = not visible. */
export async function resolveOrg(cf: CfClient, name: string): Promise<RawOrg> {
  const { resources } = await cf.list('/v3/organizations', CfOrgSchema, { names: name });
  // `names` is a comma-separated list filter, so match the exact name again.
  const org = resources.find((o) => o.name === name);
  if (org === undefined) {
    throw new ConfigError(`Organization "${name}" was not found, or your user has no role in it.`);
  }
  return { guid: org.guid, name: org.name };
}

/** GET /v3/spaces?organization_guids=<g>[&names=<space>]. Filtered to visible spaces. */
export async function listSpaces(
  cf: CfClient,
  org: RawOrg,
  spaceName?: string,
): Promise<RawSpace[]> {
  const query: Record<string, string> = { organization_guids: org.guid };
  if (spaceName !== undefined) query.names = spaceName;
  const { resources: all } = await cf.list('/v3/spaces', CfSpaceSchema, query);
  const resources = spaceName === undefined ? all : all.filter((s) => s.name === spaceName);
  if (spaceName !== undefined && resources.length === 0) {
    throw new ConfigError(
      `Space "${spaceName}" was not found in "${org.name}", or your user has no role in it.`,
    );
  }
  return resources.map((space) => ({
    guid: space.guid,
    name: space.name,
    orgGuid: space.relationships.organization.data.guid,
  }));
}
