import { z } from 'zod';

/**
 * Cloud Foundry roles a check can need. A check lists every role that is
 * sufficient on its own; an empty list means no CF role is needed (e.g. a
 * public data source).
 */
export const CfRoleSchema = z.enum([
  'OrgAuditor',
  'SpaceAuditor',
  'SpaceSupporter',
  'SpaceDeveloper',
]);
export type CfRole = z.infer<typeof CfRoleSchema>;

export const CheckStatusSchema = z.enum(['ran', 'skipped']);
export type CheckStatus = z.infer<typeof CheckStatusSchema>;

export const SkipReasonCodeSchema = z.enum([
  /** The API answered 403 for the current user. */
  'insufficient_role',
  /** The check needs --deep (SpaceDeveloper-level access) and it was not set. */
  'requires_deep',
  /** The check was turned off by a flag. */
  'disabled',
  /** A collector this check depends on was skipped. */
  'dependency_skipped',
  /** The check failed with an error; the scan continued. */
  'error',
]);
export type SkipReasonCode = z.infer<typeof SkipReasonCodeSchema>;

export const CheckResultSchema = z.object({
  id: z.string(),
  title: z.string(),
  roles: z.array(CfRoleSchema),
  status: CheckStatusSchema,
  reason: z.string().optional(),
  reasonCode: SkipReasonCodeSchema.optional(),
});
export type CheckResult = z.infer<typeof CheckResultSchema>;
