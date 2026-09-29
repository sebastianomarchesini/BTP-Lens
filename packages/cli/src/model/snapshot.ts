import { z } from 'zod';
import { CfRoleSchema, CheckResultSchema } from './check.js';
import { FindingSchema } from './finding.js';
import { LifecycleTypeSchema, RawDataSchema } from './raw.js';
import { SeveritySchema } from './severity.js';

export const SNAPSHOT_SCHEMA_VERSION = 1;

const Timestamp = z.iso.datetime({ offset: true });

const SeverityCountsSchema = z.object({
  critical: z.number().int().nonnegative(),
  high: z.number().int().nonnegative(),
  medium: z.number().int().nonnegative(),
  low: z.number().int().nonnegative(),
  info: z.number().int().nonnegative(),
});
export type SeverityCounts = z.infer<typeof SeverityCountsSchema>;

export const AppInventoryItemSchema = z.object({
  guid: z.string(),
  name: z.string(),
  org: z.string(),
  space: z.string(),
  state: z.enum(['STARTED', 'STOPPED']),
  lifecycleType: LifecycleTypeSchema,
  stack: z.string().nullable(),
  buildpacks: z.array(z.object({ name: z.string(), version: z.string().nullable() })),
  createdAt: Timestamp,
  updatedAt: Timestamp,
  /** When the current droplet was staged; null when unknown or not visible. */
  lastDeployAt: Timestamp.nullable(),
  findingCounts: SeverityCountsSchema,
  highestSeverity: SeveritySchema.nullable(),
  /** Weighted sum of findings, used to sort apps by risk (see docs/rules.md). */
  riskScore: z.number().nonnegative(),
});
export type AppInventoryItem = z.infer<typeof AppInventoryItemSchema>;

export const RuleMetaSchema = z.object({
  id: z.string().regex(/^[A-Z0-9_]+$/),
  title: z.string(),
  description: z.string(),
  roles: z.array(CfRoleSchema),
  helpUri: z.url(),
});
export type RuleMeta = z.infer<typeof RuleMetaSchema>;

export const ScopeSchema = z.object({
  apiEndpoint: z.url(),
  orgs: z.array(z.string()),
  spaces: z.array(z.string()).optional(),
});

export const ScanOptionsSchema = z.object({
  deep: z.boolean(),
  probeRoutes: z.boolean(),
});

export const SnapshotSchema = z.object({
  schemaVersion: z.literal(SNAPSHOT_SCHEMA_VERSION),
  tool: z.object({ name: z.string(), version: z.string() }),
  scannedAt: Timestamp,
  scope: ScopeSchema,
  options: ScanOptionsSchema,
  checks: z.array(CheckResultSchema),
  raw: RawDataSchema,
  apps: z.array(AppInventoryItemSchema),
  findings: z.array(FindingSchema),
});
export type Snapshot = z.infer<typeof SnapshotSchema>;

/**
 * What the reports (JSON, HTML) carry: the snapshot without the raw data,
 * plus precomputed summary counts.
 */
export const ReportDataSchema = SnapshotSchema.omit({ raw: true }).extend({
  /** Metadata for every rule known to this tool version. */
  rules: z.array(RuleMetaSchema),
  summary: z.object({
    apps: z.number().int().nonnegative(),
    findings: z.number().int().nonnegative(),
    findingsBySeverity: SeverityCountsSchema,
    checksSkipped: z.number().int().nonnegative(),
  }),
});
export type ReportData = z.infer<typeof ReportDataSchema>;
