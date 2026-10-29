import { z } from 'zod';
import { CfRoleSchema, CheckResultSchema } from './check.js';
import { FindingSchema } from './finding.js';
import { OwaspCategorySchema } from './owasp.js';
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

export const InventoryKindSchema = z.enum(['app', 'project']);
export type InventoryKind = z.infer<typeof InventoryKindSchema>;

export const AppInventoryItemSchema = z.object({
  guid: z.string(),
  name: z.string(),
  org: z.string(),
  space: z.string(),
  /** A CF app, or a local project scanned with `btp-lens project`. Missing in 0.1 snapshots. */
  kind: InventoryKindSchema.default('app'),
  /** null for projects. */
  state: z.enum(['STARTED', 'STOPPED']).nullable(),
  lifecycleType: LifecycleTypeSchema,
  stack: z.string().nullable(),
  buildpacks: z.array(z.object({ name: z.string(), version: z.string().nullable() })),
  createdAt: Timestamp.nullable(),
  updatedAt: Timestamp.nullable(),
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
  /** OWASP Top 10 (2025) categories the rule maps to. */
  owasp: z.array(OwaspCategorySchema),
  helpUri: z.url(),
});
export type RuleMeta = z.infer<typeof RuleMetaSchema>;

export const ScopeSchema = z.object({
  /** Absent for a project scan. */
  apiEndpoint: z.url().optional(),
  orgs: z.array(z.string()),
  spaces: z.array(z.string()).optional(),
  /** Ids of the local projects scanned with `btp-lens project`. */
  projects: z.array(z.string()).optional(),
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
    /** Inventory items of kind `app`. */
    apps: z.number().int().nonnegative(),
    /** Inventory items of kind `project`. */
    projects: z.number().int().nonnegative(),
    findings: z.number().int().nonnegative(),
    findingsBySeverity: SeverityCountsSchema,
    checksSkipped: z.number().int().nonnegative(),
  }),
});
export type ReportData = z.infer<typeof ReportDataSchema>;
