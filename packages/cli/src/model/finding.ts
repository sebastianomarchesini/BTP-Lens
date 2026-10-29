import { z } from 'zod';
import { RelativePathSchema } from './paths.js';
import { SeveritySchema } from './severity.js';

export const AppRefSchema = z.object({
  guid: z.string(),
  name: z.string(),
  space: z.string(),
  org: z.string(),
});
export type AppRef = z.infer<typeof AppRefSchema>;

/** Where in a scanned project a finding is: a project-relative file and, when known, a line. */
export const FindingLocationSchema = z.object({
  file: RelativePathSchema,
  line: z.number().int().positive().optional(),
});
export type FindingLocation = z.infer<typeof FindingLocationSchema>;

export const FindingSchema = z.object({
  /** Stable rule id, e.g. "RUNTIME_NODE_EOL". */
  id: z.string().regex(/^[A-Z0-9_]+$/),
  severity: SeveritySchema,
  title: z.string(),
  app: AppRefSchema,
  /** The facts that triggered the finding. Never secrets or personal data. */
  evidence: z.record(z.string(), z.unknown()),
  /** Concrete next step. */
  remediation: z.string(),
  references: z.array(z.url()),
  /** Set by project rules only; CF findings have no file. */
  location: FindingLocationSchema.optional(),
});
export type Finding = z.infer<typeof FindingSchema>;
