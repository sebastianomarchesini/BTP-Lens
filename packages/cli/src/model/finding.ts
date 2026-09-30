import { z } from 'zod';
import { SeveritySchema } from './severity.js';

export const AppRefSchema = z.object({
  guid: z.string(),
  name: z.string(),
  space: z.string(),
  org: z.string(),
});
export type AppRef = z.infer<typeof AppRefSchema>;

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
});
export type Finding = z.infer<typeof FindingSchema>;
