import { z } from 'zod';
import { ConfigError } from './http/errors.js';
import { SEVERITIES, type Severity } from './model/severity.js';
import { type ReportFormat, parseFormats } from './reporters/index.js';

export const FAIL_ON_VALUES = ['none', ...SEVERITIES] as const;
export type FailOn = (typeof FAIL_ON_VALUES)[number];

export const ApiUrlSchema = z
  .string()
  .trim()
  .transform((value, ctx) => {
    try {
      const url = new URL(/^[a-z]+:\/\//i.test(value) ? value : `https://${value}`);
      if (url.protocol !== 'https:') {
        ctx.addIssue({ code: 'custom', message: '--api must use https' });
        return z.NEVER;
      }
      if (url.username || url.password || url.search || url.hash) {
        ctx.addIssue({
          code: 'custom',
          message: '--api must be a plain URL like https://api.cf.eu10.hana.ondemand.com',
        });
        return z.NEVER;
      }
      return url;
    } catch {
      ctx.addIssue({ code: 'custom', message: `--api is not a valid URL: ${value}` });
      return z.NEVER;
    }
  });

const FailOnSchema = z.enum(FAIL_ON_VALUES, {
  error: () => `--fail-on must be one of: ${FAIL_ON_VALUES.join(', ')}`,
});

const FormatsSchema = z.string().transform((value, ctx): ReportFormat[] => {
  try {
    return parseFormats(value);
  } catch (error) {
    ctx.addIssue({
      code: 'custom',
      message: error instanceof Error ? error.message : String(error),
    });
    return z.NEVER;
  }
});

const CommonSchema = z.object({
  out: z.string().min(1),
  format: FormatsSchema,
  failOn: FailOnSchema,
});

export const ScanConfigSchema = CommonSchema.extend({
  api: ApiUrlSchema,
  org: z.string().trim().min(1, '--org is required'),
  space: z.string().trim().min(1).optional(),
  deep: z.boolean(),
  probeRoutes: z.boolean(),
  concurrency: z.coerce
    .number({ error: () => '--concurrency must be a number' })
    .int('--concurrency must be a whole number')
    .min(1, '--concurrency must be at least 1')
    .max(20, '--concurrency must be at most 20'),
  quiet: z.boolean(),
});
export type ScanConfig = z.infer<typeof ScanConfigSchema>;

export const ReportConfigSchema = CommonSchema.extend({
  from: z.string().min(1, '--from is required'),
});
export type ReportConfig = z.infer<typeof ReportConfigSchema>;

function parseOrThrow<T>(schema: z.ZodType<T>, input: unknown): T {
  const result = schema.safeParse(input);
  if (!result.success) {
    throw new ConfigError(result.error.issues.map((i) => i.message).join('\n'));
  }
  return result.data;
}

export const parseScanConfig = (input: unknown): ScanConfig =>
  parseOrThrow(ScanConfigSchema, input);
export const parseReportConfig = (input: unknown): ReportConfig =>
  parseOrThrow(ReportConfigSchema, input);

export function failThreshold(failOn: FailOn): Severity | undefined {
  return failOn === 'none' ? undefined : failOn;
}

/** Parses a CF API endpoint the way --api does (https only, no query, no credentials). */
export function parseApiUrl(value: string): URL {
  return parseOrThrow(ApiUrlSchema, value);
}
