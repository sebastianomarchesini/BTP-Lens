import { z } from 'zod';

export const MAX_RELATIVE_PATH_LENGTH = 512;

/*
 * A path that is safe to store and to render: relative, `/`-separated, with no
 * `..` or empty segment, no drive letter, no backslash and no control
 * character. Findings, SARIF locations and the project collector all go
 * through this one check, so an absolute path or a traversal can never reach
 * a report.
 */
export function isSafeRelativePath(value: string): boolean {
  if (value.length === 0 || value.length > MAX_RELATIVE_PATH_LENGTH) return false;
  if (/[\\\0\r\n]/.test(value)) return false;
  if (value.startsWith('/') || /^[A-Za-z]:/.test(value)) return false;
  return value.split('/').every((segment) => segment !== '' && segment !== '.' && segment !== '..');
}

export const RelativePathSchema = z
  .string()
  .refine(isSafeRelativePath, 'must be a relative path without "..", "\\" or a drive letter');
export type RelativePath = z.infer<typeof RelativePathSchema>;
