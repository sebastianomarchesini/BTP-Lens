import { describeUrl } from '../net/errors.js';

/**
 * The innermost cause of a fetch failure. Node's fetch throws
 * `TypeError: fetch failed` and hides the real reason (ENOTFOUND, ECONNREFUSED,
 * DEPTH_ZERO_SELF_SIGNED_CERT, ...) in the `cause` chain.
 */
export function rootCause(error: unknown): { code?: string; message: string } {
  let current: unknown = error;
  for (let depth = 0; depth < 10; depth += 1) {
    const next = (current as { cause?: unknown } | null | undefined)?.cause;
    if (next === undefined || next === null || next === current) break;
    current = next;
  }
  if (current instanceof Error) {
    const code = (current as { code?: unknown }).code;
    return { ...(typeof code === 'string' ? { code } : {}), message: current.message };
  }
  return { message: String(current) };
}

/** The request could not be completed (DNS, TLS, reset, timeout) after retries. */
export class HttpNetworkError extends Error {
  override readonly name = 'HttpNetworkError';
  /** Node error code of the root cause, e.g. ENOTFOUND, when there is one. */
  readonly code: string | undefined;

  constructor(url: URL, cause: unknown) {
    const root = rootCause(cause);
    const detail = [root.code, root.message].filter(Boolean).join(': ');
    super(`Network error for ${describeUrl(url)}: ${detail}`);
    this.code = root.code;
  }
}

/** The response exceeded the size limit for this request. */
export class HttpBodyTooLargeError extends Error {
  override readonly name = 'HttpBodyTooLargeError';

  constructor(url: URL, limit: number) {
    super(`Response from ${describeUrl(url)} exceeded ${limit} bytes`);
  }
}

/** Base for Cloud Foundry API errors; carries the CF error code and title. */
export class CfApiError extends Error {
  override name = 'CfApiError';

  constructor(
    readonly status: number,
    url: URL,
    readonly cfCode?: number,
    readonly cfTitle?: string,
    detail?: string,
  ) {
    const cf = cfTitle ? ` ${cfTitle}${cfCode === undefined ? '' : ` (${cfCode})`}` : '';
    super(`CF API ${status}${cf} for ${describeUrl(url)}${detail ? `: ${detail}` : ''}`);
  }
}

/** 403: the user's role does not allow this call. Recorded as a skipped check. */
export class CfForbiddenError extends CfApiError {
  override name = 'CfForbiddenError';
}

/** 404: the resource does not exist or is not visible to the user. */
export class CfNotFoundError extends CfApiError {
  override name = 'CfNotFoundError';
}

/** 401 after a token refresh: the scan cannot continue. */
export class CfAuthError extends Error {
  override readonly name = 'CfAuthError';
}

/** A user-facing configuration problem (exit code 2). */
export class ConfigError extends Error {
  override readonly name = 'ConfigError';
}
