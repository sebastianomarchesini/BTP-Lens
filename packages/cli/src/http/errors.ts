import { describeUrl } from '../net/errors.js';

/** The request could not be completed (DNS, TLS, reset, timeout) after retries. */
export class HttpNetworkError extends Error {
  override readonly name = 'HttpNetworkError';

  constructor(url: URL, cause: unknown) {
    const detail = cause instanceof Error ? cause.message : String(cause);
    super(`Network error for ${describeUrl(url)}: ${detail}`);
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
