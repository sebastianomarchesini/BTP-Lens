/** Removes query string and fragment so error messages never echo parameters. */
export function describeUrl(url: URL): string {
  return `${url.origin}${url.pathname}`;
}

/** A request was blocked by the egress allow-list before it was sent. */
export class EgressDeniedError extends Error {
  override readonly name = 'EgressDeniedError';

  constructor(
    readonly method: string,
    url: URL,
    readonly reason: string,
  ) {
    super(`Egress denied: ${method} ${describeUrl(url)} (${reason})`);
  }
}
