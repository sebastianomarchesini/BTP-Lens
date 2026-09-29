import type { FetchLike } from '../../src/http/httpClient.js';

export interface RecordedCall {
  method: string;
  url: URL;
  headers: Record<string, string>;
  body: string | undefined;
  redirect: RequestRedirect | undefined;
}

type Responder = (call: RecordedCall) => Response | Promise<Response>;

interface Route {
  method: string;
  match: (url: URL) => boolean;
  respond: Responder;
  times: number;
}

export function jsonResponse(
  body: unknown,
  status = 200,
  headers: Record<string, string> = {},
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', ...headers },
  });
}

/** Canonical "path?sorted-query" key, so routes don't depend on param order. */
export function routeKey(url: URL): string {
  const params = [...url.searchParams.entries()].sort(([a], [b]) => a.localeCompare(b));
  const query = new URLSearchParams(params).toString();
  return `${url.host}${url.pathname}${query ? `?${query}` : ''}`;
}

/**
 * A scripted fetch. Unmatched requests throw, so a test fails loudly on any
 * call it did not expect. Every call is recorded for assertions.
 */
export class FakeFetch {
  readonly calls: RecordedCall[] = [];
  private readonly routes: Route[] = [];

  on(
    method: string,
    match: string | RegExp | ((url: URL) => boolean),
    respond: Responder | Response,
    times = Infinity,
  ): this {
    const matcher =
      typeof match === 'function'
        ? match
        : typeof match === 'string'
          ? (url: URL) => routeKey(url) === match || url.href === match
          : (url: URL) => match.test(url.href);
    // A fresh Response per call: clone() would tee the body, and cancelling one
    // branch of a tee never settles while the other branch stays open.
    const responder: Responder =
      respond instanceof Response
        ? async () =>
            new Response(respond.body === null ? null : await respond.clone().arrayBuffer(), {
              status: respond.status,
              headers: respond.headers,
            })
        : respond;
    this.routes.push({ method, match: matcher, respond: responder, times });
    return this;
  }

  readonly fetch: FetchLike = async (input, init) => {
    const headers: Record<string, string> = {};
    new Headers(init.headers).forEach((value, key) => {
      headers[key] = value;
    });
    const call: RecordedCall = {
      method: init.method ?? 'GET',
      url: new URL(input.href),
      headers,
      body: typeof init.body === 'string' ? init.body : undefined,
      redirect: init.redirect,
    };
    this.calls.push(call);
    const route = this.routes.find(
      (r) => r.times > 0 && r.method === call.method && r.match(call.url),
    );
    if (route === undefined) {
      throw new Error(`FakeFetch: unexpected ${call.method} ${call.url.href}`);
    }
    route.times -= 1;
    return route.respond(call);
  };
}

export const noSleep = (): Promise<void> => Promise.resolve();
