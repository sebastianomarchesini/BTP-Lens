import { z } from 'zod';
import type { TokenProvider } from './auth.js';
import { CfApiError, CfAuthError, CfForbiddenError, CfNotFoundError } from './errors.js';
import type { HttpClient, HttpResponse } from './httpClient.js';

const LinkSchema = z.object({ href: z.string() }).nullish();

export const CfRootSchema = z.object({
  links: z.object({
    self: LinkSchema,
    cloud_controller_v3: LinkSchema,
    uaa: LinkSchema,
    login: LinkSchema,
    log_cache: LinkSchema,
  }),
});
export type CfRoot = z.infer<typeof CfRootSchema>;

const PageSchema = z.object({
  pagination: z.object({
    total_results: z.number().optional(),
    next: z.object({ href: z.string() }).nullish(),
  }),
  resources: z.array(z.unknown()),
  included: z.record(z.string(), z.array(z.unknown())).optional(),
});
type CfPage = z.infer<typeof PageSchema>;

const CfErrorBodySchema = z.object({
  errors: z.array(z.object({ code: z.number().optional(), title: z.string().optional() })).min(1),
});

export interface ListResult<T> {
  resources: T[];
  /** Resources merged from `included` across all pages, keyed by type. */
  included: Record<string, unknown[]>;
  /** Resources that did not match the expected schema and were dropped. */
  invalid: number;
}

export type Query = Record<string, string | number | boolean>;

const MAX_PAGES = 1000;

/**
 * Read-only Cloud Foundry v3 client. It has no method other than GET, and the
 * egress allow-list denies every other method for the CF API host as well.
 */
export class CfClient {
  private tokens: TokenProvider | undefined;
  private readonly basePath: string;

  constructor(
    private readonly http: HttpClient,
    readonly apiUrl: URL,
  ) {
    this.basePath = apiUrl.pathname.replace(/\/+$/, '');
  }

  setTokenProvider(tokens: TokenProvider): void {
    this.tokens = tokens;
  }

  /** GET / (unauthenticated): links to UAA, login and log cache. */
  async root(): Promise<CfRoot> {
    const body = await this.getJson(this.url('/'), false);
    return this.parse(CfRootSchema, body, this.url('/'));
  }

  async get<T>(path: string, schema: z.ZodType<T>, query: Query = {}): Promise<T> {
    const url = this.url(path, query);
    return this.parse(schema, await this.getJson(url, true), url);
  }

  /** GET a v3 list endpoint and follow `pagination.next` to the last page. */
  async list<T>(path: string, schema: z.ZodType<T>, query: Query = {}): Promise<ListResult<T>> {
    const result: ListResult<T> = { resources: [], included: {}, invalid: 0 };
    let url: URL | undefined = this.url(path, { per_page: 5000, ...query });
    const seen = new Set<string>();
    while (url !== undefined) {
      if (seen.has(url.href) || seen.size >= MAX_PAGES) {
        throw new CfApiError(200, url, undefined, undefined, 'pagination loop detected');
      }
      seen.add(url.href);
      const page: CfPage = this.parse(PageSchema, await this.getJson(url, true), url);
      for (const resource of page.resources) {
        const parsed = schema.safeParse(resource);
        if (parsed.success) result.resources.push(parsed.data);
        else result.invalid += 1;
      }
      for (const [type, items] of Object.entries(page.included ?? {})) {
        (result.included[type] ??= []).push(...items);
      }
      url = page.pagination.next ? this.nextPage(page.pagination.next.href, url) : undefined;
    }
    return result;
  }

  private url(path: string, query: Query = {}): URL {
    const url = new URL(`${this.basePath}${path}`, this.apiUrl.origin);
    for (const [key, value] of Object.entries(query)) url.searchParams.set(key, String(value));
    return url;
  }

  /** A next-page link must stay on the CF API; anything else is refused. */
  private nextPage(href: string, current: URL): URL {
    let next: URL;
    try {
      next = new URL(href);
    } catch {
      throw new CfApiError(200, current, undefined, undefined, 'invalid pagination link');
    }
    if (next.origin !== this.apiUrl.origin || !next.pathname.startsWith(`${this.basePath}/v3/`)) {
      throw new CfApiError(200, current, undefined, undefined, 'pagination link leaves the CF API');
    }
    return next;
  }

  private async getJson(url: URL, authenticated: boolean): Promise<unknown> {
    let res = await this.send(url, authenticated);
    if (res.status === 401 && authenticated && this.tokens) {
      this.tokens.invalidate();
      res = await this.send(url, authenticated);
    }
    if (res.status === 401) {
      throw new CfAuthError(
        'The CF API rejected the access token (401). Log in again with `cf login` and retry.',
      );
    }
    if (res.status < 200 || res.status >= 300) throw this.toError(res);
    try {
      return JSON.parse(res.text) as unknown;
    } catch {
      throw new CfApiError(res.status, url, undefined, undefined, 'response is not valid JSON');
    }
  }

  private async send(url: URL, authenticated: boolean): Promise<HttpResponse> {
    const headers: Record<string, string> = {};
    if (authenticated) {
      if (!this.tokens) throw new CfAuthError('No credentials configured for the CF API.');
      headers.authorization = `bearer ${await this.tokens.getToken()}`;
    }
    return this.http.request({ url, method: 'GET', headers });
  }

  private toError(res: HttpResponse): CfApiError {
    let code: number | undefined;
    let title: string | undefined;
    try {
      const body = CfErrorBodySchema.safeParse(JSON.parse(res.text));
      if (body.success) ({ code, title } = body.data.errors[0] ?? {});
    } catch {
      // Not a CF error body; keep status only.
    }
    if (res.status === 403) return new CfForbiddenError(403, res.url, code, title);
    if (res.status === 404) return new CfNotFoundError(404, res.url, code, title);
    const detail = res.status >= 300 && res.status < 400 ? 'redirect not followed' : undefined;
    return new CfApiError(res.status, res.url, code, title, detail);
  }

  private parse<T>(schema: z.ZodType<T>, body: unknown, url: URL): T {
    const parsed = schema.safeParse(body);
    if (!parsed.success) {
      throw new CfApiError(200, url, undefined, undefined, 'unexpected response shape');
    }
    return parsed.data;
  }
}
