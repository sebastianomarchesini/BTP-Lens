import type { EgressPolicy, HttpMethod } from '../net/allowlist.js';
import { HttpBodyTooLargeError, HttpNetworkError } from './errors.js';
import { Semaphore } from './semaphore.js';

export type FetchLike = (input: URL, init: RequestInit) => Promise<Response>;

export interface HttpRequest {
  url: URL;
  method?: HttpMethod;
  headers?: Record<string, string>;
  body?: string;
  timeoutMs?: number;
  /** Maximum response size; the body is streamed and cut off above it. */
  maxBytes?: number;
  /** Retry on network errors, 429 and 5xx (default true). */
  retry?: boolean;
}

export interface HttpResponse {
  url: URL;
  status: number;
  headers: Headers;
  text: string;
}

export interface HttpClientOptions {
  policy: EgressPolicy;
  userAgent: string;
  fetch?: FetchLike;
  concurrency?: number;
  maxRetries?: number;
  timeoutMs?: number;
  sleep?: (ms: number) => Promise<void>;
  now?: () => number;
  random?: () => number;
}

interface RateLimitState {
  limit: number;
  remaining: number;
  resetAtMs: number;
}

const RETRYABLE_STATUS = new Set([429, 500, 502, 503, 504]);
const DEFAULT_MAX_BYTES = 64 * 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 30_000;
const MAX_RETRY_AFTER_MS = 120_000;
const MAX_PACING_DELAY_MS = 10_000;
const LOW_BUDGET_RATIO = 0.05;
const BACKOFF_BASE_MS = 500;
const BACKOFF_CAP_MS = 8_000;

const defaultSleep = (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));

function lowerCaseKeys(headers: Record<string, string> = {}): Record<string, string> {
  return Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]));
}

/**
 * Releases a body we will not read. Not awaited: cancelling a tee'd stream
 * only settles once every branch is cancelled, which must not block us.
 */
function discardBody(res: Response): void {
  res.body?.cancel().catch(() => {
    // The body is not needed; ignore stream errors.
  });
}

async function readBody(res: Response, url: URL, maxBytes: number): Promise<string> {
  const declared = Number(res.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > maxBytes) {
    discardBody(res);
    throw new HttpBodyTooLargeError(url, maxBytes);
  }
  if (res.body === null) return '';
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      reader.cancel().catch(() => {
        // Already failing; ignore stream errors.
      });
      throw new HttpBodyTooLargeError(url, maxBytes);
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString('utf8');
}

/**
 * The single outbound HTTP path. Every request is checked against the egress
 * allow-list before it is sent; redirects are never followed, so a redirect
 * cannot lead to a host the allow-list does not know.
 */
export class HttpClient {
  readonly policy: EgressPolicy;
  private readonly fetchImpl: FetchLike;
  private readonly semaphore: Semaphore;
  private readonly maxRetries: number;
  private readonly timeoutMs: number;
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly now: () => number;
  private readonly random: () => number;
  private readonly userAgent: string;
  private readonly rateLimits = new Map<string, RateLimitState>();

  constructor(options: HttpClientOptions) {
    this.policy = options.policy;
    this.userAgent = options.userAgent;
    this.fetchImpl = options.fetch ?? ((input, init) => fetch(input, init));
    this.semaphore = new Semaphore(options.concurrency ?? 5);
    this.maxRetries = options.maxRetries ?? 3;
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.sleep = options.sleep ?? defaultSleep;
    this.now = options.now ?? Date.now;
    this.random = options.random ?? Math.random;
  }

  async request(req: HttpRequest): Promise<HttpResponse> {
    const method = req.method ?? 'GET';
    const headers = lowerCaseKeys(req.headers);
    // Throws before anything is sent when the request is not allowed.
    this.policy.authorize(req.url, method, 'authorization' in headers);
    return this.semaphore.run(() => this.send(req, method, headers));
  }

  private async send(
    req: HttpRequest,
    method: HttpMethod,
    headers: Record<string, string>,
  ): Promise<HttpResponse> {
    const maxRetries = req.retry === false ? 0 : this.maxRetries;
    for (let attempt = 0; ; attempt += 1) {
      await this.pace(req.url.host);
      let res: Response;
      try {
        res = await this.fetchImpl(req.url, {
          method,
          headers: { accept: 'application/json', 'user-agent': this.userAgent, ...headers },
          body: req.body,
          redirect: 'manual',
          signal: AbortSignal.timeout(req.timeoutMs ?? this.timeoutMs),
        });
      } catch (error) {
        if (attempt < maxRetries) {
          await this.sleep(this.backoff(attempt));
          continue;
        }
        throw new HttpNetworkError(req.url, error);
      }
      this.recordRateLimit(req.url.host, res.headers);
      if (RETRYABLE_STATUS.has(res.status) && attempt < maxRetries) {
        discardBody(res);
        await this.sleep(this.retryDelay(res.headers, attempt));
        continue;
      }
      const text = await readBody(res, req.url, req.maxBytes ?? DEFAULT_MAX_BYTES);
      return { url: req.url, status: res.status, headers: res.headers, text };
    }
  }

  /** Exponential backoff with jitter: 50-100% of min(cap, base * 2^attempt). */
  private backoff(attempt: number): number {
    const ceiling = Math.min(BACKOFF_CAP_MS, BACKOFF_BASE_MS * 2 ** attempt);
    return Math.round(ceiling * (0.5 + this.random() / 2));
  }

  private retryDelay(headers: Headers, attempt: number): number {
    const retryAfter = headers.get('retry-after');
    if (retryAfter !== null) {
      const seconds = Number(retryAfter);
      const ms = Number.isFinite(seconds) ? seconds * 1000 : Date.parse(retryAfter) - this.now();
      if (Number.isFinite(ms)) return Math.min(Math.max(ms, 0), MAX_RETRY_AFTER_MS);
    }
    return this.backoff(attempt);
  }

  private recordRateLimit(host: string, headers: Headers): void {
    const limit = Number(headers.get('x-ratelimit-limit'));
    const remaining = Number(headers.get('x-ratelimit-remaining'));
    const reset = Number(headers.get('x-ratelimit-reset'));
    if (
      headers.has('x-ratelimit-limit') &&
      Number.isFinite(limit) &&
      Number.isFinite(remaining) &&
      Number.isFinite(reset)
    ) {
      this.rateLimits.set(host, { limit, remaining, resetAtMs: reset * 1000 });
    }
  }

  /** Spreads the remaining budget over the reset window once it runs low. */
  private async pace(host: string): Promise<void> {
    const state = this.rateLimits.get(host);
    if (state === undefined || state.limit <= 0) return;
    if (state.remaining / state.limit >= LOW_BUDGET_RATIO) return;
    const windowMs = Math.max(0, state.resetAtMs - this.now());
    const delay = Math.min(windowMs / Math.max(state.remaining, 1), MAX_PACING_DELAY_MS);
    if (delay > 0) await this.sleep(delay);
  }
}
