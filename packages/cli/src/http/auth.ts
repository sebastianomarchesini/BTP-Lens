import { readFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { z } from 'zod';
import { describeUrl } from '../net/errors.js';
import { CfAuthError, ConfigError } from './errors.js';
import type { HttpClient } from './httpClient.js';

export interface TokenProvider {
  /** Human-readable source, e.g. "cf CLI session"; never the token itself. */
  readonly source: string;
  getToken(): Promise<string>;
  /** Called after a 401: the next getToken() must not reuse the token. */
  invalidate(): void;
}

/** Refresh this long before the JWT `exp` claim. */
const EXPIRY_MARGIN_MS = 60_000;

const TokenResponseSchema = z.object({
  access_token: z.string().min(1),
  refresh_token: z.string().optional(),
});

const CfCliConfigSchema = z.object({
  AccessToken: z.string().default(''),
  RefreshToken: z.string().default(''),
  Target: z.string().default(''),
  UAAOAuthClient: z.string().default(''),
  UAAOAuthClientSecret: z.string().default(''),
});
export type CfCliConfig = z.infer<typeof CfCliConfigSchema>;

function stripBearer(token: string): string {
  return token.replace(/^bearer\s+/i, '').trim();
}

/** Reads the JWT `exp` claim locally. Returns undefined when not a JWT. */
export function jwtExpiryMs(token: string): number | undefined {
  const payload = token.split('.')[1];
  if (payload === undefined) return undefined;
  try {
    const claims: unknown = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    const exp = z.object({ exp: z.number() }).safeParse(claims);
    return exp.success ? exp.data.exp * 1000 : undefined;
  } catch {
    return undefined;
  }
}

/** Compares two API endpoints ignoring case of the host and trailing slashes. */
export function sameEndpoint(a: string, b: URL): boolean {
  try {
    const left = new URL(a);
    const trim = (u: URL): string => u.pathname.replace(/\/+$/, '');
    return left.origin === b.origin && trim(left) === trim(b);
  } catch {
    return false;
  }
}

async function requestToken(
  http: HttpClient,
  tokenUrl: URL,
  clientId: string,
  clientSecret: string,
  form: Record<string, string>,
): Promise<z.infer<typeof TokenResponseSchema>> {
  // RFC 6749 §2.3.1: client id and secret are form-encoded, then base64'd.
  const basic = Buffer.from(
    `${encodeURIComponent(clientId)}:${encodeURIComponent(clientSecret)}`,
  ).toString('base64');
  const res = await http.request({
    url: tokenUrl,
    method: 'POST',
    headers: {
      authorization: `Basic ${basic}`,
      'content-type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams(form).toString(),
  });
  if (res.status !== 200) {
    let code = '';
    try {
      const body = z.object({ error: z.string() }).safeParse(JSON.parse(res.text));
      if (body.success) code = ` (${body.data.error})`;
    } catch {
      // Not JSON; report the status only.
    }
    throw new CfAuthError(
      `Token request to ${describeUrl(tokenUrl)} failed with HTTP ${res.status}${code}.`,
    );
  }
  try {
    const parsed = TokenResponseSchema.safeParse(JSON.parse(res.text));
    if (parsed.success) return parsed.data;
  } catch {
    // Fall through.
  }
  throw new CfAuthError(`Token response from ${describeUrl(tokenUrl)} was not understood.`);
}

/** A token handed in via BTP_LENS_ACCESS_TOKEN (e.g. from `cf oauth-token`). */
export class StaticTokenProvider implements TokenProvider {
  readonly source = 'BTP_LENS_ACCESS_TOKEN';
  private rejected = false;
  private readonly token: string;

  constructor(token: string) {
    this.token = stripBearer(token);
  }

  getToken(): Promise<string> {
    if (this.rejected) {
      return Promise.reject(
        new CfAuthError(
          'The token in BTP_LENS_ACCESS_TOKEN was rejected or has expired. Get a new one with `cf oauth-token`.',
        ),
      );
    }
    return Promise.resolve(this.token);
  }

  invalidate(): void {
    this.rejected = true;
  }
}

/** Shared caching and single-flight refresh for providers that can mint tokens. */
abstract class RefreshingTokenProvider implements TokenProvider {
  abstract readonly source: string;
  protected token: string | undefined;
  private pending: Promise<string> | undefined;

  constructor(private readonly now: () => number) {}

  protected abstract fetchToken(): Promise<string>;

  async getToken(): Promise<string> {
    if (this.token !== undefined && !this.expiresSoon(this.token)) return this.token;
    this.pending ??= this.fetchToken().finally(() => {
      this.pending = undefined;
    });
    this.token = await this.pending;
    return this.token;
  }

  invalidate(): void {
    this.token = undefined;
  }

  private expiresSoon(token: string): boolean {
    const exp = jwtExpiryMs(token);
    return exp !== undefined && exp - EXPIRY_MARGIN_MS <= this.now();
  }
}

/** OAuth client credentials from BTP_LENS_CLIENT_ID / BTP_LENS_CLIENT_SECRET. */
export class ClientCredentialsTokenProvider extends RefreshingTokenProvider {
  readonly source = 'client credentials';

  constructor(
    private readonly http: HttpClient,
    private readonly tokenUrl: URL,
    private readonly clientId: string,
    private readonly clientSecret: string,
    now: () => number = Date.now,
  ) {
    super(now);
  }

  protected async fetchToken(): Promise<string> {
    const res = await requestToken(this.http, this.tokenUrl, this.clientId, this.clientSecret, {
      grant_type: 'client_credentials',
    });
    return res.access_token;
  }
}

/**
 * Reuses the cf CLI session from ~/.cf/config.json. A refreshed token is kept
 * in memory only; the config file is never written.
 */
export class CfCliTokenProvider extends RefreshingTokenProvider {
  readonly source = 'cf CLI session';
  private refreshToken: string;

  constructor(
    private readonly http: HttpClient,
    private readonly tokenUrl: URL | undefined,
    private readonly config: CfCliConfig,
    now: () => number = Date.now,
  ) {
    super(now);
    this.token = config.AccessToken ? stripBearer(config.AccessToken) : undefined;
    this.refreshToken = config.RefreshToken;
  }

  protected async fetchToken(): Promise<string> {
    if (!this.refreshToken || this.tokenUrl === undefined) {
      throw new CfAuthError('The cf CLI session has expired. Run `cf login` and retry.');
    }
    const res = await requestToken(
      this.http,
      this.tokenUrl,
      this.config.UAAOAuthClient || 'cf',
      this.config.UAAOAuthClientSecret,
      { grant_type: 'refresh_token', refresh_token: this.refreshToken },
    );
    if (res.refresh_token) this.refreshToken = res.refresh_token;
    return res.access_token;
  }
}

export function cfConfigPath(env: NodeJS.ProcessEnv): string {
  return join(env.CF_HOME ?? homedir(), '.cf', 'config.json');
}

async function readCfCliConfig(path: string): Promise<CfCliConfig | undefined> {
  let text: string;
  try {
    text = await readFile(path, 'utf8');
  } catch {
    return undefined;
  }
  try {
    const parsed = CfCliConfigSchema.safeParse(JSON.parse(text));
    if (parsed.success) return parsed.data;
  } catch {
    // Reported below.
  }
  throw new ConfigError(`Could not read the cf CLI config at ${path}.`);
}

export interface ResolveTokenOptions {
  env: NodeJS.ProcessEnv;
  http: HttpClient;
  apiUrl: URL;
  /** `/oauth/token` on the UAA discovered from the CF root, if any. */
  tokenUrl: URL | undefined;
  now?: () => number;
}

/**
 * Picks credentials in this order: BTP_LENS_ACCESS_TOKEN, then
 * BTP_LENS_CLIENT_ID + BTP_LENS_CLIENT_SECRET, then the cf CLI session.
 */
export async function resolveTokenProvider(options: ResolveTokenOptions): Promise<TokenProvider> {
  const { env, http, apiUrl, tokenUrl } = options;
  const now = options.now ?? Date.now;

  if (env.BTP_LENS_ACCESS_TOKEN) return new StaticTokenProvider(env.BTP_LENS_ACCESS_TOKEN);

  if (env.BTP_LENS_CLIENT_ID || env.BTP_LENS_CLIENT_SECRET) {
    if (!env.BTP_LENS_CLIENT_ID || !env.BTP_LENS_CLIENT_SECRET) {
      throw new ConfigError('Set both BTP_LENS_CLIENT_ID and BTP_LENS_CLIENT_SECRET.');
    }
    if (tokenUrl === undefined) {
      throw new ConfigError('The CF API did not advertise a UAA endpoint for client credentials.');
    }
    return new ClientCredentialsTokenProvider(
      http,
      tokenUrl,
      env.BTP_LENS_CLIENT_ID,
      env.BTP_LENS_CLIENT_SECRET,
      now,
    );
  }

  const path = cfConfigPath(env);
  const config = await readCfCliConfig(path);
  if (config === undefined || (!config.AccessToken && !config.RefreshToken)) {
    throw new ConfigError(
      `No credentials found. Run \`cf login -a ${apiUrl.origin}\` first, or set BTP_LENS_ACCESS_TOKEN.`,
    );
  }
  if (!sameEndpoint(config.Target, apiUrl)) {
    throw new ConfigError(
      `The cf CLI is targeting ${config.Target || '(nothing)'}, but --api is ${apiUrl.origin}. ` +
        `Run \`cf login -a ${apiUrl.origin}\` or change --api.`,
    );
  }
  return new CfCliTokenProvider(http, tokenUrl, config, now);
}
