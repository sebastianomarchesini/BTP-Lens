import { analyze } from './analyzers/index.js';
import { CheckRecorder, COLLECTOR_CHECKS } from './checks.js';
import { collectApps, type Scope } from './collectors/apps.js';
import { collectCurrentDroplets } from './collectors/droplets.js';
import { listSpaces, resolveOrg } from './collectors/orgs.js';
import { type TokenProvider, resolveTokenProvider } from './http/auth.js';
import { ConfigError } from './http/errors.js';
import { CfClient, type CfRoot } from './http/cfClient.js';
import { type FetchLike, HttpClient } from './http/httpClient.js';
import { EgressPolicy, cfApiRule, logCacheRule, uaaRule } from './net/allowlist.js';
import type { RawApp, RawDroplet } from './model/raw.js';
import { SNAPSHOT_SCHEMA_VERSION, type Snapshot } from './model/snapshot.js';
import { TOOL_NAME, TOOL_VERSION } from './version.js';

export interface ScanOptions {
  apiUrl: URL;
  org: string;
  space?: string;
  deep: boolean;
  probeRoutes: boolean;
  concurrency: number;
  env: NodeJS.ProcessEnv;
  /** Credentials already obtained (guided mode); otherwise resolved from env and the cf CLI. */
  tokens?: TokenProvider;
  /** Injected in tests; defaults to the global fetch. */
  fetch?: FetchLike;
  /** Injected in tests; defaults to the current time. */
  now?: () => Date;
  log?: (message: string) => void;
}

function toUrl(href: string | undefined): URL | undefined {
  if (href === undefined) return undefined;
  try {
    return new URL(href);
  } catch {
    return undefined;
  }
}

/**
 * Adds the platform endpoints the CF root advertises to the allow-list, and
 * returns the OAuth token endpoint (UAA preferred, login server as fallback).
 */
export function trustRootLinks(policy: EgressPolicy, root: CfRoot): URL | undefined {
  const uaa = toUrl(root.links.uaa?.href);
  const login = toUrl(root.links.login?.href);
  const logCache = toUrl(root.links.log_cache?.href);
  for (const auth of [uaa, login]) if (auth) policy.add(uaaRule(auth));
  if (logCache) policy.add(logCacheRule(logCache));
  const base = uaa ?? login;
  return base
    ? new URL(`${base.pathname.replace(/\/+$/, '')}/oauth/token`, base.origin)
    : undefined;
}

export async function scan(options: ScanOptions): Promise<Snapshot> {
  const log = options.log ?? (() => {});
  const scannedAt = (options.now?.() ?? new Date()).toISOString();

  const policy = new EgressPolicy();
  policy.add(cfApiRule(options.apiUrl));
  const http = new HttpClient({
    policy,
    userAgent: `${TOOL_NAME}/${TOOL_VERSION}`,
    fetch: options.fetch,
    concurrency: options.concurrency,
  });
  const cf = new CfClient(http, options.apiUrl);

  log(`Connecting to ${options.apiUrl.origin}`);
  const tokenUrl = trustRootLinks(policy, await cf.root());
  const tokens =
    options.tokens ??
    (await resolveTokenProvider({ env: options.env, http, apiUrl: options.apiUrl, tokenUrl }));
  cf.setTokenProvider(tokens);
  log(`Credentials: ${tokens.source}`);

  const org = await resolveOrg(cf, options.org);
  const spaces = await listSpaces(cf, org, options.space);
  // The v3 list endpoints filter by visibility instead of answering 403, so a
  // user without a space role would otherwise get an empty report that looks clean.
  if (spaces.length === 0) {
    throw new ConfigError(
      `You can see the org "${org.name}" but none of its spaces, so there is nothing to scan.\n` +
        'Ask your administrator for the Space Auditor role (read-only) on the spaces you want to scan; docs/permissions.md has the text to send.',
    );
  }
  const scope: Scope = {
    orgGuid: org.guid,
    ...(options.space === undefined ? {} : { spaceGuids: spaces.map((s) => s.guid) }),
  };
  log(
    `Scanning org "${org.name}" (${spaces.length} visible space${spaces.length === 1 ? '' : 's'})`,
  );

  const recorder = new CheckRecorder({ deep: options.deep }, log);
  const apps = await recorder.run(COLLECTOR_CHECKS.apps, () => collectApps(cf, scope));
  const droplets = await recorder.run(COLLECTOR_CHECKS.droplets, () =>
    collectCurrentDroplets(cf, scope),
  );
  const dropped = (apps?.invalid ?? 0) + (droplets?.invalid ?? 0);
  if (dropped > 0) log(`Ignored ${dropped} resource(s) with an unexpected shape`);

  const appItems: RawApp[] = apps?.items ?? [];
  const appGuids = new Set(appItems.map((a) => a.guid));
  const raw = {
    orgs: [org],
    spaces,
    apps: appItems,
    droplets: (droplets?.items ?? []).filter((d: RawDroplet) => appGuids.has(d.appGuid)),
    projects: [],
  };
  log(`Collected ${raw.apps.length} app(s)`);

  const collectorChecks = recorder.list();
  const analysis = analyze(raw, scannedAt, collectorChecks);
  return {
    schemaVersion: SNAPSHOT_SCHEMA_VERSION,
    tool: { name: TOOL_NAME, version: TOOL_VERSION },
    scannedAt,
    scope: {
      apiEndpoint: options.apiUrl.href,
      orgs: [org.name],
      ...(options.space === undefined ? {} : { spaces: [options.space] }),
    },
    // No collector probes app routes yet (planned with UI5_OUT_OF_MAINTENANCE), so the
    // snapshot records what happened, whatever --no-probe-routes said.
    options: { deep: options.deep, probeRoutes: false },
    checks: [...collectorChecks, ...analysis.ruleChecks],
    raw,
    apps: analysis.apps,
    findings: analysis.findings,
  };
}
