import { access, mkdtemp, rm } from 'node:fs/promises';
import { constants } from 'node:fs';
import { join } from 'node:path';
import { explainConnectionError } from './guided/wizard.js';
import { cfConfigPath, jwtExpiryMs, readCfCliConfig, sameEndpoint } from './http/auth.js';
import { CfClient } from './http/cfClient.js';
import { type FetchLike, HttpClient } from './http/httpClient.js';
import { EgressPolicy, cfApiRule } from './net/allowlist.js';
import { TOOL_NAME, TOOL_VERSION } from './version.js';

export interface DoctorOptions {
  /** API to test; defaults to the cf CLI target when present. */
  api?: URL;
  env: NodeJS.ProcessEnv;
  cwd: string;
  fetch?: FetchLike;
  nodeVersion?: string;
  now?: () => number;
}

export interface DoctorCheck {
  name: string;
  ok: boolean;
  /** One sentence: what was found. */
  detail: string;
  /** One sentence: what to do. Only when not ok. */
  fix?: string;
}

export const MIN_NODE = { major: 22, minor: 12 };

function checkNode(version: string): DoctorCheck {
  const [major = 0, minor = 0] = version.split('.').map(Number);
  const ok = major > MIN_NODE.major || (major === MIN_NODE.major && minor >= MIN_NODE.minor);
  return {
    name: 'Node.js',
    ok,
    detail: `Node.js ${version}`,
    ...(ok
      ? {}
      : {
          fix: `${TOOL_NAME} needs Node.js ${MIN_NODE.major}.${MIN_NODE.minor} or newer. Install the LTS version from https://nodejs.org (next, next, finish), then open a new terminal.`,
        }),
  };
}

async function checkApi(api: URL, fetchImpl: FetchLike | undefined): Promise<DoctorCheck> {
  const policy = new EgressPolicy();
  policy.add(cfApiRule(api));
  const http = new HttpClient({
    policy,
    userAgent: `${TOOL_NAME}/${TOOL_VERSION}`,
    fetch: fetchImpl,
    maxRetries: 0,
    timeoutMs: 10_000,
  });
  const started = Date.now();
  try {
    await new CfClient(http, api).root();
    return {
      name: 'Cloud Foundry API',
      ok: true,
      detail: `${api.host} answered in ${Date.now() - started} ms`,
    };
  } catch (error) {
    const [detail, fix] = explainConnectionError(error, api).split('\n');
    return {
      name: 'Cloud Foundry API',
      ok: false,
      detail: detail ?? 'unreachable',
      fix: fix ?? '',
    };
  }
}

async function checkCfSession(o: DoctorOptions, api: URL | undefined): Promise<DoctorCheck> {
  const name = 'cf CLI login';
  const path = cfConfigPath(o.env);
  const now = o.now?.() ?? Date.now();
  let config;
  try {
    config = await readCfCliConfig(path);
  } catch {
    return {
      name,
      ok: false,
      detail: `${path} could not be read`,
      fix: 'Run `cf login` again, or use guided mode (`npx btp-lens`) which does not need the cf CLI.',
    };
  }
  if (!config || (!config.AccessToken && !config.RefreshToken)) {
    return {
      name,
      ok: true,
      detail: 'No cf CLI login found (not required)',
      fix: undefined,
    };
  }
  if (api && !sameEndpoint(config.Target, api)) {
    return {
      name,
      ok: false,
      detail: `cf CLI targets ${config.Target || '(nothing)'}, not ${api.origin}`,
      fix: `Run \`cf login -a ${api.origin}\`, or let guided mode sign you in.`,
    };
  }
  const exp = jwtExpiryMs(config.AccessToken.replace(/^bearer\s+/i, ''));
  if (exp !== undefined && exp <= now) {
    return {
      name,
      ok: config.RefreshToken !== '',
      detail: config.RefreshToken
        ? 'Access token expired; it will be refreshed in memory'
        : 'cf CLI login has expired',
      ...(config.RefreshToken
        ? {}
        : { fix: 'Run `cf login` again, or use guided mode (`npx btp-lens`).' }),
    };
  }
  const hours = exp === undefined ? undefined : Math.max(0, Math.round((exp - now) / 3_600_000));
  return {
    name,
    ok: true,
    detail: hours === undefined ? 'Logged in' : `Logged in, token valid for about ${hours} h`,
  };
}

async function checkWritable(cwd: string): Promise<DoctorCheck> {
  const name = 'Output folder';
  try {
    await access(cwd, constants.W_OK);
    const probe = await mkdtemp(join(cwd, '.btp-lens-doctor-'));
    await rm(probe, { recursive: true, force: true });
    return { name, ok: true, detail: `${cwd} is writable` };
  } catch {
    return {
      name,
      ok: false,
      detail: `Cannot write in ${cwd}`,
      fix: 'Change to a folder you own (for example your Documents folder) and run the command again.',
    };
  }
}

export async function runDoctor(o: DoctorOptions): Promise<DoctorCheck[]> {
  const checks: DoctorCheck[] = [checkNode(o.nodeVersion ?? process.versions.node)];
  let api = o.api;
  if (api === undefined) {
    try {
      const config = await readCfCliConfig(cfConfigPath(o.env));
      if (config?.Target) api = new URL(config.Target);
    } catch {
      // Reported by checkCfSession.
    }
  }
  if (api) checks.push(await checkApi(api, o.fetch));
  else {
    checks.push({
      name: 'Cloud Foundry API',
      ok: true,
      detail: 'Not tested (no --api given and no cf CLI target)',
    });
  }
  checks.push(await checkCfSession(o, api));
  checks.push(await checkWritable(o.cwd));
  return checks;
}

export function formatDoctor(checks: DoctorCheck[]): string {
  const lines = checks.map(
    (c) => `${c.ok ? 'OK  ' : 'FAIL'} ${c.name}: ${c.detail}${c.fix ? `\n     → ${c.fix}` : ''}`,
  );
  const failed = checks.filter((c) => !c.ok).length;
  lines.push(
    failed === 0
      ? `Everything looks fine. Run \`${TOOL_NAME}\` to start a scan.`
      : `${failed} check${failed === 1 ? ' needs' : 's need'} attention. Fix the lines marked FAIL and run \`${TOOL_NAME} doctor\` again.`,
  );
  return `${lines.join('\n')}\n`;
}
