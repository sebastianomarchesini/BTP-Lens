import { join } from 'node:path';
import { z } from 'zod';
import { listSpaces } from '../collectors/orgs.js';
import { parseApiUrl } from '../config.js';
import {
  StaticTokenProvider,
  type TokenProvider,
  UaaSessionTokenProvider,
  cfConfigPath,
  passcodeGrant,
  passwordGrant,
  readCfCliConfig,
  sameEndpoint,
  CfCliTokenProvider,
} from '../http/auth.js';
import { CfClient, type CfRoot } from '../http/cfClient.js';
import { CfAuthError, ConfigError, HttpNetworkError } from '../http/errors.js';
import { type FetchLike, HttpClient } from '../http/httpClient.js';
import { EgressPolicy, cfApiRule } from '../net/allowlist.js';
import { writeReports } from '../reporters/index.js';
import { toReportData } from '../reporters/reportData.js';
import { scan, trustRootLinks } from '../scan.js';
import { writeSnapshot } from '../snapshot.js';
import { TOOL_NAME, TOOL_VERSION } from '../version.js';
import type { OpenInBrowser } from './open.js';
import { type Prompter, WizardCancelled } from './prompt.js';
import { REGIONS } from './regions.js';

export interface WizardOptions {
  prompter: Prompter;
  env: NodeJS.ProcessEnv;
  /** Where ./btp-lens-reports is created. */
  cwd: string;
  /** Open the finished report with the OS default browser. */
  open: OpenInBrowser | null;
  fetch?: FetchLike;
  now?: () => Date;
}

const ORG_SCHEMA = z.object({ guid: z.string(), name: z.string() });
const MAX_ATTEMPTS = 3;

/** ./btp-lens-reports/2026-09-30-1412 */
export function reportDirName(now: Date): string {
  const p = (n: number) => String(n).padStart(2, '0');
  return `${now.getFullYear()}-${p(now.getMonth() + 1)}-${p(now.getDate())}-${p(now.getHours())}${p(now.getMinutes())}`;
}

/** One sentence on what went wrong, one on what to do. No stack traces. */
export function explainConnectionError(error: unknown, apiUrl: URL): string {
  const text = error instanceof Error ? error.message : String(error);
  const lower = text.toLowerCase();
  if (/certificate|cert_|self.signed|unable to verify/.test(lower)) {
    return (
      `The connection to ${apiUrl.host} is not trusted, which usually means your company inspects HTTPS traffic.\n` +
      'Ask IT for the company root certificate and set NODE_EXTRA_CA_CERTS to its path. BTP Lens never skips certificate checks.'
    );
  }
  if (/enotfound|eai_again|getaddrinfo/.test(lower)) {
    return (
      `The address ${apiUrl.host} could not be found.\n` +
      'Check the API endpoint in the BTP cockpit (Subaccount → Overview → Cloud Foundry Environment), or set your company proxy: HTTPS_PROXY=http://proxy.company:8080 and NODE_USE_ENV_PROXY=1.'
    );
  }
  if (/econnrefused|etimedout|fetch failed|network error|socket/.test(lower)) {
    return (
      `${apiUrl.host} could not be reached.\n` +
      'If you are on a company network, set HTTPS_PROXY=http://proxy.company:8080 and NODE_USE_ENV_PROXY=1 (ask IT for the address), then try again.'
    );
  }
  return `${text}\nRun \`${TOOL_NAME} doctor\` for a check of your environment.`;
}

interface Session {
  http: HttpClient;
  cf: CfClient;
  root: CfRoot;
  tokenUrl: URL | undefined;
  apiUrl: URL;
}

async function stepWhere(o: WizardOptions): Promise<Session> {
  const { prompter: p } = o;
  p.say('');
  p.say('Step 1 of 4 · Where is your landscape?');
  p.say(
    'The "API Endpoint" is shown in the BTP cockpit under Subaccount → Overview → Cloud Foundry Environment.',
  );
  const choice = await p.choose(
    'Paste it, or pick your region:',
    ['Paste the API endpoint', ...REGIONS.map((r) => `${r.id}  ${r.label}`)],
    0,
  );
  for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt += 1) {
    let apiUrl: URL;
    try {
      const value =
        choice === 0
          ? await p.ask('API endpoint (https://api.cf.…)')
          : (REGIONS[choice - 1]?.api ?? '');
      apiUrl = parseApiUrl(value);
    } catch (error) {
      if (error instanceof WizardCancelled) throw error;
      p.say(error instanceof Error ? error.message : String(error));
      continue;
    }
    const policy = new EgressPolicy();
    policy.add(cfApiRule(apiUrl));
    const http = new HttpClient({
      policy,
      userAgent: `${TOOL_NAME}/${TOOL_VERSION}`,
      fetch: o.fetch,
      maxRetries: 1,
    });
    const cf = new CfClient(http, apiUrl);
    p.say(`Checking ${apiUrl.host} …`);
    try {
      const root = await cf.root();
      const tokenUrl = trustRootLinks(policy, root);
      p.say('Connected.');
      return { http, cf, root, tokenUrl, apiUrl };
    } catch (error) {
      p.say(explainConnectionError(error, apiUrl));
      if (choice !== 0 || !(error instanceof HttpNetworkError))
        throw new ConfigError('Could not connect.');
    }
  }
  throw new ConfigError('Could not connect after three attempts.');
}

async function existingCfSession(
  s: Session,
  env: NodeJS.ProcessEnv,
): Promise<TokenProvider | undefined> {
  try {
    const config = await readCfCliConfig(cfConfigPath(env));
    if (!config || (!config.AccessToken && !config.RefreshToken)) return undefined;
    if (!sameEndpoint(config.Target, s.apiUrl)) return undefined;
    return new CfCliTokenProvider(s.http, s.tokenUrl, config);
  } catch {
    return undefined;
  }
}

async function verify(tokens: TokenProvider): Promise<string | undefined> {
  try {
    await tokens.getToken();
    return undefined;
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
}

async function stepSignIn(o: WizardOptions, s: Session): Promise<TokenProvider> {
  const { prompter: p } = o;
  p.say('');
  p.say('Step 2 of 4 · Sign in');
  if (o.env.BTP_LENS_ACCESS_TOKEN) {
    p.say('Using the token from BTP_LENS_ACCESS_TOKEN.');
    return new StaticTokenProvider(o.env.BTP_LENS_ACCESS_TOKEN);
  }
  const existing = await existingCfSession(s, o.env);
  const loginBase = s.root.links.login?.href ?? s.root.links.uaa?.href;
  const choices: { label: string; kind: 'existing' | 'passcode' | 'password' }[] = [];
  if (existing)
    choices.push({
      label: 'Use my existing cf CLI login (found on this computer)',
      kind: 'existing',
    });
  if (s.tokenUrl && loginBase) {
    choices.push({
      label: 'Open a browser and sign in with my company account (recommended)',
      kind: 'passcode',
    });
    choices.push({ label: 'Type my username and password', kind: 'password' });
  }
  if (choices.length === 0) {
    throw new ConfigError(
      `This API does not advertise a login endpoint. Run \`cf login -a ${s.apiUrl.origin}\` first and start ${TOOL_NAME} again.`,
    );
  }
  const kind =
    choices[
      await p.choose(
        'How do you want to sign in?',
        choices.map((c) => c.label),
        0,
      )
    ]?.kind;

  if (kind === 'existing' && existing) {
    const problem = await verify(existing);
    if (problem === undefined) return existing;
    p.say(`Your cf CLI login could not be used: ${problem}`);
  }

  for (let attempt = 0; attempt < MAX_ATTEMPTS && s.tokenUrl && loginBase; attempt += 1) {
    let tokens: TokenProvider;
    if (kind === 'password') {
      const username = await p.ask('Username (usually your e-mail address)');
      const password = await p.ask('Password', { hidden: true });
      tokens = new UaaSessionTokenProvider(
        s.http,
        s.tokenUrl,
        'username and password',
        passwordGrant(username, password),
      );
    } else {
      const passcodeUrl = `${loginBase.replace(/\/+$/, '')}/passcode`;
      p.say(`Sign in in your browser, then copy the one-time code shown there: ${passcodeUrl}`);
      if (o.open) await o.open(passcodeUrl);
      const code = await p.ask('One-time code', { hidden: true });
      tokens = new UaaSessionTokenProvider(
        s.http,
        s.tokenUrl,
        'one-time passcode',
        passcodeGrant(code),
      );
    }
    const problem = await verify(tokens);
    if (problem === undefined) {
      p.say('Signed in.');
      return tokens;
    }
    p.say(`Sign-in failed: ${problem}`);
    if (kind === 'password') {
      p.say('If your company uses single sign-on, choose the browser option instead.');
    }
  }
  throw new CfAuthError('Sign-in did not succeed.');
}

async function stepOrg(
  o: WizardOptions,
  s: Session,
): Promise<{ guid: string; name: string; spaces: number }> {
  const { prompter: p } = o;
  p.say('');
  p.say('Step 3 of 4 · Which org?');
  const { resources: orgs } = await s.cf.list('/v3/organizations', ORG_SCHEMA);
  if (orgs.length === 0) {
    throw new ConfigError(
      'Your user has no role in any Cloud Foundry org on this API.\n' +
        'Ask your administrator for the Space Auditor role (read-only) on the spaces you want to scan; docs/permissions.md has the text to send.',
    );
  }
  const sorted = [...orgs].sort((a, b) => a.name.localeCompare(b.name));
  let org = sorted[0];
  if (sorted.length === 1 && org) {
    p.say(`You have access to one org: ${org.name}.`);
  } else {
    org =
      sorted[
        await p.choose(
          'Pick the org to scan:',
          sorted.map((x) => x.name),
          0,
        )
      ];
  }
  if (!org) throw new WizardCancelled();
  const spaces = await listSpaces(s.cf, org);
  if (spaces.length === 0) {
    throw new ConfigError(
      `You can see the org "${org.name}" but none of its spaces.\n` +
        'Ask your administrator for the Space Auditor role (read-only) on the spaces you want to scan.',
    );
  }
  return { guid: org.guid, name: org.name, spaces: spaces.length };
}

function plural(n: number, word: string): string {
  return `${n} ${word}${n === 1 ? '' : 's'}`;
}

/**
 * Guided mode: `btp-lens` with no arguments. Four questions, standard
 * (Space Auditor) checks only, report opened in the browser. Returns the
 * process exit code. Findings never make guided mode exit non-zero.
 */
export async function runWizard(o: WizardOptions): Promise<number> {
  const { prompter: p } = o;
  const now = o.now?.() ?? new Date();
  try {
    p.say(`${TOOL_NAME} ${TOOL_VERSION} · read-only health check for your Cloud Foundry landscape`);
    p.say(
      'Nothing is changed in your account, and nothing is sent anywhere except your own CF API.',
    );
    p.say('Press Ctrl+C at any time to stop; nothing is written until the scan starts.');

    const session = await stepWhere(o);
    const tokens = await stepSignIn(o, session);
    session.cf.setTokenProvider(tokens);
    const org = await stepOrg(o, session);

    const outDir = join(o.cwd, 'btp-lens-reports', reportDirName(now));
    p.say('');
    p.say('Step 4 of 4 · Ready');
    p.say(`Standard checks only: they need the Space Auditor role and change nothing.`);
    p.say(
      `Scan org "${org.name}" (${plural(org.spaces, 'space')}) and write the report to ${outDir}`,
    );
    if (!(await p.confirm('Start the scan?'))) throw new WizardCancelled();

    const snapshot = await scan({
      apiUrl: session.apiUrl,
      org: org.name,
      deep: false,
      probeRoutes: true,
      concurrency: 5,
      env: o.env,
      tokens,
      fetch: o.fetch,
      now: () => now,
      log: (message) => p.say(`  ${message}`),
    });
    const snapshotPath = await writeSnapshot(snapshot, outDir);
    const data = toReportData(snapshot);
    const files = await writeReports(data, ['html', 'json', 'csv', 'sarif'], outDir);
    const html = files.find((f) => f.endsWith('.html')) ?? files[0] ?? outDir;
    const c = data.summary.findingsBySeverity;

    p.say('');
    p.say(
      `Done. ${plural(data.summary.apps, 'app')} scanned, ${plural(data.summary.findings, 'finding')}` +
        (data.summary.findings > 0
          ? ` (${c.critical} critical · ${c.high} high · ${c.medium} medium · ${c.low} low · ${c.info} info).`
          : '.'),
    );
    if (data.summary.checksSkipped > 0) {
      p.say(
        `${plural(data.summary.checksSkipped, 'check')} could not run with your role; the report says which. Nothing is wrong with your apps because of that.`,
      );
    }
    p.say(`Report: ${html}`);
    p.say(`Snapshot (for re-running offline): ${snapshotPath}`);
    p.say(
      'Nothing in your account was changed. Reports describe your landscape: share them only with people who may see it.',
    );
    if (o.open) {
      const opened = await o.open(html);
      p.say(
        opened
          ? 'The report was opened in your browser.'
          : 'Open the report file above in your browser.',
      );
    }
    return 0;
  } catch (error) {
    if (error instanceof WizardCancelled) {
      p.say('');
      p.say(error.message);
      return 0;
    }
    throw error;
  } finally {
    p.close();
  }
}
