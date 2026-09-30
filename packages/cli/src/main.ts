import { Command, CommanderError } from 'commander';
import { reanalyze } from './analyzers/index.js';
import {
  type FailOn,
  type ReportConfig,
  type ScanConfig,
  failThreshold,
  parseReportConfig,
  parseScanConfig,
} from './config.js';
import type { FetchLike } from './http/httpClient.js';
import { meetsThreshold } from './model/severity.js';
import type { ReportData } from './model/snapshot.js';
import { writeReports } from './reporters/index.js';
import { toReportData } from './reporters/reportData.js';
import { scan } from './scan.js';
import { readSnapshot, writeSnapshot } from './snapshot.js';
import { TOOL_NAME, TOOL_VERSION } from './version.js';

export interface CliIo {
  stdout: (text: string) => void;
  stderr: (text: string) => void;
  env: NodeJS.ProcessEnv;
  /** Injected in tests. */
  fetch?: FetchLike;
  /** Injected in tests. */
  now?: () => Date;
}

export const EXIT = { ok: 0, findings: 1, error: 2 } as const;

const DEFAULT_FORMATS = 'html,json,csv,sarif';
const FAIL_ON_HELP =
  'exit 1 on a finding at or above: critical, high, medium, low, info (default: none)';

function exitCodeFor(data: ReportData, failOn: FailOn): number {
  const threshold = failThreshold(failOn);
  if (threshold === undefined) return EXIT.ok;
  return data.findings.some((f) => meetsThreshold(f.severity, threshold)) ? EXIT.findings : EXIT.ok;
}

function printSummary(data: ReportData, files: string[], io: CliIo): void {
  const s = data.summary.findingsBySeverity;
  const skipped = data.summary.checksSkipped;
  io.stdout(
    `Scanned ${data.summary.apps} app(s) in ${data.scope.orgs.join(', ')}: ` +
      `${data.summary.findings} finding(s) (${s.critical} critical, ${s.high} high, ` +
      `${s.medium} medium, ${s.low} low, ${s.info} info)` +
      `${skipped > 0 ? `, ${skipped} check(s) skipped` : ''}.\n`,
  );
  for (const check of data.checks.filter((c) => c.status === 'skipped')) {
    io.stdout(`  skipped ${check.id}: ${check.reason ?? ''}\n`);
  }
  io.stdout(`Wrote:\n${files.map((f) => `  ${f}\n`).join('')}`);
}

async function runScan(config: ScanConfig, io: CliIo): Promise<number> {
  const log = config.quiet ? () => {} : (message: string) => io.stderr(`${message}\n`);
  const snapshot = await scan({
    apiUrl: config.api,
    org: config.org,
    space: config.space,
    deep: config.deep,
    probeRoutes: config.probeRoutes,
    concurrency: config.concurrency,
    env: io.env,
    fetch: io.fetch,
    now: io.now,
    log,
  });
  const snapshotPath = await writeSnapshot(snapshot, config.out);
  const data = toReportData(snapshot);
  const files = await writeReports(data, config.format, config.out);
  if (!config.quiet) printSummary(data, [snapshotPath, ...files], io);
  return exitCodeFor(data, config.failOn);
}

async function runReport(config: ReportConfig, io: CliIo): Promise<number> {
  const snapshot = reanalyze(await readSnapshot(config.from));
  const data = toReportData(snapshot);
  const files = await writeReports(data, config.format, config.out);
  printSummary(data, files, io);
  return exitCodeFor(data, config.failOn);
}

function buildProgram(io: CliIo, setExit: (code: number) => void): Command {
  const program = new Command()
    .name(TOOL_NAME)
    .description(
      'Read-only scanner for Cloud Foundry landscapes on SAP BTP. Not affiliated with SAP.',
    )
    .version(TOOL_VERSION, '-V, --version')
    .exitOverride()
    .configureOutput({ writeOut: io.stdout, writeErr: io.stderr })
    .showHelpAfterError();

  program
    .command('scan')
    .description('scan one CF org (GET requests only) and write a snapshot and reports')
    .requiredOption('--api <url>', 'CF API endpoint, e.g. https://api.cf.eu10.hana.ondemand.com')
    .requiredOption('--org <name>', 'org to scan')
    .option('--space <name>', 'scan only this space')
    .option('--deep', 'also run checks that need SpaceDeveloper or SpaceSupporter', false)
    .option('--no-probe-routes', 'do not read resources/sap-ui-version.json from app routes')
    .option('--out <dir>', 'output directory', './reports')
    .option('--format <list>', 'report formats: html,json,csv,sarif', DEFAULT_FORMATS)
    .option('--fail-on <severity>', FAIL_ON_HELP, 'none')
    .option('--concurrency <n>', 'parallel API requests (1-20)', '5')
    .option('--quiet', 'print errors only', false)
    .action(async (options: Record<string, unknown>) => {
      setExit(await runScan(parseScanConfig(options), io));
    });

  program
    .command('report')
    .description('re-analyze a snapshot offline and write reports')
    .requiredOption('--from <snapshot>', 'snapshot JSON written by `btp-lens scan`')
    .option('--format <list>', 'report formats: html,json,csv,sarif', DEFAULT_FORMATS)
    .option('--out <dir>', 'output directory', './reports')
    .option('--fail-on <severity>', FAIL_ON_HELP, 'none')
    .action(async (options: Record<string, unknown>) => {
      setExit(await runReport(parseReportConfig(options), io));
    });

  program
    .command('version')
    .description('print the version')
    .action(() => {
      io.stdout(`${TOOL_NAME} ${TOOL_VERSION}\n`);
    });

  return program;
}

/** Runs the CLI and returns the exit code: 0 ok, 1 findings at --fail-on, 2 tool error. */
export async function main(argv: string[], io: CliIo): Promise<number> {
  let exitCode: number = EXIT.ok;
  const program = buildProgram(io, (code) => {
    exitCode = code;
  });
  try {
    await program.parseAsync(argv, { from: 'user' });
    return exitCode;
  } catch (error) {
    if (error instanceof CommanderError) {
      return error.exitCode === 0 ? EXIT.ok : EXIT.error;
    }
    const message = error instanceof Error ? error.message : String(error);
    io.stderr(`${TOOL_NAME}: ${message}\n`);
    if (io.env.BTP_LENS_DEBUG && error instanceof Error && error.stack)
      io.stderr(`${error.stack}\n`);
    return EXIT.error;
  }
}
