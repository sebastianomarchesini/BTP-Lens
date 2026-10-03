import type { ReportData } from '@btp-lens/model';
import { formatDate } from './format';

/** Plain-language phrases per rule, for readers who are not developers. */
const RULE_PHRASES: Record<string, (n: number) => string> = {
  RUNTIME_NODE_EOL: (n) =>
    `${n} ${run(n)} a Node.js version that no longer receives security fixes`,
  RUNTIME_JAVA_EOL: (n) => `${n} ${run(n)} a Java version that no longer receives security fixes`,
  BUILDPACK_OUTDATED: (n) => `${n} ${were(n)} built with an outdated buildpack`,
  STACK_DEPRECATED: (n) => `${n} ${run(n)} on a deprecated operating system stack`,
  APP_IDLE: (n) => `${n} ${look(n)} unused`,
  APP_NO_RECENT_DEPLOY: (n) => `${n} ${have(n)} not been deployed in over a year`,
  UI5_OUT_OF_MAINTENANCE: (n) => `${n} ${use(n)} a SAPUI5 version that is out of maintenance`,
  SAP_PKG_OUTDATED: (n) => `${n} ${use(n)} outdated SAP libraries`,
  DEP_KNOWN_CVE: (n) => `${n} ${use(n)} a library with a known vulnerability`,
  ENV_SECRET_PLAINTEXT: (n) => `${n} ${have(n)} environment variable names that look like secrets`,
};

const run = (n: number) => (n === 1 ? 'runs' : 'run');
const were = (n: number) => (n === 1 ? 'was' : 'were');
const look = (n: number) => (n === 1 ? 'looks' : 'look');
const have = (n: number) => (n === 1 ? 'has' : 'have');
const use = (n: number) => (n === 1 ? 'uses' : 'use');
const apps = (n: number) => `${n} app${n === 1 ? '' : 's'}`;

/**
 * Three to four sentences a manager can read without knowing Cloud Foundry.
 * Everything is computed from the report data, so it is always true of the
 * scan being shown.
 */
export function startHereSentences(data: ReportData): string[] {
  const sentences: string[] = [];
  const where = data.scope.orgs.join(', ');
  sentences.push(
    `${apps(data.summary.apps)} in ${where} ${were(data.summary.apps)} scanned on ${formatDate(data.scannedAt)}.`,
  );

  const affected = new Set(data.findings.map((f) => f.app.guid)).size;
  if (affected === 0) {
    sentences.push('No rule found a problem in the checks that ran.');
  } else {
    const byRule = new Map<string, Set<string>>();
    for (const f of data.findings)
      (byRule.get(f.id) ?? byRule.set(f.id, new Set()).get(f.id))?.add(f.app.guid);
    const parts = [...byRule.entries()]
      .sort((a, b) => b[1].size - a[1].size)
      .slice(0, 3)
      .map(([id, guids]) => {
        const phrase = RULE_PHRASES[id];
        const rule = data.rules.find((r) => r.id === id);
        return phrase
          ? phrase(guids.size)
          : `${guids.size} ${have(guids.size)} "${rule?.title ?? id}"`;
      });
    sentences.push(
      `${apps(affected)} need${affected === 1 ? 's' : ''} attention: ${parts.join('; ')}.`,
    );
  }

  const skipped = data.summary.checksSkipped;
  if (skipped > 0) {
    sentences.push(
      `${skipped} check${skipped === 1 ? '' : 's'} could not run with your role, so some things were not looked at. That is not a problem with your apps.`,
    );
  }
  sentences.push('Nothing in your account was changed: this scan only read information.');
  return sentences;
}
