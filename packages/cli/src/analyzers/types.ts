import type { CheckDefinition } from '../checks.js';
import type { AppRef, Finding } from '../model/finding.js';
import type { RawData } from '../model/raw.js';
import type { RuleMeta } from '../model/snapshot.js';

export interface AnalyzerContext {
  /** Reference time: the scan time, so offline re-analysis is reproducible. */
  now: Date;
  raw: RawData;
  /** Resolves an app guid to the names used in findings. */
  appRef: (appGuid: string) => AppRef | undefined;
}

/** A rule: a pure function from raw scan data to findings. */
export interface Analyzer {
  rule: RuleMeta;
  /** Collector checks that must have run for the result to be meaningful. */
  requires: string[];
  analyze(context: AnalyzerContext): Finding[];
}

export const RULES_DOC_URL =
  'https://github.com/sebastianomarchesini/BTP-Lens/blob/main/docs/rules.md';

export function ruleHelpUri(ruleId: string): string {
  return `${RULES_DOC_URL}#${ruleId.toLowerCase()}`;
}

export function ruleCheck(rule: RuleMeta): CheckDefinition {
  return { id: `rule.${rule.id}`, title: rule.title, roles: rule.roles };
}

export const DAY_MS = 24 * 60 * 60 * 1000;

export function ageInDays(from: string, now: Date): number {
  return Math.floor((now.getTime() - new Date(from).getTime()) / DAY_MS);
}
