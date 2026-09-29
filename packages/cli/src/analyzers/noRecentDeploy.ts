import type { Finding } from '../model/finding.js';
import type { Severity } from '../model/severity.js';
import { type Analyzer, ageInDays, ruleHelpUri } from './types.js';

export const RULE_ID = 'APP_NO_RECENT_DEPLOY';

/** Days after which a droplet counts as stale, and when it becomes medium. */
export const STALE_AFTER_DAYS = 365;
export const MEDIUM_AFTER_DAYS = 730;

function severityFor(ageDays: number): Severity {
  return ageDays > MEDIUM_AFTER_DAYS ? 'medium' : 'low';
}

/**
 * APP_NO_RECENT_DEPLOY: the current droplet is older than 12 months, so the
 * app still runs with the dependencies and buildpack it was staged with back
 * then. See docs/rules.md.
 */
export const noRecentDeploy: Analyzer = {
  rule: {
    id: RULE_ID,
    title: 'No deploy in the last 12 months',
    description:
      'The current droplet was staged more than 12 months ago. The app runs with the libraries, ' +
      'buildpack and runtime from that time, so fixes released since then are missing.',
    roles: ['SpaceAuditor'],
    helpUri: ruleHelpUri(RULE_ID),
  },
  requires: ['collect.apps', 'collect.droplets'],
  analyze({ now, raw, appRef }) {
    const findings: Finding[] = [];
    for (const droplet of raw.droplets) {
      const app = appRef(droplet.appGuid);
      if (app === undefined) continue;
      const ageDays = ageInDays(droplet.createdAt, now);
      if (ageDays <= STALE_AFTER_DAYS) continue;
      findings.push({
        id: RULE_ID,
        severity: severityFor(ageDays),
        title: `Last deployed ${Math.floor(ageDays / 30)} months ago`,
        app,
        evidence: {
          lastDeployAt: droplet.createdAt,
          ageDays,
          thresholdDays: STALE_AFTER_DAYS,
        },
        remediation:
          'Update the app dependencies and redeploy (`cf push`), or restage (`cf restage`) to pick up ' +
          'the current buildpack and runtime patches. If the app is no longer needed, delete it.',
        references: [
          'https://docs.cloudfoundry.org/devguide/deploy-apps/start-restart-restage.html',
        ],
      });
    }
    return findings;
  },
};
