import { CfAuthError, CfForbiddenError, ConfigError } from './http/errors.js';
import type { CfRole, CheckResult, SkipReasonCode } from './model/check.js';

export interface CheckDefinition {
  id: string;
  title: string;
  /** Any one of these CF roles is enough. Empty: no CF role needed. */
  roles: CfRole[];
  /** Needs SpaceDeveloper-level access; runs only with --deep. */
  deep?: boolean;
}

/** Collectors. Rule checks are declared next to their analyzers. */
export const COLLECTOR_CHECKS = {
  apps: {
    id: 'collect.apps',
    title: 'App inventory (GET /v3/apps)',
    roles: ['SpaceAuditor'],
  },
  droplets: {
    id: 'collect.droplets',
    title: 'Current droplets (GET /v3/droplets?current=true)',
    roles: ['SpaceAuditor'],
  },
} as const satisfies Record<string, CheckDefinition>;

function roleText(roles: readonly CfRole[]): string {
  return roles.length === 0 ? 'no CF role' : roles.join(' or ');
}

/**
 * Runs checks so that one failing check never fails the scan: a 403 is
 * recorded as "insufficient role", other errors as "error". Only auth and
 * configuration errors abort, because nothing else could succeed after them.
 */
export class CheckRecorder {
  private readonly results = new Map<string, CheckResult>();

  constructor(
    private readonly options: { deep: boolean },
    private readonly log: (message: string) => void = () => {},
  ) {}

  async run<T>(check: CheckDefinition, task: () => Promise<T>): Promise<T | undefined> {
    if (check.deep && !this.options.deep) {
      this.skip(check, 'requires_deep', `requires --deep (${roleText(check.roles)})`);
      return undefined;
    }
    try {
      const value = await task();
      this.ran(check);
      return value;
    } catch (error) {
      if (error instanceof CfAuthError || error instanceof ConfigError) throw error;
      if (error instanceof CfForbiddenError) {
        this.skip(check, 'insufficient_role', `insufficient role: needs ${roleText(check.roles)}`);
      } else {
        const message = error instanceof Error ? error.message : String(error);
        this.skip(check, 'error', `error: ${message}`);
      }
      return undefined;
    }
  }

  ran(check: CheckDefinition): void {
    this.results.set(check.id, {
      id: check.id,
      title: check.title,
      roles: [...check.roles],
      status: 'ran',
    });
  }

  skip(check: CheckDefinition, reasonCode: SkipReasonCode, reason: string): void {
    this.log(`skipped ${check.id}: ${reason}`);
    this.results.set(check.id, {
      id: check.id,
      title: check.title,
      roles: [...check.roles],
      status: 'skipped',
      reason,
      reasonCode,
    });
  }

  list(): CheckResult[] {
    return [...this.results.values()];
  }
}
