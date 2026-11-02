import type { Analyzer } from '../types.js';
import { capMockedAuthInProd } from './capMockedAuthInProd.js';
import { capMockedUserPassword } from './capMockedUserPassword.js';
import { capAuditlogMissing } from './capAuditlogMissing.js';
import { capAuditlogNotBound } from './capAuditlogNotBound.js';
import { capPersonalDataUnannotated } from './capPersonalDataUnannotated.js';
import { capServiceNoRestriction } from './capServiceNoRestriction.js';
import { capRoleNotInXsuaa } from './capRoleNotInXsuaa.js';
import { xsuaaScopeUnused } from './xsuaaScopeUnused.js';
import { approuterRouteNoAuth } from './approuterRouteNoAuth.js';
import { approuterCsrfDisabled } from './approuterCsrfDisabled.js';
import { deployArtifactInRepo } from './deployArtifactInRepo.js';
import { seedDataSensitive } from './seedDataSensitive.js';
import { ui5BootstrapExternal } from './ui5BootstrapExternal.js';

/** Rules for local projects (`btp-lens project`), in report order (docs/rules.md). */
export const PROJECT_ANALYZERS: readonly Analyzer[] = [
  capMockedAuthInProd,
  capMockedUserPassword,
  capAuditlogMissing,
  capAuditlogNotBound,
  capPersonalDataUnannotated,
  capServiceNoRestriction,
  capRoleNotInXsuaa,
  xsuaaScopeUnused,
  approuterRouteNoAuth,
  approuterCsrfDisabled,
  deployArtifactInRepo,
  seedDataSensitive,
  ui5BootstrapExternal,
];
