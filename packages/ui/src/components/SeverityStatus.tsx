import type { Severity } from '@btp-lens/model';
import { ObjectStatus } from '@ui5/webcomponents-react';
import { SEVERITY_LABEL, SEVERITY_STATE } from '../data/severity';

/** A severity as a Fiori ObjectStatus: icon + text, never color alone. */
export function SeverityStatus({ severity }: { severity: Severity | null }) {
  if (severity === null) {
    return <ObjectStatus state="None">No findings</ObjectStatus>;
  }
  const { state, inverted } = SEVERITY_STATE[severity];
  return (
    <ObjectStatus state={state} inverted={inverted} showDefaultIcon={state !== 'None'}>
      {SEVERITY_LABEL[severity]}
    </ObjectStatus>
  );
}
