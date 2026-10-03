/**
 * Convenience list for the wizard. The pasted "API Endpoint" from the BTP
 * cockpit always wins; UAA and log cache are still discovered from GET /
 * (docs/data-sources.md §1.1). 🟡 The host pattern
 * `api.cf.<region>.hana.ondemand.com` is well known but help.sap.com was not
 * reachable from the build environment to re-verify every region, so the
 * wizard checks the endpoint with GET / before going on.
 */
export interface Region {
  id: string;
  label: string;
  api: string;
}

export const REGIONS_VERIFIED_ON = '2026-09-30';

export const REGIONS_HELP_URL =
  'https://help.sap.com/docs/btp/sap-business-technology-platform/regions-and-api-endpoints-available-for-cloud-foundry-environment';

const region = (id: string, label: string): Region => ({
  id,
  label,
  api: `https://api.cf.${id}.hana.ondemand.com`,
});

export const REGIONS: readonly Region[] = [
  region('eu10', 'Europe (Frankfurt), AWS'),
  region('eu20', 'Europe (Netherlands), Azure'),
  region('us10', 'US East (Virginia), AWS'),
  region('us20', 'US West (Washington), Azure'),
  region('us21', 'US East (Virginia), Azure'),
  region('ap10', 'Australia (Sydney), AWS'),
  region('ap11', 'Singapore, AWS'),
  region('ap12', 'South Korea (Seoul), AWS'),
  region('ap20', 'Australia (Sydney), Azure'),
  region('ap21', 'Singapore, Azure'),
  region('jp10', 'Japan (Tokyo), AWS'),
  region('jp20', 'Japan (Tokyo), Azure'),
  region('br10', 'Brazil (São Paulo), AWS'),
  region('ca10', 'Canada (Montreal), AWS'),
  region('us10-001', 'Trial account (US East), AWS'),
];
