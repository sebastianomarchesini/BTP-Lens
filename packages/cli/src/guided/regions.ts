/**
 * Convenience list for the wizard. The pasted "API Endpoint" from the BTP
 * cockpit always wins; UAA and log cache are still discovered from GET /
 * (docs/data-sources.md §1.1). Verified against the source of the SAP help
 * page (github.com/SAP-docs/btp-cloud-platform, "Regions and API Endpoints
 * Available for the Cloud Foundry Environment"). The wizard still checks the
 * endpoint with GET / before going on.
 */
export interface Region {
  id: string;
  label: string;
  api: string;
}

export const REGIONS_VERIFIED_ON = '2026-10-10';

export const REGIONS_HELP_URL =
  'https://help.sap.com/docs/btp/sap-business-technology-platform/regions-and-api-endpoints-available-for-cloud-foundry-environment';

const DEFAULT_DOMAIN = 'hana.ondemand.com';
/** Regions operated in China use their own domain. */
const CHINA_DOMAIN = 'platform.sapcloud.cn';

const region = (id: string, label: string, domain = DEFAULT_DOMAIN): Region => ({
  id,
  label,
  api: `https://api.cf.${id}.${domain}`,
});

export const REGIONS: readonly Region[] = [
  // Amazon Web Services
  region('eu10', 'Europe (Frankfurt), AWS'),
  region('eu10-002', 'Europe (Frankfurt), AWS, extension landscape'),
  region('eu10-003', 'Europe (Frankfurt), AWS, extension landscape'),
  region('eu10-004', 'Europe (Frankfurt), AWS, extension landscape'),
  region('eu10-005', 'Europe (Frankfurt), AWS, extension landscape'),
  region('eu11', 'Europe (Frankfurt), AWS, EU Access'),
  region('eu13', 'Europe (Milan), AWS'),
  region('us10', 'US East (Virginia), AWS, also trial'),
  region('us10-001', 'US East (Virginia), AWS, extension landscape'),
  region('us10-002', 'US East (Virginia), AWS, extension landscape'),
  region('us11', 'US West (Oregon), AWS'),
  region('ap10', 'Australia (Sydney), AWS'),
  region('ap11', 'Singapore, AWS'),
  region('ap12', 'South Korea (Seoul), AWS'),
  region('jp10', 'Japan (Tokyo), AWS'),
  region('br10', 'Brazil (São Paulo), AWS'),
  region('ca10', 'Canada (Montreal), AWS'),
  // Microsoft Azure
  region('eu20', 'Europe (Netherlands), Azure'),
  region('eu20-001', 'Europe (Netherlands), Azure, extension landscape'),
  region('eu20-002', 'Europe (Netherlands), Azure, extension landscape'),
  region('eu22', 'Europe (Frankfurt), Azure'),
  region('ch20', 'Switzerland (Zurich), Azure'),
  region('uk20', 'UK South (London), Azure'),
  region('us20', 'US West (Washington), Azure'),
  region('us21', 'US East (Virginia), Azure'),
  region('ap20', 'Australia (Sydney), Azure'),
  region('ap21', 'Singapore, Azure, also trial'),
  region('jp20', 'Japan (Tokyo), Azure'),
  region('br20', 'Brazil (São Paulo), Azure'),
  region('ca20', 'Canada Central (Toronto), Azure'),
  region('cn20', 'China (North 3), Azure', CHINA_DOMAIN),
  // Google Cloud
  region('eu30', 'Europe (Frankfurt), Google Cloud'),
  region('us30', 'US Central (Iowa), Google Cloud'),
  region('in30', 'India (Mumbai), Google Cloud'),
  region('il30', 'Israel (Tel Aviv), Google Cloud'),
  region('jp30', 'Japan (Osaka), Google Cloud'),
  region('jp31', 'Japan (Tokyo), Google Cloud'),
  region('ap30', 'Australia (Sydney), Google Cloud'),
  region('br30', 'Brazil (São Paulo), Google Cloud'),
  region('sa30', 'KSA (Dammam), Google Cloud, regulated customers'),
  region('sa31', 'KSA (Dammam), Google Cloud, non-regulated customers'),
  // Alibaba Cloud
  region('cn40', 'China (Shanghai), Alibaba Cloud', CHINA_DOMAIN),
  // SAP Cloud Infrastructure
  region('eu01', 'Europe (Frankfurt), SAP Cloud Infrastructure, EU Access'),
  region('eu02', 'Europe (Rot), SAP Cloud Infrastructure, EU Access'),
  region('us01', 'US (Sterling), SAP Cloud Infrastructure'),
  region('us02', 'US West (Colorado), SAP Cloud Infrastructure'),
  region('ap01', 'Australia (Sydney), SAP Cloud Infrastructure'),
  region('jp01', 'Japan (Tokyo), SAP Cloud Infrastructure'),
  region('ae01', 'UAE (Dubai), SAP Cloud Infrastructure'),
];

/** "eu10", "eu10-004" or the technical key "cf-eu10-004". */
const REGION_ID = /^(?:cf-)?([a-z]{2}\d{2}(?:-\d{3})?)$/i;
/** "us10-001.hana.ondemand.com" or "cf.us10-001.hana.ondemand.com", without the "api." prefix. */
const REGION_DOMAIN =
  /^(?:cf\.)?([a-z]{2}\d{2}(?:-\d{3})?)\.(hana\.ondemand\.com|platform\.sapcloud\.cn)$/i;

/**
 * Turns what people actually paste into a CF API endpoint: a region id
 * ("eu10-004"), a technical key ("cf-eu10-004") or the region domain
 * ("us10-001.hana.ondemand.com") all become https://api.cf.<region>.<domain>.
 * Anything else is returned unchanged for the URL check to judge.
 */
export function toApiEndpoint(input: string): string {
  const value = input.trim().replace(/\/+$/, '');
  const id = REGION_ID.exec(value)?.[1]?.toLowerCase();
  if (id) {
    return REGIONS.find((r) => r.id === id)?.api ?? `https://api.cf.${id}.${DEFAULT_DOMAIN}`;
  }
  const host = value.replace(/^https:\/\//i, '');
  const match = REGION_DOMAIN.exec(host);
  if (match?.[1] && match[2]) {
    return `https://api.cf.${match[1].toLowerCase()}.${match[2].toLowerCase()}`;
  }
  return input;
}
