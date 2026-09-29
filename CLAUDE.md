# Build prompt: BTP Lens v0.1

## Role and goal

You are a senior TypeScript engineer and SAP BTP specialist. Build **BTP Lens** (working name), a free, open-source, **read-only** CLI that scans an SAP BTP Cloud Foundry landscape. It reports app inventory, usage, runtime health, outdated or vulnerable libraries, and security posture.

The first milestone is **v0.1**: a working CLI that a stranger can install with `npx`, point at one CF org, and get a useful HTML and JSON report within 5 minutes.

> Always read `docs/data-sources.md` before touching a collector. It records verified endpoints, roles and known limits.

## Non-negotiable constraints

1. **Read-only.** Never call a CF API method other than GET, except the OAuth token endpoint. Enforce this in the HTTP client itself and cover it with a unit test.
2. **Least privilege.** Every check declares the CF role it needs (`OrgAuditor`, `SpaceAuditor`, `SpaceDeveloper`). Checks that need `SpaceDeveloper` are off by default and enabled with `--deep`. If a call returns 403, record the check as `skipped: insufficient role` and continue. Never fail the whole scan.
3. **No data leaves the machine.** The only outbound calls allowed are to the customer's CF API, UAA and log cache, to `api.osv.dev`, to `endoflife.date`, and to the SAPUI5 version overview. Keep this allow-list in one config file. Add no telemetry.
4. **Privacy.** Never write user names, emails or IDs to reports. Anything user-level must be hashed with a per-scan random salt and aggregated. User usage ships in v0.2, not v0.1.
5. **Secrets.** Never print tokens, env var values or service keys. When a secret-looking env var is found, report the variable **name** only.
6. **No SAP branding.** Do not use "SAP" in the package name, CLI name or logo. The README must state that the project is not affiliated with SAP.
7. **Verify, don't assume.** Before implementing a collector, check the current Cloud Foundry v3 API documentation for the exact endpoint, fields and role permissions. Write down what you confirmed in `docs/data-sources.md`. If something can't be confirmed, implement it defensively and flag it in that file.

## Tech stack

- TypeScript (strict), Node.js active LTS, ESM
- CLI: `commander`; config and schema validation: `zod`
- HTTP: native `fetch` with retry and backoff, a concurrency limit (default 5), and respect for rate-limit headers
- Tests: `vitest`, with recorded API fixtures (no live calls in CI)
- Lint and format: `eslint` and `prettier`
- SBOM: CycloneDX JSON; CVEs: OSV.dev `/v1/querybatch`
- Reports: JSON, CSV, SARIF 2.1.0, and an HTML report that is the React UI built as one self-contained file (see UI below)
- Packaging: npm workspaces monorepo; the CLI package has a `bin` entry, so `npx btp-lens scan` works

## UI: React with the SAP Fiori (UI5) look

The UI is **React + TypeScript** using **UI5 Web Components for React** (`@ui5/webcomponents-react`, SAP's official open-source React wrapper for UI5 Web Components). Use the current major version, and check its docs before starting. This gives the SAP Fiori Horizon look in a normal React app.

- Build: Vite. Routing: `react-router`. State: React Query for data, with no global store unless it's needed.
- Theme: `sap_horizon`, following the OS setting for `sap_horizon_dark`, with a manual toggle. Use theming parameters and CSS variables only, never hard-coded colors.
- Charts: `@ui5/webcomponents-react-charts` (or the charts package the current docs recommend).
- Follow the SAP Fiori design guidelines: floorplans, severity semantics (Negative, Critical, Positive, Information), empty states, and responsive behavior down to phone width.
- Screens:
  1. **Overview**: `ShellBar` plus a KPI row of cards (apps scanned, critical and high findings, idle apps, EOL runtimes), a findings-by-severity chart, and top risky apps.
  2. **Apps**: `AnalyticalTable` with filtering, sorting and grouping by org or space; each severity shown as an `ObjectStatus`; row click goes to app detail.
  3. **App detail**: `ObjectPage` with header facts (runtime, buildpack, stack, last deploy) and sections for findings, SBOM dependencies and usage.
  4. **Findings**: a list grouped by rule, with remediation text and reference links, filterable by severity.
  5. **Scan info**: which checks ran or were skipped and why (missing role), tool version, scan time.
- One codebase, two build targets:
  - **Report mode**: `vite-plugin-singlefile` bundles the UI into a single offline HTML file with the snapshot JSON embedded. This is the `btp-lens report --format html` output, and it must open from disk with no network access.
  - **Server mode** (v0.3): the same UI served by `btp-lens serve` locally, or deployed to BTP behind an approuter with XSUAA, reading snapshots from a small CAP service.
- Branding: use the Fiori look but no SAP logo or SAP name in the ShellBar. The product logo is our own.
- Licensing check: confirm the licenses of `@ui5/webcomponents-react` and its bundled fonts and icons allow redistribution in a single-file report. Record the result in `NOTICE`.
- Accessibility: keyboard navigation and screen-reader labels, which UI5 components mostly provide. Don't break them with custom wrappers.

## Repository layout

```
btp-lens/
  packages/ui/              # React + UI5 Web Components for React (Vite)
    src/pages/  Overview.tsx  Apps.tsx  AppDetail.tsx  Findings.tsx  ScanInfo.tsx
    src/data/               # loads embedded snapshot (report mode) or API (server mode)
    vite.config.ts          # two builds: singlefile report, normal SPA
  packages/cli/src/
    cli.ts                  # commander entry: scan, sbom, report, version
    config.ts               # zod schema, env and flag parsing
    http/cfClient.ts        # GET-only client, paging (v3 pagination.next), retry
    http/auth.ts            # token from cf CLI config, or client credentials
    collectors/             # one file per source, returns typed raw data
      apps.ts  processes.ts  droplets.ts  buildpacks.ts  stacks.ts
      routes.ts  serviceBindings.ts  usageEvents.ts  auditEvents.ts
    analyzers/              # pure functions: raw data -> Finding[]
      runtimeEol.ts  buildpackAge.ts  stackEol.ts  idleApps.ts
      ui5Maintenance.ts  sapPackages.ts  osvCves.ts  secretsInEnv.ts
    sbom/                   # CycloneDX from package-lock.json, pom.xml, mta.yaml
    model/                  # Finding, Severity, Snapshot types (zod + TS)
    reporters/              # json.ts csv.ts sarif.ts; html.ts injects the snapshot into the packages/ui singlefile build
    snapshot.ts             # writes one snapshot JSON per scan
  test/  fixtures/          # recorded API responses, anonymized
  docs/  data-sources.md  rules.md  privacy.md  permissions.md
  .github/workflows/ci.yml  # lint, test, build
  action.yml                # GitHub Action wrapper (v0.2)
  LICENSE (Apache-2.0)  NOTICE  CONTRIBUTING.md (CLA required)  SECURITY.md  README.md
```

## Core data model

```ts
type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

interface Finding {
  id: string;            // stable rule id, e.g. "RUNTIME_NODE_EOL"
  severity: Severity;
  title: string;
  app: { guid: string; name: string; space: string; org: string };
  evidence: Record<string, unknown>;  // the facts that triggered it
  remediation: string;   // concrete next step
  references: string[];  // URLs
}

interface Snapshot {
  tool: { name: string; version: string };
  scannedAt: string;     // ISO 8601
  scope: { apiEndpoint: string; orgs: string[] };
  checks: { id: string; status: 'ran' | 'skipped'; reason?: string }[];
  apps: AppInventoryItem[];
  findings: Finding[];
}
```

Analyzers must be pure functions of the snapshot's raw data, so they can be unit tested with fixtures and rerun offline with `btp-lens report --from snapshot.json`.

## v0.1 rule catalog

Document every rule in `docs/rules.md` with its id, severity logic, evidence and remediation text.

| Rule id | Finding |
| --- | --- |
| `RUNTIME_NODE_EOL` / `RUNTIME_JAVA_EOL` | Runtime version past or within 90 days of end of life (endoflife.date) |
| `BUILDPACK_OUTDATED` | Droplet built with a buildpack version older than the platform's current one |
| `STACK_DEPRECATED` | App on a deprecated stack (e.g. cflinuxfs3) |
| `APP_IDLE` | Stopped for more than 90 days, or running with no restage or usage events in 180 days |
| `APP_NO_RECENT_DEPLOY` | Last droplet older than 12 months (dependency risk) |
| `UI5_OUT_OF_MAINTENANCE` | SAPUI5 version served by the app is out of maintenance (read `resources/sap-ui-version.json` from the app route, GET only, with a timeout) |
| `SAP_PKG_OUTDATED` | `@sap/cds`, `@sap/approuter`, `@sap/xssec`, `@sap/xsenv` major versions behind current (from SBOM) |
| `DEP_KNOWN_CVE` | Any dependency in the SBOM with an OSV advisory; severity from CVSS |
| `ENV_SECRET_PLAINTEXT` | `--deep` only: env var name matches a secret pattern and is not a service binding |

## Commands

```
btp-lens scan   --api <cf api url> --org <name> [--space <name>] [--deep] [--out ./reports]
btp-lens sbom   --path <project dir or .mtar> [--out sbom.json]
btp-lens report --from <snapshot.json> --format html,json,csv,sarif
btp-lens version
```

Exit codes: 0 means no findings at or above `--fail-on` (default: none); 1 means findings met the threshold; 2 means a tool error.

## Working method

1. Start by writing `docs/data-sources.md` from the official CF v3 and SAP BTP documentation: endpoints, fields, required roles, pagination and known BTP limits. Stop and show me this file before writing collectors.
2. Build in vertical slices. Each slice goes from collector to analyzer to report with tests. Order: apps inventory, runtime EOL, SBOM with OSV, idle apps, UI5, then the rest.
3. After each slice: run lint, tests and build, and show a sample report generated from fixtures.
4. Keep functions small and typed. No `any`. Handle every API error path.
5. The HTML report is the React UI in report mode (see UI above). Build the Overview, Apps and Findings screens in v0.1; App detail and Scan info can follow in v0.2. Test the UI with React Testing Library, and add one Playwright check that the single-file report opens from disk with networking disabled.
6. README: a 30-second pitch, a quickstart with `npx`, the permissions table, the privacy statement, a sample report screenshot, and a "not affiliated with SAP" notice.

## Definition of done for v0.1

- [ ] `npx btp-lens scan` works against a real trial BTP CF org using only Space Auditor
- [ ] All v0.1 rules implemented, documented and unit tested (target over 85% line coverage on analyzers)
- [ ] A GET-only client test proves no mutating calls are possible
- [ ] Reports in HTML, JSON, CSV and SARIF generated from one snapshot
- [ ] The HTML report is the React + UI5 Web Components UI as a single offline file, in Horizon light and dark themes, usable at phone width
- [ ] No secrets, tokens or personal data appear in any output (add a test that scans the output for them)
- [ ] CI green; package published to npm as 0.1.0; GitHub release with changelog

## After v0.1 (do not build yet)

- v0.2: opt-in user usage from the SAP Audit Log service (hashed and aggregated), log-cache request metrics, XSUAA scope analysis, GitHub Action
- v0.3: server mode for the same React UI (`btp-lens serve`, or deployed on BTP with approuter, XSUAA and a small CAP service for snapshots); Kyma support
- Later: opt-in anonymous aggregate statistics for a yearly public report
