# Changelog

## Unreleased

### Added

- **`btp-lens project --path <dir>`:** a second scan target, a local CAP or MTA project directory, read from the file system only (no network, no child process, no `git`). It writes the same snapshot and reports as `scan`, `report --from` works on its snapshots, and `--fail-on` applies. The collector opens an allow-list of files (`package.json`, `.cdsrc.json`, `.cdsrc.yaml`, `mta.yaml`, `xs-security.json`, `xs-app.json`, `*.cds`, seed `*.csv`, `*.html`; `*.mtar` is only stat'ed) and never opens `.cdsrc-private.json`, `.cdsrc.js`, `default-env.json`, `.env*`, `*.mtaext`, keys, `*.http` or `*.md`; it keeps identifiers, counts and booleans, never file contents, CSV values, mocked user names, passwords or absolute paths ([docs/data-sources.md §8](docs/data-sources.md#8-local-project-files-btp-lens-project), [docs/privacy.md](docs/privacy.md#project-scans)).
- **Thirteen project rules**, derived from the OWASP Top 10 (2025) patterns of the public SAP TechEd 2026 workshop XP261: `CAP_MOCKED_AUTH_IN_PROD`, `CAP_MOCKED_USER_PASSWORD`, `CAP_AUDITLOG_MISSING`, `CAP_AUDITLOG_NOT_BOUND`, `CAP_PERSONAL_DATA_UNANNOTATED`, `CAP_SERVICE_NO_RESTRICTION`, `CAP_ROLE_NOT_IN_XSUAA`, `XSUAA_SCOPE_UNUSED`, `APPROUTER_ROUTE_NO_AUTH`, `APPROUTER_CSRF_DISABLED`, `DEPLOY_ARTIFACT_IN_REPO`, `SEED_DATA_SENSITIVE`, `UI5_BOOTSTRAP_EXTERNAL`. Each is documented in [docs/rules.md](docs/rules.md#project-rules) with its data, trigger, severity, evidence, remediation, verified references and limits.
- **OWASP Top 10 (2025) tags** on every rule (`owasp` in the rule metadata, `owasp/<id>` tags in SARIF, shown per rule in the HTML report), and a **criticality matrix** (impact × ease of attack → severity, `packages/cli/src/model/criticality.ts`) that the new rules use; findings record the two inputs as `impact` and `easeOfAttack` in their evidence.
- **Findings with a file location:** project findings carry `location: { file, line? }`; SARIF emits it as a `physicalLocation` with `uriBaseId: PROJECTROOT` (and a region when the line is known), the HTML report shows `file:line` under the finding, and the findings CSV gains `file` and `line` columns.
- **HTML report for project scans:** "Projects scanned", "Services open to all users" and "Personal data without annotations" key figures, a Projects tab instead of Apps, the OWASP category in each rule panel, and a "Start here" summary for the project.
- `npm run sample` also renders the project sample report (`reports/sample-project/`), and a Playwright check opens it from disk with networking disabled.
- `docs/due-diligence.md`: answers to the questions that managers and security, legal and procurement teams ask before a first run, each pointing to the code, test or document behind it.

### Changed

- **Snapshot (schema version unchanged, older snapshots still load):** `scope.projects`, `raw.projects`, `kind` (`app` or `project`) on inventory items, `state`, `createdAt` and `updatedAt` nullable for projects, `owasp` on rule metadata, `location` on findings, and `summary.projects` next to `summary.apps` in the report data. A test loads the 0.1.0 sample snapshot and checks that it re-analyses to the same findings.
- **CSV:** the findings file ends with three new trailing columns `owasp`, `file`, `line`, and the apps file with `kind`; existing columns keep their order.
- **SARIF:** rule tags gain `owasp/<id>`; fingerprints of Cloud Foundry findings are unchanged, and project findings add the file and subject to theirs so that two findings of one rule on one project stay distinct.
- The Cloud Foundry client is typed against `ReadOnlyHttp`, a view of the HTTP layer with a single `get` method whose request has no method and no body field, so its code cannot ask for anything but `GET`. A type-level test fails CI if the client is ever given more. The allow-list still refuses every other method for the CF API host, as before.
- The CLI depends on `yaml` (ISC) in addition to `commander` and `zod`, to read `mta.yaml` and `.cdsrc.yaml`.

## 0.1.0 (2026-10-10)

First public release. It covers guided mode, the app inventory, the `APP_NO_RECENT_DEPLOY` rule and every report format. The other rules in [docs/rules.md](docs/rules.md) (runtime and stack end of life, buildpack age, idle apps, SAPUI5 maintenance, `@sap/*` packages, known CVEs and plain-text secrets) and the `sbom` command arrive in the next releases.

### Fixed (pre-release audit, 2026-10-11)

- **HTML report:** grouping the Apps table by org or space no longer blanks the whole report; a page that fails now shows a message and the other sections keep working. The theme menu (Light, Dark, Same as system) is now visible and usable; it rendered with no size before. A scan limited with `--space` now says so in the headline, the title bar and the summary.
- **Guided mode:** org names and error texts from the CF API now pass through the same escape-sequence and token filter as the rest of the CLI. Ctrl+C now stops the wizard while it is connecting, signing in or scanning, as the banner promises. The login URL from the CF root is validated as plain https before it is shown or opened. "The report was opened in your browser" is only printed when the opener succeeded.
- **Windows:** files and URLs are opened through PowerShell with a literal argument instead of `cmd /c start`, so `&`, `%` and `|` in a path or URL cannot run anything.
- **Connection errors:** the real cause behind Node's `fetch failed` (DNS, refused connection, TLS interception, proxy 407) is kept, so `doctor` and guided mode now give the right advice; TLS interception was previously reported as a proxy problem. The proxy advice (`NODE_USE_ENV_PROXY=1`) is only given on Node.js 22.21 or 24 and newer, where it exists; older versions are told to upgrade.
- **Scan:** a user who can see the org but none of its spaces now gets a clear message and exit code 2 instead of an empty report with every check "ran" (the CF list endpoints filter by visibility instead of answering 403). `--org` and `--space` are matched exactly; a comma in a name no longer widens the filter. A `401` on the unauthenticated root call is no longer reported as a rejected token.
- **Output files:** reports are never written through a symbolic link, an existing report file is tightened to `0600`, and file-system errors are explained in plain words.
- **Terminal filter:** `Basic` credentials and the cf CLI config field names (`AccessToken`, `RefreshToken`, `UAAOAuthClientSecret`) are redacted too.
- `--no-probe-routes` is hidden from `--help` and the snapshot records `probeRoutes: false`, because no route probe exists yet. `--fail-on` no longer prints its default twice. `btp-lens guided` in a script (no terminal) prints the usage hint and exits 2 instead of writing escape codes to the pipe.
- **CSV:** the files start with a UTF-8 byte-order mark, so Excel opens non-ASCII org, space and app names correctly, and control characters are dropped from cells.
- **Report accessibility:** the document title names the section (`Apps · BTP Lens report`), every section has a page heading, and focus moves to the page on navigation so screen readers announce it.
- **Licenses:** the report and `THIRD_PARTY_LICENSES.md` now carry the Unicode CLDR notice (locale data) and the Preact MIT notice (vendored by UI5 Web Components).
- **Docs:** README, privacy, FAQ, permissions, data sources, security policy and the landing page describe what 0.1.0 does rather than what is planned; the CLA text now exists (`docs/CLA.md`); links to GitHub Discussions were replaced by issues.
- **Release workflow:** runs the same gates as CI (coverage, sample report, offline Playwright check); CI also runs on version tags; the README shipped to npm has its links pinned to the release tag.
- `btp-lens doctor` no longer tells you to run `btp-lens doctor` when the API check fails. A `401`, `403` or `407` from the API root is now explained as a proxy or firewall block, with the fix.

### Added

- **Logo and app icon:** a cloud-and-magnifier mark. It is the report's ShellBar logo and favicon (inlined, so the report stays one offline file), and the README, landing page and social card use it. Light and dark variants of the horizontal logo live in `docs/assets/`.
- **Guided mode:** `btp-lens` with no arguments asks four questions (region or API endpoint, sign-in, org, confirm) and opens the report. Sign-in works like `cf login --sso` with a one-time code from the company login, or with username and password; the session is held in memory only. Reports go to `./btp-lens-reports/<date-time>/`.
- **`btp-lens doctor`:** checks Node.js, API reachability, TLS trust, the cf CLI login and the output folder, with a one-sentence fix per failure.
- **"Start here" panel** on the report's Overview: three or four plain-language sentences computed from the scan.
- **Hardening:** a Content Security Policy in the HTML report (`connect-src 'none'`, hashed scripts); terminal output stripped of escape sequences and token shapes; report folders `0700` and files `0600`; a 256 MB cap on `report --from`; the allow-list refuses the CF endpoints that return credentials even for `GET`; CI actions pinned by commit SHA and installed with `--ignore-scripts`.
- `scan` and `report` end with a one-line reminder that reports describe your landscape and should not be committed.
- **Docs for non-developers:** `docs/getting-started-no-terminal.md`, `docs/faq.md`, and text to send to an administrator in `docs/permissions.md`.
- **`btp-lens scan`:** a read-only scan of one CF org, or one space, that writes a snapshot and reports.
- **`btp-lens report --from`:** offline re-analysis of a snapshot.
- **`btp-lens version`**, and exit codes 0, 1 and 2 with `--fail-on`.
- **HTTP layer:** an egress allow-list with per-host methods and paths; a GET-only CF client with same-origin pagination; retry with backoff; `Retry-After` and `X-RateLimit-*` handling; and a concurrency limit.
- **Credentials:** the cf CLI session (refreshed in memory), `BTP_LENS_ACCESS_TOKEN`, or client credentials.
- **Collectors:** orgs, spaces, apps and current droplets. A 403 skips the check without failing the scan.
- **Rule `APP_NO_RECENT_DEPLOY`.**
- **Reports:** JSON, CSV (with formula-injection guard), SARIF 2.1.0, and a single-file offline HTML report. The HTML report uses React and UI5 Web Components for React with the Horizon light and dark themes. It has Overview, Apps and Findings screens and embeds the third-party licenses.
- **Documentation:** verified data sources, rules, permissions, privacy and security policy.
