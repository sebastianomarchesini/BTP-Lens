# Changelog

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
