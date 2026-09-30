# Changelog

## Unreleased (v0.1 in development)

### Added

- **Guided mode:** `btp-lens` with no arguments asks four questions (region or API endpoint, sign-in, org, confirm) and opens the report. Sign-in works like `cf login --sso` with a one-time code from the company login, or with username and password; the session is held in memory only. Reports go to `./btp-lens-reports/<date-time>/`.
- **`btp-lens doctor`:** checks Node.js, API reachability, TLS trust, the cf CLI login and the output folder, with a one-sentence fix per failure.
- **"Start here" panel** on the report's Overview: three or four plain-language sentences computed from the scan.
- **Hardening:** a Content Security Policy in the HTML report (`connect-src 'none'`, hashed scripts); terminal output stripped of escape sequences and token shapes; report folders `0700` and files `0600`; a 256 MB cap on `report --from`; the allow-list refuses the CF endpoints that return credentials even for `GET`; CI actions pinned by commit SHA and installed with `--ignore-scripts`.
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
