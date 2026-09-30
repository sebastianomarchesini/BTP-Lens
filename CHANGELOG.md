# Changelog

## Unreleased (v0.1 in development)

### Added

- **`btp-lens scan`:** a read-only scan of one CF org, or one space, that writes a snapshot and reports.
- **`btp-lens report --from`:** offline re-analysis of a snapshot.
- **`btp-lens version`**, and exit codes 0, 1 and 2 with `--fail-on`.
- **HTTP layer:** an egress allow-list with per-host methods and paths; a GET-only CF client with same-origin pagination; retry with backoff; `Retry-After` and `X-RateLimit-*` handling; and a concurrency limit.
- **Credentials:** the cf CLI session (refreshed in memory), `BTP_LENS_ACCESS_TOKEN`, or client credentials.
- **Collectors:** orgs, spaces, apps and current droplets. A 403 skips the check without failing the scan.
- **Rule `APP_NO_RECENT_DEPLOY`.**
- **Reports:** JSON, CSV (with formula-injection guard), SARIF 2.1.0, and a single-file offline HTML report. The HTML report uses React and UI5 Web Components for React with the Horizon light and dark themes. It has Overview, Apps and Findings screens and embeds the third-party licenses.
- **Documentation:** verified data sources, rules, permissions, privacy and security policy.
