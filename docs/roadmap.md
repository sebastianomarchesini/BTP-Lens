# Roadmap

Public and revised at every minor release. Ordered, not dated: dates depend on how many people help. Everything here is and stays Apache-2.0; there is no paid tier.

Propose a change by opening an issue. Rules go through the "Rule proposal" template.

## v0.1

Released as 0.1.0 on 2026-10-10:

- [x] GET-only Cloud Foundry client with an egress allow-list and tests
- [x] App inventory, current droplets, `APP_NO_RECENT_DEPLOY`
- [x] JSON, CSV, SARIF and single-file offline HTML report (React + UI5 Web Components, Horizon light and dark, phone width)
- [x] Guided mode (`btp-lens` with no arguments), `btp-lens doctor`, "Start here" panel
- [x] Security review, disclosure policy, CSP-protected report, CI with gitleaks, CodeQL and Scorecard

Moved to the 0.1.x and 0.2 releases:

- [ ] Rules: `RUNTIME_NODE_EOL`, `RUNTIME_JAVA_EOL` (endoflife.date), `BUILDPACK_OUTDATED`, `STACK_DEPRECATED`, `APP_IDLE`, `UI5_OUT_OF_MAINTENANCE`, `SAP_PKG_OUTDATED`, `DEP_KNOWN_CVE` (OSV.dev), `ENV_SECRET_PLAINTEXT` (`--deep`)
- [ ] `btp-lens sbom` from `package-lock.json`, `pom.xml`, `mta.yaml` and `.mtar`
- [ ] `report --redact` so people can share screenshots
- [ ] Route probe for the UI5 version with the SSRF guards from the security review
- [ ] Three usability sessions with non-developers (0.1.0 shipped without them, for developers and platform teams; due before 0.1.1)
- [x] npm publish with provenance; GitHub release with changelog (tag-triggered `release.yml`)

Done since 0.1.0 (unreleased, see the [changelog](../CHANGELOG.md)):

- [x] `btp-lens project --path <dir>`: a read-only scan of a local CAP or MTA project with thirteen rules derived from the OWASP Top 10 (2025) patterns of the SAP TechEd 2026 XP261 workshop, OWASP tags on every rule, a criticality matrix, `file:line` locations in the reports and SARIF
- [x] XSUAA scope analysis for the project scan (`CAP_ROLE_NOT_IN_XSUAA`, `XSUAA_SCOPE_UNUSED`); the Cloud Foundry side (bound xsuaa instances) stays in v0.2

## v0.1.1

Small items left open by the [pre-release audit](audits/2026-10-11-release-0.1.0-audit.md), all low severity; each is a self-contained change with a test:

- Findings page: virtualize the list (it freezes for seconds above about 1500 findings)
- Report accessibility: live region for filter result counts, forced-colors styling of the selected severity filter, a text alternative for the severity chart, distinct card landmark names, a print stylesheet
- Proxy and Windows: Windows syntax for `HTTPS_PROXY`, `NODE_USE_ENV_PROXY` and `NODE_EXTRA_CA_CERTS` in README and the hints; say that the certificate file must be PEM; a plain message instead of Node's stack trace when the proxy URL is malformed; read `HOMEDRIVE`/`HOMEPATH` like the cf CLI when looking for its config
- Analyzer: an invalid droplet timestamp must not produce "NaN months ago" or an unloadable snapshot; note on future-dated droplets
- CLI: retry budget and hints for 407 and TLS failures during a scan; `--api` with a trailing path; guided-mode messages that mention `--api`; verify an existing cf CLI session with one API call before accepting it; swallow input typed while the wizard is busy; `report --from` on a non-regular file; a hint on 403 at the bootstrap org lookup; clearer messages for an empty `--out` and non-snapshot JSON
- Getting-started guide: the report folder is relative to the terminal's current directory

## v0.2

- Single executables for Windows and macOS (Node single-executable application), signed once funding allows
- GitHub Action wrapper (`action.yml`) with SARIF upload to code scanning
- Opt-in user usage from the SAP Audit Log service, hashed and aggregated; log-cache request metrics
- XSUAA scope analysis of the bound instances in a Cloud Foundry scan (the project scan already checks the security descriptor)
- `--accept-risks <file>`: a committed list of accepted findings (rule id and subject, with a reason and an expiry) that the project scan and `--fail-on` leave out but still list as accepted
- `report --compare <older snapshot>`: new, fixed and unchanged findings between two snapshots
- App detail and Scan info screens in the report; print stylesheet; glossary
- `BTP_LENS_CLIENT_SECRET_FILE` for CI secret managers

## v0.3

- Server mode: `btp-lens serve` locally, or the same UI on BTP behind an approuter with XSUAA and a small CAP service for snapshots
- Kyma support

## Later, if the community wants it

- Opt-in, anonymous aggregate statistics for a yearly public "State of BTP CF landscapes" report
- Trend view across snapshots
- Rule packs contributed and maintained by the community (for example per industry or per company policy)

## Good first issues

Each of these is scoped to one file, one test and one doc line, and a maintainer will pair on it if asked. They are turned into labelled issues in Phase 0 of the campaign.

1. ~~Print a one-line "reports contain internal details, do not commit them" warning after `scan` (SEC-22).~~ Done 2026-10-03.
2. Add a fixture-linter test that fails on e-mail addresses, JWTs, real BTP hostnames and IP addresses in `packages/cli/test/fixtures`.
3. ~~Add `npm pack --dry-run` to CI and assert that only `dist`, `README.md`, `LICENSE` and `NOTICE` ship.~~ Done in the release workflow 2026-10-10; still worth adding to `ci.yml`.
4. `btp-lens doctor`: add the role check (list spaces visible in the target org when a session exists).
5. Guided mode: remember the last API endpoint and org in `~/.config/btp-lens/last-scan.json` (never the token) and offer "run the same scan again"; add `btp-lens reset`.
6. Report: a glossary page (org, space, buildpack, droplet, stack, runtime, EOL, SBOM, CVE, one sentence each).
7. Report: print stylesheet (A4 and Letter, light theme when printing).
8. Hand-written error message and test for the PowerShell execution-policy failure (`npx.ps1` blocked).
9. Translate `docs/getting-started-no-terminal.md` into German, Italian or another language you speak.
10. Take the Windows and macOS screenshots for `docs/getting-started-no-terminal.md`.
