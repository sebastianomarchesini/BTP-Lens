# Roadmap

Public and revised at every minor release. Ordered, not dated: dates depend on how many people help. Everything here is and stays Apache-2.0; there is no paid tier.

Propose a change by opening an issue. Rules go through the "Rule proposal" template.

## v0.1 (in progress)

Done on the development branches:

- [x] GET-only Cloud Foundry client with an egress allow-list and tests
- [x] App inventory, current droplets, `APP_NO_RECENT_DEPLOY`
- [x] JSON, CSV, SARIF and single-file offline HTML report (React + UI5 Web Components, Horizon light and dark, phone width)
- [x] Guided mode (`btp-lens` with no arguments), `btp-lens doctor`, "Start here" panel
- [x] Security review, disclosure policy, CSP-protected report, CI with gitleaks, CodeQL and Scorecard

Still to do before tagging 0.1.0:

- [ ] Rules: `RUNTIME_NODE_EOL`, `RUNTIME_JAVA_EOL` (endoflife.date), `BUILDPACK_OUTDATED`, `STACK_DEPRECATED`, `APP_IDLE`, `UI5_OUT_OF_MAINTENANCE`, `SAP_PKG_OUTDATED`, `DEP_KNOWN_CVE` (OSV.dev), `ENV_SECRET_PLAINTEXT` (`--deep`)
- [ ] `btp-lens sbom` from `package-lock.json`, `pom.xml`, `mta.yaml` and `.mtar`
- [ ] `report --redact` so people can share screenshots
- [ ] Route probe for the UI5 version with the SSRF guards from the security review
- [ ] Three usability sessions with non-developers
- [ ] npm publish with provenance; GitHub release with changelog

## v0.2

- Single executables for Windows and macOS (Node single-executable application), signed once funding allows
- GitHub Action wrapper (`action.yml`) with SARIF upload to code scanning
- Opt-in user usage from the SAP Audit Log service, hashed and aggregated; log-cache request metrics
- XSUAA scope analysis
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

1. Print a one-line "reports contain internal details, do not commit them" warning after `scan` (SEC-22).
2. Add a fixture-linter test that fails on e-mail addresses, JWTs, real BTP hostnames and IP addresses in `packages/cli/test/fixtures`.
3. Add `npm pack --dry-run` to CI and assert that only `dist`, `README.md`, `LICENSE` and `NOTICE` ship.
4. `btp-lens doctor`: add the role check (list spaces visible in the target org when a session exists).
5. Guided mode: remember the last API endpoint and org in `~/.config/btp-lens/last-scan.json` (never the token) and offer "run the same scan again"; add `btp-lens reset`.
6. Report: a glossary page (org, space, buildpack, droplet, stack, runtime, EOL, SBOM, CVE, one sentence each).
7. Report: print stylesheet (A4 and Letter, light theme when printing).
8. Hand-written error message and test for the PowerShell execution-policy failure (`npx.ps1` blocked).
9. Translate `docs/getting-started-no-terminal.md` into German, Italian or another language you speak.
10. Take the Windows and macOS screenshots for `docs/getting-started-no-terminal.md`.
