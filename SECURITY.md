# Security policy

BTP Lens is a read-only scanner that runs with a customer's Cloud Foundry credentials and produces reports about their landscape. We treat anything that could expose a token, send data to an unexpected host, or execute attacker-controlled content from a report as a security bug.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

1. Use GitHub's private reporting: [Report a vulnerability](https://github.com/sebastianomarchesini/BTP-Lens/security/advisories/new).
2. If that is not possible, e-mail the maintainer listed on the GitHub profile with the subject `BTP Lens security`.

Include the version (`btp-lens version`), the command you ran with any secrets removed, and what you observed. **Never paste tokens, `~/.cf/config.json`, service keys or environment variable values.** If a report accidentally contains a secret, we will delete it and ask you to rotate the credential.

## What to expect

- Acknowledgement within **72 hours**.
- A first assessment and a target fix date within **7 days**.
- Coordinated disclosure: we ask for up to **90 days** before public details, and we credit reporters in the release notes unless they prefer not to be named.
- Fixes ship as a patch release on npm and a GitHub Security Advisory.

## Scope

In scope:

- The `btp-lens` npm package and this repository's code and workflows.
- Any request to a host that is not on the documented allow-list (`docs/data-sources.md` §6), or any non-GET request to a Cloud Foundry API.
- Leakage of tokens, environment variable values, service credentials, user names or e-mails into terminal output, logs or reports.
- Script execution or formula execution from a generated HTML, CSV or SARIF report.
- Path traversal, zip-slip or unsafe parsing in the `sbom` command.

Out of scope:

- Vulnerabilities in SAP BTP, Cloud Foundry, OSV.dev, endoflife.date or npm themselves (please report those to the respective projects).
- Findings that require a compromised operator machine.
- Reports produced by automated scanners without a demonstrated impact.

## Safe harbour

Good-faith research that stays within the scope above, does not access data of third parties and does not degrade any service is welcome. We will not pursue legal action for such research.

## Supported versions

Only the latest minor release receives security fixes.

## Security design

The design goals and the review that produced them are public: see `docs/security-review.md`, `docs/privacy.md` and `docs/permissions.md`.
