# README draft (to merge into `README.md` on the development branch)

Merge this over the current README once v0.1.0 exists. Placeholders in `<…>`. Keep the non-affiliation notice.

---

<p align="center"><img src="docs/assets/logo.svg" width="96" alt="BTP Lens logo"></p>

# BTP Lens

**The free, read-only health check for your SAP BTP Cloud Foundry landscape.** One command, five minutes, nothing leaves your machine.

[![npm](https://img.shields.io/npm/v/btp-lens)](https://www.npmjs.com/package/btp-lens)
[![CI](https://github.com/sebastianomarchesini/BTP-Lens/actions/workflows/ci.yml/badge.svg)](https://github.com/sebastianomarchesini/BTP-Lens/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/sebastianomarchesini/BTP-Lens/badge)](https://scorecard.dev/viewer/?uri=github.com/sebastianomarchesini/BTP-Lens)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

<p align="center"><img src="docs/assets/report-overview.png" width="720" alt="Overview page of the HTML report"></p>

## Try it in five minutes

You need [Node.js](https://nodejs.org) 20 or newer and a BTP login with the **Space Auditor** role (read-only). No cf CLI needed.

```
npx btp-lens
```

It asks where your landscape is, opens your browser to sign in, lets you pick the org, and opens the report. Never used a terminal? Follow the [no-terminal guide](docs/getting-started-no-terminal.md).

Developers and CI:

```
btp-lens scan --api https://api.cf.eu10.hana.ondemand.com --org my-org --out ./reports
btp-lens report --from ./reports/snapshot.json --format html,json,csv,sarif
```

[See a sample report](https://sebastianomarchesini.github.io/BTP-Lens/sample-report.html) generated from test fixtures.

## What it checks

| Rule | Finds |
|---|---|
| `RUNTIME_NODE_EOL`, `RUNTIME_JAVA_EOL` | Runtimes past or within 90 days of end of life |
| `BUILDPACK_OUTDATED` | Apps built with a buildpack older than the platform's current one |
| `STACK_DEPRECATED` | Apps on a deprecated stack such as cflinuxfs3 |
| `APP_IDLE` | Stopped for 90+ days, or running without activity for 180+ days |
| `APP_NO_RECENT_DEPLOY` | No deployment in 12 months |
| `UI5_OUT_OF_MAINTENANCE` | SAPUI5 versions out of maintenance |
| `SAP_PKG_OUTDATED` | `@sap/cds`, `@sap/approuter`, `@sap/xssec`, `@sap/xsenv` majors behind |
| `DEP_KNOWN_CVE` | Dependencies with a known vulnerability (OSV.dev) |
| `ENV_SECRET_PLAINTEXT` | `--deep` only: environment variable *names* that look like secrets |

Every finding comes with what it means, what to do, and a link. Details in [docs/rules.md](docs/rules.md).

## Read-only, by construction

- The HTTP client can only send **GET** requests to the Cloud Foundry API. [A unit test proves it](packages/cli/src/http/cfClient.test.ts).
- Works with the **Space Auditor** role. Checks that need more are off unless you pass `--deep`. See [permissions](docs/permissions.md), including text you can send to your administrator.
- The only hosts it talks to are your CF API and UAA, `api.osv.dev`, `endoflife.date` and the SAPUI5 version feed. [The allow-list is one file](packages/cli/src/net/allowlist.ts). Anything else is refused before the request is made.
- **No telemetry.** No user names or e-mails in reports. Secret values are never read or printed.
- Security review, threat model and disclosure policy: [docs/security-review.md](docs/security-review.md), [SECURITY.md](SECURITY.md).

## Permissions

| Check | Role needed | Default |
|---|---|---|
| Inventory, runtime, buildpacks, stacks, routes, idle apps, UI5, CVEs | Space Auditor | on |
| Environment variable names | Space Developer | `--deep` |

## Support the project

BTP Lens is free and will stay free. If it saved you an afternoon, consider [sponsoring](https://github.com/sponsors/sebastianomarchesini). Current goal: a code-signing certificate so administrators can run the downloadable executable without warnings. Sponsorship never influences what the tool reports.

## Not affiliated with SAP

BTP Lens is an independent open-source project. It is **not affiliated with, endorsed by or sponsored by SAP SE** or its affiliates. "SAP", "SAP BTP", "SAPUI5" and "Fiori" are trademarks of SAP SE, used here only to describe compatibility.

## License

[Apache-2.0](LICENSE)
