# Privacy

BTP Lens runs on your machine and writes files to your disk. This page lists what it reads, what it keeps, and where requests go.

## Principles

1. **Read-only.** The HTTP client allows only `GET` to the CF API. This is enforced per host by the egress allow-list in `packages/cli/src/net/allowlist.ts`, and unit tests prove it.
2. **No data leaves the machine.** The allow-list is the only way out, and redirects are never followed. There is no telemetry.
3. **No personal data** in any output.
4. **No secret values** in any output.

## Where requests go

| Host | Why | What is sent |
| --- | --- | --- |
| Your CF API (`--api`) | inventory | `GET` only, with your token |
| Your UAA or login server (from the CF root) | token refresh or client credentials | `POST /oauth/token` only |
| Your log cache | from v0.2 | `GET` only |
| `api.osv.dev` | known vulnerabilities | public package names and versions from your SBOM |
| `endoflife.date` | runtime end-of-life dates | product names such as `nodejs` |
| `ui5.sap.com` | UI5 maintenance status | a request for `/versionoverview.json` |
| `registry.npmjs.org` | current `@sap/*` versions | four fixed package names |
| Your app routes | the UI5 version served | one unauthenticated `GET /resources/sap-ui-version.json` per app, with no redirects; turn it off with `--no-probe-routes` |

Your CF token is sent to the CF API only. The allow-list refuses an `Authorization` header to any other host.

## What is kept

The snapshot and reports contain only allow-listed fields. The parsers drop everything else before it is stored.

- **Orgs and spaces:** GUID and name.
- **Apps:**
  - GUID, name, space, state, created and updated times, lifecycle type, and requested buildpacks.
  - Credentials in buildpack URLs are removed.
- **Current droplets:**
  - GUID, app, state, timestamps, stack, and the detected buildpack names and versions.
  - Detect output is cut to 200 characters.
  - For Docker droplets, the image reference with credentials removed.
- **Findings:** rule id, severity, app reference, evidence (facts such as dates and versions), remediation and links.

## What is never kept

- **User identities:**
  - User names, emails and IDs are never stored.
  - Audit-event `actor` fields are dropped when the events are read.
  - App annotations and labels (which often hold owner emails) are not collected.
- **Secrets:**
  - Tokens, refresh tokens and client secrets.
  - Environment variable **values**; with `--deep`, only variable names are kept.
  - Service credentials and service keys.
  - Droplet `execution_metadata` and start commands (which can contain passwords).
- **Logs** are not read in v0.1.

A test scans the snapshot and every report format for planted secrets, emails, JWTs and credential URLs (`packages/cli/test/e2e/leak.test.ts`).

## Side effects in your landscape

`GET` requests do not change anything. One read is audited by Cloud Foundry: with `--deep`, reading an app's environment variables creates an `audit.app.environment_variables.show` event for that app. Tell your security team before you run `--deep` scans.

## User-level usage (v0.2)

Usage per user is not collected in v0.1. When it arrives in v0.2, it will be opt-in. User identifiers will be hashed with a random salt created for each scan and never stored, and only aggregated counts will be reported.

## Retention

Snapshots and reports are ordinary files in your `--out` folder. Delete them when you no longer need them. BTP Lens keeps no other copy.
