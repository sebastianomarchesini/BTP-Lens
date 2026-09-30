# Rules

Every finding has a stable rule id, a severity, the evidence that triggered it, a concrete remediation and reference links. Rules are pure functions of the collected data. They use the **scan time** as "now", so `btp-lens report --from snapshot.json` gives the same result offline. The data behind each rule, and its limits, are recorded in [data-sources.md](data-sources.md).

| Rule id | Status | Severity | Needs |
| --- | --- | --- | --- |
| [`APP_NO_RECENT_DEPLOY`](#app_no_recent_deploy) | implemented | low / medium | Space Auditor |
| [`RUNTIME_NODE_EOL`, `RUNTIME_JAVA_EOL`](#runtime_node_eol--runtime_java_eol) | planned, slice 2 | medium / high | Space Auditor |
| [`DEP_KNOWN_CVE`](#dep_known_cve) | planned, slice 3 | from CVSS | none (local SBOM) |
| [`APP_IDLE`](#app_idle) | planned, slice 4 | low | Space Auditor |
| [`UI5_OUT_OF_MAINTENANCE`](#ui5_out_of_maintenance) | planned, slice 5 | medium / high | Space Auditor |
| [`BUILDPACK_OUTDATED`](#buildpack_outdated) | planned | low / medium | Space Auditor |
| [`STACK_DEPRECATED`](#stack_deprecated) | planned | medium / high | Space Auditor |
| [`SAP_PKG_OUTDATED`](#sap_pkg_outdated) | planned | medium / high | none (local SBOM) |
| [`ENV_SECRET_PLAINTEXT`](#env_secret_plaintext) | planned | high | Space Developer or Space Supporter, `--deep` |

For planned rules, the severity logic below is the design, and it is confirmed or adjusted when the rule is implemented.

## Risk score

Apps are ranked by a weighted sum of their findings: critical 100, high 25, medium 5, low 1, info 0. A single critical finding outranks any number of lower ones in practice. A score of 0 means that no rule matched; it does not mean the app is safe.

---

## APP_NO_RECENT_DEPLOY

**Last deploy older than 12 months.** The app still runs with the libraries, buildpack and runtime from when its current droplet was staged, so fixes released since then are missing.

- **Data:** the current droplet's `created_at` (`GET /v3/droplets?current=true`).
- **Severity:**
  - `low`: the droplet is more than 365 days old.
  - `medium`: it is more than 730 days old.
  - Apps that were never staged have no droplet and produce no finding.
- **Evidence:** `lastDeployAt`, `ageDays` and `thresholdDays`.
- **Remediation:** Update the app dependencies and redeploy (`cf push`), or restage (`cf restage`) to pick up the current buildpack and runtime patches. If the app is no longer needed, delete it.
- **References:** <https://docs.cloudfoundry.org/devguide/deploy-apps/start-restart-restage.html>
- **If the droplet collector is skipped** (for example after a 403), the rule is recorded as skipped and produces no findings.

## RUNTIME_NODE_EOL / RUNTIME_JAVA_EOL

**The runtime version is past, or within 90 days of, its end of life.**

- **Data:**
  - The Node.js or Java version comes from the droplet's detected buildpacks.
  - EOL dates come from endoflife.date: `nodejs`, and for Java `sapmachine` (SAP Java buildpack) or `eclipse-temurin`.
- **Severity:**
  - `high`: past end of life.
  - `medium`: end of life within 90 days.
  - An unknown version produces no finding and is shown as "unknown" in the inventory.
- **Evidence:** runtime, version, release cycle, `eolFrom` and days until or since EOL.
- **Remediation:** Move to a supported release line (named in the finding), then restage.

## DEP_KNOWN_CVE

**A dependency in the SBOM has a known vulnerability.** The SBOM is built locally with `btp-lens sbom` from `package-lock.json`, `pom.xml` or `mta.yaml`.

- **Data:** OSV.dev `POST /v1/querybatch`, then `GET /v1/vulns/{id}` for severity.
- **Severity:** from the highest CVSS base score.
  - `critical`: 9.0 or higher.
  - `high`: 7.0 to 8.9.
  - `medium`: 4.0 to 6.9.
  - `low`: under 4.0.
  - `medium` when the advisory has no score.
- **Evidence:** package, version, advisory ids and aliases, and the fixed version if known.
- **Remediation:** Upgrade the package to the fixed version named in the advisory.

## APP_IDLE

**The app is stopped for a long time, or runs with no sign of use.**

- **Data:** app `state` and `updated_at`, droplet and process timestamps, plus app usage and audit events.
- **CF limit:** CF keeps events for **31 days** by default, so "no events in 180 days" cannot be proven from events alone. The evidence names the window that was checked.
- **Severity:** `low`.
  - Stopped, with `updated_at` more than 90 days ago.
  - Or running, with droplet and process unchanged for more than 180 days **and** no events in the retention window.
- **Remediation:** Confirm that the app is still needed; delete it or its route if not.

## UI5_OUT_OF_MAINTENANCE

**The SAPUI5 version served by the app is out of maintenance.**

- **Data:**
  - One unauthenticated `GET` of `resources/sap-ui-version.json` on the app's route, with a 5 s timeout and redirects not followed. Turn it off with `--no-probe-routes`.
  - The maintenance status comes from `ui5.sap.com/versionoverview.json`.
- **Severity:**
  - `medium`: out of maintenance.
  - `high`: past end of cloud provisioning.
  - Apps behind a login redirect, or that load UI5 from the CDN, are shown as "unknown".
- **Remediation:** Move the app to a maintained UI5 version (a long-term maintenance release if possible).

## BUILDPACK_OUTDATED

**The droplet was built with an older buildpack than the platform currently offers.**

- **Data:**
  - The droplet buildpack `version`, compared with `/v3/buildpacks`.
  - That endpoint has **no version field**, so the version is parsed from `filename`.
  - When parsing fails, the rule compares dates instead, and says so in the evidence.
- **Severity:**
  - `medium`: older version.
  - `low`: date comparison only.
- **Remediation:** `cf restage` the app to build it with the current buildpack.

## STACK_DEPRECATED

**The app runs on a deprecated stack** (for example `cflinuxfs3`).

- **Data:**
  - The stack `state` from `/v3/stacks`.
  - If a Cloud Controller does not report `state`, a built-in list is used, marked as such in the evidence.
- **Severity:**
  - `high`: `DEPRECATED` or `DISABLED`.
  - `medium`: `RESTRICTED`.
- **Remediation:** Push the app to the current stack (`cf push -s cflinuxfs4`) and test it.

## SAP_PKG_OUTDATED

**`@sap/cds`, `@sap/approuter`, `@sap/xssec` or `@sap/xsenv` is behind the current major version.**

- **Data:** versions from the SBOM, compared with `dist-tags.latest` from the npm registry. Only these four packages are queried.
- **Severity:**
  - `medium`: one major version behind.
  - `high`: two or more behind.
- **Remediation:** Upgrade to the current major version, following the package's migration guide.

## ENV_SECRET_PLAINTEXT

**An environment variable whose name looks like a secret is set directly on the app** instead of coming from a service binding.

- **Data:**
  - Keys from `GET /v3/apps/:guid/environment_variables`, which returns only user-provided variables.
  - This rule runs only with `--deep`, because Space Auditor cannot read environment variables.
  - Values are discarded when they are read, and only the **name** is reported.
- **Severity:** `high`.
- **Remediation:** Move the value into a service binding or a user-provided service, and rotate the secret.
- **Side effect:** CF records `audit.app.environment_variables.show` for each app that is read (see [privacy.md](privacy.md)).
