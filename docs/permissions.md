# Permissions

BTP Lens follows least privilege. Every check declares which Cloud Foundry roles are enough to run it, and any one of the listed roles works. The roles come from the Cloud Controller v3 docs (see [data-sources.md](data-sources.md) §2).

## Recommended setup

Give the scanning user **Space Auditor** in every space you want to scan:

```sh
cf set-space-role scanner@example.com my-org my-space SpaceAuditor
```

Space Auditor can read apps, droplets, processes, routes and service binding *metadata*. It cannot read environment variables or service credentials, and it cannot change anything.

## Roles per check

| Check id | What it reads | Roles | Default |
| --- | --- | --- | --- |
| `collect.apps` | `GET /v3/apps` | Space Auditor | on |
| `collect.droplets` | `GET /v3/droplets?current=true` | Space Auditor | on |
| `rule.APP_NO_RECENT_DEPLOY` | droplets (above) | Space Auditor | on |
| planned: processes, stacks, buildpacks, routes, binding metadata | `GET /v3/...` | Space Auditor | on |
| planned: audit events | `GET /v3/audit_events` | Space Auditor or Org Auditor | on |
| planned: app usage events | `GET /v3/app_usage_events` | not documented for BTP; skipped on 403 | on |
| planned: `ENV_SECRET_PLAINTEXT` | `GET /v3/apps/:guid/environment_variables` (names only) | Space Developer or Space Supporter | `--deep` |

**Not used at all:** `GET /v3/apps/:guid/env` (it returns service credentials) and `GET /v3/service_credential_bindings/:guid/details`.

## `--deep`

Reading environment variables needs **Space Developer** or **Space Supporter**. Space Supporter is the narrower of the two: it cannot push apps or manage services. It is still **not read-only**, though, because it can restart and scale apps. Use `--deep` only when you accept giving the scanning user that access, and consider a separate, short-lived user for it.

## When a role is missing

- A call that returns **403** records the check as `skipped` with reason `insufficient role: needs <roles>`, and the scan continues.
- Rules that depend on a skipped collector are skipped too.
- Skipped checks appear in every report: on the HTML overview, in the JSON `checks`, and as SARIF notifications. Missing data is therefore never mistaken for "no findings".
- Only a **401** after a token refresh, or a configuration error, stops the scan (exit code 2).
