# Data sources

This file records every external data source BTP Lens reads, what was **confirmed** against primary documentation, and what could **not** be confirmed and is therefore implemented defensively.

- **Verified on:** 2026-09-29
- **CF v3 API source of truth:** the Markdown sources of the official docs site (`v3-apidocs.cloudfoundry.org`), read from [`cloudfoundry/cloud_controller_ng` `docs/v3/source`](https://github.com/cloudfoundry/cloud_controller_ng/tree/main/docs/v3/source) at commit `8383175b` (2026-09-28). Defaults were read from `config/cloud_controller.yml` and `middleware/` in the same repository.

Legend: ✅ confirmed in primary docs or source · 🟡 confirmed second-hand (third-party code or search snippet) · ⚠️ not confirmed, implemented defensively

---

## 1. Cross-cutting CF v3 behaviour

### 1.1 Authentication ✅
- Every call sends `Authorization: bearer <token>` (UAA OAuth 2).
- Discovery: `GET /` (the global root, **no auth required**) returns `links.uaa.href`, `links.login.href` and `links.log_cache.href`. The `log_cache` link is omitted when log cache is not configured, so the code must handle its absence. BTP Lens discovers these endpoints from the root and **never hard-codes** BTP region URLs.
- Token source 1: the cf CLI config at `$CF_HOME/.cf/config.json` (default `~/.cf/config.json`). Confirmed fields from `cloudfoundry/cli` `util/configv3/json_config.go`: `AccessToken` (already prefixed with `bearer `), `RefreshToken`, `Target`, `UaaEndpoint`, `AuthorizationEndpoint`, `UAAOAuthClient` (default `cf`), `UAAOAuthClientSecret`, `SSLDisabled`, `OrganizationFields`, `SpaceFields`.
  - If `AccessToken` has expired (read `exp` from the JWT payload locally, **without** any network call), refresh it with a `POST {UaaEndpoint}/oauth/token` using `grant_type=refresh_token`. This is the only permitted non-GET call. The refreshed token is held in memory and is **never written back** to `config.json`.
  - If `Target` differs from `--api`, fail with exit code 2 and a clear message.
- Token source 2: client credentials from `BTP_LENS_CLIENT_ID` / `BTP_LENS_CLIENT_SECRET`, sent as a `POST {uaa}/oauth/token` with `grant_type=client_credentials`.
- ⚠️ On SAP BTP, a technical user with client credentials needs a UAA client that CF role assignments can target. That setup is platform-specific, so the docs recommend `cf login` with a named user holding **Space Auditor** for v0.1.

### 1.2 Pagination ✅
- List responses contain `pagination.{total_results,total_pages,first,last,next,previous}` and `resources[]`.
- Follow `pagination.next.href` until it is `null`. Never build page URLs by hand.
- `per_page` is valid from 1 to **5000** on every v3 list endpoint used here. BTP Lens uses `per_page=5000`.
- `include=space.organization` on `/v3/apps` returns parent spaces and orgs under `included.{spaces,organizations}`, which saves N+1 calls.
- Security guard: `next.href` must point to the same origin as `--api`. Otherwise stop paging and record an error. This prevents a token leak through a crafted `next` link.

### 1.3 Errors ✅
Error body: `{"errors":[{"code":int,"title":"CF-…","detail":"…"}]}`. Code on `code`/`title`, never on `detail`.

| HTTP | Title | BTP Lens behaviour |
|---|---|---|
| 400 | `CF-BadQueryParameter` (10005) | Tool bug. Record the check as `error`; the scan continues. |
| 401 | `CF-InvalidAuthToken` (1000) / `CF-NotAuthenticated` (10002) | Refresh once, then abort with exit code 2. |
| 403 | `CF-NotAuthorized` (10003) | Record the check as `skipped: insufficient role`; the scan continues. |
| 404 | `CF-ResourceNotFound` (10010) | Also returned when **the user cannot read** the resource. Treat as "not visible", not as an error. |
| 429 | `CF-UaaRateLimited` (20008) or CC rate limiter | Honour `Retry-After` (seconds), then retry. |
| 5xx | `UnknownError` (10001), 502, 503 | Exponential backoff with jitter, max 3 retries, then record the check as `error`. |

### 1.4 Rate limits
- ✅ The Cloud Controller rate limiter (`middleware/base_rate_limiter.rb`) sets `X-RateLimit-Limit`, `X-RateLimit-Remaining` and `X-RateLimit-Reset` (optionally with a suffix, e.g. `-V2-API`). On 429 it adds `Retry-After`. Open-source CF ships with it **disabled** by default, so the headers may be absent.
- 🟡 SAP BTP: according to *SAP BTP-Specific Configurations* (help.sap.com), the CC API limit is "in the range of a few 10k requests per hour per user on average", with a separate concurrency limit on service-related endpoints. help.sap.com is not reachable from the build environment, so this comes from a search snippet.
- Policy: concurrency of 5 (configurable). When `X-RateLimit-Remaining` drops below 5% of `-Limit`, pause until `-Reset`.

### 1.5 Roles ✅
The CF docs list per-endpoint *Permitted roles*. "All Roles" means the endpoint is callable by anyone, but results are **filtered to what the user can see**. An org-scoped list run by a Space Auditor therefore returns only that user's spaces, which is correct behaviour and not an error.

Global Auditor (a platform scope) can read everything except env vars and service binding details. It is rarely granted on BTP, but we support it.

### 1.6 Event retention: a design constraint ✅
Open-source CF defaults (`config/cloud_controller.yml`):

```yaml
app_usage_events: { cutoff_age_in_days: 31 }
audit_events:     { cutoff_age_in_days: 31 }
```

⚠️ The SAP BTP retention value is not published. **Assume 31 days.** Consequence: "no usage events in 180 days" cannot be proven from events (see `APP_IDLE` in §4).

---

## 2. CF v3 endpoints used by collectors

All endpoints are **GET**. "SA" = Space Auditor; "SD" = Space Developer.

| Collector | Endpoint | Key fields used | Min. role | SA? | Notes |
|---|---|---|---|---|---|
| (bootstrap) | `GET /` | `links.uaa`, `links.login`, `links.log_cache` | none | ✅ | Unauthenticated. |
| (bootstrap) | `GET /v3/organizations?names=<org>` | `guid`, `name` | any role | ✅ | 0 results means "org not found or not visible", exit code 2. |
| (bootstrap) | `GET /v3/spaces?organization_guids=<g>[&names=<space>]` | `guid`, `name`, `relationships.organization` | any role | ✅ | Filtered to visible spaces. |
| `apps.ts` | `GET /v3/apps?space_guids=…&include=space.organization&per_page=5000` | `guid`, `name`, `state` (`STARTED`/`STOPPED`), `created_at`, `updated_at`, `lifecycle.type` (`buildpack`/`cnb`/`docker`), `lifecycle.data.buildpacks[]`, `lifecycle.data.stack`, `relationships.space`, `relationships.current_droplet` | any role | ✅ | `lifecycle.data.buildpacks` may be `[]` and `stack` may be `null` for old records. |
| `droplets.ts` | `GET /v3/droplets?space_guids=…&current=true&per_page=5000` | `guid`, `state`, `created_at`, `lifecycle.data.buildpacks[].{name,buildpack_name,version,detect_output}`, `stack`, `relationships.app` | any role | ✅ | One call instead of N× `/v3/apps/:guid/droplets/current`. `GET /v3/droplets/:guid` notes "some fields are redacted" for SA. ⚠️ The exact redacted fields are not documented; we do not rely on `execution_metadata` or `process_types`. Docker droplets have `image` and no buildpacks. |
| `processes.ts` | `GET /v3/processes?space_guids=…&per_page=5000` | `type`, `instances`, `memory_in_mb`, `disk_in_mb`, `health_check.type`, `updated_at`, `relationships.app` | any role | ✅ | |
| `processes.ts` | `GET /v3/processes/:guid/stats` | `state` (`RUNNING`/`CRASHED`/`STARTING`/`STOPPING`/`DOWN`), `uptime`, `usage.{cpu,mem,disk}`, `mem_quota` | SA (redacted) | ✅ | "Some fields are redacted" for SA. ⚠️ Treat `host`, `instance_internal_ip` and `instance_ports` as possibly missing. **Never** written to reports (infrastructure detail). Only called for `STARTED` apps. |
| `buildpacks.ts` | `GET /v3/buildpacks?per_page=5000` | `name`, `stack`, `state`, `enabled`, `position`, `filename`, `lifecycle`, `updated_at` | any role | ✅ | ⚠️ **There is no `version` field.** The platform's current version must be parsed from `filename` (e.g. `nodejs_buildpack-cflinuxfs4-v1.8.40.zip`). If parsing fails, `BUILDPACK_OUTDATED` falls back to comparing the droplet's `created_at` with the buildpack's `updated_at`, at lower confidence. |
| `stacks.ts` | `GET /v3/stacks?per_page=5000` | `name`, `state` (`ACTIVE`/`RESTRICTED`/`DEPRECATED`/`DISABLED`), `state_reason`, `default`, `description` | any role | ✅ | Use `state` as the primary signal. ⚠️ The `state` field is newer, so older CC versions may omit it. Fall back to a built-in list (`cflinuxfs3` deprecated) and flag the result as "static list". |
| `routes.ts` | `GET /v3/routes?space_guids=…&per_page=5000` | `url`, `protocol` (`http`/`tcp`), `host`, `path`, `destinations[].app.guid` | any role | ✅ | Feeds the UI5 probe (§3.3). `/v3/apps/:guid/routes` (SA allowed) is the per-app fallback. |
| `serviceBindings.ts` | `GET /v3/service_credential_bindings?type=app&app_guids=…&per_page=5000` | `name`, `type`, `relationships.app`, `relationships.service_instance`, `last_operation.state` | SA | ✅ | Metadata only. `GET …/:guid/details` (the credentials) is **SD-only and never called**. |
| `usageEvents.ts` | `GET /v3/app_usage_events?created_ats[gt]=<now-31d>&order_by=-created_at&per_page=5000` | `created_at`, `state.{current,previous}`, `app.guid`, `space.guid`, `instance_count` | "All Roles" | ✅ / ⚠️ | ⚠️ Listed as "All Roles", but the doc does not say how results are filtered for space-scoped users. On BTP it may return 403 or an empty list for SA. Treat both as `skipped` and fall back to audit events. Ignore `app.name`/`task.name` beyond matching. |
| `auditEvents.ts` | `GET /v3/audit_events?space_guids=…&types=audit.app.start,audit.app.stop,audit.app.restage,audit.app.droplet.create,audit.app.build.staged,audit.app.process.crash,app.crash&created_ats[gt]=<now-31d>&per_page=5000` | `type`, `created_at`, `target.guid` | **Org Auditor** or SA | ✅ | 🔒 Contains `actor.guid`, `actor.name` and `actor.type` (user identity). The collector **drops `actor.*` and `data` at parse time**; the zod schema strips them before anything reaches the snapshot. |
| `secretsInEnv.ts` (`--deep`) | `GET /v3/apps/:guid/environment_variables` | keys of `var` only | **SD** or Space Supporter | ❌ | Returns **only user-provided env vars**, not `VCAP_SERVICES`. Service bindings are therefore excluded by construction, which is exactly what `ENV_SECRET_PLAINTEXT` needs. Values are discarded in the collector and only keys are kept. ⚠️ Calling it creates an `audit.app.environment_variables.show` audit event in the customer's landscape; this is documented in `privacy.md`. |
| (not used) | `GET /v3/apps/:guid/env` | — | SD | ❌ | **Deliberately not used**: it returns `VCAP_SERVICES` credentials. |

### 2.1 Role summary (input to `docs/permissions.md`)

| Check | Needs | Default |
|---|---|---|
| Inventory, droplets, processes, stats, buildpacks, stacks, routes, bindings metadata, audit events | Space Auditor (or Org Auditor for org-level audit events) | on |
| App usage events | ⚠️ unconfirmed on BTP | on, skips on 403 |
| `ENV_SECRET_PLAINTEXT` | Space Developer **or Space Supporter** | `--deep` only |

> **Least-privilege finding:** Space Supporter can also read `/environment_variables`, and on paper it is a narrower role than Space Developer (it cannot push apps or manage services). However, Space Supporter can restart and scale apps, so it is **not** read-only either. We document both and recommend neither for routine scans.

---

## 3. Non-CF sources

### 3.1 endoflife.date ✅
- API v1 base: `https://endoflife.date/api/v1`. The OpenAPI spec is in [`endoflife-date/endoflife.date` `api_v1/openapi.yml`](https://github.com/endoflife-date/endoflife.date/blob/master/api_v1/openapi.yml).
- `GET /products/{product}` returns all release cycles. Release fields used: `name`, `releaseDate`, `isLts`, `isEol`, `eolFrom`, `isEoas`, `eoasFrom`, `latest`. Responses: 200, 304 (conditional), 404 (unknown product) and 429.
- Products: `nodejs`, `eclipse-temurin` and **`sapmachine`**. SapMachine is the JDK shipped by SAP's Java buildpack, so it is the correct EOL source for most BTP Java apps. It exists on endoflife.date (confirmed in `products/sapmachine.md`).
- The runtime version comes from the droplet's `buildpacks[].detect_output` / `version`, or the process start command. ⚠️ The format differs by buildpack and is not standardized. The parser has unit tests per known buildpack, and anything unparseable becomes `unknown`, never a guess.
- Offline mode: responses are cached in the snapshot, so `report --from` never calls the network.

### 3.2 OSV.dev ✅
- `POST https://api.osv.dev/v1/querybatch`. Docs: [`google/osv.dev` `docs/api`](https://github.com/google/osv.dev/tree/master/docs/api).
- It returns **only `id` and `modified`** per query, with the result order matching the input order. Severity needs `GET /v1/vulns/{id}` (fields `severity[]` with CVSS vectors, `database_specific.severity`, `affected[]`, `aliases`), cached per id.
- Pagination: a per-query `next_page_token` appears when one query has more than 1,000 vulns or the batch has more than 3,000. Re-send only the paginated queries with `page_token`.
- There is no documented rate limit. Responses are capped at 32 MiB over HTTP/1.1.
- ⚠️ **This is a POST.** The GET-only rule in constraint #1 applies to the CF API. The HTTP client therefore enforces a **per-host method allow-list**: CF API → GET only; UAA → POST to `/oauth/token` only; `api.osv.dev` → POST `/v1/querybatch` plus GET `/v1/vulns/*`; everything else → GET only. The request body contains only `{ecosystem, name, version}` of public packages, with no customer identifiers.

### 3.3 SAPUI5 version overview 🟡
- `GET https://ui5.sap.com/versionoverview.json`. ⚠️ ui5.sap.com is blocked from the build environment. The structure is confirmed through the open-source parser [`DevEpos/ui5-version-check`](https://github.com/DevEpos/ui5-version-check):
  - `versions[]`: `{ version: "1.120.*", support: "Maintenance" | "Out of maintenance", lts: boolean, eom: string, eocp: "Q1/2027" }`
  - `patches[]`: `{ version: "1.120.17", eocp: "Q3/2026", removed?: boolean, hidden?: boolean }`
  - `eocp` has **quarter precision**. End of Maintenance (EOM) and End of Cloud Provisioning (EOCP) are different milestones and must not be called "EOL".
- The zod schema is lenient (`passthrough`, optional fields). If the feed shape is not recognised, the check is `skipped: unrecognised UI5 feed`.
- Version detection: `GET https://<route>/resources/sap-ui-version.json` returns `{ name, version, buildTimestamp, libraries[] }` (⚠️ structure is well known but not verified first-hand here). Only `version` is read.

**Safety rules for the app probe:**

1. Send **no `Authorization` header**, because the CF token must never reach an app.
2. Use `redirect: 'manual'`. A 302 to XSUAA or IAS login means the app is protected and the result is `unknown (protected)`. Never follow the redirect.
3. Use a 5 s timeout and a max body of 256 KB.
4. Probe only `http` routes that are mapped to the app, one per app.
5. The probed hosts are added to the allow-list **at runtime**, taken only from routes that the CF API returned for the scanned org.

⚠️ Many BTP apps bootstrap UI5 from the CDN (`ui5.sap.com/<version>/resources/...`), so the file is 404 on the app route. That case becomes `unknown` in v0.1. Parsing `index.html` for the bootstrap `src` is a candidate for v0.2.

### 3.4 Log cache (v0.2, not used in v0.1)
Discovered via `GET /` → `links.log_cache`. It is listed in the allow-list now so the config shape is stable.

---

## 4. Consequences for the v0.1 rules

| Rule | Data | Constraint found | Decision |
|---|---|---|---|
| `RUNTIME_NODE_EOL` / `RUNTIME_JAVA_EOL` | droplet `buildpacks[]` + endoflife.date | Version format varies by buildpack | Parse per buildpack; otherwise `unknown`. Java → `sapmachine` if `sap_java_buildpack`, else `eclipse-temurin`. |
| `BUILDPACK_OUTDATED` | droplet `buildpacks[].version` vs `/v3/buildpacks` `filename` | No `version` field on buildpacks | Parse from `filename`; fall back to date comparison, flagged as lower confidence in evidence. |
| `STACK_DEPRECATED` | app `lifecycle.data.stack` or droplet `stack` + `/v3/stacks` `state` | `state` may be absent on old CCs | `state` ∈ {`DEPRECATED`,`RESTRICTED`,`DISABLED`} → finding; otherwise use the static list. |
| `APP_IDLE` | app `state`/`updated_at`, audit and usage events | **Events are kept ~31 days** | "Stopped > 90 days": `state=STOPPED` and `app.updated_at` older than 90 days (`updated_at` is an upper bound on the last change). "Running, no activity in 180 days": droplet `created_at` and process `updated_at` older than 180 days **and** no events in the retention window. Evidence states the window used. |
| `APP_NO_RECENT_DEPLOY` | current droplet `created_at` | — | Direct. |
| `UI5_OUT_OF_MAINTENANCE` | app route probe + versionoverview | Protected or CDN-bootstrapped apps are not detectable | `unknown` is reported in inventory, not as a finding. |
| `SAP_PKG_OUTDATED` | local SBOM (`sbom` command) + npm registry | ⚠️ **The npm registry is not in the allow-list** | See decision D1. |
| `DEP_KNOWN_CVE` | SBOM + OSV | POST | Per-host method allow-list (§3.2). |
| `ENV_SECRET_PLAINTEXT` | `/environment_variables` keys | SD or Space Supporter only | `--deep`, keys only. |

---

## 5. HTML report (React + UI5 Web Components) constraints

Confirmed from the npm registry (2026-09-29):

| Package | Version | License |
|---|---|---|
| `@ui5/webcomponents-react` | 2.27.1 (peer: react ^18 \|\| ^19, `@ui5/webcomponents*` ~2.27.0) | Apache-2.0 |
| `@ui5/webcomponents-react-charts` | 2.27.1 | Apache-2.0 |
| `@ui5/webcomponents`, `-fiori`, `-icons`, `-base`, `-theming` | 2.27.2 | Apache-2.0 |
| `@sap-theming/theming-base-content` (contains the "72" font files) | 11.36.x | Apache-2.0 (LICENSE.txt covers the whole package, including the fonts) |
| `vite-plugin-singlefile` | 2.3.3 | MIT |

⚠️ **Offline blocker found:** by default, UI5 Web Components v2 load the "72" fonts from `https://cdn.jsdelivr.net/npm/@sap-theming/theming-base-content@…/fonts/*.woff2`, and CLDR locale data from `cdn.jsdelivr.net/npm/@openui5/sap.ui.core@…/cldr/*.json`. In report mode this would:

- (a) fail offline, and
- (b) contact a host that is not on the allow-list.

Mitigation for report mode:

1. Set `defaultFontLoading: false` via `<script data-ui5-config>`.
2. Inline the needed 72 `woff2` files as `data:` URIs in our own `@font-face`.
3. Import only the English locale and CLDR assets statically.
4. Add a Playwright test that opens the file with **all network requests blocked** and fails on any request other than `file://` or `data:`.

---

## 6. Allow-list (to become `packages/cli/src/net/allowlist.ts`)

| Host | Methods | Source |
|---|---|---|
| `--api` host | GET | user flag |
| `links.uaa` host | POST `/oauth/token` only | CF root |
| `links.log_cache` host | GET (v0.2) | CF root |
| mapped app route hosts in the scanned org | GET `/resources/sap-ui-version.json` only, no auth header, no redirects | CF routes |
| `api.osv.dev` | POST `/v1/querybatch`, GET `/v1/vulns/*` | fixed |
| `endoflife.date` | GET `/api/v1/products/*` | fixed |
| `ui5.sap.com` | GET `/versionoverview.json` | fixed |
| `registry.npmjs.org` | GET `/@sap%2F{cds,approuter,xssec,xsenv}` only | fixed (D1) |

Any other host, or any other method, throws `EgressDeniedError` before `fetch` runs. This is covered by a unit test.

---

## 7. Decisions (resolved 2026-09-29)

- **D1: npm registry allowed.** `registry.npmjs.org` is on the allow-list for GET `/<pkg>` only, restricted to `@sap/cds`, `@sap/approuter`, `@sap/xssec` and `@sap/xsenv`. It is used by `SAP_PKG_OUTDATED` for the current `dist-tags.latest`.
- **D2: both roles documented for `--deep`.** Space Developer or Space Supporter can read `/environment_variables`. `permissions.md` notes that Supporter is narrower but can still restart and scale apps.
- **D3: route probe on by default.** One unauthenticated GET per app, 5 s timeout, no redirects. `--no-probe-routes` turns it off.
- **D4: dedicated repository.** BTP Lens lives at the root of [`sebastianomarchesini/BTP-Lens`](https://github.com/sebastianomarchesini/BTP-Lens) as an npm-workspaces monorepo (`packages/cli`, `packages/ui`).
