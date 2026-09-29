# Security review: BTP Lens (design and repository), 2026-09-29

**Scope.** At the time of this review the repository contains the build spec (`CLAUDE.md`), the verified data-source notes (`docs/data-sources.md`), the README, the licence and `.gitignore`. There is no application code yet, so this is a **design review plus a repository-hygiene review**. Every design finding below is written as a requirement that the implementation must meet and, where possible, as a unit test to add. Re-run the "Code checklist" section against the code once the first slices land.

**Method.** Threat model of the read-only scanner (§1), line-by-line review of the constraints in `CLAUDE.md` and of every data flow in `docs/data-sources.md` (§2), review of the GitHub repository settings and git history (§3), and supply-chain review of the planned toolchain (§4). §5 lists what this change already fixes, §6 what only the repository owner can do, and §7 is the checklist to run against the code.

Severity scale: **High** = could expose a customer credential or run attacker-controlled code on the operator's machine; **Medium** = leaks customer-internal information or degrades the tool's trust story; **Low** = hardening.

---

## 1. Threat model

| Asset | Where it lives | Who wants it |
|---|---|---|
| CF/UAA bearer token and refresh token | `~/.cf/config.json`, process memory, `BTP_LENS_CLIENT_SECRET` | Anyone who can read logs, crash output, reports, or a proxied request |
| The landscape picture (app names, routes, versions, CVEs, findings) | snapshot JSON, HTML/CSV/SARIF reports, terminal output | Attackers doing reconnaissance; also accidental leaks through screenshots and shared files |
| Customer-internal package names | SBOM, OSV query bodies | Competitors, attackers targeting private packages |
| The operator's machine and network | wherever the CLI runs (laptop, CI runner, jump host) | A tenant of the scanned org who controls app names, routes or responses |
| The project's trust story ("read-only, nothing leaves the machine") | code, docs, CI, npm package | Typosquatters, compromised dependencies, a compromised maintainer account |

**Attackers considered.** (A) A developer with Space Developer in the scanned org who controls app names, route hosts, buildpack detect output, env var names and the HTTP responses of the app routes. (B) A network attacker between the operator and the CF API (mitigated by TLS if never disabled). (C) A supply-chain attacker: npm dependency, GitHub Action, or the npm package name itself. (D) A curious reader of the produced reports (auditor, manager, community member who receives a screenshot).

Attacker (A) is the important one: **every string the scanner reads from CF or from an app route is attacker-controlled input**, and it ends up in the terminal, in a CSV opened in Excel, and in an HTML file opened in a browser.

---

## 2. Design findings

### 2.1 Credentials

| Id | Sev | Finding | Requirement |
|---|---|---|---|
| **SEC-01** | High | `docs/data-sources.md` §1.1 lists `SSLDisabled` among the cf CLI config fields but does not say what to do with it. The cf CLI honours it (`--skip-ssl-validation`). If BTP Lens honoured it too, a token could be sent over an unverified TLS connection. | Ignore `SSLDisabled`. Never set `rejectUnauthorized: false`, never read `NODE_TLS_REJECT_UNAUTHORIZED`. If the certificate is invalid, exit 2 with "certificate not trusted; add your corporate CA with `NODE_EXTRA_CA_CERTS`". Unit test: the HTTP client has no code path that disables TLS verification (grep the built bundle). |
| **SEC-02** | High | The token is attached to requests by the client, but the spec does not bind the token to a host. A bug, or a redirect, could send the CF bearer token to `api.osv.dev`, `endoflife.date`, `ui5.sap.com` or an app route. | Bind credentials to hosts inside the client: `Authorization` is added **only** when the request host equals the `--api` host or the discovered `log_cache` host. Callers cannot pass headers. Unit test: a request to every other allow-listed host is asserted to carry no `Authorization` header. |
| **SEC-03** | High | Redirects. `fetch` follows redirects by default; a CF API or an app route answering 3xx to another host would move the request (and possibly the token) off the allow-list. `data-sources.md` sets `redirect: 'manual'` for the route probe only. | `redirect: 'manual'` (or `'error'`) for **all** requests. A 3xx from the CF API is recorded as `error` for that check. Unit test with a mocked 302. |
| **SEC-04** | High | Secrets in error paths. UAA and CF errors are printed to the terminal; stack traces and `--verbose` output can include request objects with headers, and `POST /oauth/token` bodies contain the refresh token or client secret. | A single redaction function wraps every log, error and verbose line: it removes `Authorization` headers, any `bearer …`/`eyJ…` token shape, `refresh_token`, `client_secret` and `password` fields, and the contents of `config.json`. Never log the body of `/oauth/token` requests or responses. Unit test: feed a fake token through each error path and assert the output never contains it. |
| **SEC-05** | Medium | Client credentials are read from `BTP_LENS_CLIENT_ID` / `BTP_LENS_CLIENT_SECRET` only. A `--client-secret` flag (if ever added) would land in shell history and `ps` output. | Never accept secrets as CLI flags. Add `BTP_LENS_CLIENT_SECRET_FILE` for CI and secret managers. Zero the in-memory copy after the token exchange. |
| **SEC-06** | Medium | The refreshed token is "held in memory" and "never written back". Good. Missing: the snapshot must never contain the token, the config file path, or the operator's user name (`~/.cf/config.json` contains the user's name and GUID). | The snapshot schema is `.strict()` and has no field where a token could land. The privacy test in the definition of done must scan **all** outputs for the JWT shape (`eyJ` + two dots), for `bearer `, for the operator's email/user name from `config.json`, and for `refresh_token`. |
| **SEC-07** | Low | The JWT `exp` is decoded locally. Fine, as long as nothing else in the payload is trusted. | Decode base64url payload only, read `exp`, treat anything malformed as "expired" and refresh. Never verify or trust `sub`, `scope` etc. locally; the CF API decides. |

### 2.2 Outbound requests and the allow-list

| Id | Sev | Finding | Requirement |
|---|---|---|---|
| **SEC-08** | High | **Route probe reaches internal networks.** The UI5 probe GETs `https://<route host>/resources/sap-ui-version.json` for every mapped route. Route hosts are attacker (A) controlled and can be internal domains (`apps.internal`, private DNS names) or names that resolve to private, loopback or link-local addresses. When the scan runs on a CI runner or a jump host this becomes a server-side request forgery primitive: e.g. `169.254.169.254` (cloud metadata) or `10.x` services. | Before connecting, resolve the host and refuse RFC 1918, loopback, link-local (`169.254.0.0/16`, `fe80::/10`), unique-local (`fc00::/7`), multicast and unspecified addresses; refuse `*.internal` and single-label hosts; connect only with `https:`; pin the resolved address for the request to avoid DNS rebinding (resolve once, connect to that IP with the `Host`/SNI set to the name). Cap: one probe per app, 5 s, 256 KB body, `Content-Type` must be JSON. Unit tests for each refused class. |
| **SEC-09** | Medium | `GET /` discovery returns `links.uaa`, `links.login`, `links.log_cache`. They are trusted because they come over TLS from `--api`, but the spec does not require them to be `https:`. | Validate scheme `https:` for every discovered link; otherwise exit 2. The `next.href` same-origin guard in §1.2 stays. |
| **SEC-10** | Medium | **Private package names leak to OSV.** `POST api.osv.dev/v1/querybatch` sends `{ecosystem, name, version}` for every SBOM entry, including scoped internal packages such as `@customer/billing-core`. That is customer-internal information leaving the machine, contradicting the "no data leaves the machine" pitch as users will read it. | Document it in `docs/privacy.md` in plain words. Add `--osv-exclude <glob>` (default: none) and `--no-osv`. Print, before the first OSV call, one line: "Sending N package names and versions to api.osv.dev (public packages only is recommended; use --osv-exclude '@yourorg/*')". |
| **SEC-11** | Low | Third-party services receive a default Node `User-Agent` that reveals the Node version. | Send `User-Agent: btp-lens/<version> (+https://github.com/sebastianomarchesini/BTP-Lens)` to every host and nothing about the OS. |
| **SEC-12** | Low | `Retry-After` is honoured without a cap; a misbehaving server can stall the scan for hours. Unbounded response bodies can exhaust memory. | Cap `Retry-After` at 120 s. Cap every response body (64 MB for CF list pages, 256 KB for probes, 8 MB for OSV, 1 MB for endoflife/UI5/npm) and record `error` when exceeded. |
| **SEC-13** | Low | `report --from snapshot.json` must be offline, but nothing enforces it. | The allow-list has an "offline" mode that throws `EgressDeniedError` for every host. `report` always runs in that mode. Unit test. |
| **SEC-14** | Low | Corporate proxies. Not a vulnerability, but users will be tempted to disable TLS checks when a TLS-inspecting proxy is in the way. | Honour `HTTPS_PROXY`/`NO_PROXY` (undici `EnvHttpProxyAgent`) and document `NODE_EXTRA_CA_CERTS`. This removes the main reason people reach for `--skip-ssl-validation`. |

### 2.3 Attacker-controlled strings in outputs

| Id | Sev | Finding | Requirement |
|---|---|---|---|
| **SEC-15** | High | **HTML report injection.** The single-file report embeds the snapshot JSON and renders app names, routes, buildpack names, `detect_output`, env var names and OSV advisory text (`summary`, `details`, which is Markdown from a third party). If any of it is inserted as HTML, attacker (A) gets script execution in the reader's browser. On `file://` the impact is limited, but the same UI is planned for **server mode behind XSUAA (v0.3)**, where it becomes session theft. | Embed the snapshot as `<script type="application/json">` with `<`, `>`, `&`, U+2028 and U+2029 escaped as `\uXXXX`. Never use `dangerouslySetInnerHTML`; render OSV `details` as plain text, never as Markdown/HTML. Accept reference links only with `http:`/`https:` schemes. Add a CSP meta tag to the report: `default-src 'none'; script-src 'sha256-<hash of the inline bundle>'; style-src 'unsafe-inline'; img-src data:; font-src data:; connect-src 'none'`. Tests: an app named `</script><script>alert(1)</script>` and a reference `javascript:alert(1)` in a fixture must render inert (React Testing Library), and the Playwright offline test must also assert `connect-src 'none'` and zero network requests. |
| **SEC-16** | High | **CSV injection.** A cell starting with `=`, `+`, `-`, `@`, tab or carriage return is executed as a formula by Excel and LibreOffice (DDE / `=cmd|…`). App names and remediation text end up in the CSV. | In `csv.ts`, prefix such cells with a single quote and escape quotes per RFC 4180 (OWASP CSV injection guidance). Unit test with `=cmd|' /C calc'!A0`. |
| **SEC-17** | Medium | **Terminal escape injection.** App and route names printed to the console can contain ANSI/OSC escape sequences that hide text, move the cursor, or (in some terminals) set the clipboard or title. | Strip C0/C1 control characters and ESC sequences from every string before it reaches `stdout`/`stderr`. Unit test. |
| **SEC-18** | Medium | **Path traversal through names.** File names like `snapshot-<org>-<date>.json` or per-app files would let an org/space/app name containing `/`, `\` or `..` write outside `--out`. | Never build file names from CF names. Use `snapshot-<date>-<8 hex of random>.json`. If a user-supplied name is ever used, allow `[A-Za-z0-9._-]` only. |
| **SEC-19** | Medium | **SBOM inputs.** `btp-lens sbom --path` reads `package-lock.json`, `pom.xml`, `mta.yaml` and `.mtar` (a ZIP). Risks: zip-slip (entry names with `..`), decompression bombs, symlinked entries, XML external entities and entity expansion in `pom.xml`. | Never extract `.mtar` to disk; read entries in memory, reject entry names that normalise outside the root, cap total uncompressed size (e.g. 512 MB) and ratio (100:1). Parse XML with entity processing **off** (`processEntities: false`, no DOCTYPE). Parse YAML with a safe loader only. Cap input file sizes. Unit tests with a crafted zip and a `pom.xml` containing `<!DOCTYPE … <!ENTITY …>>`. |
| **SEC-20** | Medium | **SARIF and local paths.** SARIF `artifactLocation.uri` and messages may contain absolute local paths of the SBOM source (`/Users/<name>/…` reveals the operator's user name). | Use paths relative to `--path` and `uriBaseId`. Extend the privacy test to fail on `/Users/`, `/home/`, `C:\Users\`. |
| **SEC-21** | Low | Snapshot input trust. `report --from` parses a JSON file the user may have received from someone else. | Validate with the strict zod schema before use; cap file size (256 MB); do not deep-merge parsed objects with defaults (prototype pollution); reject unknown keys. |
| **SEC-22** | Low | Report files contain the landscape picture but are written with the default umask, often world-readable on shared hosts. | Create `--out` with mode `0o700` and files with `0o600`. Print once: "Reports contain internal details of your landscape. Do not commit them; add `reports/` to `.gitignore`." |
| **SEC-23** | Low | Users will share screenshots and files of the report in the community (this is also what the marketing plan asks them to do). Real org, space, app and route names would leak. | Add `report --redact`: replaces org, space, app and route names with stable per-scan hashes (`app-3f2a`), keeps versions, findings and counts. Ship it in v0.1 because the campaign relies on shared reports. |

### 2.4 Privacy checks that are already right

- Audit events: `actor.*` and `data` are dropped at parse time (`data-sources.md` §2). Keep the zod `strip` behaviour and add a fixture containing `actor` to prove it never reaches the snapshot.
- Process stats: `host`, `instance_internal_ip`, `instance_ports` are never written. Add the same fixture proof.
- `GET /v3/apps/:guid/env` (returns `VCAP_SERVICES` credentials) is deliberately not used; `/environment_variables` returns keys only. Keep the GET-only test **and** add a test that the path `/env` is refused by the client even with GET.
- `--deep` creates an `audit.app.environment_variables.show` event in the customer landscape. Keep the disclosure in `privacy.md` and print it once when `--deep` is used.

---

## 3. Repository review (as of 2026-09-29)

Checked with the GitHub API and `git`:

| Check | Result | Action |
|---|---|---|
| Secrets in git history (all commits, all blobs; AWS, private keys, Slack, GitHub, JWT, `client_secret`, `password` patterns) | **Clean** | Keep it that way: `gitleaks` on every push (added, §5). |
| Binary or large blobs in history | None | — |
| Collaborators | 1 admin (owner) | Fine for now. When a second maintainer joins, require 2FA and use CODEOWNERS (added). |
| Branch protection on `main` | **None** (`protected: false`) | Owner action (§6): require PR, required status checks, no force-push, linear history. |
| `SECURITY.md` / disclosure policy | Missing | Added (§5). |
| Dependabot / dependency updates | Missing | Added `.github/dependabot.yml` for npm and GitHub Actions. |
| Secret scanning and push protection | Not verifiable from here | Owner action (§6): enable in Settings → Code security. |
| OpenSSF Scorecard | Not running | Added workflow; publish the badge once green. |
| CodeQL | Not running (no code yet) | Workflow added; the job skips itself until TypeScript sources exist. |
| GitHub Actions token permissions | Repository default | Workflows added here declare `permissions: read-all` at top level and elevate per job only. Owner action: set the repository default to read-only. |
| Issue templates | Missing | Added, with a "do not paste tokens or `config.json`" warning, because bug reports are the most likely place for a token to leak. |
| `.gitignore` | Covers build output and `reports/` | Recommend adding (in the development branch, not done here to avoid conflicts): `.env`, `.env.*`, `*.pem`, `*.key`, `.cf/`, `*.mtar`, `snapshot*.json`, `*.sarif`, `.DS_Store`. |
| Test fixtures | None yet | Add a fixture linter test that fails on e-mail addresses, `eyJ` tokens, `bearer `, real BTP hostnames (`*.hana.ondemand.com`, `*.cfapps.*`) and IP addresses. Fixtures must use `example.com`/`.invalid` hosts and made-up GUIDs. |
| npm package name `btp-lens` | **Unclaimed** on 2026-09-29 (also `btplens`, `@btp-lens/cli`, `create-btp-lens` are free) | Owner action, **urgent before any marketing post**: publish `btp-lens@0.0.1` as a placeholder that prints "not released yet" so the name cannot be squatted. |

---

## 4. Supply chain and release

| Id | Sev | Requirement |
|---|---|---|
| **SC-01** | High | Publish from GitHub Actions with **npm trusted publishing (OIDC) and `--provenance`**, never from a laptop token. Enable 2FA on the npm account and on GitHub. |
| **SC-02** | High | Pin every GitHub Action to a full commit SHA (done in the workflows added here) and let Dependabot bump them. |
| **SC-03** | Medium | Commit the lockfile, install with `npm ci --ignore-scripts` in CI, and keep the runtime dependency list tiny (`commander`, `zod`, an XML and a YAML parser; nothing else at runtime). Review every new dependency's install scripts. |
| **SC-04** | Medium | `package.json` `files` whitelist (`dist/`, `README.md`, `LICENSE`, `NOTICE`) so fixtures and tests never ship. Verify with `npm pack --dry-run` in CI. |
| **SC-05** | Medium | The UI bundle inlines fonts and locale data from `@sap-theming/theming-base-content` and `@openui5/sap.ui.core`. Record their licences in `NOTICE` and add a CI check that the built HTML has no `http://`/`https://` `src`/`href` attributes except in visible reference links. |
| **SC-06** | Low | Add an OpenSSF Scorecard badge and a `SECURITY.md` link in the README once the workflows are green; both are trust signals the marketing plan uses. |

---

## 5. Fixed in this change

- `SECURITY.md`: private disclosure via GitHub Security Advisories, 72-hour acknowledgement, 90-day coordinated disclosure, safe-harbour statement, what is in and out of scope.
- `.github/dependabot.yml`: weekly npm (root and both workspaces) and GitHub Actions updates, grouped, with a 5-PR cap.
- `.github/workflows/security.yml`: `gitleaks` on push and PR (full history), Dependency Review on PRs, CodeQL for JavaScript/TypeScript that skips until sources exist, and OpenSSF Scorecard on `main` weekly. Every action pinned by SHA; `permissions: read-all` by default.
- `.github/CODEOWNERS`: the owner reviews everything under `packages/cli/src/http/`, `packages/cli/src/net/`, `packages/cli/src/reporters/`, `.github/` and `SECURITY.md`.
- `.github/ISSUE_TEMPLATE/`: bug and feature templates with the token warning, and a config that routes security reports to the advisory form.
- `.github/PULL_REQUEST_TEMPLATE.md`: a short security checklist (GET-only, no new hosts, no secrets in fixtures, outputs escaped).

Nothing in `CLAUDE.md`, `README.md`, `.gitignore` or under `packages/` was touched, because development is in progress on another branch. §7 is the list to hand to whoever is writing the code.

---

## 6. Owner actions (cannot be done from a branch)

1. **Reserve `btp-lens` on npm today** (placeholder 0.0.1 with a clear "not released" message). Then set up trusted publishing for the repository.
2. GitHub → Settings → Branches: protect `main` (require a PR, require `ci` and `security` checks, block force-push and deletion). Settings → Actions → General: workflow permissions "Read repository contents", and require approval for first-time contributors.
3. Settings → Code security: enable Dependabot alerts, secret scanning **and push protection**, private vulnerability reporting.
4. Enable 2FA on GitHub and npm; add a second maintainer only with 2FA.
5. Enable GitHub Sponsors on the account (the `FUNDING.yml` added by the marketing kit only works once you are enrolled).

---

## 7. Code checklist (run before tagging v0.1.0)

Copy this list into the development session. Each line is a test or a grep.

- [ ] HTTP client refuses every method except GET on the CF API host, and every non-allow-listed host (existing constraint #1), **plus** SEC-02 (token bound to host), SEC-03 (no redirects), SEC-09 (https only), SEC-13 (offline mode for `report`).
- [ ] No code path disables TLS verification; `SSLDisabled` from `config.json` is ignored (SEC-01).
- [ ] Redaction wrapper on every log/error/verbose path; token never appears in any output (SEC-04, SEC-06).
- [ ] No secret accepted as a CLI flag; `BTP_LENS_CLIENT_SECRET_FILE` supported (SEC-05).
- [ ] Route probe: private/loopback/link-local/`.internal` refused, https only, DNS pinned, 5 s, 256 KB, JSON only (SEC-08).
- [ ] OSV: `--no-osv`, `--osv-exclude`, the one-line disclosure before the first call (SEC-10).
- [ ] Fixed `User-Agent`, capped `Retry-After`, capped body sizes (SEC-11, SEC-12).
- [ ] HTML: JSON embedded with `\u003c` escaping, no `dangerouslySetInnerHTML`, OSV text as plain text, `http(s):` links only, CSP meta with `connect-src 'none'`, XSS fixture test (SEC-15).
- [ ] CSV: formula-prefix escaping with test (SEC-16).
- [ ] Terminal output stripped of control characters (SEC-17).
- [ ] No file name derived from CF names (SEC-18).
- [ ] SBOM: in-memory zip reading, path normalisation, size and ratio caps, XML entities off, safe YAML (SEC-19).
- [ ] SARIF uses relative URIs; privacy test fails on home-directory paths (SEC-20).
- [ ] Snapshot input validated strictly and size-capped (SEC-21).
- [ ] `--out` created `0o700`, files `0o600`, warning printed (SEC-22).
- [ ] `report --redact` implemented (SEC-23).
- [ ] Fixture linter test (no e-mails, tokens, real hosts, IPs).
- [ ] `package.json` `files` whitelist, `npm pack --dry-run` check, provenance publish workflow (SC-01, SC-04).
