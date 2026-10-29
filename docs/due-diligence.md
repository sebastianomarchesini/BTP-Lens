# Due diligence

This page answers the questions a manager, a security officer, a legal or procurement team, or a customer asks before BTP Lens runs against their landscape. Every answer points to the code, test or document that backs it, so you can check the claim instead of trusting it. It describes release 0.1.0. Where something is not done yet, the answer says so.

## In short

- **It reads, and nothing else.** Towards your Cloud Foundry API it can send `GET` and no other method. The only `POST` to your systems is the sign-in to your own UAA, as `cf login` does.
- **It needs the Space Auditor role**, which cannot change anything. Even a bug in BTP Lens cannot write to your landscape with that role.
- **It runs on your machine.** There is no server, no account and no telemetry. In 0.1.0 it talks to your CF API and your UAA and to nothing else.
- **Its output holds no secrets and no personal data**, and a test plants fake ones in the input to prove that none reaches a report.
- **It is open source** (Apache-2.0), so every claim on this page can be checked. [Check it yourself](#check-it-yourself) shows how in about 30 minutes.

## Safety

### Can BTP Lens change, stop or delete anything in our landscape?

No. Three independent layers stop it:

1. **Your role.** With Space Auditor, Cloud Foundry itself refuses every change, whatever a program sends. This layer does not depend on BTP Lens being correct.
2. **The code.** Every request passes through one file, [`packages/cli/src/net/allowlist.ts`](../packages/cli/src/net/allowlist.ts), before it is sent. For your CF API it allows `GET` only, and it refuses even `GET` on the endpoints that return credentials. On top of that, the Cloud Foundry client is typed against a `get`-only interface (`ReadOnlyHttp` in [`http/httpClient.ts`](../packages/cli/src/http/httpClient.ts)), so its code cannot ask for another method in the first place.
3. **The tests.** [`allowlist.test.ts`](../packages/cli/test/unit/allowlist.test.ts) tries `POST`, `PUT`, `PATCH`, `DELETE`, `HEAD` and `OPTIONS` against the CF API and fails if any of them gets through. [`cfClient.test.ts`](../packages/cli/test/unit/cfClient.test.ts) fails the type check if the CF client is ever given more than `get`. CI runs both on every change.

### The code says `HttpMethod = 'GET' | 'POST'`. So it does send POST?

Yes, on exactly two paths, and never to your CF API:

| Host | Method and path | Why |
| --- | --- | --- |
| Your UAA (login server) | `POST /oauth/token` | Signing in or refreshing the token. OAuth requires `POST` here, and `cf login` does the same. It returns a token and changes nothing in your landscape. |
| `api.osv.dev` | `POST /v1/querybatch` | Known-vulnerability lookups for public package names and versions, with no credentials. It is on the allow-list for a coming release; **0.1.0 never calls it.** |

`PUT`, `PATCH` and `DELETE` are not in the type at all, so the code cannot express them.

### What if BTP Lens has a bug?

The first layer still holds: a Space Auditor user cannot change anything, whatever a program sends with its token. That is why BTP Lens asks for that role and nothing more. At worst a bug produces a wrong or incomplete report, or stops the scan.

### Does it put load on the platform or hit rate limits?

Hardly. A scan of an org with fewer than 5000 apps needs fewer than ten requests, because every list is read with 5000 items per page. BTP Lens sends at most 5 requests at a time (`--concurrency`, 1 to 20), honors `Retry-After`, backs off on errors, and slows down on its own when the `X-RateLimit-*` headers say the budget is running low. SAP documents the CF API limit on BTP in the range of tens of thousands of requests per hour per user ([data-sources.md §1.4](data-sources.md)).

### Does it install or create anything in our subaccount?

No. It runs on the machine where you start it. It deploys no app and creates no service instance, service key, user or role. The only files it writes are the snapshot and the reports, in an output folder on that machine.

### Will our security monitoring notice it? Will it look like an attack?

Its requests look like a person browsing the BTP cockpit: authenticated `GET` requests from your own user. Every request carries the user agent `btp-lens/<version>`, so your logs can tell it apart. 0.1.0 creates no audit event in Cloud Foundry. The planned `--deep` check will: reading environment variable names creates an `audit.app.environment_variables.show` event, which is why it will stay off unless you ask for it ([privacy.md](privacy.md#side-effects-in-your-landscape)).

## Data and privacy

### What leaves our machine, and where does it go?

In 0.1.0, requests go to two places, both yours: your CF API (`GET`, with your token) and your UAA (`POST /oauth/token`). Nothing else.

The allow-list also names `api.osv.dev`, `endoflife.date`, `ui5.sap.com` and `registry.npmjs.org` for the rules of the next releases. They will receive public product and package names, such as `nodejs` or `@sap/cds`, and never your token or the names of your orgs, spaces or apps. The vulnerability lookup will send the package names and versions from your software bill of materials; it will come with an option to leave out your internal packages or to switch the lookup off ([security review](security-review.md), SEC-10). The full table is in [privacy.md](privacy.md#where-requests-go).

Downloading BTP Lens with `npx` contacts the npm registry, like any npm package. If your company uses an internal registry mirror, install it from there.

### Could it send our data to the author, or to anyone else?

No. There is no server, account, license key, update check or telemetry. The allow-list is the only way out of the program, and it has no entry for the author or for any analytics service. Three further guards:

- Redirects are never followed, so a server cannot bounce a request to another host.
- The `Authorization` header is refused for every host except your CF API and UAA, so your token cannot go anywhere else, even by mistake.
- The HTML report carries a Content Security Policy with `connect-src 'none'`, so your browser refuses to let it connect anywhere when you open it.

### Does it read our secrets: environment variables, service keys, credentials?

No. The CF endpoints that return credentials (`/v3/apps/:guid/env`, the `details` and `parameters` of service bindings, and the `credentials` and `parameters` of service instances) are refused by the allow-list even for `GET`. The tests check both the plain and the percent-encoded path. Space Auditor cannot read environment variables anyway. The planned `--deep` check will read environment variable **names** only, never values, and it needs a stronger role that you would grant on purpose ([permissions.md](permissions.md#--deep)).

### What happens to our login and token?

BTP Lens uses the first of these that is set: a token you pass in `BTP_LENS_ACCESS_TOKEN`, an OAuth client from `BTP_LENS_CLIENT_ID` and `BTP_LENS_CLIENT_SECRET`, or the session of your cf CLI. It reads `~/.cf/config.json` and never writes to it. A refreshed token lives in memory only. In guided mode, the one-time code from your company login is exchanged once, and the session lives in memory until the program ends.

The token never appears in a report, snapshot or log line. Everything printed goes through a redaction filter ([`io/redact.ts`](../packages/cli/src/io/redact.ts)). BTP Lens never turns off TLS certificate checks, and it ignores the cf CLI's `SSLDisabled` setting. Behind a TLS-inspecting proxy, add your company's CA with `NODE_EXTRA_CA_CERTS` instead.

### Does it process personal data? What about GDPR?

BTP Lens writes no user names, e-mail addresses or user IDs to any output. It does not collect app labels and annotations, which often hold owner e-mails. When a later release reads audit events, it drops the `actor` fields as it reads them ([privacy.md](privacy.md)). The reports contain org, space and app names and technical facts such as buildpacks, stacks and dates.

The program runs on your machine and sends nothing to the project, so the project never receives or processes your data. It does not act as a processor for you, and there is no data processing agreement to sign with it. The snapshot and the reports are files under your control and your policies. This describes how the software works; it is not legal advice. Your data protection officer decides how it fits your records of processing.

### Where are the reports stored, and who can read them?

They go to the output folder: `./reports` by default for `scan`, or `./btp-lens-reports/<date-time>/` in guided mode. On macOS and Linux, folders are created readable by you only (`0700`) and files as `0600`. The reports describe your landscape, so treat them like any internal document and do not commit them to a repository; the CLI reminds you of this after every scan. No other copy exists anywhere: delete the folder and the data is gone. A `--redact` option, for sharing screenshots publicly, is planned.

### Can a report attack the person who opens it?

Your developers choose the names in Cloud Foundry, so BTP Lens treats every name as untrusted input:

- **HTML report:** the data is embedded with HTML-significant characters escaped and is never inserted as HTML. The Content Security Policy only lets the scripts bundled at build time run, and a Playwright test injects a script and checks that it does not run.
- **CSV:** a cell starting with `=`, `+`, `-` or `@` gets a leading apostrophe, so spreadsheets do not run it as a formula.
- **Terminal:** escape sequences are stripped before anything is printed.

The details are SEC-15 to SEC-17 in the [security review](security-review.md).

## Built with AI help

### Parts of it were written with an AI coding assistant. Could it steal our data or hide something?

The assistant was a development tool, like an IDE or a compiler. It is not part of the product. BTP Lens contains no AI model and calls no AI service when it runs. The assistant never saw customer data during development: the tests use synthetic fixtures with `example.org` hosts and made-up IDs.

What matters for you is what the code does, and the code is public. The allow-list described above is the only way out of the program, and you can confirm the traffic with your own proxy ([Check it yourself](#check-it-yourself)). The same holds for code written by hand: hand-written code can hide behavior too. That is why none of the controls on this page depend on trusting the author.

### Who checks the work? Does a person take responsibility?

The maintainer, Sebastiano Marchesini, set the design and the rules the code may not break: read-only, allow-list, no secrets, no personal data. He directs every change and merges it. Since the initial commit, every change has reached `main` through a pull request. CI checks each one with lint, a type check, more than 160 tests, a coverage gate on the rules, the offline report check, secret scanning (gitleaks), CodeQL static analysis and dependency review. OpenSSF Scorecard also checks the repository on every push to `main` and every week.

Before 0.1.0 was tagged, a structured audit had independent reviewers examine the release, and three adversarial verifiers judged every finding that was not cosmetic. They confirmed 67 findings, none of them blocking, and both findings rated high were fixed before the tag. The [audit record](audits/2026-10-11-release-0.1.0-audit.md) lists each finding and what happened to it. The reviewers were AI agents. Their audit complements a review by your own security team; it does not replace one.

### Could AI-written code copy someone else's code and create license risk?

The code is written for this tool's own design (a Cloud Foundry v3 client, an allow-list, the report), not adapted from another project. Dependency review runs on every pull request and refuses copyleft licenses (GPL, AGPL, LGPL-3.0) ([`security.yml`](../.github/workflows/security.yml)). Every package bundled in the report is listed with its license in [NOTICE](../NOTICE) and in `THIRD_PARTY_LICENSES.md`. If anyone shows that part of the code reproduces third-party code without permission, that part will be removed or rewritten and released as a patch.

On ownership: the maintainer publishes the project under Apache-2.0. Where a part of the code is protected by copyright, the license gives you the right to use, modify and redistribute it. Where a part is not protected (some jurisdictions do not protect output without enough human authorship), it is free to use anyway. Either way, your rights to use BTP Lens are not reduced. This is general information, not legal advice for your jurisdiction.

## Vulnerabilities and supply chain

### Could BTP Lens have security vulnerabilities?

Yes. All software can, whoever writes it, and a tool that claims otherwise is not being honest. What matters is how small the exposure is and how fast problems are found and fixed:

- **Small attack surface:** two runtime dependencies (`commander` and `zod`), no server, no listening port, no stored credentials.
- **Limited worst case:** the token it holds is a read-only one, and the program sends it to your CF API and UAA only.
- **Continuous checks:** CodeQL, gitleaks, dependency review and Dependabot run on the repository. `npm audit` reported no known vulnerabilities in the dependency tree on 2026-10-11.
- **Public threat model and review:** the [security review](security-review.md) lists every item with its status, including the ones still open.
- **Disclosure policy:** private reporting, acknowledgement within 72 hours, and fixes shipped as patch releases with a GitHub Security Advisory ([SECURITY.md](../SECURITY.md)).

### What could an attacker do with it?

The [security review](security-review.md#1-threat-model) considers four attackers: a developer in the scanned org who controls app names and content, someone on the network, a compromised dependency or package, and a reader of a shared report. The main defenses against them:

- Names from Cloud Foundry are treated as untrusted and escaped in every output.
- TLS is always verified, and the token is bound to your hosts.
- Dependencies are few, locked by the lockfile, and installed in CI with `--ignore-scripts`.
- Reports carry no secrets.

The route probe planned for the SAPUI5 rule must not ship without its guards against reaching internal networks (SEC-08).

### How do we know the npm package is the code on GitHub?

Releases are built and published by a GitHub Actions workflow, not from a laptop, with **npm provenance**. The package on npm carries a signed SLSA provenance statement that links it to the commit and the workflow that built it, and the npm page shows that link. To verify it, install the package in an empty folder and run `npm audit signatures`. Pin the version you reviewed (`npx btp-lens@0.1.0`) instead of whatever is latest, or install it from your company's registry mirror after review. The published package contains only `dist`, `README.md`, `LICENSE` and `NOTICE`, and the release workflow fails if anything else would ship.

### Has it had an independent penetration test?

Not yet. What exists today is the public security review, the pre-release audit, automated scanning in CI and the test suite. The code is small enough for an internal review: the security-relevant part is a handful of files under `packages/cli/src/http`, `net` and `io`. If your security team reviews it, findings are welcome through the private channel in [SECURITY.md](../SECURITY.md), and reporters are credited.

## Legal and commercial

### Can we use it commercially, in production, and for our customers?

Yes. The license is Apache-2.0: you may use, copy, modify and redistribute BTP Lens, also commercially and inside your company, at no charge. The license includes a patent grant from the contributors. Keep the `LICENSE` and `NOTICE` files when you redistribute it.

### Who is liable if something goes wrong?

Like nearly all open-source software, BTP Lens comes without warranty and without liability (Apache-2.0, sections 7 and 8). There is no contract and no SLA. The design limits what can go wrong: with the recommended role it cannot write to your landscape, and it keeps your data nowhere but your own disk. The open-source project does not offer commercial support today.

### Is it an SAP product? Does using it affect our SAP support or contract?

It is not an SAP product, and it is not affiliated with, endorsed by or sponsored by SAP SE. It uses the public, documented Cloud Foundry v3 API, the same API that the cf CLI and the BTP cockpit use, with your own user and the roles you grant. It does not touch SAP-internal systems or undocumented interfaces. If your contract with SAP or your internal policy has rules about third-party tools, they apply to BTP Lens as to any other tool.

### Could it become paid, or change its license later?

A version you have downloaded stays Apache-2.0: the license on it is perpetual and irrevocable, so nobody can take it back. The [roadmap](roadmap.md) commits to no paid tier. The contributor agreement ([CLA.md](CLA.md) §9) lets the maintainer distribute contributions only under Apache-2.0, a later version of it, or another license approved by the Open Source Initiative, and never under a proprietary license.

### Do you have ISO 27001, SOC 2 or a similar certification?

No, and those certifications would not apply in the usual way. They certify an organization that operates a service and handles your data. BTP Lens is software you run yourself; the project operates no service and receives no data. Your own controls for internal tools apply, and the answers on this page are meant to feed that assessment.

## Maturity, support and continuity

### What does 0.1.0 actually check? Is it ready?

0.1.0 is the first public release, aimed at developers and platform teams. It does three things:

- It inventories every app in the org with its state, buildpacks, stack and current droplet.
- It applies one rule, `APP_NO_RECENT_DEPLOY`: the last deployment is older than 12 months.
- It writes HTML, JSON, CSV and SARIF reports.

After 0.1.0 (unreleased, on `main`, not in the 0.1.0 npm package): `btp-lens project --path <dir>` checks a local CAP or MTA project against thirteen configuration and model rules tagged with the OWASP Top 10 (2025) categories, without any login or network access ([rules.md](rules.md#project-rules), [privacy.md](privacy.md#project-scans)).

The other rules and the `sbom` command are designed and documented in [rules.md](rules.md) and arrive in the next releases ([roadmap](roadmap.md)). Those rules cover end-of-life runtimes and stacks, outdated buildpacks, idle apps, SAPUI5 maintenance, outdated `@sap/*` packages, known CVEs and plain-text secrets. Treat 0.1.0 as an inventory and a first health signal, not as a full security assessment.

### How reliable are the results?

Every rule is documented in [rules.md](rules.md) with its exact logic, evidence and remediation, and every finding carries the facts that triggered it, so you can verify any line of the report. The rules are unit-tested with fixtures, and CI fails if line coverage of the rules drops below 85 % (it is 100 % today). When a check cannot run, for example because a role is missing, the report lists it as skipped, so "nothing found" is never confused with "nothing checked". A user who can see the org but none of its spaces gets an error, not an empty report.

### Who maintains it, and what if the maintainer stops?

Today one maintainer, Sebastiano Marchesini, has write access to the repository and publish rights on npm. That is a real concentration, and the project says so: [governance.md](governance.md) sets the goal of a second maintainer in the first year and defines what happens if the maintainer goes quiet. For you, the risk is limited. BTP Lens is a local program with no server and no license check, so a version you have keeps working as long as the Cloud Foundry v3 API it reads stays compatible. The Apache-2.0 license also lets you, or anyone, fork it and maintain it.

### Is there support or an SLA?

Support comes from the community through GitHub issues, with no SLA. Security reports follow the response times in [SECURITY.md](../SECURITY.md).

### How does it compare with SAP's tools or our existing scanners?

It complements them. Scanners in your CI pipeline look at source repositories; BTP Lens looks at what is actually deployed and running in Cloud Foundry, across a whole org, without installing anything in the landscape. It produces a read-only snapshot that you can archive and compare, and SARIF output that code-scanning tools can read. It does not monitor continuously, raise alerts or fix anything, and it does not replace SAP's operations and monitoring tools.

### Which environments does it support?

- **Platforms:** Cloud Foundry on SAP BTP, in any region. Kyma support is planned for v0.3. Neo and the ABAP environment are out of scope.
- **Operating systems:** Windows, macOS and Linux, with Node.js 22.12 or later.
- **Networks:** it works behind a corporate proxy (`HTTPS_PROXY` with `NODE_USE_ENV_PROXY=1`, on Node.js 22.21 or 24 and later), and behind a TLS-inspecting proxy once you add your company's CA with `NODE_EXTRA_CA_CERTS`.
- **Sign-in and automation:** it works with single sign-on (a one-time code, like `cf login --sso`) and in CI (a token or an OAuth client, `--fail-on`, SARIF output).

## Check it yourself

About 30 minutes for a technical reviewer:

1. **Read the gate.** [`packages/cli/src/net/allowlist.ts`](../packages/cli/src/net/allowlist.ts) is under 200 lines, and it decides every host, method and path the tool may use.
2. **Run the tests** on the release you plan to use:

   ```sh
   git clone https://github.com/sebastianomarchesini/BTP-Lens.git && cd BTP-Lens
   git checkout v0.1.0
   npm ci --ignore-scripts && npm run build && npm test
   ```

3. **Verify the package.** In an empty folder, run `npm install btp-lens@0.1.0 && npm audit signatures`. It should report verified registry signatures and attestations.
4. **Use a minimal user.** Create a technical user with Space Auditor on a non-production space, and run the first scan with it.
5. **Watch the traffic.** Run a scan through your company proxy, or through an inspecting proxy on your machine (set `HTTPS_PROXY`, `NODE_USE_ENV_PROXY=1`, and `NODE_EXTRA_CA_CERTS` pointing to the proxy's CA), and read its log. It should show only `GET` requests to your CF API host and `POST /oauth/token` to your UAA or login host.
6. **Open the report offline.** Disconnect the network and open the HTML file. It works, and the browser's developer tools show no network request.

## Known limits today

- No independent penetration test yet.
- One maintainer, who is also the only npm publisher.
- Most rules are still to come (see the [roadmap](roadmap.md)).
- `report --redact`, for sharing screenshots publicly, does not exist yet.
- Repository settings that only the owner can change, such as branch protection and a second admin, are tracked in [security-review.md §6](security-review.md#6-owner-actions-cannot-be-done-from-a-branch).

Questions that this page does not answer are welcome as GitHub issues. Use the private channel in [SECURITY.md](../SECURITY.md) for anything security-sensitive.
