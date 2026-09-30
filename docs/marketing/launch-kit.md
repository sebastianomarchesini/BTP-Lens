# Launch kit: ready-to-adapt copy

Drafts for every channel in `campaign.md`. Replace `<…>` placeholders, keep every claim true of the released version, and keep the non-affiliation line wherever the word SAP appears. Tone: plain, specific, no hype words.

> **Claims check (2026-09-30).** True today: read-only GET-only client with tests, allow-list in one file, offline single-file report with a `connect-src 'none'` CSP, guided mode with company-login sign-in, `doctor`, Space Auditor sufficiency, no telemetry, `APP_NO_RECENT_DEPLOY`. **Not yet true:** the other eight rules, `report --redact`, downloadable executables, "three non-developer testers" (run the sessions first). Edit each draft against this list on launch day.

---

## 1. SAP Community blog post (flagship, ~900 words)

**Title options**

- Which of your BTP Cloud Foundry apps are running on borrowed time? A free, read-only scanner
- I built a read-only health check for BTP Cloud Foundry landscapes. Here is what it found in mine.

**Outline and draft**

> **Why I built it**
> Every BTP landscape I have worked on had the same unanswered questions. Which apps still run a Node.js version that no longer gets security fixes? Which ones sit on cflinuxfs3? Which were deployed once in 2023 and never touched again? Which ship a dependency with a known CVE? The cockpit shows one space at a time, and the scripts people write against the CF API are never something a security team wants to see run with production credentials.
>
> **What BTP Lens is**
> BTP Lens is a free, open-source command-line tool. You run it on your own machine with your own login, it reads your Cloud Foundry landscape, and it writes an HTML report you can open offline, plus JSON, CSV and SARIF. It is read-only by construction: the HTTP client can only issue GET requests to the CF API, and a unit test proves it. It needs the Space Auditor role. Nothing is sent anywhere except your CF API and three public data sources (OSV.dev for CVEs, endoflife.date for runtime dates, the SAPUI5 version feed), and the list of allowed hosts is one file in the repository.
>
> **Five minutes, no flags**
> `npx btp-lens` starts a guided mode: paste your API endpoint from the cockpit, sign in with your company account in the browser, pick the org, and the report opens. I tested it with three colleagues who are not developers; all three had a report open in under five minutes. (Insert the demo GIF.)
>
> **What it checks in v0.1** (link to `docs/rules.md`)
> Runtime end of life (Node.js, Java/SapMachine), outdated buildpacks, deprecated stacks, idle apps, apps without a deployment in 12 months, SAPUI5 versions out of maintenance, outdated `@sap/*` packages, known CVEs in your SBOM, and, only if you ask for it with a developer role, environment variable names that look like secrets (names only, never values).
>
> **What it found in a real landscape** (redacted screenshot)
> <numbers from your evidence log: N apps, x% on EOL runtime, y idle, z with CVEs>
>
> **Privacy and trust**
> No telemetry. No user names or e-mails in reports. Secrets are never printed. The security review is public in the repository, as is the disclosure policy. Independent project, Apache-2.0, not affiliated with SAP.
>
> **Try it, break it, tell me**
> `npx btp-lens` on a trial account takes two minutes. Issues and Discussions are open; questions from non-developers are welcome. If it saves you a week of clicking, the repository has a Sponsor button.
>
> *BTP Lens is not affiliated with, endorsed by or sponsored by SAP SE. SAP, SAP BTP and SAPUI5 are trademarks of SAP SE.*

---

## 2. LinkedIn launch post

> Which of your BTP Cloud Foundry apps are running on borrowed time?
>
> I built BTP Lens to answer that in five minutes: a free, open-source, read-only scanner. One command, your own login, an offline HTML report.
>
> ✔ Read-only: the client can only send GET requests, and a test proves it
> ✔ Works with the Space Auditor role
> ✔ Nothing leaves your machine except calls to your CF API and three public data sources
> ✔ Guided mode for admins who have never used a terminal
>
> It checks runtime end of life, deprecated stacks, outdated buildpacks, idle apps, SAPUI5 maintenance, outdated @sap packages and known CVEs.
>
> "<quote from tester 1>" — <name, role>
>
> npx btp-lens → <repo link>
>
> Independent project, not affiliated with SAP. Feedback, issues and stars welcome.

(Attach the demo GIF or the social card. Post between 08:00 and 10:00 CET on a Tuesday or Wednesday.)

---

## 3. X thread (6 posts)

1. Your BTP Cloud Foundry landscape has apps on EOL runtimes and deprecated stacks. You just cannot see them from the cockpit. I built a free, read-only scanner that shows them in 5 minutes. 🧵
2. `npx btp-lens` → guided mode → sign in with your company account → report opens. No flags, no config file. Works for admins who have never used a terminal. (GIF)
3. Read-only by construction: the HTTP client refuses anything but GET to the CF API, and a unit test proves it. Space Auditor role is enough.
4. Nothing leaves your machine except calls to your CF API, OSV.dev, endoflife.date and the UI5 version feed. The allow-list is one file. No telemetry. No user names in reports.
5. v0.1 checks: Node/Java EOL, deprecated stacks, outdated buildpacks, idle apps, 12-month-old deploys, UI5 out of maintenance, outdated @sap packages, known CVEs.
6. Open source, Apache-2.0, independent (not affiliated with SAP). Try it on a trial account and tell me what breaks: <repo link>

---

## 4. Reddit r/SAP

**Title:** I made a free, read-only CLI that finds EOL runtimes, deprecated stacks, idle apps and known CVEs across a BTP Cloud Foundry landscape

**Body:** two paragraphs from §1 ("What BTP Lens is" and "Privacy and trust"), the rule list, the link, and: "Happy to answer questions here, including 'is it safe to run with prod creds'. Short version: Space Auditor, GET only, allow-listed hosts, no telemetry, open source."

---

## 5. Show HN

**Title:** Show HN: BTP Lens – read-only scanner for Cloud Foundry landscapes on SAP BTP

**Body:**

> Hi HN. Cloud Foundry landscapes on SAP's platform accumulate apps that nobody looks at: Node 16 runtimes, cflinuxfs3 stacks, apps last deployed in 2023, dependencies with known CVEs. The platform cockpit shows one space at a time. BTP Lens is a TypeScript CLI that reads the CF v3 API with GET only (enforced in the client, covered by a test), needs only the read-only Space Auditor role, and writes an offline single-file HTML report plus JSON/CSV/SARIF. Outbound hosts are allow-listed in one file; no telemetry.
>
> Things I would like feedback on: the egress allow-list design, the CSV/HTML injection handling for attacker-controlled app names, and whether the guided mode is actually usable by non-developers (three testers say yes; I am biased).
>
> Independent project, Apache-2.0, not affiliated with SAP.

---

## 6. YouTube demo script (3 minutes)

| Time | On screen | Say |
|---|---|---|
| 0:00 | Cockpit with many spaces | "Forty apps, six spaces, and one question: which ones are risky? Clicking through takes an afternoon." |
| 0:20 | Terminal, `npx btp-lens` | "One command. No flags." |
| 0:35 | Wizard step 1–3 | "Paste the API endpoint from the cockpit, sign in in the browser, pick the org." |
| 1:05 | Progress lines | "It reads with GET only and the Space Auditor role. Nothing is changed." |
| 1:30 | Report opens, Overview | "Start here: three sentences a manager can read. Then the top apps to look at." |
| 2:00 | Findings page, one card | "Every finding says what it means, what to do and where to read more." |
| 2:30 | `report --redact` | "Share it safely: names are replaced before you post a screenshot." |
| 2:45 | Repo page | "Free, open source, independent. Link below." |

---

## 7. E-mail to seed testers (Phase 0)

**Subject:** 15 minutes to try a read-only BTP landscape scanner before it goes public?

> Hi <name>,
>
> I am about to release BTP Lens, a free, open-source, read-only CLI that scans a BTP Cloud Foundry org and reports EOL runtimes, deprecated stacks, idle apps, outdated SAP packages and known CVEs as an offline HTML report. It needs only Space Auditor and only sends GET requests (there is a test for that).
>
> Could you run `npx btp-lens@next` against a trial or a non-critical org this week and answer three questions? (1) Did the report open within five minutes? (2) What confused you? (3) One sentence I may quote in the launch post, if you like it.
>
> If anything looks like a security problem, please tell me privately first (SECURITY.md in the repo).
>
> Thank you,
> Sebastiano

---

## 8. Sponsor pitch e-mail (companies)

**Subject:** Sponsoring BTP Lens: your logo in front of every BTP platform team that scans their landscape

> Hi <name>,
>
> Your team showed up in the BTP Lens Discussions, so you already know what it does: an independent, read-only landscape scanner that platform teams and consultants use for BTP Cloud Foundry assessments. In its first <N> days it has <downloads> downloads and <stars> stars, with no marketing budget.
>
> I am raising a small, transparent budget: a code-signing certificate so administrators can double-click an executable without warnings, and one maintainer day per week so releases stay monthly. The Landscape sponsor tier (USD 500/month) puts your logo in the README and on the public sample report, gives you a quarterly 30-minute roadmap call, and names you in the yearly "State of BTP CF landscapes" report. Sponsorship never influences what the tool reports, and it does not imply any SAP endorsement.
>
> Would a 20-minute call next week work?
>
> Sebastiano Marchesini
> Maintainer, BTP Lens · SAP Champion

---

## 9. Talk abstract (20 minutes)

**Title:** Your BTP landscape in five minutes: read-only scanning for runtime EOL, idle apps and CVEs

**Abstract:** Most BTP Cloud Foundry landscapes carry apps on end-of-life runtimes, deprecated stacks and year-old deployments, and nobody can list them. This session shows how to get a full inventory and a prioritised findings list in five minutes with BTP Lens, a free, open-source CLI that needs only the Space Auditor role and can only issue GET requests. We look at how the read-only guarantee is enforced and tested, what leaves your machine (almost nothing) and how to share results safely. Live demo on a trial account, then the rules and how to add your own. For administrators, architects and security teams; no coding required.

**Slides (12):** the problem · one command · the report · read-only by construction · what leaves the machine · the nine rules · a real landscape (redacted) · for non-developers · SARIF in GitHub · roadmap · how to help · not affiliated with SAP / links.

---

## 10. README sponsor section

> ## Support the project
>
> BTP Lens is free and will stay free. If it saved you an afternoon of clicking, consider [sponsoring](https://github.com/sponsors/sebastianomarchesini). Current goal: a code-signing certificate so administrators can run the downloadable executable without warnings. Sponsors are listed in `SPONSORS.md`; sponsorship never influences what the tool reports.

---

## 11. Short forms

- **npm description:** Read-only scanner for SAP BTP Cloud Foundry landscapes: app inventory, runtime EOL, deprecated stacks, idle apps, SAPUI5 maintenance, outdated @sap packages and known CVEs, as an offline HTML report. Not affiliated with SAP.
- **GitHub About:** Read-only health check for BTP Cloud Foundry landscapes. One command, five minutes, nothing leaves your machine.
- **Topics:** `sap-btp`, `cloud-foundry`, `security-scanner`, `sbom`, `sarif`, `typescript`, `cli`, `ui5`, `devops`, `eol`
