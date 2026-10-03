# BTP Lens: go-to-market and sponsorship plan

**Working name:** BTP Lens. **One line:** *The free, read-only health check for your SAP BTP Cloud Foundry landscape. One command, five minutes, nothing leaves your machine.*

**This is an open-source project, and the plan is written as one.** The goal is not "customers" but a community that uses, trusts, improves and eventually co-maintains BTP Lens. Marketing here means three things, in this order: (1) getting the project **used and contributed to**, (2) getting it **seen** by the people who need it, and (3) getting it **funded** enough to stay maintained, without ever selling access to a feature or a finding. §0 sets the rules; everything else follows from them. Everything here assumes v0.1.0 ships with guided mode (`docs/ease-of-use.md`) and the security posture in `docs/security-review.md`, because both are the story.

Dates are relative to **L = the day v0.1.0 is on npm**. Updated 2026-09-30; the calendar below assumes L in the second half of October 2026, which lines up with the SAP community's autumn events (Devtoberfest, TechEd season, SAP Inside Tracks). If L slips, shift the calendar, not the sequence.

### Where we stand (2026-09-30)

| Story we want to tell | State | Evidence |
|---|---|---|
| Read-only, GET-only, allow-listed | **Shipped** (slice 1) and re-reviewed; credential endpoints now refused even for GET | `packages/cli/src/net/allowlist.ts`, `docs/security-review.md` |
| Report cannot phone home | **Shipped**: CSP `connect-src 'none'` in the HTML, Playwright test with networking disabled | `e2e/offline-report.spec.ts` |
| Five minutes, no flags, for administrators | **Shipped on the development branch**: guided mode, `doctor`, "Start here" panel, no-terminal guide, FAQ | `docs/ease-of-use.md` §8 |
| Nine rules | **1 of 9** (`APP_NO_RECENT_DEPLOY`); the rest are the next slices | `docs/rules.md` |
| Public sample report | Workflow ready (`.github/workflows/pages.yml`); needs Pages enabled once | landing page in `docs/marketing/landing.html` |
| Sponsor button | `FUNDING.yml` and `SPONSORS.md` ready; needs GitHub Sponsors enrolment | — |
| npm name | **Still unclaimed** on 2026-09-30. Reserve before the first public post. | `npm view btp-lens` |

Every public claim must match the "Shipped" rows. Until the remaining rules land, launch copy says "checks in v0.1 include …" only for what exists, and lists the rest as "coming in the next releases".

---

## 0. Open source is the strategy, not a checkbox

These rules are binding for every post, tier, asset and decision below. When something in this plan conflicts with them, the rules win.

1. **Everything stays free and open.** Apache-2.0 for all of it: every rule, every report format, guided mode, server mode when it comes. There is no "pro" tier, no gated feature, no enterprise fork. The only thing sponsorship buys is maintainer time.
2. **Build in public.** Roadmap (`docs/roadmap.md`), decisions (`docs/data-sources.md` §7), the security review, the evidence log and the funding numbers are all in the repository. Announcements link to issues and pull requests, not to landing pages.
3. **Contributions beat broadcasts.** A merged pull request from a stranger is worth more than a thousand impressions. Every metric in §3 that counts people (contributors, rule proposals, answered questions) outranks every metric that counts views.
4. **The community owns the rule catalogue.** Rules are how the tool gets smarter. Anyone can propose one with the "Rule proposal" issue template, and the maintainer's job is to make adding a rule a one-file, one-test, one-doc change (see `CONTRIBUTING.md`).
5. **Governance is written down before it is needed.** Who decides what, how someone becomes a maintainer, and what happens if the maintainer disappears: `docs/governance.md`. Companies adopt tools with a bus factor above one; contributors join projects that will let them in.
6. **A Code of Conduct, enforced.** `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1). Non-developers asking basic questions are the audience, not a nuisance.
7. **Sponsorship is transparent and never buys influence.** Public tiers, public sponsor list, public funding goals, and a written promise in `SPONSORS.md` that money never softens a check or hides a finding.
8. **No dark patterns.** No telemetry, no "sign up to see the sample", no newsletter gate, no mailing list scraped from issues, no astroturfed reviews, no SAP branding or implied endorsement.
9. **Credit generously.** Contributors in the release notes and the changelog by name (if they wish), testers quoted with permission, the "one rule, explained" posts co-authored with whoever wrote the rule.

The word "open source" appears in the first sentence of every launch post, and the link goes to the repository, never to a brochure.

## 1. Positioning

### The problem, in the words of the buyer

"We have 40, 400 or 4,000 apps on BTP Cloud Foundry across dozens of subaccounts. Nobody can say which ones run an end-of-life Node.js or Java, which are on a deprecated stack, which have not been deployed in a year, or which ship a library with a known CVE. Finding out means clicking through the cockpit space by space, or writing scripts against the CF API that nobody trusts to be read-only."

### What BTP Lens is

- A **CLI** you run on your laptop or in CI with your own credentials. It calls the CF API with **GET only**, enforced in the HTTP client and proven by a test.
- Works with **Space Auditor**, the read-only role. Anything needing more is off by default.
- Produces an **offline HTML report** in the Fiori look (plus JSON, CSV, SARIF) from one snapshot.
- **No telemetry, no account, no SaaS.** The only outbound hosts are your CF API, OSV.dev, endoflife.date and the UI5 version feed, listed in one file.
- **Open source, Apache-2.0**, independent, not affiliated with SAP.

### Five message pillars (use at least two in every piece of content; "Open" is always one of them in launch week)

| Pillar | Proof we can point at |
|---|---|
| **Trust**: read-only, nothing leaves your machine | GET-only unit test, allow-list file, `SECURITY.md`, OpenSSF Scorecard badge, the security review in the repo |
| **Speed**: five minutes from `npx` to report | The guided-mode demo GIF, timed in the usability sessions |
| **Actionable**: every finding has a remediation and a link | `docs/rules.md`, screenshots of a finding card |
| **For everyone**: admins and managers, not only developers | Guided mode, the "Start here" panel, the no-terminal getting-started guide |
| **Open**: Apache-2.0, built in public, yours to extend | The repository itself, `docs/roadmap.md`, `docs/governance.md`, the "Rule proposal" template, contributors named in every release |

### Objections and answers

| They say | We say |
|---|---|
| "I will not run an unknown tool with production credentials." | Read-only role, GET-only client with a test, allow-list in one file, open source, Scorecard and CodeQL public. Run it on trial first; run `report --redact` to share results. |
| "SAP already has this." | The cockpit shows one space at a time and has no EOL, CVE or idle logic. Cloud ALM and the Alert Notification service monitor operations, not dependency and runtime age. BTP Lens is the missing landscape-wide inventory and it complements them. |
| "I can script the CF API myself." | You can; the value is the rules, the EOL and CVE data joined in, the report, and the fact that it is maintained. Your script is welcome as a contribution. |
| "Is this an SAP product?" | No. Independent open-source project; the README says so. |
| "What does it cost?" | Nothing. If it saves you a week, sponsor it (§6). |

### Naming and trademark risk

"SAP" never appears in the package, CLI or logo (`CLAUDE.md` constraint 6), and the README carries the non-affiliation notice. "BTP" on its own is descriptive of the platform, and we use it descriptively, but a trademark objection is not impossible. Mitigation: keep the notice everywhere, avoid SAP's blue and its logo shapes in ours, reserve a fallback package name (`cf-lens` or `landscape-lens`) at the same time as `btp-lens`, and decide in advance that we rename rather than argue.

---

## 2. Audiences and where they are

| Segment | Size and role | Where they read | What converts them |
|---|---|---|---|
| **BTP administrators and basis teams** | Run subaccounts; often not developers | SAP Community (Q&A, blogs), LinkedIn groups, internal SAP CoE newsletters | Guided mode demo, "send this to your admin" role text |
| **Developers and architects** | Build and operate the apps | SAP Community, GitHub, X, YouTube, Reddit r/SAP, dev.to, Devtoberfest, CodeJams | `npx` quickstart, SARIF in GitHub, the rules doc |
| **Security and compliance** | Ask "which apps have CVEs?" | LinkedIn, internal audit requests | Read-only proof, CSV export, `SECURITY.md`, CVE rule |
| **SAP partners and consultancies** | Do landscape assessments for clients | Partner networks, LinkedIn, events | A repeatable assessment report they can brand around; sponsorship (§6) |
| **Community multipliers** | SAP Champions, SAP Mentors, Developer Advocates, newsletter and podcast hosts | Direct message | Early access, a quote in the launch post, a co-presented session |

Your own position as an SAP Champion is the single biggest asset: the Champions and Mentors network is the seed list for pre-launch testing (§4, Phase 0).

---

## 3. Goals and metrics (no telemetry, so these are the only numbers)

Community metrics come first and decide whether the plan is working; reach metrics come second and only explain why.

| Metric | Source | L+30 | L+90 | L+180 |
|---|---|---|---|---|
| **External contributors (merged PR)** | GitHub | 2 | 6 | 12 |
| **Rule proposals from others** (issue template) | GitHub | 3 | 10 | 20 |
| **Rules contributed by others** (merged) | GitHub | 0 | 2 | 5 |
| **Questions answered by someone other than the maintainer** | Discussions | 0 | 5 | 20 |
| **Good-first-issues closed by first-time contributors** | GitHub | 1 | 5 | 12 |
| **Second maintainer** with merge rights | governance.md | — | — | 1 |
| GitHub stars | GitHub | 150 | 500 | 1,000 |
| npm weekly downloads | npmjs.com | 200 | 800 | 2,000 |
| Unique visitors to the repo | GitHub Insights → Traffic | 2,000 | 8,000 | 15,000 |
| Discussions threads by people other than the maintainer | GitHub | 15 | 60 | 120 |
| Talks and podcast appearances | log | 1 | 4 | 8 |
| Sponsors (individual / company) | GitHub Sponsors | 5 / 0 | 20 / 1 | 40 / 3 |
| Mentions by name in SAP Community content by others | search | 3 | 10 | 25 |

Keep an **evidence log** (`docs/marketing/evidence-log.md`, started; keep it private if you prefer): date, metric snapshot, links to every talk, article, mention, adoption e-mail and quote. It is what you need for sponsor pitches, award nominations, grant applications and any application where you must document impact.

---

## 4. Campaign phases

### Phase 0: Pre-launch (now → L−1)

0. **Finish the product story first**: the remaining v0.1 rules, `report --redact` (needed so testers can share screenshots), and the three usability sessions. Marketing before that burns the one launch a project gets.
1. **Reserve the names today**: `btp-lens` on npm (placeholder 0.0.1, see security review §3), the fallback name, a GitHub Discussions space, and the social handles you intend to use.
1a. **Make the repository contributor-ready** (done on the development branch): `CODE_OF_CONDUCT.md`, a `CONTRIBUTING.md` with a 15-minute first contribution and the recipe for adding a rule, `docs/roadmap.md`, `docs/governance.md`, the "Rule proposal" issue template. Then seed **ten `good first issue` items** from `docs/roadmap.md` §"Good first issues", each with the file to touch and the test to add, and enable Discussions with categories "Q&A", "Show your report (redacted)", "Rule ideas".
1b. **Enable GitHub Pages** (Settings → Pages → Source: GitHub Actions) so `pages.yml` publishes the landing page and the sample report at `https://sebastianomarchesini.github.io/BTP-Lens/`.
2. **Assets** (§5): logo, social card, demo GIF, sample report on GitHub Pages.
3. **README** rewritten from `docs/marketing/readme-draft.md`: pitch, `npx` first, permissions table, privacy statement, screenshot, non-affiliation notice, sponsor section.
4. **Seed testers**: 10 people from the Champions and Mentors network plus 3 non-developers (for the usability sessions in `ease-of-use.md` §7). Ask each for one sentence of feedback you may quote and one redacted screenshot.
5. **Three quotes** secured for the launch post.
6. **Pitch the SAP Community**: ask whether a launch blog can be featured; ask two newsletter curators to hold a slot in launch week.
7. **Line up one talk**: a Devtoberfest or SAP Inside Track slot, or a community call, within 30 days of L.
8. **Enable GitHub Sponsors** and set the tiers (§6) so the button exists on day one.
9. Dry run: a colleague follows the README on a clean laptop; fix what breaks.

### Phase 1: Launch week (L → L+7)

| Day | Action |
|---|---|
| L | Tag v0.1.0, publish to npm with provenance, GitHub release with changelog and executables (if ready). Repo topics set. |
| L | SAP Community blog post (the flagship; draft in `launch-kit.md` §1). |
| L | LinkedIn post with the demo GIF and the three quotes; X thread; Reddit r/SAP; dev.to cross-post. |
| L+1 | "Show HN" and Lobste.rs, written for a non-SAP audience: "a read-only landscape scanner for Cloud Foundry". |
| L+2 | 3-minute YouTube demo, unlisted first for the testers, public on L+2. |
| L+3 | Answer every comment and Discussion within 24 hours all week. Convert each question into a FAQ entry. |
| L+5 | "What we learned in the first 5 days" post: bugs fixed, first external PR, download count. |
| L+7 | v0.1.1 with launch-week fixes. Thank testers publicly. |

### Phase 2: Sustain (L+7 → L+90)

One piece per week, alternating channels, always with a redacted real screenshot:

- **"One rule, explained"** series (nine rules = nine posts): what it detects, why it matters, what to do. Each doubles as documentation.
- **Case studies**: "We scanned 300 apps in a Fortune-500 landscape: 18% on an EOL runtime" (with the customer's permission, or on a trial landscape).
- **Live sessions**: a CodeJam-style 45-minute "scan your trial account with me" session, recorded.
- **Integrations**: GitHub Action (v0.2) launch post targeted at platform teams.
- **Community answers**: search SAP Community Q&A and Reddit weekly for "cflinuxfs3", "Node.js end of life BTP", "buildpack outdated" and answer with the tool where it genuinely helps. Never spam; one link, real help.
- **Contributor care**: reply to every first pull request within 24 hours, pair on it if needed, merge generously and polish afterwards. A first-timer who gets a kind review comes back; one who waits two weeks does not.
- **"Add your own rule" post** at L+30: the recipe from `CONTRIBUTING.md`, with a real community-proposed rule as the example.
- **Sponsor pitch** to three consultancies and three product companies that showed up in Discussions (§6), always after they have contributed or adopted, never cold.

### Phase 3: Compounding (L+90 → L+365)

- Propose sessions to SAP TechEd, SAP Inside Tracks, reBTP-style community conferences, and DSAG/ASUG user groups where you have access.
- Yearly "State of BTP CF landscapes" report from opt-in aggregate statistics (roadmap "Later" item). This is the single most linkable asset the project can produce and the strongest reason for companies to sponsor.
- Contributor programme: label `good first issue` weekly, keep the 15-minute path in `CONTRIBUTING.md` green, a monthly community call once there are 5 regular contributors, and offer maintainer rights (per `docs/governance.md`) to the first person who has sustained contributions for three months. The project's success condition is that it survives its founder.
- Apply for open-source support programmes that fit (GitHub Sponsors matching where available, OpenSSF resources, cloud credits for CI); record each in the evidence log.
- Kyma support (v0.3) opens the second half of the BTP audience.

---

## 5. Assets checklist

| Asset | Spec | Owner / cost |
|---|---|---|
| Logo | A lens/aperture mark, no SAP blue (#0070F2) or SAP logo shapes; SVG plus 512 px PNG; works in Horizon light and dark | **Draft done:** `docs/assets/logo.svg` (from the UI); a designer pass is optional |
| Social card | 1280×640, logo, one line, "read-only · offline · open source" | **Draft done:** `docs/assets/social-card.svg`; export to PNG for LinkedIn and X, which do not accept SVG |
| Demo GIF | 20 s, guided mode → report opens, on a trial account, redacted names | Terminal recording (asciinema → GIF) |
| Sample report | The fixture-generated HTML on GitHub Pages: `https://sebastianomarchesini.github.io/BTP-Lens/sample-report.html` | **Done:** `.github/workflows/pages.yml` + `docs/marketing/landing.html`; owner enables Pages once |
| Landing page | One screen: tagline, `npx btp-lens`, four proof cards, links, non-affiliation | **Done:** `docs/marketing/landing.html` |
| Screenshots | Overview, Apps table, one finding card; light and dark | From the sample report |
| Badges | npm version, license, CI, OpenSSF Scorecard, "read-only: GET-only tested" | README |
| Slide deck | 12 slides for a 20-minute talk (`launch-kit.md` §9) | Maintainer |
| Code-signing certificate | For Windows/macOS executables (v0.2) | ~USD 200–400/year; first sponsorship goal |

---

## 6. Sponsorship programme

### What sponsorship is, and is not

Sponsorship funds **maintainer time** on an open-source project. It does not buy features, priority fixes, private builds, early access, or a say in what the tool reports. The roadmap call in the higher tiers is a conversation, not a vote; the roadmap stays public and the maintainers decide. Consultancies and product companies get a tool their clients trust *because* it is independent, and a public "we fund the commons we use" association. Individuals get a thank-you. Be explicit that sponsorship **never** buys a check being softened or a finding being hidden, and never implies SAP endorsement. Money is reported in the evidence log once a quarter: what came in, what it paid for.

### Tiers (GitHub Sponsors; add Open Collective when a company needs an invoice)

| Tier | Monthly | They get |
|---|---|---|
| Supporter | USD 5 | Name in `SPONSORS.md`, sponsor badge |
| Backer | USD 25 | Above, plus name in the release notes |
| Team | USD 150 | Small logo in the README sponsors row |
| Landscape sponsor | USD 500 | Logo in README and on the sample-report page, a quarterly 30-minute conversation about the public roadmap, named in the yearly report |
| Founding sponsor (first three only) | USD 1,500 | Above, plus "founding sponsor" for life, one workshop per year for their team |

### Funding goals, stated publicly

1. USD 300/month: code-signing certificate and domain, so non-developers can double-click an executable without warnings.
2. USD 1,000/month: one day per week of maintainer time; monthly releases guaranteed.
3. USD 3,000/month: a second maintainer; v0.3 server mode on a fixed date.

### Prefer the open-source channels

Use **GitHub Sponsors** first (no fees for the project, visible on the repository). Add **Open Collective** when a company needs an invoice: its ledger is public by design, which fits §0.7. Do not set up a private bank-transfer path.

### Non-monetary sponsorship

- **Landscapes**: companies that let you scan a real (non-trial) landscape and quote anonymised numbers are worth more than money in year one. Offer a private readout in exchange.
- **Time**: a partner assigning one engineer for a slice (for example SBOM for Java).
- **Reach**: a newsletter or podcast feature.

### Sponsor pitch, in one paragraph (e-mail draft in `launch-kit.md` §8)

"BTP Lens is the independent, read-only landscape scanner your consultants and your clients' platform teams already use for assessments. We are funding a code-signing certificate and one maintainer day a week so it stays trustworthy and current. A Landscape sponsorship puts your logo in front of every reader of the README and the yearly report and gives you a quarterly say on the roadmap. It never influences what the tool reports."

---

## 7. Twelve-week calendar (from L)

| Week | Content | Channel | Pillar |
|---|---|---|---|
| 1 | Launch post, demo, Show HN, Reddit | Community blog, LinkedIn, X, HN, Reddit, YouTube | Trust, Speed |
| 2 | "Nothing leaves your machine": the allow-list and GET-only test, explained | Blog, LinkedIn | Trust |
| 3 | Rule 1: `RUNTIME_NODE_EOL` and why 90 days matters | Blog, X | Actionable |
| 4 | "For admins, not only developers": guided mode walkthrough with a non-developer tester | LinkedIn, YouTube | For everyone |
| 5 | Rule 2: `STACK_DEPRECATED` (cflinuxfs3) with real numbers | Blog | Actionable |
| 6 | Live session: scan your trial account with me | Community call / CodeJam, recorded | Speed, For everyone |
| 7 | Rule 3: `DEP_KNOWN_CVE` and SARIF in GitHub code scanning | Blog, dev.to | Actionable, Trust |
| 8 | Case study 1 (anonymised) | LinkedIn, blog | All |
| 9 | Rule 4: `APP_IDLE` and cost | Blog | Actionable |
| 10 | GitHub Action (v0.2) launch | Blog, X, HN | Speed |
| 11 | Rule 5: `UI5_OUT_OF_MAINTENANCE` | Blog | Actionable |
| 12 | 90-day retrospective: numbers, contributors, sponsors, what is next; sponsor drive | Blog, LinkedIn | All |

Rules 6–9 continue the series in weeks 13–20.

---

## 8. Rules of engagement

- Never post a screenshot with real org, space, app or route names. Use `report --redact` or the fixture report.
- Never claim SAP endorsement, partnership or review. Never use the SAP logo.
- Answer every issue and Discussion within 48 hours during the first 90 days.
- Every claim in a post must be true of the released version, not the roadmap. Roadmap items are labelled as such.
- Numbers come from the evidence log, with a date.
- Every launch post says "open source, Apache-2.0" in its first sentence and links the repository.
- Contributors are credited by name in the post about the thing they built. Never present community work as the maintainer's.
- When someone forks or builds a competing tool, link to it and wish them well. Open source is not a zero-sum market.

---

## 9. Budget

| Item | Cost | Needed by |
|---|---|---|
| Logo and social card | USD 0–300 | L−14 |
| Domain (optional, e.g. `btplens.dev`) | ~USD 15/year | L−14 |
| Code-signing certificate (Windows EV or OV + Apple Developer ID) | USD 200–400/year + USD 99/year | v0.2 |
| Everything else | USD 0 | — |

The plan works at zero budget; the certificate is the only spend that changes what non-developers experience, which is why it is funding goal 1.
