# Ease of use: the "basic version for everyone" specification

**Goal.** A person who is not a developer, has never opened a terminal on purpose, and has a normal BTP cockpit login with Space Auditor, gets a readable HTML report of their Cloud Foundry landscape in **under 5 minutes** and without reading any documentation.

> **Status (2026-09-30).** Implemented on this branch: guided mode (`btp-lens` with no arguments: region or pasted endpoint, sign-in with a one-time code or username and password, org pick, confirm, report auto-opened, `--no-open`), `btp-lens doctor`, the "Start here" panel, the no-terminal guide, the FAQ and the administrator text. Still open: the region list needs re-verification against help.sap.com, `report --redact`, the glossary and print stylesheet, `btp-lens reset` and remembering the last scan, single executables (v0.2), and the three usability sessions. Section 8 tracks each item.

This document defines what "basic version" means, who it is for, the exact interaction, and how we measure it. It complements `CLAUDE.md`; where the two differ on UX, this document wins. Nothing here weakens a security or privacy constraint: guided mode uses the same read-only client, the same allow-list and the same Space Auditor defaults.

---

## 1. Who we build for

| Persona | Has | Does not have | Wants |
|---|---|---|---|
| **Anna, BTP administrator** (primary) | Cockpit login via corporate SSO, Space Auditor or Org Auditor in the subaccounts, a Windows laptop behind a proxy | Node.js, the cf CLI, any idea what "npx" is | A list of apps that are risky, in plain language, that she can forward to the team lead |
| **Marco, team lead / architect** | Node.js, the cf CLI, several orgs | Time | Numbers he can put in a slide and a SARIF he can wire into GitHub |
| **Priya, security / compliance** | Read access, audit questions | CF vocabulary | Evidence that nothing was changed and nothing left the machine, plus CSV |

Every screen, message and default is checked against Anna first.

---

## 2. The three tiers

| Tier | Who | How they start | Status |
|---|---|---|---|
| **A. Guided mode** | Anyone with Node.js | `npx btp-lens` (no flags) or double-click a downloaded executable | v0.1 |
| **B. Power mode** | Developers, CI | `btp-lens scan --api … --org …`, GitHub Action | v0.1 CLI, v0.2 Action |
| **C. Browser mode** | Whole teams, no install | Team deploys `btp-lens serve` once on BTP; everyone opens a URL and signs in with SSO | v0.3 |

Tier A is the "basic version for everyone". Tier C is the eventual answer for people who will never install anything; until then Tier A must be good enough that an administrator succeeds with a colleague's help at most once.

---

## 3. Guided mode, step by step

Running `npx btp-lens` with no arguments (or `btp-lens` with no subcommand in an interactive terminal) starts the wizard. Every step has one question, a sensible default, and a one-line explanation. Nothing is written until step 5.

```
BTP Lens  ·  read-only health check for your Cloud Foundry landscape
Nothing is changed in your account and nothing is sent anywhere except your CF API.

Step 1 of 5 · Where is your landscape?
  Paste the "API Endpoint" from the BTP cockpit (Subaccount → Overview → Cloud Foundry Environment)
  or pick a region:
  › eu10 (Frankfurt)    us10 (Virginia)    ap10 (Sydney)    jp10 (Tokyo)    trial (us10-001)    other…

Step 2 of 5 · Sign in
  › Open a browser and sign in with your company account (recommended)
    I already ran "cf login"  (detected: api.cf.eu10.hana.ondemand.com, user found)
    Username and password

  Opening https://login.cf.eu10.hana.ondemand.com/passcode … paste the one-time code here: ______

Step 3 of 5 · Which org and space?
  › All spaces I can see in org "acme-prod"  (3 spaces)
    Pick one space

Step 4 of 5 · What to check
  Standard checks need only the Space Auditor role and change nothing.   [default]
  Deep checks (environment variable names) need Space Developer.         [off in guided mode]

Step 5 of 5 · Ready
  Scan 3 spaces, 41 apps → write the report to ./btp-lens-reports/2026-09-29-1412/ and open it.
  › Start    Change something    Cancel
```

Then a progress line per collector ("Apps 41/41 · Droplets · Processes · Routes · Runtime EOL · UI5 …"), and at the end:

```
Done in 48 s.
  12 findings: 1 critical · 3 high · 6 medium · 2 low
  Report opened in your browser: btp-lens-reports/2026-09-29-1412/report.html
  Share it safely: btp-lens report --redact --from btp-lens-reports/2026-09-29-1412/snapshot.json
```

### 3.1 Decisions behind the wizard

- **Sign in without the cf CLI (Step 2).** The recommended path is the UAA one-time passcode flow, the same one `cf login --sso` uses: the user signs in with corporate SSO in the browser, copies a code, pastes it once. BTP Lens then exchanges the passcode for a token at `POST {uaa}/oauth/token` (already the one permitted non-GET call). The token lives in memory only. **Verify before implementing** (`CLAUDE.md` constraint 7): read `cloudfoundry/cli` `api/uaa` and `command/v7/login_command.go` for the exact grant parameters and the `cf` client, and record them in `docs/data-sources.md` §1.1. Username/password is the fallback; it never works for SSO-only users, so the wizard says so.
- **Region list (Step 1).** A convenience only. The list lives in one JSON file with a "last verified" date and a link to the SAP help page for regions; the pasted URL always wins; UAA and log cache are still discovered from `GET /`, never hard-coded (data-sources §1.1).
- **Org and space by name, never by GUID.** GUIDs appear nowhere in the wizard.
- **`--deep` is not offered in guided mode.** Anna should not be asked to choose a role she does not understand. Deep checks stay a Tier B flag.
- **Output directory:** `./btp-lens-reports/<date-time>/` in the current folder, created `0o700`. On Windows the wizard prints the full path with backslashes. The report opens automatically with the OS default browser (`open`/`start`/`xdg-open`), never by spawning a browser with flags.
- **Re-runs:** the wizard remembers the API URL and org name (not the token) in `~/.config/btp-lens/last-scan.json` and offers "Run the same scan again" as the first choice next time. Delete with `btp-lens reset`.
- **No colour-only meaning.** Severity is always a word plus a symbol; colours are decoration (colour-blind users, plain CI logs).
- **Ctrl+C** at any step exits with code 0 and no files written.

### 3.2 `btp-lens doctor`

Non-developers hit environment problems, not tool problems. `doctor` runs before the wizard when anything fails, and can be run on its own:

| Check | Pass text | Fail text (what to do) |
|---|---|---|
| Node.js version | Node 22.22 ✓ | "BTP Lens needs Node.js 22.12 or newer. Install it from nodejs.org (2 minutes, next-next-finish)." |
| Reaching the API | api.cf.eu10… ✓ 210 ms | "Cannot reach the API. If you are on a company network, set your proxy: `HTTPS_PROXY=http://proxy.company:8080`. Ask IT for the address." |
| TLS interception | Certificate trusted ✓ | "Your company inspects HTTPS traffic. Export the company root certificate and set `NODE_EXTRA_CA_CERTS=C:\path\root.cer`. BTP Lens will never skip certificate checks." |
| Sign-in | Token valid for 11 h ✓ | "Not signed in. Run `npx btp-lens` and choose 'Open a browser'." |
| Role | Space Auditor in 3 spaces ✓ | "You can see the org but no spaces. Ask your admin for the Space Auditor role (read-only) on the spaces you want to scan." |
| Write access | ./btp-lens-reports writable ✓ | "Cannot write here. Move to your Documents folder and try again." |

Each line is one sentence and names one action. No stack traces unless `--verbose`.

### 3.3 Error messages

Rules for every error the CLI prints:

1. First line: what happened, in plain words. Second line: what to do. Optional third line: a link.
2. Never print a stack trace, a request object or an HTTP body by default (also a security rule: SEC-04 in `docs/security-review.md`).
3. Exit code 2 for tool and environment errors, always with a "what to do" line.
4. The 10 most likely errors get hand-written text and a test: no Node, no network, proxy needed, TLS interception, wrong API URL, expired login, no orgs visible, no spaces visible (role), output folder not writable, PowerShell execution policy blocking `npx.ps1` ("run `npx.cmd btp-lens` or use Command Prompt").

---

## 4. Installation paths for people without Node.js

| Path | Effort for the user | Effort for us | When |
|---|---|---|---|
| **Install Node.js, then `npx btp-lens`** | One installer, next-next-finish, then one command | A docs page with screenshots for Windows and macOS (`docs/getting-started-no-terminal.md`) | v0.1 |
| **Single executable** (`btp-lens-win-x64.exe`, `btp-lens-macos-arm64`) built with Node's Single Executable Application feature, attached to each GitHub release | Download, double-click; a terminal window opens the wizard | Build job in CI; unsigned binaries trigger SmartScreen and Gatekeeper warnings, so budget a code-signing certificate (see the marketing plan) | v0.2 |
| **Browser mode on BTP** | Open a URL, sign in with SSO | v0.3 server mode | v0.3 |
| **GitHub Action** | For teams already on GitHub; the report appears as a workflow artifact and SARIF in the Security tab | v0.2 | v0.2 |

We do not ship a Docker image for Tier A; it does not help Anna.

---

## 5. The report, for readers who are not developers

The HTML report is the product most people will actually see. Requirements on top of the UI spec in `CLAUDE.md`:

1. **"Start here" panel on the Overview:** three sentences in plain language generated from the snapshot, e.g. "41 apps were scanned. 4 need attention this month: 1 runs a Node.js version that stopped receiving security fixes, 3 have not been deployed in over a year. Nothing in your account was changed." Then the top three apps to look at.
2. **Every finding has a "What this means" sentence** written for a manager, before the technical evidence. Rule text lives in `docs/rules.md` and is reused verbatim by the UI, so there is one source.
3. **Print to PDF works**: A4 and Letter, page breaks between sections, no dark theme when printing.
4. **"Share safely" button** that explains `report --redact` and what it removes.
5. **Empty and partial states are honest**: "This check was skipped because your role does not allow it (needs Space Developer). Nothing is wrong." rather than an empty table.
6. **Glossary** page: org, space, buildpack, droplet, stack, runtime, EOL, SBOM, CVE, each in one sentence.
7. Phone width works (already in the spec) because reports get opened from e-mail on phones.

---

## 6. Docs for the basic version

- `README.md`: the first screen a visitor sees must show the non-developer path first (`npx btp-lens`), then the developer path. A draft is in `docs/marketing/readme-draft.md`.
- `docs/getting-started-no-terminal.md`: Windows and macOS, with screenshots: install Node.js, open a terminal, paste one command, sign in, read the report. Target length: one screen per step.
- `docs/permissions.md`: written for the person who has to *ask* for a role: "Send this to your administrator: please grant me Space Auditor on spaces X and Y. It is read-only."
- `docs/faq.md`: "Is it safe?", "Will SAP know?", "Does it change anything?", "Why does it need my login?", "What leaves my machine?", "It says my role is insufficient".

---

## 7. How we measure "easy"

No telemetry (constraint 3), so we measure by hand:

- **Usability sessions:** before v0.1.0 and before each minor release, three people matching Anna run the tool on a trial account while we watch and do not help. Success = report open in the browser in under 5 minutes without a question. Record every hesitation as an issue labelled `ux`.
- **First-run failure list:** every environment error seen in sessions and in Discussions gets a hand-written message and a test (§3.3).
- **Docs test:** a person who has never used the tool follows `getting-started-no-terminal.md` on a clean Windows VM once per release.
- **Public signals:** questions in Discussions tagged `how-do-i` (fewer over time is the goal), and the ratio of "it worked" to "it failed" in the launch-week feedback thread.

---

## 8. Requirements summary for the development branch

Hand these to whoever implements v0.1:

- [x] `btp-lens` with no subcommand in a TTY starts the wizard (§3); in a non-TTY it prints usage and exits 2.
- [x] Sign-in options: passcode (SSO), existing cf CLI login, username/password. Passcode flow verified against the cf CLI source and recorded in `data-sources.md` §1.1.
- [x] Region convenience list in one module with a verification date; pasted URL wins. 🟡 Re-verify the list against help.sap.com before 0.1.0.
- [x] `btp-lens doctor` with Node.js, API reachability, TLS trust, cf CLI login and output folder. Open: the role check (needs a signed-in session; guided mode reports it instead).
- [ ] The ten hand-written error messages in §3.3, each with a test. Done: no network, proxy needed, TLS interception, wrong API URL, no orgs visible, no spaces visible, output folder not writable. Open: no Node (cannot be caught from Node itself; covered by the guide), expired login wording, PowerShell execution policy.
- [x] Output in `./btp-lens-reports/<timestamp>/`, report auto-opened, `--no-open` to disable.
- [ ] UI (§5): done "Start here" panel and honest skipped states. Open: "What this means" per finding, print stylesheet, glossary.
- [ ] `report --redact` (also SEC-23).
- [x] `docs/getting-started-no-terminal.md`, `docs/faq.md`, and the administrator-facing wording in `docs/permissions.md`. Screenshots for the guide still to be taken on Windows and macOS.
- [ ] Three usability sessions recorded as issues before tagging 0.1.0.
