# Getting started without being a developer

This guide is for administrators, team leads and anyone who has a BTP cockpit login but has never used a terminal on purpose. It takes about five minutes the first time and one minute after that. You do not need the cf CLI, and nothing you do here changes anything in your account.

**You need**

- A BTP login (the one you use for the cockpit) with the **Space Auditor** role in the spaces you want to look at. Space Auditor is read-only. If you do not have it, [send this text to your administrator](permissions.md#asking-for-the-role).
- A Windows or macOS computer where you may install software.

---

## Step 1 · Install Node.js (once, 2 minutes)

BTP Lens runs on Node.js, a free program that many tools use.

1. Open <https://nodejs.org> and click the big **LTS** download button.
2. Run the installer. Accept every default: Next, Next, Install, Finish.
3. Close any terminal windows that were open before the installation.

> Company laptop? If the installer is blocked, ask IT to install "Node.js LTS" for you. It is a common request.

## Step 2 · Open a terminal

- **Windows:** press the Windows key, type `cmd`, press Enter. A black window opens. (PowerShell works too. If it complains about "execution policy", use `cmd` instead, or type `npx.cmd btp-lens` in step 3.)
- **macOS:** press ⌘ + Space, type `Terminal`, press Enter.

Move to a folder you own so the report lands somewhere you can find it. Type this and press Enter:

```
cd Documents
```

## Step 3 · Run BTP Lens

Type this and press Enter:

```
npx btp-lens
```

The first time, `npx` asks whether it may download `btp-lens`. Type `y` and press Enter. Then the guided mode starts:

```
btp-lens 0.1.0 · read-only health check for your Cloud Foundry landscape
Nothing is changed in your account, and nothing is sent anywhere except your own CF API.
Press Ctrl+C at any time to stop; nothing is written until the scan starts.
```

## Step 4 · Answer four questions

**1 · Where is your landscape?**
Pick your region from the list by typing its number, or choose `1` and paste the **API Endpoint** from the BTP cockpit: open your subaccount, look at **Overview → Cloud Foundry Environment**, and copy the address that starts with `https://api.cf.`. BTP Lens checks that it can reach the address before going on.

**2 · Sign in**
Choose **Open a browser and sign in with my company account**. Your browser opens a page from your own landscape's login server. Sign in the way you always do (single sign-on, two-factor, whatever your company uses). The page then shows a **one-time code**. Copy it, go back to the terminal, paste it, press Enter. The code works once and is not stored anywhere.

If you already use the cf CLI, BTP Lens offers your existing login first.

**3 · Which org?**
If you have access to one org, it is chosen for you. Otherwise pick it by number.

**4 · Ready**
BTP Lens tells you how many spaces it can see and where the report will be written, then asks **Start the scan? [Y/n]**. Press Enter.

## Step 5 · Read the report

After a few seconds to a minute the report opens in your browser. If it does not, the terminal shows the path of `btp-lens-report.html`; open that file.

Start with the **Start here** box on the Overview page. It says, in plain words, how many apps were scanned, how many need attention and why. Then look at **Top risky apps**. The **Findings** page explains every item: what it means, what to do, and where to read more.

The report is a single file. You can e-mail it, put it on a shared drive, or print it. It contains the names of your orgs, spaces and apps, so share it only with people who may see those.

## Run it again

Type `npx btp-lens` again. Each run creates a new folder under `Documents\btp-lens-reports\` (Windows) or `Documents/btp-lens-reports/` (macOS) named after the date and time.

---

## When something goes wrong

Type `npx btp-lens doctor` and press Enter. It checks the five things that usually break and tells you what to do about each one, in one sentence:

| It says | What to do |
| --- | --- |
| `FAIL Node.js` | Install the LTS version from nodejs.org, then open a new terminal window. |
| `FAIL Cloud Foundry API: … could not be reached` | You are probably behind a company proxy. Ask IT for the proxy address, then set `HTTPS_PROXY` and `NODE_USE_ENV_PROXY=1` as the message says. |
| `FAIL Cloud Foundry API: … is not trusted` | Your company inspects HTTPS traffic. Ask IT for the company root certificate file and set `NODE_EXTRA_CA_CERTS` to its path. BTP Lens never skips certificate checks. |
| `FAIL Output folder` | Move to a folder you own (`cd Documents`) and try again. |
| "Your user has no role in any Cloud Foundry org" | Ask your administrator for Space Auditor: [text to send](permissions.md#asking-for-the-role). |

Still stuck? Open a [question in Discussions](https://github.com/sebastianomarchesini/BTP-Lens/discussions). Never paste tokens, passwords or your `.cf/config.json` file.

## What BTP Lens does not do

- It does not change, restart, or deploy anything. It only sends read requests.
- It does not send your data anywhere. The only servers it contacts are your own Cloud Foundry API and login server, plus three public reference sites for version information. See [privacy.md](privacy.md).
- It does not record who you are. Your name and e-mail never appear in a report.

*BTP Lens is an independent open-source project, not affiliated with SAP SE.*
