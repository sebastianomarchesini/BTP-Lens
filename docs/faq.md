# Frequently asked questions

### Is it safe to run with my production login?

BTP Lens only reads. The HTTP client can send `GET` requests to the Cloud Foundry API and nothing else; the one exception is the login request to your own UAA server. This is enforced in one file (`packages/cli/src/net/allowlist.ts`) and covered by tests that try every other method and fail if one gets through. The Space Auditor role, which is read-only, is all it needs. A public [security review](security-review.md) and a [disclosure policy](../SECURITY.md) exist for the same reason you are asking.

### Will SAP know I ran it?

Cloud Foundry logs API calls like any platform does, and your `GET` requests look like someone browsing the cockpit. BTP Lens sends no telemetry to anyone, including its author. The only thing that leaves your machine besides calls to your own landscape are lookups of public version information (end-of-life dates, known vulnerabilities, the SAPUI5 version list), and those requests carry no data about your landscape apart from, for vulnerability lookups, the names and versions of open-source packages in your own software bill of materials.

### Does it change anything?

No. It cannot: non-`GET` requests to the Cloud Foundry API are refused before they are sent. One thing to know: with the optional `--deep` flag, reading environment variable **names** creates an audit event in your landscape (`audit.app.environment_variables.show`). Guided mode never uses `--deep`.

### Why does it need my login?

Because the Cloud Foundry API only answers people with a role. BTP Lens uses your own identity, so it sees exactly what you see in the cockpit, no more. The one-time code you paste in guided mode works once, is exchanged for a session token held in memory, and is gone when the program ends. Nothing is written to disk except the report.

### What leaves my machine?

Requests to your CF API and login server, and to `api.osv.dev`, `endoflife.date`, `ui5.sap.com` and `registry.npmjs.org` for public version data. The full list, with what is sent to each, is in [privacy.md](privacy.md). The HTML report itself carries a Content Security Policy with `connect-src 'none'`, so even the browser refuses to let it connect anywhere.

### It says my role is insufficient. What now?

You can see the org but not the spaces, or a check was skipped. Ask your administrator for **Space Auditor** on the spaces you want to scan; [permissions.md](permissions.md#asking-for-the-role) has the text to send. Skipped checks are listed in the report so that "nothing found" is never mistaken for "nothing checked".

### Can I share the report?

Yes, it is one file that works without a network. It contains your org, space, app and route names, so treat it like any internal document. A `--redact` option that replaces those names with stable placeholders is planned for v0.1 so that screenshots can be shared publicly.

### Is this an SAP product?

No. BTP Lens is an independent open-source project (Apache-2.0). It is not affiliated with, endorsed by or sponsored by SAP SE. "SAP", "SAP BTP" and "SAPUI5" are trademarks of SAP SE, used only to describe compatibility.

### I am a developer. Do I have to use the wizard?

No. `btp-lens scan --api <url> --org <name>` does the same without questions, reads your cf CLI session or `BTP_LENS_ACCESS_TOKEN`, and has `--fail-on` for CI. See the [README](../README.md#commands).

### What does it cost?

Nothing, now and later. If it saves your team an afternoon, the repository has a Sponsor button; sponsorship never influences what the tool reports.
