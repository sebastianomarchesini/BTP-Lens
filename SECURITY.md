# Security policy

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Report them privately through GitHub's [private vulnerability reporting](https://github.com/sebastianomarchesini/BTP-Lens/security/advisories/new) for this repository.

Include what you found, how to reproduce it, and the impact. We aim to acknowledge reports within 5 working days and to agree on a disclosure date with you.

## Scope

These properties are security guarantees, and anything that breaks one is in scope:

- **Read-only:** no request other than `GET` reaches the Cloud Foundry API.
- **Egress:** no request goes to a host outside the allow-list (`packages/cli/src/net/allowlist.ts`), and no credentials go to any host other than the CF API and UAA.
- **No secrets or personal data** in snapshots, reports or console output.
- **The HTML report** makes no network request when opened, and data from the scanned landscape cannot inject script into it.

## Supported versions

Until 1.0, only the latest release gets security fixes.
