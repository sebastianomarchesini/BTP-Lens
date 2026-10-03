# Governance

BTP Lens is an independent open-source project under the Apache License 2.0. This page says who decides what, how to gain that responsibility, and what happens if a maintainer goes quiet. It is deliberately short; it grows when the project does.

## Roles

| Role | Who | Can |
| --- | --- | --- |
| **Maintainer** | Sebastiano Marchesini (founder) | Merge, release, publish to npm, change this document, moderate |
| **Reviewer** | anyone the maintainers name after sustained contributions | Approve pull requests in the areas they know; cannot merge security-sensitive paths alone (see `.github/CODEOWNERS`) |
| **Contributor** | anyone with a merged pull request | Named in the changelog and release notes; may propose rules and vote in polls |
| **User** | anyone | Open issues and Discussions, propose rules, share redacted reports |

## How decisions are made

1. **Small changes** (a rule, a fix, a doc): one maintainer or reviewer approval on the pull request. Lazy consensus: if nobody objects within three working days, it goes in.
2. **Changes to the non-negotiables** (`CLAUDE.md` constraints: read-only, least privilege, allow-list, privacy, no secrets, no SAP branding): need a maintainer approval **and** an entry in `docs/data-sources.md` §7 or `docs/security-review.md` explaining why. These constraints are the project's identity; loosening one is a governance decision, not a code review.
3. **Roadmap** (`docs/roadmap.md`): proposed by anyone in an issue, ordered by the maintainers in public, revised at each minor release. Sponsors get a conversation, not a vote.
4. **Disagreements** are settled on the issue in writing. If two maintainers disagree, the founder decides until there are three or more, then a simple majority.

## Becoming a reviewer or maintainer

- **Reviewer:** three or more merged, non-trivial pull requests over at least two months, and a track record of constructive review comments. A maintainer proposes you in a public issue; you accept.
- **Maintainer:** reviewer for at least three months, familiar with the security review and the release process, 2FA on GitHub and npm. Existing maintainers agree in a public issue. The first external maintainer is an explicit goal for the project's first year (see `docs/marketing/campaign.md` §3).

Rights are removed the same way they are granted: in public, with a reason, and with thanks.

## If a maintainer goes quiet

If the only maintainer has not responded to issues or pull requests for **60 days**, any reviewer may open an issue titled "Maintainer inactivity" and notify the maintainer by every listed channel. After a further **30 days** without response, the reviewers may agree, in that issue, to add one of themselves as maintainer, using the emergency access below.

To make that possible, from the first release onward: a second person holds publish rights on npm (via trusted publishing from CI, not a personal token), the GitHub repository has at least one other admin or is transferred to an organisation, and the domain (if any) has a second contact. These are owner actions and are tracked in `docs/security-review.md` §6.

## Money

Sponsorship (GitHub Sponsors, and Open Collective when invoices are needed) pays for maintainer time and for the costs listed in `docs/marketing/campaign.md` §9. Income and spend are summarised in `docs/marketing/evidence-log.md` every quarter. Nobody's approval or merge can be bought; see `SPONSORS.md`.

## Trademarks and naming

"BTP Lens" is the project's name. It does not use SAP's logo, and it states everywhere that it is not affiliated with SAP SE. If a trademark objection is ever raised, the project renames rather than argues (`docs/marketing/campaign.md` §1). Forks are welcome under the licence; please pick a different name so users are not confused.

## Changing this document

Pull request, maintainer approval, and a note in the changelog. Anyone can propose a change.
