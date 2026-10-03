# Contributing

Thanks for helping improve BTP Lens. It is an open-source project in the plain sense: everything is Apache-2.0, the roadmap and governance are public (`docs/roadmap.md`, `docs/governance.md`), and contributions from people who are not developers count just as much as code. Please read the [Code of Conduct](CODE_OF_CONDUCT.md).

## Ways to contribute without writing code

- **Test guided mode** on a trial account and tell us where you hesitated (open a Discussion, label `ux`).
- **Propose a rule** with the "Rule proposal" issue template. You describe the problem; someone else can implement it.
- **Improve the docs**: fix a sentence, add a screenshot, translate `docs/getting-started-no-terminal.md`.
- **Answer questions** in Discussions. Non-developers helping non-developers is the best thing that can happen here.
- **Share a redacted report** (once `report --redact` exists) so we can see real-world shapes.

## Your first code contribution in 15 minutes

1. Fork and clone, then `npm ci && npm run build && npm test`. Everything runs offline; there are no live calls in tests.
2. Pick an issue labelled `good first issue` (the list also lives in `docs/roadmap.md`). Each names the file to touch and the test to add.
3. Make the change, then `npm run lint && npm run typecheck && npm run format:check && npm test`.
4. Open a pull request. The template has a short security checklist. A maintainer replies within 24 hours on working days and will pair with you if anything is unclear.
5. You are named in the changelog and the release notes unless you prefer not to be.

## Adding a rule (the most valuable contribution)

A rule is one analyzer file, one test, and one section in `docs/rules.md`:

1. **Check the data source first.** Confirm the endpoint, fields and roles in `docs/data-sources.md`; if the rule needs something not listed there, verify it against the CF v3 docs and add it. Rules must work with Space Auditor unless they are `--deep`.
2. **Create `packages/cli/src/analyzers/<ruleName>.ts`** exporting an `Analyzer` (see `noRecentDeploy.ts`): the `rule` metadata (id, title, description, roles, `helpUri` from `ruleHelpUri`), the collector checks it `requires`, and a pure `analyze(context)` that returns `Finding[]` from `context.raw`. No clock, no network: `context.now` is the scan time so `report --from` stays reproducible.
3. **Register it** in `ANALYZERS` in `packages/cli/src/analyzers/index.ts` (report order).
4. **Test it** in `packages/cli/test/unit/analyzers.test.ts` with the `acme` fixture or a small inline `RawData`: one case that fires, one that does not, one edge case. Analyzers must stay above 85% line coverage (CI checks).
5. **Document it** in `docs/rules.md`: id, what it detects, severity logic, evidence fields, remediation text and references. The UI reads the same text.
6. If the rule adds a plain-language phrase for the report's "Start here" panel, add it to `packages/ui/src/data/summary.ts`.

## Contributor License Agreement (required)

Every contribution needs a signed **Contributor License Agreement (CLA)** before it can be merged. The CLA confirms that you have the right to contribute your change, and that the project may distribute it under the Apache License 2.0.

The CLA text and the automatic check that asks first-time contributors to sign are still being set up. Until they are, a maintainer will send you the CLA before merging. Pull requests without a signed CLA are not merged.

## Ground rules

These come from the project constraints in `CLAUDE.md`:
- **Read-only:** never add a CF API call other than `GET`. The egress allow-list and its tests must stay green.
- **Least privilege:** every check declares the CF roles it needs, and a 403 must skip the check, never fail the scan.
- **No new outbound hosts** without an update to `docs/data-sources.md` and `docs/privacy.md`.
- **No personal data or secret values** in any output. Extend the leak test when you add a field.
- **Verify, don't assume:** before touching a collector, confirm the endpoint, fields and roles in the Cloud Foundry v3 docs, and record what you confirmed in `docs/data-sources.md`.
- **No SAP branding** in names or logos.

## Workflow

```sh
npm ci
npm run build
npm run lint && npm run typecheck && npm run format:check
npm test             # no live calls; use fixtures in packages/cli/test/fixtures
npm run e2e          # after `npm run sample`
```

- Fixtures are synthetic or anonymized. Never commit real GUIDs, names, hosts or tokens from a customer landscape.
- When you change a rule or the report data, regenerate the golden samples with `UPDATE_SAMPLE=1 npm test -w btp-lens` and review the diff.
- Document new rules in `docs/rules.md`: the id, severity logic, evidence and remediation.
