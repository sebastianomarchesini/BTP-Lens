# Contributing

Thanks for helping improve BTP Lens.

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
