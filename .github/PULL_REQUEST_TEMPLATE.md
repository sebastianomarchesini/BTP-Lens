## What

<!-- One or two sentences. Link the issue if there is one. -->

## Security checklist

- [ ] No new HTTP method other than GET against the CF API; no new outbound host outside `docs/data-sources.md` §6.
- [ ] Nothing user-controlled is inserted into HTML, CSV or terminal output without escaping.
- [ ] No tokens, e-mails, real hostnames or real GUIDs in fixtures or tests.
- [ ] New checks declare their CF role and skip on 403.
- [ ] `docs/data-sources.md` and `docs/rules.md` updated if a collector or rule changed.

## How it was tested

<!-- Commands run, fixtures added. -->
