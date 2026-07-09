# Contributing

Thanks for helping make Privit Aegis clearer, safer, and easier to trust.

## Before You Start

- Keep security checks passive unless explicit scope authorization exists.
- Do not commit credentials, tokens, cookies, live payment data, or private
  customer data.
- Keep documentation changes multilingual when the public entry point changes.
- Prefer deterministic checks over AI-generated security conclusions.

## Local Validation

```sh
npm run site:check
npm run security:audit
npm run security:hardening
npm run ci:aegis
npm run gate:ready
npm run ai:doctor
```

`npm run completion:audit` is useful while iterating. It may report external
GitHub blockers separately from code TODOs.

## Pull Requests

Include:

- What changed and why
- Which commands passed
- Whether `aegis.scope.json` changed
- Whether any new check can submit forms, mutate state, or touch third-party
  systems

PRs that add security checks should document:

- Detection purpose
- Pass criteria
- Evidence retained in reports
- Scope and safety limitations

## Documentation

When editing a root README section, update the matching language files:

- `README.md`
- `README.ko.md`
- `README.ja.md`
- `README.zh-CN.md`

For deeper guides, use the locale folders under `docs/`.
