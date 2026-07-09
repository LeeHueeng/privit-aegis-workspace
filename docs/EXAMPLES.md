# Examples

These recipes show common Privit Aegis workflows. They assume the target is
authorized in `aegis.scope.json`.

## Run the Local Web Console

```sh
npm run setup
npm run web
```

Open `http://127.0.0.1:4317`, confirm the target, choose a language, and run
Start. The console generates catalog data, verifies scope, maps the frontend,
runs passive advisory checks, localizes the HTML report, and creates the
penetration/security testing report.

## Generate Reports from the CLI

```sh
npm run catalog:generate
npm run security:verify
npm run security:map
npm run security:target
npm run security:report
npm run security:penetration
```

Outputs are written under `.aegis/reports/`. The HTML report is localized by
`npm run security:report`; the raw report is available through
`npm run security:report:raw`.

## Check Security Hardening

```sh
npm run security:audit
npm run security:hardening
npm run completion:audit
```

`completion:audit` separates code TODOs from external blockers such as GitHub
repository settings or private-repository Pages limits.

## Prepare for Git Push

```sh
npm run gate
npm run gate:ready
git status --short
git push origin main
```

AIGate is intentionally kept out of the web console. It belongs to git push and
CI readiness, where repository state and branch policies matter.

## Review AI Provider Readiness

```sh
npm run ai:model:show
npm run ai:model:commands
npm run ai:model:check
npm run ai:doctor
```

AI providers can be used for readiness checks and remediation prompts. Passive
scan findings remain deterministic.

## Validate the Documentation Site

```sh
npm run site:check
```

This verifies root multilingual README files, the language index, GitHub Pages
setup notes, the Pages site, JavaScript translations, and required navigation
anchors.
