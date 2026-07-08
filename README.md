# Privit Aegis Workspace

Local security testing workspace for the Privit web app. It wraps the Aegis CLI
and AIGate so a developer can generate the check catalog, verify scope, run a
passive frontend site map, and open an HTML report from one local console.

## Repository Layout

- `LeeHueeng/privit-project`: Aegis CLI engine source. This is where scanner
  logic, reports, scope guards, and multilingual CLI behavior live.
- `LeeHueeng/privit-aegis-workspace`: Privit-specific workspace. This repo keeps
  local scope, web console wiring, AI integration, GitHub workflow, and reports.

## Start

```sh
npm run setup
npm run web
```

Open `http://127.0.0.1:4317` to review scope settings, run checks, and view the
latest HTML report.

The console supports Korean, English, Japanese, and Chinese. The Discovery tab
controls same-scope passive crawling depth, page limits, sitemap paths, and
login-route indicators.

## Quality Gate

```sh
npm run security:audit
npm run ci:aegis
npm run gate:ready
```

All configured checks are passive by default. Discovery follows only allowlisted
hosts and paths, does not submit forms, and does not run brute-force tests.
Active or destructive tests must be approved in scope before they are added.

## AI Assistants

```sh
npm run ai:integrate
npm run ai:doctor
npm run ai:report
npm run ai:model:show
npm run ai:model:check
```

Codex, Gemini, and Claude share the same Aegis scope, AIGate quality gate, and
upload workflow. Local AI and direct API providers can also be enabled from the
AI tab or with `npm run ai:model:set -- --provider local --enable`. See
`docs/ai-integration.md`.

## GitHub Security

The GitHub workflow pins Aegis and AIGate versions, runs `npm audit`, and
requires an `AEGIS_CLI_TOKEN` repository secret because the Aegis CLI source
repository is private. See `docs/github-security-hardening.md`.
