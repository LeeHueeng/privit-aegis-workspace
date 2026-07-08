# Privit Aegis Workspace

Local security testing workspace for the Privit web app. It wraps the Aegis CLI
and AIGate so a developer can generate the check catalog, verify scope, run a
passive dry run, and open an HTML report from one local console.

## Start

```sh
npm run setup
npm run web
```

Open `http://127.0.0.1:4317` to review scope settings, run checks, and view the
latest HTML report.

## Quality Gate

```sh
npm run ci:aegis
npm run gate:ready
```

All configured checks are passive by default. Active or destructive tests must
be approved in scope before they are added.

## AI Assistants

```sh
npm run ai:integrate
npm run ai:doctor
npm run ai:report
```

Codex, Gemini, and Claude share the same Aegis scope, AIGate quality gate, and
upload workflow. See `docs/ai-integration.md`.
