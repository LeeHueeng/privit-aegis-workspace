# Privit Aegis Workspace

<p align="center">
  <a href="https://github.com/LeeHueeng/privit-aegis-workspace/actions/workflows/ci.yml"><img alt="AIGate" src="https://github.com/LeeHueeng/privit-aegis-workspace/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/LeeHueeng/privit-aegis-workspace/actions/workflows/pages.yml"><img alt="GitHub Pages" src="https://github.com/LeeHueeng/privit-aegis-workspace/actions/workflows/pages.yml/badge.svg"></a>
  <img alt="Passive by default" src="https://img.shields.io/badge/security-passive%20by%20default-0f766e">
  <img alt="Multilingual" src="https://img.shields.io/badge/i18n-ko%20%7C%20en%20%7C%20ja%20%7C%20zh-2563eb">
</p>

<p align="center">
  <a href="./README.ko.md">한국어</a> ·
  <a href="./README.md">English</a> ·
  <a href="./README.ja.md">日本語</a> ·
  <a href="./README.zh-CN.md">中文</a> ·
  <a href="https://leehueeng.github.io/privit-aegis-workspace/">GitHub Pages</a>
</p>

Privit Aegis Workspace is an authorized security testing console for the Privit
web app. It combines the Aegis CLI, a local web console, passive site discovery,
deterministic web security checks, localized reports, AI-assisted remediation
prompts, and AIGate push readiness in one repo.

The project is built for approved assets only. It is passive by default,
scope-guarded, and designed to show exactly what was checked, what passed, what
failed, and what evidence was retained.

## Why Star It

- Web console and CLI workflows live together, so local testing and CI use the
  same security baseline.
- Korean, English, Japanese, and Chinese documentation are first-class entry
  points instead of afterthought translations.
- Reports explain executed checks, pass criteria, redacted evidence, and
  recommended fixes.
- AI is optional and transparent: it helps with provider readiness and
  remediation prompts, while scan findings stay deterministic.
- GitHub Actions are pinned, scoped to least privilege, and separated from local
  AIGate/git-push workflows.

## Live Documentation

- Public project site after Pages is enabled: <https://leehueeng.github.io/privit-aegis-workspace/>
- Security scanning guide: [`docs/security-scanning.md`](./docs/security-scanning.md)
- Hardening baseline: [`docs/security-hardening-baseline.md`](./docs/security-hardening-baseline.md)
- AI integration: [`docs/ai-integration.md`](./docs/ai-integration.md)
- GitHub workflow security: [`docs/github-security-hardening.md`](./docs/github-security-hardening.md)
- GitHub Pages setup: [`docs/github-pages.md`](./docs/github-pages.md)
- Language index: [`docs/LANGUAGES.md`](./docs/LANGUAGES.md)

## Quick Start

```sh
npm run setup
npm run web
```

Open `http://127.0.0.1:4317` to review scope settings, run checks, and view the
latest localized HTML report.

## Security Checks

Aegis keeps the default workflow low-impact:

- Generates a security-check catalog and validates authorized scope.
- Discovers same-scope routes, links, forms, auth surfaces, sitemap entries, and
  blocked URLs.
- Reviews browser security headers, authentication cache posture, cookies,
  forms, redirect-like parameters, API surfaces, GraphQL/OpenAPI/OIDC/JWKS
  metadata, CORS/CSP quality, SRI, mixed content, bundle leakage, and sensitive
  public files.
- Produces an HTML report plus a penetration/security testing report that lists
  executed checks, pass criteria, and redacted evidence.

All configured checks are passive by default. Discovery follows only allowlisted
hosts and paths, does not submit forms, and does not run brute-force or
destructive tests.

## Quality Gate

```sh
npm run site:check
npm run security:audit
npm run security:hardening
npm run ci:aegis
npm run gate:ready
```

`AIGate` is reserved for git push and CI quality gates. The local web console
focuses on Aegis actions such as catalog generation, scope verification,
discovery, target advisory checks, localized reports, and penetration reports.

## AI Assistants

```sh
npm run ai:integrate
npm run ai:doctor
npm run ai:report
npm run ai:model:show
npm run ai:model:check
npm run ai:settings:show
```

Codex, Gemini, Claude, local AI, and direct API providers share the same scope
and handoff model. AI does not decide passive scan results; it supports
configuration checks, provider readiness, remediation prompts, and optional
AIGate AI reports.

## Repository Map

- `scripts/`: local console, report localization, hardening checks, AI settings,
  GitHub readiness, and report generation helpers.
- `docs/`: security guides, multilingual human/agent guides, roadmap, and Pages
  documentation.
- `docs/pages/`: GitHub Pages static site.
- `.github/workflows/`: pinned CI and GitHub Pages workflows.
- `catalog/`: generated Aegis security-check catalog.

## GitHub Pages

The Pages site is deployed from `docs/pages` through
`.github/workflows/pages.yml`. The workflow uses GitHub Pages Actions with
minimal permissions: `contents: read`, `pages: write`, and `id-token: write`.
See [`docs/github-pages.md`](./docs/github-pages.md) for the activation command
and private-repository plan note.

## Security Model

This repository is for authorized security testing only. Do not add production
credentials, live payment paths, destructive actions, or third-party systems
unless written authorization is recorded in `aegis.scope.json`. Secrets,
cookies, tokens, passwords, API keys, private keys, email addresses, and payment
identifiers are redacted before reporting.

## Contributing

Issues, feature ideas, docs improvements, and carefully scoped security checks
are welcome. Start with [`CONTRIBUTING.md`](./CONTRIBUTING.md), keep changes
passive by default, and run the local quality gate before opening a PR.
