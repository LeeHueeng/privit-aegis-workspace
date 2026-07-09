# Showcase

Privit Aegis is designed to be understood quickly by developers, security
reviewers, and AI coding agents. This page is the short tour for people who are
deciding whether to star, fork, or try the project.

![Privit Aegis console and report preview](./assets/aegis-readme-preview.svg)

## What It Shows Well

- A security tool can be useful without being noisy or destructive.
- The same checks can run from a local web console, CLI, and GitHub Actions.
- Reports can explain what happened instead of only listing findings.
- AI can help with configuration and remediation without inventing scan results.
- Multilingual documentation makes security workflows easier for mixed teams.

## Visitor Journey

1. Read the root README and understand the promise in under a minute.
2. Open the GitHub Pages site or `docs/pages/index.html` locally.
3. Run `npm run setup` and `npm run web`.
4. Confirm the authorized target in `aegis.scope.json`.
5. Run Start from the web console or use the CLI examples.
6. Review the localized Aegis report and penetration/security testing report.
7. Run `npm run gate:ready` before pushing changes.

## Best Demo Flow

```sh
npm run site:check
npm run security:map
npm run security:target
npm run security:report
npm run security:penetration
npm run gate:ready
```

This sequence demonstrates the docs gate, passive discovery, target advisory,
localized report generation, penetration report generation, and AIGate readiness
without running destructive tests.

## Star-Friendly Signals

- Clear README with badges and a visual preview
- Four-language README entry points
- Dedicated examples and launch checklist
- Issue templates for bug reports and feature requests
- Pinned GitHub Actions and least-privilege permissions
- GitHub Pages site that validates even when deployment is unavailable
