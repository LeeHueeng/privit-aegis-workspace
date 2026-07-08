# Branch Strategy

Privit uses a merge-request based flow for this security workspace.

- Protected branches: `main`, `develop`
- Work branches: `codex/*`, `feature/*`, `feat/*`, `fix/*`, `docs/*`, `chore/*`
- Every merge request should include the Aegis report status and AIGate result.
- Security scope changes should stay in focused branches so reviewers can audit
  target URLs, allowed paths, and denied paths.

Before upload:

```sh
npm run ci:aegis
npm run gate:ready
```
