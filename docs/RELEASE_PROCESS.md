# Release Process

This repository is currently a workspace, not a published npm package. Releases
still help users understand milestones and security posture.

## Before a Release

```sh
npm run site:check
npm run security:audit
npm test
npm run gate
npm run gate:ready
npm run completion:audit
```

`completion:audit` may report external blockers such as private Pages support or
branch protection. Resolve code TODOs before release; document external blockers
in release notes.

## Release Notes

Use GitHub's generated release notes. `.github/release.yml` groups changes into:

- Security checks
- Web console
- Documentation
- AI and automation
- Other changes

## Versioning

Use small version increments for workspace milestones. A release should include:

- User-facing changes
- Validation commands
- Known external blockers
- Any scope or safety model changes
- Links to updated docs

## Public Launch Release

Before the first public launch:

1. Run the launch checklist.
2. Confirm repo visibility and Pages support.
3. Confirm `aegis.scope.json` uses safe demo defaults.
4. Confirm all generated reports are ignored or sanitized.
5. Tag the launch commit.
