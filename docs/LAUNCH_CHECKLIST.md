# Open Source Launch Checklist

Use this before turning the repository public or promoting it for stars.

## Repository Safety

- [ ] Remove private target URLs or keep them only in ignored local files.
- [ ] Confirm `aegis.scope.json` contains safe demo defaults.
- [ ] Confirm `.aegis/` and generated reports are ignored unless intentionally
      sanitized.
- [ ] Run `npm run gate:ready` and confirm no secrets are detected.
- [ ] Review the GitHub repository visibility before sharing links publicly.

## Project Presentation

- [ ] README has badges, language links, visual preview, quick start, and safety
      model.
- [ ] `README.ko.md`, `README.ja.md`, and `README.zh-CN.md` are in sync with the
      root README promise.
- [ ] GitHub repository description is short and searchable.
- [ ] GitHub topics include security, OWASP, CLI, web security, i18n, and AI
      remediation terms.
- [ ] GitHub Pages is enabled or the workflow summary explains why deployment is
      skipped.

## Quality Gate

```sh
npm run site:check
npm run security:audit
npm test
npm run gate
npm run gate:ready
```

## Suggested GitHub Topics

```text
security-tools, web-security, owasp, penetration-testing, passive-scanner,
security-automation, github-actions, cli, i18n, ai-remediation
```

## Launch Notes

For a public release, create a short announcement that says:

- What problem the project solves
- What makes it safe by default
- Which languages are supported
- How to run the first local report
- How AI is used and where it is not used
