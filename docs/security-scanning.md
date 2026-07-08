# Security Scanning

The local and CI security gate is:

```sh
npm run ci:aegis
npm run security:hardening
npm run security:target
npm run completion:audit
npm run gate:ready
```

The gate performs:

- Aegis catalog generation
- Scope verification
- Passive frontend plan generation
- Passive frontend site discovery
- Frontend response header, auth-page cache, cookie flag, and autocomplete advisory
- Completion audit for CLI, web, i18n, AI providers, target advisory, and GitHub readiness
- OWASP/GitHub hardening baseline review
- HTML report generation
- AIGate upload readiness check

Report outputs:

- HTML: `.aegis/reports/aegis-report.html`
- SARIF: `.aegis/reports/aegis-report.sarif`
- Hardening: `.aegis/reports/security-hardening.json`
- Frontend advisory: `.aegis/reports/frontend-advisory.json`

The web console serves the latest HTML report at:

```sh
npm run web
```

Then open `http://127.0.0.1:4317`.

Frontend discovery starts from the configured base URL, follows only in-scope
links, reads `robots.txt` and `sitemap.xml` when present, inventories forms, and
records login-like routes without submitting credentials.

The hardening baseline is documented in `docs/security-hardening-baseline.md`.
It checks local scope safety, web-console security headers, GitHub Actions
permissions, checkout credential persistence, job timeout, and passive
authentication/CSRF advisories.

The frontend advisory is also passive. It reuses the latest discovered site map
and only requests in-scope HTML/auth-like URLs. It checks the live target for
OWASP-style response header coverage, `Cache-Control: no-store` on
authentication-like pages, defensive cookie attributes, and password-manager
autocomplete hints. It does not submit forms or send attack payloads.

Use `npm run completion:audit` when iterating on the workspace. It reports code
TODO items separately from external GitHub blockers such as repository secrets
or private-repository branch protection limits.
