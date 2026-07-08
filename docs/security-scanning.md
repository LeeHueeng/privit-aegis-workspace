# Security Scanning

The local and CI security gate is:

```sh
npm run ci:aegis
npm run security:hardening
npm run gate:ready
```

The gate performs:

- Aegis catalog generation
- Scope verification
- Passive frontend plan generation
- Passive frontend site discovery
- OWASP/GitHub hardening baseline review
- HTML report generation
- AIGate upload readiness check

Report outputs:

- HTML: `.aegis/reports/aegis-report.html`
- SARIF: `.aegis/reports/aegis-report.sarif`
- Hardening: `.aegis/reports/security-hardening.json`

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
