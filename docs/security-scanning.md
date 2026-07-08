# Security Scanning

The local and CI security gate is:

```sh
npm run ci:aegis
npm run gate:ready
```

The gate performs:

- Aegis catalog generation
- Scope verification
- Passive frontend plan generation
- Passive dry-run execution
- HTML report generation
- AIGate upload readiness check

Report outputs:

- HTML: `.aegis/reports/aegis-report.html`
- SARIF: `.aegis/reports/aegis-report.sarif`

The web console serves the latest HTML report at:

```sh
npm run web
```

Then open `http://127.0.0.1:4317`.
