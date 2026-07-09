# Security Policy

This workspace is for authorized Privit security testing only.

## Scope

- Default frontend target: `http://localhost:3000`
- Default mode: passive
- Reports: `.aegis/reports/`
- Catalog: `catalog/security-checks.jsonl`

Do not add production credentials, live payment paths, destructive actions, or
third-party systems unless written authorization is recorded in `aegis.scope.json`.

## Scanning

Run the local gate before upload:

```sh
npm run site:check
npm run ci:aegis
npm run gate:ready
```

Generate SARIF when a CI or review system needs machine-readable security data:

```sh
aegis report --format sarif
```

Secrets, cookies, tokens, passwords, API keys, private keys, email addresses,
and payment identifiers are redacted from Aegis reports.
