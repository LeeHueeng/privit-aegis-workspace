# Security Policy

This workspace is for authorized Privit security testing only.

## Supported Version

The `main` branch is the active public workspace line.

## Scope

- Default frontend target: `http://localhost:3000`
- Default mode: passive
- Reports: `.aegis/reports/`
- Catalog: `catalog/security-checks.jsonl`

Do not add production credentials, live payment paths, destructive actions, or
third-party systems unless written authorization is recorded in `aegis.scope.json`.

## Reporting

Do not open public issues containing secrets, private target data, exploit
payloads, or sensitive reports. Use GitHub private vulnerability reporting or a
private maintainer contact channel.

When reporting a vulnerability, include the affected command or web workflow,
the target class, expected safe behavior, observed behavior, and a minimal
reproduction that stays inside authorized test targets.

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

## Repository Guardrails

- The `main` branch requires AIGate, CodeQL, and Dependency Review before merge.
- Secret scanning, push protection, and Dependabot security updates are enabled
  at the repository level.
- GitHub Actions workflows use pinned action SHAs and least-privilege
  permissions.
- Destructive, brute-force, exfiltration, persistence, and evasion behavior must
  remain disabled by default.
