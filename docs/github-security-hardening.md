# GitHub Security Hardening

This repository installs the public Aegis CLI source from
`LeeHueeng/privit-project` during GitHub Actions. No private deploy key or
fine-grained repository token is required for the CLI install path.

Check the remaining GitHub-side readiness items locally with:

```sh
npm run github:ready
```

## Workflow Pinning

The workflow pins:

- Aegis CLI source commit:
  `e5bcf4d0bac456a44b9548084cd8366fcc00c0a3`
- AIGate CLI package: `aigate-cli@0.1.7`
- GitHub Actions:
  - `actions/checkout` v5.0.1:
    `93cb6efe18208431cddfb8368fd83d5badbf9bfd`
  - `actions/setup-node` v5.0.0:
    `a0853c24544627f65ddf259abe73b1d18a591444`

Update both intentionally after reviewing release notes and rerunning:

```sh
npm run ci:security
```

GitHub Actions uses `npm run ci:aegis:github`, which intentionally avoids the
live `localhost:3000` crawl because the hosted runner does not own the local
target app. Run `npm run ci:security` locally when the target app is running to
refresh site-map and form evidence.

The workflow also sets `permissions: contents: read`, applies a job timeout,
pins GitHub actions by full commit SHA, and uses `persist-credentials: false` on
checkout so the workflow token is not left in the local git configuration.
`security:hardening` verifies these controls in local and CI runs.

## Branch Protection

AIGate reports `89/100` until GitHub server-side enforcement is verified. Enable
branch protection or required status checks for the `AIGate` workflow when the
repository plan supports protected branches.

The readiness check reports this as a TODO until GitHub verifies `AIGate` as a
required status check on `main`.

## Dependency Audit

`package-lock.json` is committed so `npm audit --audit-level=moderate` runs
deterministically in local checks and CI.
