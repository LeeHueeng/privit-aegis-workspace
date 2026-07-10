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
  - `actions/checkout` v7.0.0:
    `9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0`
  - `actions/setup-node` v6.4.0:
    `48b55a011bda9f5d6aeb4c2d9c7362e8dae4041e`
  - `github/codeql-action` v4.37.0:
    `99df26d4f13ea111d4ec1a7dddef6063f76b97e9`
  - `actions/dependency-review-action` v5.0.0:
    `a1d282b36b6f3519aa1f3fc636f609c47dddb294`
  - `ossf/scorecard-action` v2.4.3:
    `4eaacf0543bb3f2c246792bd56e8cdeffafb205a`
  - `actions/upload-artifact` v7.0.1:
    `043fb46d1a93c77aae656e7c1c64a875d1fc6a0a`
  - `actions/attest-build-provenance` v4.1.1:
    `0f67c3f4856b2e3261c31976d6725780e5e4c373`

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

## Public Repository Security Baseline

The repository also runs:

- CodeQL code scanning for JavaScript and TypeScript security analysis.
- Dependency Review on pull requests to block high-severity vulnerable
  dependency introductions.
- OpenSSF Scorecard for open-source security posture signals.
- SBOM generation with CycloneDX and SPDX outputs.
- GitHub artifact attestations for generated SBOM provenance.

Secret scanning, push protection, and Dependabot security updates should stay
enabled in GitHub repository settings. Non-provider secret patterns and validity
checks should be enabled when the account or plan exposes them.

## Branch Protection

Branch protection requires the `AIGate` workflow on `main`, with server-side
enforcement recorded in AIGate settings. `npm run github:ready` should report
`READY` and AIGate should report `100/100`.

## Dependency Audit

`package-lock.json` is committed so `npm audit --audit-level=moderate` runs
deterministically in local checks and CI.
