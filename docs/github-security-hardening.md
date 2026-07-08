# GitHub Security Hardening

This repository is private and installs the private Aegis CLI from
`LeeHueeng/privit-project` during GitHub Actions.

## Required Secret

Create a fine-grained GitHub token for `LeeHueeng/privit-project` with the
minimum repository read permissions needed to clone the source repository, then
store it in this repository as:

```text
AEGIS_CLI_TOKEN
```

Do not reuse a broad local `gh` token for CI. Rotate this token if it is exposed
or if the Aegis CLI repository access changes.

## Workflow Pinning

The workflow pins:

- Aegis CLI source commit:
  `f3511404a2d983218b717035eadbd4ec89832d84`
- AIGate CLI package: `aigate-cli@0.1.7`
- GitHub Actions:
  - `actions/checkout` v4.2.2:
    `11bd71901bbe5b1630ceea73d27597364c9af683`
  - `actions/setup-node` v4.4.0:
    `49933ea5288caeca8642d1e84afbd3f7d6820020`

Update both intentionally after reviewing release notes and rerunning:

```sh
npm run ci:security
```

The workflow also sets `permissions: contents: read`, applies a job timeout,
pins GitHub actions by full commit SHA, and uses `persist-credentials: false` on
checkout so the workflow token is not left in the local git configuration.
`security:hardening` verifies these controls in local and CI runs.

## Branch Protection

AIGate reports `89/100` until GitHub server-side enforcement is verified. Enable
branch protection or required status checks for the `AIGate` workflow when the
repository plan supports protected branches for private repositories.

## Dependency Audit

`package-lock.json` is committed so `npm audit --audit-level=moderate` runs
deterministically in local checks and CI.
