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

Check the remaining GitHub-side readiness items locally with:

```sh
npm run github:ready
```

To set the secret without printing it in shell history:

```sh
read -s AEGIS_CLI_TOKEN
gh secret set AEGIS_CLI_TOKEN --repo LeeHueeng/privit-aegis-workspace --body "$AEGIS_CLI_TOKEN"
unset AEGIS_CLI_TOKEN
```

## Workflow Pinning

The workflow pins:

- Aegis CLI source commit:
  `f3511404a2d983218b717035eadbd4ec89832d84`
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
repository plan supports protected branches for private repositories.

The readiness check reports this as a TODO until GitHub verifies `AIGate` as a
required status check on `main`.

## Dependency Audit

`package-lock.json` is committed so `npm audit --audit-level=moderate` runs
deterministically in local checks and CI.
