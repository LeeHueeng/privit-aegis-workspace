# Supply-Chain Security

Privit Aegis keeps repository security controls separate from target scanning.
Target scanning remains passive and scope-guarded; repository security protects
the code, workflows, dependencies, and generated artifacts that make up this
workspace.

## Automated Controls

| Control | Workflow | Purpose |
| --- | --- | --- |
| Privit Aegis | `.github/workflows/ci.yml` | AIGate, Aegis checks, hardening baseline, AI readiness |
| CodeQL | `.github/workflows/codeql.yml` | JavaScript security and quality analysis in GitHub code scanning |
| Dependency Review | `.github/workflows/dependency-review.yml` | Blocks high-severity vulnerable dependencies introduced in pull requests |
| OpenSSF Scorecard | `.github/workflows/scorecard.yml` | Publishes open-source security posture signals |
| SBOM and Provenance | `.github/workflows/sbom.yml` | Generates CycloneDX/SPDX SBOM files and attests the CycloneDX artifact |

## Action Pinning

Actions are pinned by commit SHA instead of mutable tags. Version comments stay
next to each action so upgrades remain reviewable.

## Secret Protection

This public repository should keep these GitHub settings enabled:

- Secret scanning
- Push protection
- Dependabot security updates
- Non-provider secret pattern scanning, when available
- Secret validity checks, when available

Do not commit local `.aegis/` reports, real target credentials, cookies, API
tokens, private keys, or customer-specific scope files.

## SBOM Outputs

The SBOM workflow writes:

- `privit-aegis-workspace.cdx.json`
- `privit-aegis-workspace.spdx.json`

The CycloneDX SBOM is attested with GitHub artifact attestations so consumers
can verify where the artifact was generated.
