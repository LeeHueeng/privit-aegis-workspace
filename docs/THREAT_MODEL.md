# Threat Model

This threat model covers the Privit Aegis workspace repository and local web
console. It does not cover the target application itself.

## Assets

- Authorized target scope in `aegis.scope.json`
- Local generated reports under `.aegis/`
- AIGate reports under `.aigate/reports/`
- GitHub Actions credentials and repository secrets
- AI provider settings and environment variables
- Public Aegis CLI source reference

## Trust Boundaries

- Local developer machine
- Target application selected in scope
- GitHub Actions runner
- Public Aegis CLI repository
- Optional external AI providers
- GitHub Pages static site

## Primary Risks

| Risk | Mitigation |
| --- | --- |
| Private target URLs committed publicly | Keep safe demo scope in `aegis.scope.example.json`; review launch checklist |
| Generated reports leaking sensitive data | Ignore `.aegis/`; redact report outputs; review before sharing |
| CI token over-permission | Use least-privilege workflow permissions and `persist-credentials: false` |
| Supply-chain drift in workflows | Pin third-party actions to commit SHA |
| AI exfiltration of private report data | Keep AI optional and document provider boundaries |
| Unsafe scanning against unauthorized targets | Scope verification, passive defaults, denied paths, safety flags |
| GitHub Pages misconfiguration | Validate static site and skip deploy when Pages is unavailable |

## Non-Goals

- Brute force
- Credential stuffing
- Persistence
- Data exfiltration
- Destructive payload execution
- Live payment testing
- Unauthorized third-party testing

## Review Cadence

Review this model when:

- New scanner behavior is added
- A new external provider is integrated
- Scope file behavior changes
- GitHub workflow permissions change
- The repository is made public
