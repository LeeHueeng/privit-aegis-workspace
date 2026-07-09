# Privacy and Data Handling

Privit Aegis is designed to keep security testing evidence local, minimal, and
redacted.

## Local Data

Generated data is written under `.aegis/` and `.aigate/reports/`. These paths are
ignored by git by default, except for placeholder files. Review and sanitize any
generated artifact before sharing it.

## Report Redaction

Reports should redact or avoid storing:

- Authorization headers
- Cookies
- Tokens
- Passwords
- API keys
- Private keys
- Email addresses
- Payment identifiers
- Sensitive query or fragment values

## Evidence Policy

Passive checks should retain the smallest useful evidence:

- URL path instead of full sensitive URL when possible
- Header names and security-relevant values
- Cookie names and attributes, not cookie values
- Form field names, not submitted values
- Metadata fields, not secrets
- Finding IDs and pass criteria

## AI Provider Boundaries

AI features are optional. AI can help with readiness checks, provider settings,
and remediation prompts, but passive scan results are deterministic. Do not send
private report data to external AI providers unless the target owner has
approved that data flow.

## Public Launch

Before making the repository public, confirm:

- `aegis.scope.json` does not contain private target URLs.
- Generated `.aegis/` reports are not committed.
- The README links to `aegis.scope.example.json` for safe demos.
- Issue templates ask reporters to redact sensitive data.
