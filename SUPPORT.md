# Support

Privit Aegis is an authorized security testing workspace. Support requests must
avoid secrets, private target data, and unauthorized system details.

## Best Channels

- Bugs: use the bug report issue template.
- Feature ideas: use the feature request template.
- Security-sensitive reports: follow `SECURITY.md`.
- Usage questions: include sanitized commands, sanitized scope snippets, and the
  exact validation step that failed.

## What to Include

- Workspace commit or branch
- Operating system and Node.js version
- Command that failed
- Redacted output
- Whether the target is local, staging, or demo
- Confirmation that the target is authorized

## What Not to Include

- API keys, cookies, passwords, private keys, tokens, or session IDs
- Live customer data
- Private target URLs unless disclosure is approved
- Exploit payloads against unauthorized systems
- Generated reports that have not been reviewed and sanitized

## Response Expectations

This repository prioritizes safe, passive, reproducible workflows. Requests that
would require destructive testing, third-party targets, brute force, or live
payment flows should be converted into documentation or safe local fixtures
first.
