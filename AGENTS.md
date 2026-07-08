# AIGate Agent Instructions

This directory is an authorized security testing workspace.

- Keep Aegis runs passive unless `aegis.scope.json` explicitly allows a stronger mode.
- Run `npm run ci:aegis` before pushing changes that affect security checks,
  reports, scope, CI, or scripts.
- Run `npm run gate:ready` before upload.
- Use `npm run ai:report` for AI handoff context before larger security changes.
- Use `npm run ai:prompt` only to create a remediation prompt; do not auto-apply
  AI edits unless the user explicitly asks for that.
- Do not commit generated `.aegis/` report artifacts unless the reviewer asks for
  a specific evidence bundle.
- Keep GitHub Actions and GitLab CI gate files intact; do not remove them to work
  around token or workflow permission issues.
