# FAQ

## Is this a scanner or a workspace?

It is a Privit-specific workspace around the Aegis CLI. The reusable scanner
engine lives in `LeeHueeng/privit-project`, while this repository keeps scope,
local web-console orchestration, reports, CI, AI settings, and docs.

## Why are there two repositories?

They have different jobs. `privit-project` is the reusable CLI engine and should
stay small, package-like, and easy to install. `privit-aegis-workspace` is the
showcase and operating workspace: web console, localized reports, GitHub Pages,
Privit scope, AI settings, and AIGate CI. See `docs/REPOSITORY_ROLES.md`.

## Does it attack the target?

No by default. The normal workflow is passive and scope-guarded. It discovers
allowed pages, reviews metadata, checks headers and routes, and avoids
destructive tests.

## Why is AIGate not a web-console button?

AIGate belongs to git push and CI readiness. It evaluates repository state,
secrets, and quality gates, so keeping it attached to git workflows is clearer
and safer.

## Where is AI used?

AI is used for provider readiness, command references, remediation prompts, and
optional AIGate AI reports. AI does not decide passive scan findings.

## Why is GitHub Pages not live yet?

GitHub Pages is enabled and deployed from `docs/pages`. See
`docs/github-pages.md`.

## Can this be made public for stars?

Yes, after a launch review. Use `docs/LAUNCH_CHECKLIST.md` to confirm that no
private target URLs, generated sensitive reports, or secrets are exposed.

## Why is `aegis.scope.json` sometimes dirty locally?

Developers may point local scope at an authorized staging target while testing.
For public launch and CI, the committed default should stay safe and local.
Use `aegis.scope.example.json` to reset to the public demo default.
