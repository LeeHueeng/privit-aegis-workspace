# Security Scanning

The local and CI security gate is:

```sh
npm run ci:aegis
npm run security:hardening
npm run security:target
npm run security:penetration
npm run completion:audit
npm run gate:ready
```

The gate performs:

- Aegis catalog generation
- Scope verification
- Passive frontend plan generation
- Passive frontend site discovery
- Frontend response header, auth-page cache, cookie flag, and autocomplete advisory
- Passive penetration report with executed checks, pass criteria, evidence summaries, and remediation guidance
- Completion audit for CLI, web, i18n, AI providers, target advisory, and GitHub readiness
- OWASP/GitHub hardening baseline review
- HTML report generation
- AIGate upload readiness check

The web console Start All flow is Aegis-only: catalog, docs, scope verification,
plan, passive discovery, target advisory, and localized report generation.
It also generates the local penetration report from the latest advisory output.
AIGate is reserved for git push and CI quality-gate commands such as
`npm run gate:ready` and `npm run ci:security`.

Report outputs:

- HTML: `.aegis/reports/aegis-report.html`
- Localized JSON: `.aegis/reports/aegis-report.json`
- SARIF: `.aegis/reports/aegis-report.sarif`
- Hardening: `.aegis/reports/security-hardening.json`
- Frontend advisory: `.aegis/reports/frontend-advisory.json`
- Penetration report HTML: `.aegis/reports/penetration-report.html`
- Penetration report JSON: `.aegis/reports/penetration-report.json`

The web console serves the latest HTML report at:

```sh
npm run web
```

Then open `http://127.0.0.1:4317`.

Frontend discovery starts from the configured base URL, follows only in-scope
links, reads `robots.txt` and `sitemap.xml` when present, inventories forms, and
records login-like routes without submitting credentials.

The hardening baseline is documented in `docs/security-hardening-baseline.md`.
It checks local scope safety, web-console security headers, GitHub Actions
permissions, checkout credential persistence, job timeout, and passive
authentication/CSRF advisories.

The frontend advisory is also passive. It reuses the latest discovered site map
and only requests in-scope HTML/auth-like URLs. It checks the live target for
OWASP-style response header coverage, `Cache-Control: no-store` on
authentication-like pages, defensive cookie attributes, and password-manager
autocomplete hints. It also reviews public transport posture for cleartext HTTP,
basic TLS certificate validity, and precise web server version banners. It also
performs header-misconfiguration checks for deprecated HPKP, obsolete
`X-Frame-Options: ALLOW-FROM`, permissive cross-domain policy headers, HSTS
placement, CSP Report-Only rollout, and COOP/COEP/CORP browser isolation
posture, plus CNAME takeover fingerprints, Host-style header reflection,
sensitive cookie scope, and logout cache/browser-cleanup signals. It also reads
a small HTML preview to identify reverse tabnabbing link patterns. It does not
submit forms or send attack payloads.

The target advisory also runs low-impact passive penetration probes based on
OWASP WSTG and OWASP API Security Top 10 themes. These probes use GET/OPTIONS
only and check for anonymously reachable sensitive files, VCS metadata, backup
or database dumps, editor backup copies, server-side/config file extensions,
dependency manifests, directory listings, phpinfo pages, OpenAPI/Swagger/ReDoc
docs, admin/debug surfaces, metrics/actuator/server-status endpoints,
webserver metafiles
(`robots.txt`, `sitemap.xml`, `security.txt`, `crossdomain.xml`,
`clientaccesspolicy.xml`), generic error pages for stack trace/framework/SQL
detail, source map files, risky HTTP methods, GraphQL endpoints and public
IDE/schema-like exposure signals, versioned API route inventory, legacy/beta/
internal API exposure, upload/import/
export surfaces, OIDC/OAuth/JWKS metadata, CORS trust decisions, CSP quality,
CSP Report-Only policy inventory, COOP/COEP/CORP isolation header inventory and
value validation, Permissions-Policy least-privilege quality and deprecated
Feature-Policy detection, authentication form GET submissions, state-changing form CSRF
token candidates, external form actions, sensitive cleartext form submissions,
file-upload form controls, account-recovery and well-known change-password routes,
logout/sign-out route inventory with Cache-Control, Clear-Site-Data, and cookie
clearing signals, visible Retry-After/RateLimit headers on authentication surfaces,
dynamic HTML route cache posture for web-cache-deception review,
sensitive URL query/fragment parameter names, authentication-flow token URL
inventory for reset/verification/invite/magic-link/OAuth/SSO paths, OAuth/SSO
callback cache and Referrer-Policy posture, OAuth authorization request parameter
inventory and risky response/redirect mode signals, anonymously readable user/account/profile/session API JSON,
auth/session API cache and `nosniff` headers, security.txt contact metadata,
client-side bundle leakage signals, external subresource integrity, HTTPS mixed
content references, DOM XSS source/sink patterns, Web Messaging patterns, URL-controlled
redirect/resource-loading patterns, client-side template sinks,
prototype-pollution candidate flows, sensitive browser-storage keys, cleartext
public WebSocket endpoints, JWT header algorithm signals, XSSI JSON candidates,
cloud storage references, framework fingerprint markers, duplicate URL
parameters for HTTP Parameter Pollution review, SSRF-style URL/webhook/proxy/
remote-media input names, redirect-like URL parameters and observed external
redirect destination hosts for open-redirect
review, mass-assignment sensitive role/permission/tenant/account-state/billing
field names, mobile App/Universal Link association file inventory, ID-bearing
routes that should receive BOLA/BFLA review, and an
OWASP attack-surface matrix for XSS/HTML injection,
SQL/NoSQL/ORM injection, LDAP/XML/XPath parser risks, SSRF, file inclusion,
command/code/template injection, HTTP splitting/smuggling, mass assignment,
GraphQL/API review, and upload business logic review. Response bodies and
sensitive query or fragment values are not stored in reports; only URL path,
status, headers, redirect, DNS, field names, parameter names, flow types, and
detection signals are recorded.

The web console includes a Detection Guide tab that explains each detection
family, pass criteria, and the evidence retained in reports. The same console is
also available directly at `/detections`.

Use `npm run completion:audit` when iterating on the workspace. It reports code
TODO items separately from external GitHub blockers such as repository secrets
or private-repository branch protection limits.

`npm run security:report` runs the Aegis HTML report first, then rewrites the
HTML with the current web console language from `.aegis/web-settings.json`.
Supported report languages are Korean, English, Japanese, and Chinese. Stale
findings that are no longer reproduced by the latest scan are excluded from the
localized report.

`npm run security:penetration` creates the human-readable penetration/security
testing report. It answers three audit questions for each check: what was run,
what pass criterion was used, and what redacted evidence was observed. The web
console serves it at `/penetration-report` and exposes it from the report tab.

AI is not used to decide passive scan results or penetration-report findings.
Those checks are deterministic and based on scope, response metadata, headers,
cookies, and low-impact probes. AI settings are used for provider readiness,
model command references, optional AIGate AI reports, and remediation prompt
generation.
