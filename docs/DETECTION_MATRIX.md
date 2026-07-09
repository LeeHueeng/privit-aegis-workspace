# Detection Matrix

The matrix summarizes what Privit Aegis looks for and how evidence is handled.
Detailed behavior lives in `docs/security-scanning.md`.

| Area | Examples | Default impact | Evidence retained |
| --- | --- | --- | --- |
| Scope safety | Allowed hosts, denied paths, passive flags | Local file review | Scope fields and status |
| Discovery | Routes, links, forms, auth-like paths, sitemap | GET/HEAD style passive requests | URLs, status, form metadata |
| Browser headers | CSP, HSTS, Referrer-Policy, nosniff, XFO, COOP/COEP/CORP | Header review | Header names and values |
| Cookie posture | Secure, HttpOnly, SameSite, prefixes, Partitioned | Header review | Cookie names and attributes |
| Auth surfaces | Login, forgot password, logout, MFA, WebAuthn | Passive page/route review | Paths, form methods, cache headers |
| API surfaces | OpenAPI, GraphQL, versioned APIs, auth/session endpoints | Passive route review | Paths, status, exposed metadata |
| Identity metadata | OIDC, OAuth metadata, JWKS quality | Public metadata fetch | Metadata fields, key metadata |
| Client-side posture | SRI, mixed content, DOM XSS patterns, storage keys | HTML/static asset preview | Signal names, paths, snippets avoided |
| Exposure checks | Backups, source maps, debug/admin paths, security.txt | Low-impact request inventory | Paths, status, headers |
| Reporting | HTML, JSON, SARIF, penetration report | Local file generation | Redacted findings and pass criteria |

## Pass Criteria Pattern

Each report-friendly check should answer:

- What was checked?
- What is the pass condition?
- What redacted evidence was observed?
- What is the safest recommended fix?

## Out of Scope by Default

- Brute force
- Credential stuffing
- Form submission with credentials
- Destructive payloads
- Persistence
- Data exfiltration
- Live payment paths
- Third-party systems without written authorization
