# Security Hardening Baseline

Privit Aegis now keeps a local hardening baseline in
`.aigate/security-baseline.json` and verifies it with:

```sh
npm run security:hardening
```

The check writes `.aegis/reports/security-hardening.json`.

## What It Checks

- Local Aegis scope remains non-destructive, loopback-only, and bounded by
  passive discovery depth/page limits.
- The local web console sends browser defense-in-depth headers:
  `Content-Security-Policy`, `X-Content-Type-Options`, `Referrer-Policy`,
  `X-Frame-Options`, `Permissions-Policy`, `Cross-Origin-Opener-Policy`, and
  `Cache-Control`.
- GitHub Actions uses read-only `contents` permission, avoids
  `pull_request_target`, has a job timeout, and does not persist checkout
  credentials.
- Latest passive discovery is reviewed for authentication-like forms submitted
  with `GET` and state-changing forms without obvious CSRF tokens.

Application findings from passive discovery are warnings by default so the
workspace can keep producing reports while the target application is fixed.
Workspace guardrail failures are blocking.

## Source Baseline

The baseline follows these primary references:

- OWASP HTTP Security Response Headers Cheat Sheet:
  https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
- OWASP Authentication Cheat Sheet:
  https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- OWASP Cross-Site Request Forgery Prevention Cheat Sheet:
  https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
- GitHub Actions secure use reference:
  https://docs.github.com/en/actions/reference/security/secure-use
- MDN Content Security Policy:
  https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP

## Target App Follow-Up

The latest scan currently flags a login-like form using `GET`. The application
should change authentication and reset flows to `POST`, avoid credentials or
tokens in URLs, and add CSRF protection for state-changing cookie-authenticated
requests. This is tracked as a warning in the hardening report until the target
application is patched.
