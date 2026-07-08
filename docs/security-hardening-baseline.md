# Security Hardening Baseline

Privit Aegis now keeps a local hardening baseline in
`.aigate/security-baseline.json` and verifies it with:

```sh
npm run security:hardening
```

The check writes `.aegis/reports/security-hardening.json`.

The live target advisory is separate and runs with:

```sh
npm run security:target
```

It writes `.aegis/reports/frontend-advisory.json`.

The overall completion audit runs with:

```sh
npm run completion:audit
```

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
- The live target advisory checks discovered in-scope HTML/auth URLs for
  security response headers, auth-page cache controls, cookie attributes, and
  password-manager autocomplete hints without submitting forms. It also warns
  when framework fingerprinting headers such as `X-Powered-By` are exposed.

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

## Target App Status

The running `localhost:3000` target app has been patched so the discovered
login and password-recovery forms render as `POST` forms and expose a
`csrfToken` control. The public auth API routes now require the matching
`X-CSRF-Token` header before proxying login, MFA, or password-recovery requests.

Patched target app files:

- `/Volumes/develop/develop/company_develop/admin-project/adminpage/apps/root/src/lib/auth/csrf.ts`
- `/Volumes/develop/develop/company_develop/admin-project/adminpage/apps/root/src/components/auth/RootLogin.tsx`
- `/Volumes/develop/develop/company_develop/admin-project/adminpage/apps/root/src/views/auth/ForgotPassword.tsx`
- `/Volumes/develop/develop/company_develop/admin-project/adminpage/apps/root/src/app/api/v1/auth/login/route.ts`
- `/Volumes/develop/develop/company_develop/admin-project/adminpage/apps/root/src/app/api/v1/auth/mfa-verify/route.ts`
- `/Volumes/develop/develop/company_develop/admin-project/adminpage/apps/root/src/app/api/v1/auth/forgot-password/route.ts`

After regenerating discovery with `npm run security:map`, the hardening review
passes all checks with `npm run security:hardening`.
