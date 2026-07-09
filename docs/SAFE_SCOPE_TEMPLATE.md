# Safe Scope Template

Use `aegis.scope.example.json` as the public demo scope. It points to localhost
only and keeps destructive behavior disabled.

```sh
cp aegis.scope.example.json aegis.scope.json
npm run security:verify
npm test
```

## Why This Exists

Developers often need to test staging targets locally. Those local target edits
should not become the public default. The example scope gives contributors a
safe reset point before opening issues, pull requests, or public demos.

## Required Demo Properties

- `environment` is `local`
- `frontend.base_url` is loopback
- `allowed_hosts` contains only `localhost` and `127.0.0.1`
- Destructive, brute force, exfiltration, persistence, and production active
  scan flags are `false`
- Discovery depth and page limits are bounded

## Before Public Launch

```sh
cp aegis.scope.example.json aegis.scope.json
npm run site:check
npm run gate:ready
```

Then review the diff before committing. Private staging targets should remain
local and uncommitted.
