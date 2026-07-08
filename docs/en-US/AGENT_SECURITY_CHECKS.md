# Agent Security Checks

This document is generated for Aegis CLI agents and tool adapters. It defines safe operating rules for non-destructive security testing inside approved scope only.

## Agent Operating Principles

- Require `aegis.scope.json` before planning or running checks.
- Execute only non-destructive checks from `catalog/security-checks.jsonl`.
- Use allowlisted tool adapters only.
- Treat LLM output as planning and summarization, not direct shell authority.
- Redact secrets before LLM use and before report generation.

## Scope Guard Rules

- Every URL must match the target `allowed_hosts` and `allowed_paths`.
- Any `denied_paths` match blocks the request.
- Production environments default to `passive` mode only.
- `authenticated` and `db_audit` require explicit manual approval.
- Destructive, brute-force, exfiltration, persistence, and evasion behaviors are blocked.

## Allowed Tools

| Adapter | Tool | Allowed modes |
| --- | --- | --- |
| scope_guard_adapter | Aegis Scope Guard | passive, safe_active, authenticated, ci, db_audit |
| playwright_adapter | Playwright | passive, safe_active, authenticated, ci |
| semgrep_adapter | Semgrep | ci, local_static_analysis |
| trivy_adapter | Trivy | ci, local_static_analysis |
| syft_adapter | Syft | ci, local_static_analysis |
| zap_adapter | OWASP ZAP | passive, safe_active, authenticated |
| nuclei_adapter | Nuclei | passive, safe_active |
| db_readonly_adapter | Internal DB Audit | db_audit |

## Execution Mode Matrix

| Mode | Safe for production | Manual approval | Description |
| --- | --- | --- | --- |
| passive | true | false | Minimal requests and passive metadata checks. |
| safe_active | false | false | Non-destructive validation for staging or development. |
| authenticated | passive_only | true | Role-aware tests with approved test accounts. |
| ci | true | false | Static, supply-chain, SBOM, IaC, and secret scanning gates. |
| db_audit | false | true | Read-only database configuration audit. |

## Check Catalog Selection

- governance_scope_policy: 80 checks, passive, ci_cd
- asset_inventory_passive_discovery: 140 checks, passive, frontend
- frontend_browser_runtime: 180 checks, passive, frontend
- frontend_static_bundle: 140 checks, ci, frontend
- backend_api_authentication: 160 checks, authenticated, backend_api
- backend_api_authorization: 220 checks, authenticated, backend_api
- backend_api_input_validation: 200 checks, safe_active, backend_api
- session_cookie_token: 150 checks, passive, frontend
- security_headers_tls_cors: 120 checks, passive, frontend
- database_readonly_audit: 140 checks, db_audit, database
- supply_chain_sast_sca_container_iac: 260 checks, ci, ci_cd
- ci_cd_secret_release: 150 checks, ci, ci_cd
- business_logic_safe_checks: 140 checks, safe_active, backend_api
- logging_monitoring_error_handling: 90 checks, passive, backend_api
- cloud_kubernetes_config_audit: 180 checks, ci, iac
- privacy_data_minimization: 80 checks, passive, backend_api

1. Load the verified scope.
2. Filter by target type and execution mode.
3. Reject checks with `destructive=true`.
4. Reject manual-approval checks unless approval is present.
5. Reject unknown tool adapters.
6. Apply rate limits and concurrency from scope safety settings.

## Evidence Collection

Artifacts are stored in `.aegis/artifacts/<target>/<scan-id>/`, and normalized results are stored in `.aegis/scans/<scan-id>/results.json`. Request and response metadata is stored without sensitive values.

## Frontend Anomaly Capture

Capture console errors, page errors, failed network requests, auth state mismatches, visual regressions, and browser security policy events.

## Authenticated Testing Rules

Use dedicated test accounts only and never reuse production user credentials. Store role names and session metadata while redacting tokens and cookies.

## Finding Normalization

Every finding should include id, project, environment, asset, target type, category, title, severity, confidence, status, redacted evidence, impact, safe reproduction, recommendation, mapped standards, and timestamps.

## Report Generation

Reports may be generated as JSON, Markdown, HTML, or SARIF. Reports must redact secrets and avoid payload catalogs, bypass procedures, privilege escalation steps, or data extraction procedures.
