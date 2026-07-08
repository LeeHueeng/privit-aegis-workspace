# 에이전트 보안 체크

이 문서는 Aegis CLI 에이전트와 도구 어댑터를 위한 생성 문서입니다. 승인된 범위 안에서만 비파괴 보안 테스트를 실행하도록 운영 규칙을 정의합니다.

## 에이전트 운영 원칙

- `aegis.scope.json`이 없으면 계획과 실행을 시작하지 않습니다.
- `catalog/security-checks.jsonl`의 비파괴 체크만 실행합니다.
- allowlist에 등록된 도구 어댑터만 사용합니다.
- LLM 출력은 계획과 요약에만 사용하고 직접 셸 권한으로 취급하지 않습니다.
- LLM 사용 전과 보고서 생성 전 민감정보를 redaction합니다.

## 범위 보호 규칙

- 모든 URL은 대상의 `allowed_hosts`와 `allowed_paths`에 일치해야 합니다.
- `denied_paths`에 일치하면 요청을 차단합니다.
- 운영 환경은 기본적으로 `passive` 모드만 허용합니다.
- `authenticated`와 `db_audit`는 명시적인 수동 승인이 필요합니다.
- 파괴적 테스트, 무차별 시도, 탈취, 지속성, 회피 행위는 차단됩니다.

## 허용 도구

| 어댑터 | 도구 | 허용 모드 |
| --- | --- | --- |
| scope_guard_adapter | Aegis Scope Guard | passive, safe_active, authenticated, ci, db_audit |
| playwright_adapter | Playwright | passive, safe_active, authenticated, ci |
| semgrep_adapter | Semgrep | ci, local_static_analysis |
| trivy_adapter | Trivy | ci, local_static_analysis |
| syft_adapter | Syft | ci, local_static_analysis |
| zap_adapter | OWASP ZAP | passive, safe_active, authenticated |
| nuclei_adapter | Nuclei | passive, safe_active |
| db_readonly_adapter | Internal DB Audit | db_audit |

## 실행 모드 매트릭스

| 모드 | 운영 안전성 | 수동 승인 | 설명 |
| --- | --- | --- | --- |
| passive | true | false | Minimal requests and passive metadata checks. |
| safe_active | false | false | Non-destructive validation for staging or development. |
| authenticated | passive_only | true | Role-aware tests with approved test accounts. |
| ci | true | false | Static, supply-chain, SBOM, IaC, and secret scanning gates. |
| db_audit | false | true | Read-only database configuration audit. |

## 체크 카탈로그 선택

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

1. 검증된 scope를 불러옵니다.
2. 대상 유형과 실행 모드로 필터링합니다.
3. `destructive=true` 체크를 거부합니다.
4. 수동 승인 체크는 승인이 없으면 거부합니다.
5. 알 수 없는 도구 어댑터를 거부합니다.
6. scope safety 설정의 rate limit과 concurrency를 적용합니다.

## 증거 수집

artifact는 `.aegis/artifacts/<target>/<scan-id>/`에 저장하고 정규화된 결과는 `.aegis/scans/<scan-id>/results.json`에 저장합니다. 요청/응답 메타데이터는 저장하되 민감한 값은 저장하지 않습니다.

## 프론트엔드 이상 캡처

console error, page error, failed network request, auth state mismatch, visual regression, browser security policy event를 캡처합니다.

## 인증 테스트 규칙

전용 테스트 계정만 사용하고 운영 사용자 자격 증명은 재사용하지 않습니다. 역할 이름과 세션 메타데이터만 저장하고 token/cookie는 redaction합니다.

## Finding 정규화

모든 finding은 id, project, environment, asset, target type, category, title, severity, confidence, status, redacted evidence, impact, safe reproduction, recommendation, mapped standards, timestamps를 포함해야 합니다.

## 보고서 생성

보고서는 JSON, Markdown, HTML, SARIF로 생성할 수 있습니다. 보고서에는 secret redaction을 적용하고 페이로드 카탈로그, 우회 절차, 권한 상승 단계, 데이터 추출 절차를 포함하지 않습니다.
