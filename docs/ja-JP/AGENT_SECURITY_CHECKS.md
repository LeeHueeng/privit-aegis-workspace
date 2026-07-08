# エージェント向けセキュリティチェック

この文書は Aegis CLI のエージェントとツールアダプター向けに生成されます。承認済みスコープ内でのみ非破壊のセキュリティテストを実行するための運用ルールを定義します。

## エージェント運用原則

- `aegis.scope.json` がない場合、計画または実行を開始しません。
- `catalog/security-checks.jsonl` の非破壊チェックのみ実行します。
- allowlist に登録されたツールアダプターのみ使用します。
- LLM 出力は計画と要約に限定し、直接のシェル権限として扱いません。
- LLM 利用前とレポート生成前に機密情報を redaction します。

## スコープ保護ルール

- すべての URL は対象の `allowed_hosts` と `allowed_paths` に一致する必要があります。
- `denied_paths` に一致した場合、リクエストをブロックします。
- 本番環境では既定で `passive` モードのみ許可します。
- `authenticated` と `db_audit` は明示的な手動承認が必要です。
- 破壊的テスト、総当たり、持ち出し、永続化、回避行為はブロックされます。

## 許可ツール

| アダプター | ツール | 許可モード |
| --- | --- | --- |
| scope_guard_adapter | Aegis Scope Guard | passive, safe_active, authenticated, ci, db_audit |
| playwright_adapter | Playwright | passive, safe_active, authenticated, ci |
| semgrep_adapter | Semgrep | ci, local_static_analysis |
| trivy_adapter | Trivy | ci, local_static_analysis |
| syft_adapter | Syft | ci, local_static_analysis |
| zap_adapter | OWASP ZAP | passive, safe_active, authenticated |
| nuclei_adapter | Nuclei | passive, safe_active |
| db_readonly_adapter | Internal DB Audit | db_audit |

## 実行モードマトリクス

| モード | 本番安全性 | 手動承認 | 説明 |
| --- | --- | --- | --- |
| passive | true | false | Minimal requests and passive metadata checks. |
| safe_active | false | false | Non-destructive validation for staging or development. |
| authenticated | passive_only | true | Role-aware tests with approved test accounts. |
| ci | true | false | Static, supply-chain, SBOM, IaC, and secret scanning gates. |
| db_audit | false | true | Read-only database configuration audit. |

## チェックカタログ選択

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

1. 検証済みの scope を読み込みます。
2. 対象タイプと実行モードでフィルタリングします。
3. `destructive=true` のチェックを拒否します。
4. 手動承認チェックは承認がない場合拒否します。
5. 不明なツールアダプターを拒否します。
6. scope safety 設定の rate limit と concurrency を適用します。

## 証拠収集

artifact は `.aegis/artifacts/<target>/<scan-id>/` に保存し、正規化された結果は `.aegis/scans/<scan-id>/results.json` に保存します。リクエスト/レスポンスのメタデータは保存しますが、機密値は保存しません。

## フロントエンド異常キャプチャ

console error、page error、failed network request、auth state mismatch、visual regression、browser security policy event をキャプチャします。

## 認証テストルール

専用テストアカウントのみ使用し、本番ユーザーの認証情報を再利用しません。ロール名とセッションメタデータのみ保存し、token/cookie は redaction します。

## Finding 正規化

すべての finding には id、project、environment、asset、target type、category、title、severity、confidence、status、redacted evidence、impact、safe reproduction、recommendation、mapped standards、timestamps を含めます。

## レポート生成

レポートは JSON、Markdown、HTML、SARIF で生成できます。secret redaction を適用し、ペイロードカタログ、回避手順、権限昇格手順、データ抽出手順は含めません。
