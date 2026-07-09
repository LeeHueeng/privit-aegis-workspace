import { mkdir, readFile, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";

const cwd = process.cwd();
const htmlPath = resolve(cwd, ".aegis/reports/penetration-report.html");
const jsonPath = resolve(cwd, ".aegis/reports/penetration-report.json");

const translations = {
  ko: {
    lang: "ko",
    title: "보안침투검사 리포트",
    subtitle: "승인된 범위 안에서 수행한 패시브 침투/보안 검사의 실행 항목, 통과 기준, 증거 요약입니다.",
    generated: "생성",
    statusPass: "통과",
    statusWarn: "검토 필요",
    statusFail: "실패",
    statusNotRun: "미실행",
    statusInfo: "정보",
    scope: "범위 및 승인",
    project: "프로젝트",
    environment: "환경",
    mode: "모드",
    frontend: "프론트엔드",
    backend: "백엔드 API",
    owner: "소유자",
    proofType: "증명 유형",
    expiresAt: "승인 만료일",
    safety: "안전 제한",
    summary: "요약",
    tests: "시행한 검사와 통과 기준",
    test: "검사",
    category: "분류",
    passCriteria: "통과 기준",
    result: "결과",
    evidence: "증거 요약",
    findings: "발견 항목",
    noFindings: "현재 리포트 기준 검토가 필요한 발견 항목이 없습니다.",
    methodology: "검사 방법",
    sources: "참고 기준",
    recommendations: "권장 조치",
    redaction: "마스킹 정책",
    redactionText: "토큰, 쿠키, Authorization 헤더, API 키, 비밀번호, 이메일 주소, 개인 키처럼 민감할 수 있는 값은 저장/표시 전에 마스킹합니다. HTTP 응답 본문은 저장하지 않습니다.",
    probes: "프로브",
    warnings: "경고",
    errors: "오류",
    passed: "통과",
    targetWarning: "승인 범위와 소유권을 다시 확인한 뒤 운영 환경에서는 passive 모드만 사용하세요.",
    aiUsage: "AI 사용 현황",
    aiScanUse: "스캔 판정",
    aiReportUse: "리포트 생성",
    aiDefaultProvider: "기본 프로바이더",
    aiEnabledProviders: "활성 프로바이더",
    aiAvailableActions: "사용 가능한 AI 작업",
    aiNotUsedForScan: "이 침투/보안 점검은 정해진 규칙과 패시브 증거로 판정하며 LLM을 호출하지 않습니다.",
    aiNotUsedForReport: "이 리포트도 AI가 작성한 판단문이 아니라 검사 결과를 템플릿으로 정리한 것입니다.",
    aiUsedFor: "AI는 모델 설정, provider 점검, AIGate AI 리포트/수정 프롬프트 생성에 사용됩니다."
  },
  en: {
    lang: "en",
    title: "Security Penetration Test Report",
    subtitle: "Executed passive penetration/security checks, pass criteria, and evidence summaries inside the authorized scope.",
    generated: "generated",
    statusPass: "Pass",
    statusWarn: "Review needed",
    statusFail: "Fail",
    statusNotRun: "Not run",
    statusInfo: "Info",
    scope: "Scope and Authorization",
    project: "Project",
    environment: "Environment",
    mode: "Mode",
    frontend: "Frontend",
    backend: "Backend API",
    owner: "Owner",
    proofType: "Proof type",
    expiresAt: "Authorization expires",
    safety: "Safety limits",
    summary: "Summary",
    tests: "Executed Checks and Pass Criteria",
    test: "Check",
    category: "Category",
    passCriteria: "Pass criteria",
    result: "Result",
    evidence: "Evidence summary",
    findings: "Findings",
    noFindings: "No findings currently require review in this report.",
    methodology: "Methodology",
    sources: "References",
    recommendations: "Recommended Actions",
    redaction: "Redaction Policy",
    redactionText: "Potentially sensitive values such as tokens, cookies, Authorization headers, API keys, passwords, email addresses, and private keys are redacted before storage/display. HTTP response bodies are not stored.",
    probes: "probes",
    warnings: "warnings",
    errors: "errors",
    passed: "passed",
    targetWarning: "Reconfirm authorization and ownership before testing; use passive mode for production targets.",
    aiUsage: "AI Usage",
    aiScanUse: "Scan decisions",
    aiReportUse: "Report generation",
    aiDefaultProvider: "Default provider",
    aiEnabledProviders: "Enabled providers",
    aiAvailableActions: "Available AI actions",
    aiNotUsedForScan: "This penetration/security check uses deterministic passive evidence and does not call an LLM for scan decisions.",
    aiNotUsedForReport: "This report is template-generated from check results, not authored by AI.",
    aiUsedFor: "AI is used for model settings, provider checks, AIGate AI reports, and remediation prompt generation."
  },
  ja: {
    lang: "ja",
    title: "セキュリティ侵入テストレポート",
    subtitle: "承認範囲内で実行したパッシブ侵入/セキュリティ検査、合格基準、証跡サマリーです。",
    generated: "生成",
    statusPass: "合格",
    statusWarn: "確認必要",
    statusFail: "失敗",
    statusNotRun: "未実行",
    statusInfo: "情報",
    scope: "スコープと承認",
    project: "プロジェクト",
    environment: "環境",
    mode: "モード",
    frontend: "フロントエンド",
    backend: "バックエンドAPI",
    owner: "所有者",
    proofType: "証明種別",
    expiresAt: "承認期限",
    safety: "安全制限",
    summary: "サマリー",
    tests: "実施検査と合格基準",
    test: "検査",
    category: "分類",
    passCriteria: "合格基準",
    result: "結果",
    evidence: "証跡サマリー",
    findings: "検出項目",
    noFindings: "このレポートで確認が必要な検出項目はありません。",
    methodology: "検査方法",
    sources: "参考基準",
    recommendations: "推奨対応",
    redaction: "マスキングポリシー",
    redactionText: "トークン、Cookie、Authorizationヘッダー、APIキー、パスワード、メールアドレス、秘密鍵などの機密値は保存/表示前にマスクします。HTTPレスポンス本文は保存しません。",
    probes: "プローブ",
    warnings: "警告",
    errors: "エラー",
    passed: "合格",
    targetWarning: "検査前に承認範囲と所有権を再確認し、本番環境ではpassiveモードのみ使用してください。",
    aiUsage: "AI利用状況",
    aiScanUse: "スキャン判定",
    aiReportUse: "レポート生成",
    aiDefaultProvider: "既定プロバイダー",
    aiEnabledProviders: "有効プロバイダー",
    aiAvailableActions: "利用可能なAI操作",
    aiNotUsedForScan: "この侵入/セキュリティ検査は決定的なpassive証跡で判定し、スキャン判定にLLMを呼び出しません。",
    aiNotUsedForReport: "このレポートは検査結果からテンプレート生成され、AIが判断文を作成したものではありません。",
    aiUsedFor: "AIはモデル設定、provider診断、AIGate AIレポート、修正プロンプト生成に使用されます。"
  },
  zh: {
    lang: "zh",
    title: "安全渗透测试报告",
    subtitle: "在授权范围内执行的被动渗透/安全检查、通过标准和证据摘要。",
    generated: "生成",
    statusPass: "通过",
    statusWarn: "需复核",
    statusFail: "失败",
    statusNotRun: "未运行",
    statusInfo: "信息",
    scope: "范围与授权",
    project: "项目",
    environment: "环境",
    mode: "模式",
    frontend: "前端",
    backend: "后端 API",
    owner: "所有者",
    proofType: "证明类型",
    expiresAt: "授权到期",
    safety: "安全限制",
    summary: "摘要",
    tests: "执行的检查与通过标准",
    test: "检查",
    category: "分类",
    passCriteria: "通过标准",
    result: "结果",
    evidence: "证据摘要",
    findings: "发现项",
    noFindings: "本报告当前没有需要复核的发现项。",
    methodology: "检查方法",
    sources: "参考标准",
    recommendations: "建议措施",
    redaction: "脱敏策略",
    redactionText: "令牌、Cookie、Authorization 头、API 密钥、密码、邮箱地址和私钥等敏感值在存储/展示前会被脱敏。不会保存 HTTP 响应正文。",
    probes: "探测",
    warnings: "警告",
    errors: "错误",
    passed: "通过",
    targetWarning: "测试前请再次确认授权范围和所有权；生产环境仅使用 passive 模式。",
    aiUsage: "AI 使用情况",
    aiScanUse: "扫描判定",
    aiReportUse: "报告生成",
    aiDefaultProvider: "默认提供方",
    aiEnabledProviders: "启用提供方",
    aiAvailableActions: "可用 AI 操作",
    aiNotUsedForScan: "此渗透/安全检查使用确定性的被动证据进行判定，不会调用 LLM 做扫描结论。",
    aiNotUsedForReport: "此报告由检查结果按模板生成，并非 AI 生成判断文本。",
    aiUsedFor: "AI 用于模型设置、提供方检查、AIGate AI 报告和修复提示生成。"
  }
};

const references = [
  {
    name: "OWASP Web Security Testing Guide",
    url: "https://owasp.org/www-project-web-security-testing-guide/"
  },
  {
    name: "OWASP WSTG Reporting",
    url: "https://owasp.org/www-project-web-security-testing-guide/v42/5-Reporting/README"
  },
  {
    name: "OWASP Application Security Verification Standard",
    url: "https://owasp.org/www-project-application-security-verification-standard/"
  },
  {
    name: "NIST SP 800-115 Technical Guide to Information Security Testing and Assessment",
    url: "https://csrc.nist.gov/pubs/sp/800/115/final"
  }
];

const criteria = {
  "aegis.authorization_proof": {
    category: "Authorization",
    criteria: "Public non-loopback targets have a non-placeholder owner and concrete authorization proof before testing.",
    remediation: "Replace placeholder owner values and add explicit proof metadata before scanning public third-party or production-like targets."
  },
  "frontend.reachable": {
    category: "Availability",
    criteria: "All configured in-scope target URLs respond without request errors; at least one target is reachable.",
    remediation: "Start the target application, correct the base URL/allowlist, then rerun the scan."
  },
  "frontend.headers.csp": {
    category: "Browser hardening",
    criteria: "Every discovered HTML response sends a Content-Security-Policy header.",
    remediation: "Configure a CSP that matches the application and includes safe script/style/frame policies."
  },
  "frontend.headers.csp_quality": {
    category: "Browser hardening",
    criteria: "CSP avoids weak script directives, wildcard sources, data/http script sources, and missing object-src/base-uri/frame-ancestors safeguards.",
    remediation: "Tighten CSP by removing unsafe-eval, using nonce/hash based script allowances, avoiding wildcards, and setting object-src/base-uri/frame-ancestors."
  },
  "frontend.headers.nosniff": {
    category: "Browser hardening",
    criteria: "Every checked response sends X-Content-Type-Options: nosniff.",
    remediation: "Add X-Content-Type-Options: nosniff at the web server or application gateway."
  },
  "frontend.headers.referrer": {
    category: "Browser hardening",
    criteria: "Every discovered HTML response sends Referrer-Policy and does not use unsafe-url.",
    remediation: "Use a restrictive Referrer-Policy such as strict-origin-when-cross-origin or no-referrer."
  },
  "frontend.headers.permissions": {
    category: "Browser hardening",
    criteria: "Every discovered HTML response sends Permissions-Policy.",
    remediation: "Disable unused browser capabilities such as camera, microphone, geolocation, and payment."
  },
  "frontend.headers.cross_origin_isolation": {
    category: "Browser hardening",
    criteria: "Discovered HTML responses are inventoried for COOP, COEP, COEP-Report-Only, and CORP browser isolation headers.",
    remediation: "Review missing isolation headers against the application embedding model; add COOP/COEP/CORP when the app can safely isolate cross-origin opener, embedder, or resource access."
  },
  "frontend.headers.cross_origin_isolation_values": {
    category: "Browser hardening",
    criteria: "Present COOP, COEP, COEP-Report-Only, and CORP headers use recognized values and do not explicitly opt out with unsafe-none.",
    remediation: "Use values such as COOP same-origin, COEP require-corp or credentialless, and CORP same-origin/same-site/cross-origin as appropriate; remove invalid or explicit unsafe-none values."
  },
  "frontend.headers.csp_report_only": {
    category: "Browser hardening",
    criteria: "Discovered HTML responses are inventoried for Content-Security-Policy-Report-Only policies, reporting directives, and CSP quality signals.",
    remediation: "Use CSP Report-Only to trial policy changes with report-to or report-uri before enforcing them with Content-Security-Policy."
  },
  "frontend.headers.powered_by": {
    category: "Fingerprinting",
    criteria: "No checked response exposes X-Powered-By.",
    remediation: "Disable framework disclosure headers in the app server, reverse proxy, or framework config."
  },
  "frontend.headers.server_version": {
    category: "Fingerprinting",
    criteria: "Checked responses do not expose precise web server product/version banners in the Server header.",
    remediation: "Hide or normalize Server version banners at the web server, reverse proxy, CDN, or application gateway."
  },
  "frontend.headers.misconfiguration": {
    category: "Browser hardening",
    criteria: "Security headers avoid deprecated HPKP, obsolete X-Frame-Options ALLOW-FROM, permissive X-Permitted-Cross-Domain-Policies, and HSTS on cleartext HTTP.",
    remediation: "Remove deprecated headers, set X-Permitted-Cross-Domain-Policies to none when used, and keep HSTS only on HTTPS responses."
  },
  "frontend.fingerprint.framework_markers": {
    category: "Fingerprinting",
    criteria: "Responses do not expose framework-identifying headers or well-known framework session cookie names.",
    remediation: "Remove optional framework disclosure headers and rename generic framework cookies where the application stack allows it."
  },
  "frontend.headers.framing": {
    category: "Clickjacking",
    criteria: "Every discovered HTML response sets CSP frame-ancestors or X-Frame-Options DENY/SAMEORIGIN.",
    remediation: "Add CSP frame-ancestors or X-Frame-Options to all HTML responses."
  },
  "frontend.content.reverse_tabnabbing": {
    category: "Client-side testing",
    criteria: "HTML links that open new tabs with target=_blank also include rel=noopener or rel=noreferrer.",
    remediation: "Add rel=noopener or rel=noreferrer to new-tab links, especially for external destinations."
  },
  "frontend.content.subresource_integrity": {
    category: "Client-side testing",
    criteria: "External scripts and stylesheet resources referenced by HTML pages use Subresource Integrity where applicable.",
    remediation: "Add integrity attributes to third-party script/style resources and pin them to reviewed versions."
  },
  "frontend.content.mixed_content": {
    category: "Transport",
    criteria: "HTTPS pages do not load active resources or submit forms over cleartext HTTP.",
    remediation: "Replace cleartext subresources and form actions with HTTPS URLs or same-origin secure routes."
  },
  "frontend.headers.auth_cache": {
    category: "Authentication",
    criteria: "Authentication-like pages use Cache-Control: no-store.",
    remediation: "Set Cache-Control: no-store on login, account, password reset, and session pages."
  },
  "frontend.headers.auth_rate_limit": {
    category: "Abuse control",
    criteria: "Authentication-like pages are inventoried for visible Retry-After or RateLimit headers.",
    remediation: "Use this evidence with server-side throttling and lockout tests; add visible rate-limit headers where operationally useful."
  },
  "frontend.headers.hsts": {
    category: "Transport",
    criteria: "Non-loopback HTTPS targets send Strict-Transport-Security; loopback/local HTTP targets are skipped.",
    remediation: "Enable HSTS on real HTTPS environments after confirming HTTPS is enforced."
  },
  "frontend.headers.cors": {
    category: "CORS",
    criteria: "Responses do not reflect an arbitrary untrusted Origin and do not combine wildcard or reflected origins with credentials.",
    remediation: "Replace dynamic origin reflection with an explicit allowlist and avoid Access-Control-Allow-Credentials unless strictly needed."
  },
  "frontend.headers.host_injection": {
    category: "Input validation",
    criteria: "Responses do not reflect attacker-controlled Host, X-Forwarded-Host, X-Original-Host, or Forwarded headers in redirects or response content.",
    remediation: "Use a strict canonical host allowlist and build absolute URLs from trusted configuration rather than request headers."
  },
  "frontend.cookies.flags": {
    category: "Session",
    criteria: "Session-like cookies use HttpOnly, SameSite, and Secure when applicable.",
    remediation: "Set HttpOnly, SameSite=Lax/Strict, and Secure on session/auth cookies."
  },
  "frontend.cookies.scope": {
    category: "Session",
    criteria: "Sensitive cookies do not use broad Domain scope or Path=/ unless explicitly justified.",
    remediation: "Host-scope sensitive cookies where possible and narrow Path to the smallest application area that needs the cookie."
  },
  "frontend.forms.autocomplete": {
    category: "Authentication UX",
    criteria: "Authentication fields provide explicit password-manager autocomplete hints.",
    remediation: "Use autocomplete=current-password/new-password for passwords and username/email for login identifiers."
  },
  "frontend.forms.auth_get_method": {
    category: "Authentication",
    criteria: "Authentication-like forms do not submit with GET.",
    remediation: "Submit authentication and password-reset forms with POST and avoid placing credentials or tokens in URLs."
  },
  "frontend.forms.csrf_tokens": {
    category: "CSRF",
    criteria: "State-changing forms expose CSRF token candidates for passive inventory.",
    remediation: "Add anti-CSRF tokens to state-changing forms and validate them server-side for authenticated browser requests."
  },
  "frontend.forms.external_actions": {
    category: "Data leakage",
    criteria: "Form actions submit only to approved in-scope frontend or backend targets.",
    remediation: "Replace unexpected external form actions with approved same-site/API endpoints or explicitly document trusted third-party processors."
  },
  "frontend.forms.sensitive_cleartext_action": {
    category: "Transport",
    criteria: "Authentication, state-changing, and sensitive forms do not submit over cleartext HTTP outside loopback environments.",
    remediation: "Serve sensitive form pages and action endpoints over HTTPS and redirect cleartext HTTP to HTTPS."
  },
  "frontend.forms.file_upload_inventory": {
    category: "File handling",
    criteria: "File upload controls are inventoried for controlled upload validation review.",
    remediation: "Review upload controls for file type validation, malware scanning, storage isolation, authorization, and executable-path restrictions."
  },
  "frontend.transport.auth_https": {
    category: "Transport",
    criteria: "Authentication surfaces avoid cleartext transport outside loopback hosts.",
    remediation: "Serve authentication/account flows over HTTPS on non-local environments."
  },
  "frontend.transport.public_https": {
    category: "Transport",
    criteria: "Configured public non-loopback frontend/backend base URLs use HTTPS instead of cleartext HTTP.",
    remediation: "Serve public environments over HTTPS and redirect HTTP to HTTPS at the edge."
  },
  "frontend.transport.tls_certificate": {
    category: "Transport",
    criteria: "Public HTTPS targets negotiate TLSv1.2 or TLSv1.3, present a trusted certificate, and have more than 14 days before certificate expiry.",
    remediation: "Renew or replace invalid/expiring certificates and disable legacy TLS protocols at the edge."
  },
  "frontend.dns.dangling_cname": {
    category: "DNS",
    criteria: "Public target hostnames do not have CNAMEs pointing to known third-party services that also return unclaimed-resource takeover fingerprints.",
    remediation: "Remove dangling DNS records or claim/provision the referenced third-party resource before exposing the hostname."
  },
  "frontend.content.client_secrets": {
    category: "Information leakage",
    criteria: "Discovered client-side JavaScript and JSON assets do not expose obvious private keys, provider keys, JWT literals, or secret assignments.",
    remediation: "Remove client-side secrets, rotate exposed credentials, and move privileged tokens to server-side storage."
  },
  "frontend.content.web_messaging": {
    category: "Client-side testing",
    criteria: "Client bundles do not use wildcard postMessage targets or message listeners without visible origin validation signals.",
    remediation: "Use explicit postMessage target origins and validate event.origin before trusting message data."
  },
  "frontend.content.dom_xss": {
    category: "Client-side testing",
    criteria: "Client bundles do not show obvious URL/document source data flowing into DOM/script execution sinks.",
    remediation: "Encode or sanitize untrusted client-side data before DOM insertion, and avoid eval-like sinks."
  },
  "frontend.content.client_redirects": {
    category: "Client-side testing",
    criteria: "Client bundles do not appear to drive navigation or document writes directly from URL-controlled values.",
    remediation: "Validate redirect targets against an allowlist and avoid writing URL-controlled values into document output."
  },
  "frontend.content.resource_manipulation": {
    category: "Client-side testing",
    criteria: "Client bundles do not appear to load scripts, iframes, or other resources directly from URL-controlled values.",
    remediation: "Resolve client-selected resources through a server-approved allowlist or fixed route identifiers."
  },
  "frontend.content.template_injection": {
    category: "Client-side testing",
    criteria: "Client bundles do not appear to feed URL-controlled data into framework template HTML sinks.",
    remediation: "Avoid rendering untrusted values through template/HTML sinks such as v-html, ng-bind-html, x-html, or dangerouslySetInnerHTML."
  },
  "frontend.content.prototype_pollution": {
    category: "Input validation",
    criteria: "Client bundles do not show obvious query/hash/JSON input reaching prototype-sensitive object key handling.",
    remediation: "Reject __proto__, constructor, and prototype keys before deep merge/clone/assign operations and use patched parsing libraries."
  },
  "frontend.content.browser_storage": {
    category: "Client-side testing",
    criteria: "Client bundles do not appear to store token/session/password-like keys in localStorage or sessionStorage.",
    remediation: "Keep sensitive session material in HttpOnly cookies or server-side storage and clear non-sensitive browser storage on logout."
  },
  "frontend.content.websockets": {
    category: "WebSocket",
    criteria: "Client bundles do not reference cleartext public ws:// WebSocket endpoints.",
    remediation: "Use wss:// for public WebSocket endpoints and apply the same origin/authentication controls as HTTP APIs."
  },
  "frontend.content.jwt_algorithms": {
    category: "Session",
    criteria: "JWT literals discovered in client assets do not advertise alg=none, missing algorithms, or empty signatures.",
    remediation: "Avoid shipping JWT literals in client bundles; reject unsigned JWTs and enforce expected algorithms server-side."
  },
  "frontend.content.xssi_json": {
    category: "Client-side testing",
    criteria: "JSON responses discovered in client assets are inventoried for manual Cross Site Script Inclusion review.",
    remediation: "For sensitive JSON endpoints, use correct JSON content types, nosniff, CSRF/session controls, and anti-XSSI prefixes where appropriate."
  },
  "frontend.content.cloud_storage_refs": {
    category: "Cloud storage",
    criteria: "Cloud storage URLs found in client assets are inventoried for manual access-control review.",
    remediation: "Review referenced buckets/containers for least-privilege access, public listing restrictions, and sensitive object exposure."
  },
  "frontend.probes.sensitive_files": {
    category: "Exposure",
    criteria: "Common sensitive files, VCS metadata, backup archives, database dumps, and phpinfo pages are not publicly readable.",
    remediation: "Remove exposed files, block dotfiles/backups at the web server, and rotate secrets if exposure is confirmed."
  },
  "frontend.probes.backup_files": {
    category: "Exposure",
    criteria: "Common backup archives, editor copies, snapshots, and database dump names are not publicly readable.",
    remediation: "Remove old backups from the web root, block backup extensions at the web server, and rotate any exposed credentials."
  },
  "frontend.probes.sensitive_extensions": {
    category: "Exposure",
    criteria: "Server-side include/config/source/dependency files with sensitive extensions are not publicly served.",
    remediation: "Block server-side and configuration extensions from static serving and keep build/dependency metadata outside the web root."
  },
  "frontend.probes.api_docs": {
    category: "API exposure",
    criteria: "OpenAPI, Swagger UI, ReDoc, and similar API docs are absent, authenticated, IP-restricted, or intentionally approved for the environment.",
    remediation: "Disable public API docs outside development or protect them with authentication/IP allowlisting."
  },
  "frontend.probes.graphql": {
    category: "API exposure",
    criteria: "GraphQL endpoints are inventoried for schema exposure, introspection, and object/function authorization review.",
    remediation: "Protect GraphQL IDEs in production, disable unnecessary introspection, and add authenticated authorization tests for queries and mutations."
  },
  "frontend.probes.upload_surfaces": {
    category: "File handling",
    criteria: "Upload, import, export, and attachment surfaces are inventoried for controlled file-handling review.",
    remediation: "Validate file type and content server-side, scan uploads, store files outside executable paths, and require authentication/authorization."
  },
  "frontend.probes.identity_metadata": {
    category: "Identity",
    criteria: "OIDC, OAuth, and JWKS metadata endpoints are inventoried so issuer, key, scope, and token posture can be reviewed.",
    remediation: "Confirm metadata is intentionally public, rotate signing keys safely, restrict token endpoints, and validate issuer/audience consistently."
  },
  "frontend.probes.unauthenticated_user_api": {
    category: "API authorization",
    criteria: "Common user, account, profile, and session API paths do not anonymously return identity, role, permission, tenant, or session JSON.",
    remediation: "Require authentication and object/function authorization for user/session APIs, and return 401/403 for anonymous requests."
  },
  "frontend.probes.account_recovery": {
    category: "Authentication",
    criteria: "Common account-recovery and password-change routes are inventoried without submitting credentials or reset tokens.",
    remediation: "Review discovered recovery routes for POST-only submissions, CSRF protection, HTTPS, rate limiting, and token handling."
  },
  "frontend.probes.logout_routes": {
    category: "Session",
    criteria: "Common logout and sign-out routes are inventoried without cookies or form submissions, including cache-control, Clear-Site-Data, and cookie-clearing signals.",
    remediation: "Review logout routes for server-side session invalidation, POST/CSRF protections where state changes occur, cache cleanup, and browser storage cleanup where appropriate."
  },
  "frontend.probes.logout_cache": {
    category: "Session caching",
    criteria: "Successful logout and sign-out responses use private/no-store/no-cache style cache controls and avoid public caching.",
    remediation: "Set Cache-Control: no-store or private/no-cache on logout and authentication-state transition responses."
  },
  "frontend.probes.auth_api_rate_limit": {
    category: "Abuse control",
    criteria: "Auth and session API probes are inventoried for visible Retry-After or RateLimit headers.",
    remediation: "Pair this passive evidence with authenticated brute-force/throttling tests and avoid leaking sensitive rate-limit state."
  },
  "frontend.probes.auth_api_cache": {
    category: "API caching",
    criteria: "Auth and session API JSON responses use private/no-store/no-cache style cache controls and avoid public caching.",
    remediation: "Set Cache-Control: no-store or private/no-cache on user, account, and session JSON responses."
  },
  "frontend.probes.auth_api_nosniff": {
    category: "API hardening",
    criteria: "Auth and session API JSON responses send X-Content-Type-Options: nosniff.",
    remediation: "Add X-Content-Type-Options: nosniff to JSON API responses at the app server or edge."
  },
  "frontend.probes.admin_debug": {
    category: "Administration/debug",
    criteria: "Admin consoles, debug endpoints, metrics, actuator, server-status, and hot-reload endpoints are absent or require authentication.",
    remediation: "Block debug/admin endpoints from anonymous internet access and restrict them to internal networks or authenticated admins."
  },
  "frontend.probes.source_maps": {
    category: "Information leakage",
    criteria: "Production source map files are not publicly reachable unless intentionally approved for the environment.",
    remediation: "Disable production source map publishing or restrict access to internal/debug environments."
  },
  "frontend.probes.metafiles": {
    category: "Information leakage",
    criteria: "robots.txt, sitemap.xml, security.txt, and legacy cross-domain policy files do not disclose sensitive paths or permissive wildcard access.",
    remediation: "Remove sensitive path hints from public metafiles and replace wildcard cross-domain policy files with explicit trusted origins."
  },
  "frontend.probes.security_txt": {
    category: "Vulnerability disclosure",
    criteria: "The security.txt endpoint is inventoried for Contact, Expires, Policy, and Preferred-Languages fields.",
    remediation: "Publish /.well-known/security.txt with a monitored Contact field and keep Expires current if the organization accepts vulnerability reports."
  },
  "frontend.probes.error_disclosure": {
    category: "Error handling",
    criteria: "Safe error-page probes do not reveal stack traces, framework internals, SQL errors, or verbose implementation details.",
    remediation: "Return generic error pages to users and route detailed diagnostics only to protected server-side logs."
  },
  "frontend.probes.directory_listing": {
    category: "Exposure",
    criteria: "Common public directories do not return auto-generated directory index listings.",
    remediation: "Disable directory indexing and require explicit routes or authenticated file listings."
  },
  "frontend.probes.http_methods": {
    category: "HTTP method exposure",
    criteria: "OPTIONS does not advertise TRACE or unintended state-changing methods such as PUT, DELETE, or PATCH.",
    remediation: "Restrict allowed HTTP methods at the web server/router and disable TRACE."
  },
  "frontend.discovery.object_ids": {
    category: "Authorization review",
    criteria: "ID-bearing routes are inventoried for manual or authenticated BOLA/BFLA review; passive discovery itself does not prove authorization safety.",
    remediation: "Add authenticated role-matrix tests for object-level and function-level authorization."
  },
  "frontend.discovery.redirect_parameters": {
    category: "Redirect review",
    criteria: "Redirect-like URL parameters are inventoried for manual open-redirect review; passive discovery itself does not prove exploitability.",
    remediation: "Validate redirect targets against an allowlist and prefer server-side route identifiers over arbitrary URL parameters."
  },
  "frontend.discovery.duplicate_parameters": {
    category: "Input validation",
    criteria: "Observed URLs and form actions are inventoried when they already contain duplicate parameter names.",
    remediation: "Define deterministic server-side behavior for repeated parameters and add tests for validation bypass risks."
  },
  "frontend.discovery.sensitive_url_parameters": {
    category: "Data leakage",
    criteria: "Discovered routes and form actions do not pass tokens, passwords, API keys, or session identifiers through URL query or fragment parameters.",
    remediation: "Move sensitive values to POST bodies, headers, or server-side state; rotate exposed secrets and avoid logging sensitive request data."
  },
  "frontend.discovery.auth_flow_token_urls": {
    category: "Data leakage",
    criteria: "Password reset, verification, invitation, magic-link, OAuth, and SSO URL parameters are inventoried without storing token values.",
    remediation: "Review discovered auth-flow URL parameters for HTTPS-only delivery, short lifetime, single use, strict Referrer-Policy, and form_post or server-side state where appropriate."
  },
  "frontend.discovery.attack_surface_matrix": {
    category: "Input validation",
    criteria: "Discovered routes, URL parameters, and form fields are mapped to OWASP WSTG/API review families without sending exploit payloads.",
    remediation: "Use the matrix to plan authorized authenticated tests for XSS, injection, SSRF, file inclusion, upload, and authorization cases."
  }
};

const localizedCriteria = {
  ko: {
    "aegis.authorization_proof": {
      title: "공개 대상 승인 증거가 구체적임",
      category: "승인",
      criteria: "공개 non-loopback 대상은 테스트 전 placeholder가 아닌 소유자와 구체적인 승인 증거를 가져야 합니다.",
      remediation: "공개 또는 운영 유사 대상을 스캔하기 전에 placeholder 소유자 값을 교체하고 명시적인 승인 메타데이터를 추가하세요."
    },
    "aegis.scope_guard": {
      title: "범위, 승인, 안전 플래그, 실행 모드가 검증됨",
      category: "범위 보호",
      criteria: "대상 요청을 보내기 전에 scope 검증이 통과해야 합니다.",
      remediation: "범위 파일, 승인 파일, 안전 플래그를 확인한 뒤 다시 실행하세요."
    },
    "aegis.site_discovery": {
      title: "사이트 탐색 맵이 생성됨",
      category: "탐색",
      criteria: "폼 제출 없이 범위 안의 경로, 링크, 폼, 인증 표면, 차단 URL이 기록되어야 합니다.",
      remediation: "대상이 실행 중인지 확인하고 탐색 설정의 허용 호스트/경로를 조정하세요."
    },
    "frontend.reachable": {
      title: "설정된 프론트엔드 URL에 접근 가능",
      category: "가용성",
      criteria: "모든 범위 내 대상 URL이 요청 오류 없이 응답하고, 최소 하나 이상의 대상이 접근 가능해야 합니다.",
      remediation: "대상 애플리케이션을 실행하고 base URL/허용 목록을 수정한 뒤 다시 스캔하세요."
    },
    "frontend.headers.csp": {
      title: "HTML 응답이 Content-Security-Policy를 전송함",
      category: "브라우저 하드닝",
      criteria: "발견된 모든 HTML 응답이 Content-Security-Policy 헤더를 전송해야 합니다.",
      remediation: "애플리케이션에 맞는 CSP를 설정하고 script/style/frame 정책을 안전하게 구성하세요."
    },
    "frontend.headers.csp_quality": {
      title: "Content-Security-Policy가 약한 지시자를 피함",
      category: "브라우저 하드닝",
      criteria: "CSP는 약한 script 지시자, wildcard source, data/http script source, object-src/base-uri/frame-ancestors 누락을 피해야 합니다.",
      remediation: "unsafe-eval 제거, nonce/hash 기반 script 허용, wildcard 회피, object-src/base-uri/frame-ancestors 설정으로 CSP를 강화하세요."
    },
    "frontend.headers.nosniff": {
      title: "응답이 X-Content-Type-Options: nosniff를 전송함",
      category: "브라우저 하드닝",
      criteria: "검사한 모든 응답이 X-Content-Type-Options: nosniff를 전송해야 합니다.",
      remediation: "웹 서버 또는 애플리케이션 게이트웨이에 X-Content-Type-Options: nosniff를 추가하세요."
    },
    "frontend.headers.referrer": {
      title: "HTML 응답이 안전한 Referrer-Policy를 전송함",
      category: "브라우저 하드닝",
      criteria: "발견된 모든 HTML 응답이 Referrer-Policy를 전송하고 unsafe-url을 사용하지 않아야 합니다.",
      remediation: "strict-origin-when-cross-origin 또는 no-referrer 같은 제한적인 Referrer-Policy를 사용하세요."
    },
    "frontend.headers.permissions": {
      title: "HTML 응답이 Permissions-Policy를 전송함",
      category: "브라우저 하드닝",
      criteria: "발견된 모든 HTML 응답이 Permissions-Policy를 전송해야 합니다.",
      remediation: "camera, microphone, geolocation, payment 등 사용하지 않는 브라우저 기능을 비활성화하세요."
    },
    "frontend.headers.cross_origin_isolation": {
      title: "교차 출처 격리 헤더가 인벤토리됨",
      category: "브라우저 하드닝",
      criteria: "발견된 HTML 응답의 COOP, COEP, COEP-Report-Only, CORP 브라우저 격리 헤더를 기록해야 합니다.",
      remediation: "애플리케이션의 임베딩/리소스 공유 모델을 검토하고 가능한 경우 COOP/COEP/CORP를 적용하세요."
    },
    "frontend.headers.cross_origin_isolation_values": {
      title: "교차 출처 격리 헤더가 약하거나 잘못된 값을 피함",
      category: "브라우저 하드닝",
      criteria: "설정된 COOP, COEP, COEP-Report-Only, CORP 헤더는 알려진 값을 사용하고 unsafe-none으로 명시적 비활성화하지 않아야 합니다.",
      remediation: "필요에 따라 COOP same-origin, COEP require-corp 또는 credentialless, CORP same-origin/same-site/cross-origin 값을 사용하고 잘못된 값이나 unsafe-none을 제거하세요."
    },
    "frontend.headers.csp_report_only": {
      title: "CSP Report-Only 정책이 인벤토리됨",
      category: "브라우저 하드닝",
      criteria: "발견된 HTML 응답의 Content-Security-Policy-Report-Only 정책, 보고 지시자, CSP 품질 신호를 기록해야 합니다.",
      remediation: "Content-Security-Policy로 강제 적용하기 전에 report-to 또는 report-uri가 포함된 CSP Report-Only로 정책 변경을 검증하세요."
    },
    "frontend.headers.powered_by": {
      title: "응답이 X-Powered-By를 노출하지 않음",
      category: "핑거프린팅",
      criteria: "검사한 응답은 X-Powered-By를 노출하지 않아야 합니다.",
      remediation: "앱 서버, 리버스 프록시, 프레임워크 설정에서 프레임워크 노출 헤더를 비활성화하세요."
    },
    "frontend.headers.server_version": {
      title: "응답이 정확한 Server 버전을 노출하지 않음",
      category: "핑거프린팅",
      criteria: "검사한 응답의 Server 헤더가 웹 서버 제품/버전을 자세히 노출하지 않아야 합니다.",
      remediation: "웹 서버, 리버스 프록시, CDN, 애플리케이션 게이트웨이에서 Server 버전 배너를 숨기거나 일반화하세요."
    },
    "frontend.headers.misconfiguration": {
      title: "보안 헤더가 deprecated 또는 과도하게 허용적인 설정을 피함",
      category: "브라우저 하드닝",
      criteria: "보안 헤더는 deprecated HPKP, obsolete X-Frame-Options ALLOW-FROM, 허용적인 X-Permitted-Cross-Domain-Policies, HTTP 응답의 HSTS를 피해야 합니다.",
      remediation: "deprecated 헤더를 제거하고, 필요한 경우 X-Permitted-Cross-Domain-Policies를 none으로 설정하며, HSTS는 HTTPS 응답에만 유지하세요."
    },
    "frontend.fingerprint.framework_markers": {
      title: "응답이 프레임워크 식별 헤더/쿠키명을 피함",
      category: "핑거프린팅",
      criteria: "응답이 프레임워크 식별 헤더나 잘 알려진 프레임워크 세션 쿠키명을 노출하지 않아야 합니다.",
      remediation: "불필요한 프레임워크 노출 헤더를 제거하고 가능한 경우 일반 프레임워크 쿠키명을 변경하세요."
    },
    "frontend.headers.framing": {
      title: "HTML 응답이 클릭재킹을 방어함",
      category: "클릭재킹",
      criteria: "모든 발견된 HTML 응답이 CSP frame-ancestors 또는 X-Frame-Options DENY/SAMEORIGIN을 설정해야 합니다.",
      remediation: "모든 HTML 응답에 CSP frame-ancestors 또는 X-Frame-Options를 추가하세요."
    },
    "frontend.content.reverse_tabnabbing": {
      title: "새 탭 링크가 rel=noopener 또는 noreferrer를 사용함",
      category: "클라이언트 측 테스트",
      criteria: "target=_blank로 새 탭을 여는 HTML 링크는 rel=noopener 또는 rel=noreferrer를 포함해야 합니다.",
      remediation: "특히 외부 링크에 rel=noopener 또는 rel=noreferrer를 추가하세요."
    },
    "frontend.content.subresource_integrity": {
      title: "외부 script/style 리소스가 Subresource Integrity를 사용함",
      category: "클라이언트 측 테스트",
      criteria: "HTML 페이지가 참조하는 외부 script 및 stylesheet 리소스는 가능한 경우 Subresource Integrity를 사용해야 합니다.",
      remediation: "제3자 script/style 리소스에 integrity 속성을 추가하고 검토된 버전으로 고정하세요."
    },
    "frontend.content.mixed_content": {
      title: "HTTPS 페이지가 평문 리소스 또는 form action을 피함",
      category: "전송 보안",
      criteria: "HTTPS 페이지는 active resource를 cleartext HTTP로 로드하거나 form을 cleartext HTTP로 제출하지 않아야 합니다.",
      remediation: "cleartext subresource와 form action을 HTTPS URL 또는 same-origin secure route로 교체하세요."
    },
    "frontend.headers.auth_cache": {
      title: "인증 유사 페이지가 Cache-Control: no-store를 사용함",
      category: "인증",
      criteria: "로그인/계정/비밀번호 재설정/세션 페이지는 Cache-Control: no-store를 사용해야 합니다.",
      remediation: "인증 관련 페이지에 Cache-Control: no-store를 설정하세요."
    },
    "frontend.headers.auth_rate_limit": {
      title: "인증 유사 페이지의 rate-limit 헤더가 인벤토리됨",
      category: "남용 방지",
      criteria: "인증 유사 페이지는 보이는 Retry-After 또는 RateLimit 헤더 신호를 인벤토리해야 합니다.",
      remediation: "이 증거를 서버 측 throttling/lockout 테스트와 함께 사용하고 운영상 유용한 경우 rate-limit 헤더를 노출하세요."
    },
    "frontend.headers.hsts": {
      title: "HTTPS non-loopback 응답이 HSTS를 전송함",
      category: "전송 보안",
      criteria: "non-loopback HTTPS 대상은 Strict-Transport-Security를 전송해야 하며 loopback/local HTTP 대상은 제외합니다.",
      remediation: "HTTPS 강제가 확인된 실제 HTTPS 환경에서 HSTS를 활성화하세요."
    },
    "frontend.headers.cors": {
      title: "CORS가 임의 Origin을 신뢰하지 않음",
      category: "CORS",
      criteria: "응답은 임의의 untrusted Origin을 반사하지 않고, wildcard/reflected Origin을 credentials와 함께 사용하지 않아야 합니다.",
      remediation: "동적 Origin 반사를 명시적 allowlist로 교체하고 Access-Control-Allow-Credentials는 꼭 필요한 경우만 사용하세요."
    },
    "frontend.headers.host_injection": {
      title: "응답이 untrusted Host 계열 헤더를 반사하지 않음",
      category: "입력 검증",
      criteria: "응답은 공격자가 제어한 Host, X-Forwarded-Host, X-Original-Host, Forwarded 헤더를 redirect나 본문에 반영하지 않아야 합니다.",
      remediation: "엄격한 canonical host allowlist를 사용하고 절대 URL은 요청 헤더가 아니라 신뢰된 설정에서 생성하세요."
    },
    "frontend.cookies.flags": {
      title: "쿠키가 방어적 속성을 사용함",
      category: "세션",
      criteria: "세션 유사 쿠키는 상황에 맞게 HttpOnly, SameSite, Secure를 사용해야 합니다.",
      remediation: "세션/인증 쿠키에 HttpOnly, SameSite=Lax/Strict, Secure를 설정하세요."
    },
    "frontend.cookies.scope": {
      title: "민감 쿠키가 넓은 Domain/Path 범위를 피함",
      category: "세션",
      criteria: "민감 쿠키는 명시적 근거 없이 넓은 Domain 범위나 Path=/를 사용하지 않아야 합니다.",
      remediation: "가능하면 host-scope 쿠키를 사용하고 Path를 필요한 최소 애플리케이션 영역으로 좁히세요."
    },
    "frontend.forms.autocomplete": {
      title: "인증 필드가 명시적 autocomplete 힌트를 사용함",
      category: "인증 UX",
      criteria: "인증 필드는 password manager용 autocomplete 힌트를 명시해야 합니다.",
      remediation: "비밀번호에는 current-password/new-password, 로그인 식별자에는 username/email을 사용하세요."
    },
    "frontend.forms.auth_get_method": {
      title: "인증 유사 form이 GET 제출을 피함",
      category: "인증",
      criteria: "인증 유사 form은 GET 방식으로 제출되지 않아야 합니다.",
      remediation: "로그인/비밀번호 재설정 form은 POST로 제출하고 credential이나 token이 URL에 들어가지 않게 하세요."
    },
    "frontend.forms.csrf_tokens": {
      title: "상태 변경 form이 CSRF token 후보를 포함함",
      category: "CSRF",
      criteria: "상태 변경 form은 passive inventory에서 CSRF token 후보 field를 포함해야 합니다.",
      remediation: "상태 변경 form에 anti-CSRF token을 추가하고 인증된 browser 요청에서 서버 측 검증을 수행하세요."
    },
    "frontend.forms.external_actions": {
      title: "form action이 승인된 범위 안의 대상으로만 제출됨",
      category: "데이터 유출",
      criteria: "form action은 승인된 frontend 또는 backend target으로만 제출되어야 합니다.",
      remediation: "예상치 못한 외부 form action을 승인된 same-site/API endpoint로 교체하거나 신뢰된 제3자 처리자를 명시적으로 문서화하세요."
    },
    "frontend.forms.sensitive_cleartext_action": {
      title: "민감 form이 loopback 외부에서 평문 제출을 피함",
      category: "전송 보안",
      criteria: "인증, 상태 변경, 민감 form은 loopback 환경이 아닌 곳에서 cleartext HTTP로 제출되지 않아야 합니다.",
      remediation: "민감 form 페이지와 action endpoint를 HTTPS로 제공하고 cleartext HTTP는 HTTPS로 리다이렉트하세요."
    },
    "frontend.forms.file_upload_inventory": {
      title: "파일 업로드 form이 통제된 검토 대상으로 인벤토리됨",
      category: "파일 처리",
      criteria: "파일 업로드 control은 통제된 업로드 검증 검토 대상으로 기록되어야 합니다.",
      remediation: "업로드 control의 file type 검증, 악성 파일 검사, 저장소 격리, 권한, 실행 가능 경로 제한을 검토하세요."
    },
    "frontend.transport.auth_https": {
      title: "인증 표면이 loopback 외부에서 평문 전송을 피함",
      category: "전송 보안",
      criteria: "인증 표면은 loopback 호스트가 아닌 환경에서 cleartext transport를 사용하지 않아야 합니다.",
      remediation: "non-local 환경의 인증/계정 플로우를 HTTPS로 제공하세요."
    },
    "frontend.transport.public_https": {
      title: "공개 non-loopback 대상이 HTTPS를 사용함",
      category: "전송 보안",
      criteria: "설정된 공개 non-loopback 프론트엔드/백엔드 base URL은 cleartext HTTP가 아니라 HTTPS를 사용해야 합니다.",
      remediation: "공개 환경은 HTTPS로 제공하고 edge에서 HTTP를 HTTPS로 리다이렉트하세요."
    },
    "frontend.transport.tls_certificate": {
      title: "공개 HTTPS 대상이 유효한 최신 TLS 인증서를 제시함",
      category: "전송 보안",
      criteria: "공개 HTTPS 대상은 TLSv1.2 또는 TLSv1.3으로 협상하고, 신뢰된 인증서를 제시하며, 만료까지 14일 이상 남아야 합니다.",
      remediation: "만료/유효하지 않은 인증서를 갱신 또는 교체하고 edge에서 legacy TLS 프로토콜을 비활성화하세요."
    },
    "frontend.dns.dangling_cname": {
      title: "공개 호스트명이 dangling CNAME takeover 지문을 보이지 않음",
      category: "DNS",
      criteria: "공개 대상 호스트명은 알려진 third-party 서비스로 향하는 CNAME과 unclaimed-resource takeover 지문을 동시에 보여서는 안 됩니다.",
      remediation: "dangling DNS 레코드를 제거하거나 노출 전 해당 third-party 리소스를 claim/provision하세요."
    },
    "frontend.content.client_secrets": {
      title: "클라이언트 번들이 명백한 시크릿을 노출하지 않음",
      category: "정보 노출",
      criteria: "발견된 클라이언트 JavaScript/JSON 자산은 private key, provider key, JWT literal, secret assignment를 노출하지 않아야 합니다.",
      remediation: "클라이언트 측 시크릿을 제거하고, 노출된 자격 증명을 교체하며, 권한 있는 토큰은 서버 측에 보관하세요."
    },
    "frontend.content.web_messaging": {
      title: "클라이언트 번들이 위험한 Web Messaging 패턴을 피함",
      category: "클라이언트 측 테스트",
      criteria: "클라이언트 번들은 wildcard postMessage target이나 Origin 검증 신호가 없는 message listener를 사용하지 않아야 합니다.",
      remediation: "명시적 postMessage target origin을 사용하고 message data를 신뢰하기 전에 event.origin을 검증하세요."
    },
    "frontend.content.dom_xss": {
      title: "클라이언트 번들이 DOM XSS source-to-sink 패턴을 피함",
      category: "클라이언트 측 테스트",
      criteria: "클라이언트 번들은 URL/document source 데이터가 DOM/script 실행 sink로 흐르는 명백한 패턴을 보이지 않아야 합니다.",
      remediation: "신뢰할 수 없는 클라이언트 데이터를 DOM에 삽입하기 전 encode/sanitize하고 eval 계열 sink를 피하세요."
    },
    "frontend.content.client_redirects": {
      title: "클라이언트 번들이 URL 제어 리다이렉트/문서 쓰기를 피함",
      category: "클라이언트 측 테스트",
      criteria: "클라이언트 번들은 URL 제어 값으로 navigation 또는 document write를 직접 수행하는 패턴을 보이지 않아야 합니다.",
      remediation: "리다이렉트 대상은 allowlist로 검증하고 URL 제어 값을 document output에 직접 쓰지 마세요."
    },
    "frontend.content.resource_manipulation": {
      title: "클라이언트 번들이 URL 제어 리소스 로딩을 피함",
      category: "클라이언트 측 테스트",
      criteria: "클라이언트 번들은 URL 제어 값으로 script, iframe, 기타 리소스를 직접 로드하는 패턴을 보이지 않아야 합니다.",
      remediation: "클라이언트가 선택한 리소스는 서버 승인 allowlist 또는 고정 route identifier를 통해 해석하세요."
    },
    "frontend.content.template_injection": {
      title: "클라이언트 템플릿 sink가 URL 제어 입력을 피함",
      category: "클라이언트 측 테스트",
      criteria: "클라이언트 번들은 URL 제어 데이터를 framework template HTML sink에 전달하는 패턴을 보이지 않아야 합니다.",
      remediation: "v-html, ng-bind-html, x-html, dangerouslySetInnerHTML 같은 template/HTML sink에 untrusted 값을 렌더링하지 마세요."
    },
    "frontend.content.prototype_pollution": {
      title: "클라이언트 번들이 prototype pollution 후보 흐름을 피함",
      category: "입력 검증",
      criteria: "클라이언트 번들은 query/hash/JSON 입력이 prototype-sensitive object key 처리로 흐르는 명백한 패턴을 보이지 않아야 합니다.",
      remediation: "deep merge/clone/assign 전에 __proto__, constructor, prototype 키를 거부하고 패치된 parsing library를 사용하세요."
    },
    "frontend.content.browser_storage": {
      title: "클라이언트 번들이 민감 키를 브라우저 저장소에 저장하지 않음",
      category: "클라이언트 측 테스트",
      criteria: "클라이언트 번들은 token/session/password 유사 키를 localStorage 또는 sessionStorage에 저장하는 패턴을 보이지 않아야 합니다.",
      remediation: "민감 세션 재료는 HttpOnly 쿠키 또는 서버 측 저장소에 보관하고, 비민감 브라우저 저장소는 로그아웃 시 정리하세요."
    },
    "frontend.content.websockets": {
      title: "클라이언트 번들이 공개 ws:// WebSocket 엔드포인트를 피함",
      category: "WebSocket",
      criteria: "클라이언트 번들은 cleartext public ws:// WebSocket 엔드포인트를 참조하지 않아야 합니다.",
      remediation: "공개 WebSocket 엔드포인트에는 wss://를 사용하고 HTTP API와 동일한 origin/authentication 통제를 적용하세요."
    },
    "frontend.content.jwt_algorithms": {
      title: "JWT literal이 unsigned 또는 malformed 알고리즘을 광고하지 않음",
      category: "세션",
      criteria: "클라이언트 자산에서 발견된 JWT literal은 alg=none, 누락된 알고리즘, 빈 서명을 광고하지 않아야 합니다.",
      remediation: "클라이언트 번들에 JWT literal을 포함하지 말고, 서버 측에서 unsigned JWT를 거부하며 예상 알고리즘을 강제하세요."
    },
    "frontend.content.xssi_json": {
      title: "JSON 자산이 XSSI 검토 대상으로 인벤토리됨",
      category: "클라이언트 측 테스트",
      criteria: "클라이언트 자산에서 발견된 JSON 응답은 Cross Site Script Inclusion 수동 검토 대상으로 기록되어야 합니다.",
      remediation: "민감 JSON 엔드포인트에는 올바른 JSON content type, nosniff, CSRF/session 통제, 필요 시 anti-XSSI prefix를 사용하세요."
    },
    "frontend.content.cloud_storage_refs": {
      title: "클라우드 스토리지 참조가 접근 제어 검토 대상으로 인벤토리됨",
      category: "클라우드 스토리지",
      criteria: "클라이언트 자산에서 발견된 클라우드 스토리지 URL은 수동 접근 제어 검토 대상으로 기록되어야 합니다.",
      remediation: "참조된 bucket/container의 least privilege, public listing 제한, 민감 object 노출 여부를 검토하세요."
    },
    "frontend.probes.sensitive_files": {
      title: "일반 민감 파일이 공개로 읽히지 않음",
      category: "노출",
      criteria: "일반적인 민감 파일, VCS metadata, backup archive, database dump, phpinfo 페이지가 공개로 읽히지 않아야 합니다.",
      remediation: "노출 파일을 제거하고 web server에서 dotfile/backup을 차단하며, 노출이 확인되면 시크릿을 교체하세요."
    },
    "frontend.probes.backup_files": {
      title: "오래된 백업 및 미참조 파일이 공개로 읽히지 않음",
      category: "노출",
      criteria: "일반 백업 archive, editor copy, snapshot, database dump 이름이 공개로 읽히지 않아야 합니다.",
      remediation: "오래된 백업을 web root에서 제거하고 backup 확장자를 차단하며, 노출된 자격 증명은 교체하세요."
    },
    "frontend.probes.sensitive_extensions": {
      title: "민감 server-side 확장자와 설정 파일이 공개 제공되지 않음",
      category: "노출",
      criteria: "민감 확장자를 가진 server-side include/config/source/dependency 파일이 공개 제공되지 않아야 합니다.",
      remediation: "server-side/config 확장자의 static serving을 차단하고 build/dependency metadata를 web root 밖에 두세요."
    },
    "frontend.probes.api_docs": {
      title: "API 문서가 익명으로 노출되지 않음",
      category: "API 노출",
      criteria: "OpenAPI, Swagger UI, ReDoc 등 API 문서는 없거나 인증/IP 제한/환경 승인 하에 공개되어야 합니다.",
      remediation: "개발 외 환경에서 공개 API 문서를 비활성화하거나 인증/IP allowlist로 보호하세요."
    },
    "frontend.probes.graphql": {
      title: "GraphQL 엔드포인트가 schema 및 권한 검토 대상으로 인벤토리됨",
      category: "API 노출",
      criteria: "GraphQL 엔드포인트는 schema 노출, introspection, 객체/기능 권한 검토 대상으로 기록되어야 합니다.",
      remediation: "운영 GraphQL IDE를 보호하고 불필요한 introspection을 비활성화하며 query/mutation 권한 테스트를 추가하세요."
    },
    "frontend.probes.upload_surfaces": {
      title: "업로드 및 import/export 표면이 파일 처리 검토 대상으로 인벤토리됨",
      category: "파일 처리",
      criteria: "upload, import, export, attachment 표면은 통제된 파일 처리 검토 대상으로 기록되어야 합니다.",
      remediation: "파일 type/content를 서버에서 검증하고, 업로드 검사를 수행하며, 실행 가능한 경로 밖에 저장하고 인증/권한을 요구하세요."
    },
    "frontend.probes.identity_metadata": {
      title: "OIDC, OAuth, JWKS 메타데이터 엔드포인트가 인벤토리됨",
      category: "인증/식별",
      criteria: "issuer, key, scope, token posture 검토를 위해 OIDC, OAuth, JWKS 메타데이터 엔드포인트가 기록되어야 합니다.",
      remediation: "메타데이터 공개가 의도된 것인지 확인하고 signing key rotation, token endpoint 제한, issuer/audience 검증을 점검하세요."
    },
    "frontend.probes.unauthenticated_user_api": {
      title: "사용자, 계정, 세션 API가 익명으로 읽히지 않음",
      category: "API 권한",
      criteria: "일반 사용자, 계정, 프로필, 세션 API 경로는 익명 요청에 identity, role, permission, tenant, session JSON을 반환하지 않아야 합니다.",
      remediation: "사용자/세션 API에 인증과 객체/기능 권한 검사를 요구하고 익명 요청에는 401/403을 반환하세요."
    },
    "frontend.probes.account_recovery": {
      title: "계정 복구 및 비밀번호 변경 경로가 인벤토리됨",
      category: "인증",
      criteria: "일반 계정 복구/비밀번호 변경 경로는 credential 또는 reset token 제출 없이 기록되어야 합니다.",
      remediation: "발견된 복구 경로의 POST-only 제출, CSRF 보호, HTTPS, rate limiting, token 처리를 검토하세요."
    },
    "frontend.probes.logout_routes": {
      title: "로그아웃 및 sign-out 경로가 세션 정리 검토 대상으로 인벤토리됨",
      category: "세션",
      criteria: "일반 logout/sign-out 경로는 cookie 또는 form 제출 없이 기록하고 cache-control, Clear-Site-Data, cookie 삭제 신호를 함께 남겨야 합니다.",
      remediation: "로그아웃 경로의 서버 측 세션 무효화, 상태 변경 시 POST/CSRF 보호, cache 정리, 필요한 브라우저 저장소 정리를 검토하세요."
    },
    "frontend.probes.logout_cache": {
      title: "로그아웃 및 sign-out 응답이 브라우저/공유 캐시 저장을 피함",
      category: "세션 캐싱",
      criteria: "성공한 logout/sign-out 응답은 private/no-store/no-cache 계열 cache control을 사용하고 public caching을 피해야 합니다.",
      remediation: "로그아웃 및 인증 상태 전환 응답에 Cache-Control: no-store 또는 private/no-cache를 설정하세요."
    },
    "frontend.probes.auth_api_rate_limit": {
      title: "인증/세션 API의 rate-limit 헤더가 인벤토리됨",
      category: "남용 방지",
      criteria: "인증 및 세션 API probe는 보이는 Retry-After 또는 RateLimit 헤더 신호를 인벤토리해야 합니다.",
      remediation: "이 passive 증거를 인증된 brute-force/throttling 테스트와 함께 사용하고 민감한 rate-limit 상태 노출은 피하세요."
    },
    "frontend.probes.auth_api_cache": {
      title: "인증/세션 API JSON 응답이 공유 캐시 노출을 피함",
      category: "API 캐싱",
      criteria: "인증 및 세션 API JSON 응답은 private/no-store/no-cache 계열 cache control을 사용하고 public caching을 피해야 합니다.",
      remediation: "사용자, 계정, 세션 JSON 응답에 Cache-Control: no-store 또는 private/no-cache를 설정하세요."
    },
    "frontend.probes.auth_api_nosniff": {
      title: "인증/세션 API JSON 응답이 nosniff를 사용함",
      category: "API 하드닝",
      criteria: "인증 및 세션 API JSON 응답은 X-Content-Type-Options: nosniff를 전송해야 합니다.",
      remediation: "앱 서버 또는 edge에서 JSON API 응답에 X-Content-Type-Options: nosniff를 추가하세요."
    },
    "frontend.probes.admin_debug": {
      title: "관리자 및 디버그 표면이 없거나 인증을 요구함",
      category: "관리/디버그",
      criteria: "관리 콘솔, 디버그 엔드포인트, metrics, actuator, server-status, hot-reload 엔드포인트는 없거나 인증을 요구해야 합니다.",
      remediation: "디버그/관리 엔드포인트의 익명 인터넷 접근을 차단하고 내부망 또는 인증된 관리자에게만 제한하세요."
    },
    "frontend.probes.source_maps": {
      title: "운영 source map이 공개 노출되지 않음",
      category: "정보 노출",
      criteria: "운영 source map 파일은 환경에서 의도적으로 승인되지 않는 한 공개 접근 가능하면 안 됩니다.",
      remediation: "운영 source map 배포를 비활성화하거나 내부/디버그 환경으로 접근을 제한하세요."
    },
    "frontend.probes.metafiles": {
      title: "웹 서버 metafile이 민감 경로나 허용적 cross-domain policy를 노출하지 않음",
      category: "정보 노출",
      criteria: "robots.txt, sitemap.xml, security.txt, legacy cross-domain policy 파일이 민감 경로나 wildcard access를 노출하지 않아야 합니다.",
      remediation: "공개 metafile에서 민감 경로 힌트를 제거하고 wildcard cross-domain policy를 명시적 trusted origin으로 교체하세요."
    },
    "frontend.probes.security_txt": {
      title: "보안 연락처 메타데이터가 인벤토리됨",
      category: "취약점 제보",
      criteria: "security.txt endpoint는 Contact, Expires, Policy, Preferred-Languages 필드 존재 여부가 기록되어야 합니다.",
      remediation: "조직이 취약점 제보를 받는다면 /.well-known/security.txt에 모니터링되는 Contact 필드를 게시하고 Expires를 최신으로 유지하세요."
    },
    "frontend.probes.error_disclosure": {
      title: "오류 응답이 stack trace 또는 프레임워크 내부 정보를 노출하지 않음",
      category: "오류 처리",
      criteria: "안전한 오류 페이지 probe가 stack trace, 프레임워크 내부, SQL 오류, verbose 구현 정보를 드러내지 않아야 합니다.",
      remediation: "사용자에게는 일반 오류 페이지를 반환하고 자세한 진단 정보는 보호된 서버 로그로만 전송하세요."
    },
    "frontend.probes.directory_listing": {
      title: "일반 공개 디렉터리에서 directory listing이 활성화되지 않음",
      category: "노출",
      criteria: "일반 공개 디렉터리는 자동 생성된 directory index listing을 반환하지 않아야 합니다.",
      remediation: "directory indexing을 비활성화하고 명시적 route 또는 인증된 파일 listing만 허용하세요."
    },
    "frontend.probes.http_methods": {
      title: "OPTIONS가 위험한 HTTP method를 광고하지 않음",
      category: "HTTP method 노출",
      criteria: "OPTIONS가 TRACE 또는 PUT, DELETE, PATCH 같은 의도하지 않은 상태 변경 method를 광고하지 않아야 합니다.",
      remediation: "웹 서버/router에서 허용 method를 제한하고 TRACE를 비활성화하세요."
    },
    "frontend.discovery.object_ids": {
      title: "객체 식별자 route가 BOLA/BFLA 검토 대상으로 인벤토리됨",
      category: "권한 검토",
      criteria: "ID가 포함된 route는 수동 또는 인증된 role-matrix BOLA/BFLA 검토 대상으로 기록되어야 하며, passive discovery만으로 권한 안전성을 증명하지 않습니다.",
      remediation: "객체 수준 및 기능 수준 권한에 대해 인증된 role-matrix 테스트를 추가하세요."
    },
    "frontend.discovery.redirect_parameters": {
      title: "리다이렉트 유사 URL 파라미터가 open redirect 검토 대상으로 인벤토리됨",
      category: "리다이렉트 검토",
      criteria: "리다이렉트 유사 URL 파라미터는 수동 open redirect 검토 대상으로 기록되어야 하며, passive discovery만으로 악용 가능성을 증명하지 않습니다.",
      remediation: "리다이렉트 대상을 allowlist로 검증하고 임의 URL 파라미터보다 서버 측 route identifier를 선호하세요."
    },
    "frontend.discovery.duplicate_parameters": {
      title: "중복 URL 파라미터가 HTTP Parameter Pollution 검토 대상으로 인벤토리됨",
      category: "입력 검증",
      criteria: "관찰된 URL과 form action에 중복 파라미터 이름이 있으면 기록되어야 합니다.",
      remediation: "반복 파라미터에 대한 서버 측 동작을 명확히 정의하고 validation bypass 위험 테스트를 추가하세요."
    },
    "frontend.discovery.sensitive_url_parameters": {
      title: "민감 값이 URL query 또는 fragment parameter로 전달되지 않음",
      category: "데이터 유출",
      criteria: "발견된 route와 form action은 token, password, API key, session identifier를 URL query 또는 fragment parameter로 전달하지 않아야 합니다.",
      remediation: "민감 값은 POST body, header, 서버 측 state로 이동하고, 노출된 secret은 교체하며, 민감 요청 데이터 logging을 피하세요."
    },
    "frontend.discovery.auth_flow_token_urls": {
      title: "인증 흐름 URL token이 유출 검토 대상으로 인벤토리됨",
      category: "데이터 유출",
      criteria: "비밀번호 재설정, 인증 확인, 초대, magic link, OAuth, SSO URL parameter는 token 값 저장 없이 이름만 기록되어야 합니다.",
      remediation: "발견된 인증 흐름 URL parameter는 HTTPS-only 전달, 짧은 만료, 단회 사용, 엄격한 Referrer-Policy, 필요 시 form_post 또는 서버 측 state 전환을 검토하세요."
    },
    "frontend.discovery.attack_surface_matrix": {
      title: "입력 및 API 공격 표면이 OWASP 검토군으로 분류됨",
      category: "입력 검증",
      criteria: "발견된 route, URL parameter, form field가 exploit payload 없이 OWASP WSTG/API 검토군으로 매핑되어야 합니다.",
      remediation: "이 matrix를 기준으로 XSS, injection, SSRF, file inclusion, upload, authorization에 대한 승인된 인증 테스트를 계획하세요."
    }
  }
};

async function readJson(file, fallback) {
  try {
    return JSON.parse(await readFile(resolve(cwd, file), "utf8"));
  } catch {
    return fallback;
  }
}

function normalizeLanguage(value) {
  const raw = String(value || "").toLowerCase();
  if (raw.startsWith("ko")) return "ko";
  if (raw.startsWith("ja")) return "ja";
  if (raw.startsWith("zh")) return "zh";
  return "en";
}

function locale(language) {
  return translations[language] || translations.en;
}

function criterionFor(id, language) {
  return {
    ...(criteria[id] || {}),
    ...(localizedCriteria[language]?.[id] || {})
  };
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function redact(value) {
  return String(value ?? "")
    .replace(/(authorization|cookie|token|api[_-]?key|password|secret|private[_-]?key)=?[^,\s;"]+/gi, "$1=[REDACTED]")
    .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, "[REDACTED_EMAIL]")
    .replace(/Bearer\s+[A-Za-z0-9._~+/=-]+/gi, "Bearer [REDACTED]");
}

function safeEvidence(value, depth = 0) {
  if (value == null) return value;
  if (depth > 4) return "[truncated]";
  if (typeof value === "string") return redact(value).slice(0, 500);
  if (typeof value === "number" || typeof value === "boolean") return value;
  if (Array.isArray(value)) return value.slice(0, 12).map((item) => safeEvidence(item, depth + 1));
  if (typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value)
        .filter(([key]) => !/body|preview|html|responseText/i.test(key))
        .slice(0, 20)
        .map(([key, item]) => [key, safeEvidence(item, depth + 1)])
    );
  }
  return String(value);
}

function isLoopbackHost(hostname) {
  return ["localhost", "127.0.0.1", "::1"].includes(String(hostname || "").toLowerCase());
}

function hostFromUrl(value) {
  try {
    return new URL(value).hostname;
  } catch {
    return "";
  }
}

function publicTargetUrls(scope) {
  return ["frontend", "backend_api"]
    .map((name) => scope?.targets?.[name])
    .filter((target) => target?.enabled !== false && target?.base_url)
    .map((target) => target.base_url)
    .filter((url) => {
      const host = hostFromUrl(url);
      return host && !isLoopbackHost(host);
    });
}

function authorizationProofStatus(scope, auth) {
  const publicTargets = publicTargetUrls(scope);
  const owner = String(scope?.authorization?.owner || "");
  const placeholderOwner = !owner || /^(security@example\.com|unknown|test@example\.com)$/i.test(owner);
  const proofType = String(scope?.authorization?.proof_type || "");
  const concreteProfiles = Array.isArray(auth?.auth_profiles) && auth.auth_profiles.length > 0;
  const proofMetadata = Boolean(auth?.proof || auth?.authorization || auth?.approved_by || auth?.ticket || auth?.scope_reference);
  const ok = publicTargets.length === 0 || (!placeholderOwner && Boolean(proofType) && (concreteProfiles || proofMetadata));
  return {
    ok,
    publicTargets,
    owner: owner || "unknown",
    proofType: proofType || "unknown",
    proofFile: scope?.authorization?.proof_file || "",
    authProfiles: auth?.auth_profiles?.length || 0,
    hasProofMetadata: proofMetadata
  };
}

function statusFromFinding(finding) {
  if (!finding) return "NOT_RUN";
  if (finding.passed) return "PASS";
  return finding.level === "error" ? "FAIL" : "WARN";
}

function statusClass(status) {
  if (status === "PASS") return "ok";
  if (status === "FAIL") return "danger";
  if (status === "WARN") return "warn";
  return "";
}

function statusLabel(status, t) {
  if (status === "PASS") return t.statusPass;
  if (status === "FAIL") return t.statusFail;
  if (status === "WARN") return t.statusWarn;
  if (status === "INFO") return t.statusInfo;
  return t.statusNotRun;
}

function localizedResult(status, language, fallback = "") {
  if (language === "en" && fallback) return fallback;
  const t = locale(language);
  if (status === "PASS") return t.statusPass;
  if (status === "FAIL") return `${t.statusFail}: ${t.evidence} / ${t.recommendations}`;
  if (status === "WARN") return `${t.statusWarn}: ${t.evidence} / ${t.recommendations}`;
  return t.statusNotRun;
}

function findingTitle(finding, language) {
  const meta = criterionFor(finding?.id, language);
  return meta.title || finding?.title || meta.category || finding?.id || "Unknown check";
}

function evidenceSummary(evidence) {
  if (!evidence || Object.keys(evidence).length === 0) return "No evidence recorded.";
  const safe = safeEvidence(evidence);
  return JSON.stringify(safe, null, 2);
}

const evidenceKeyLabels = {
  ko: {
    ok: "정상",
    publicTargets: "공개 대상",
    owner: "소유자",
    proofType: "증명 유형",
    proofFile: "증명 파일",
    authProfiles: "인증 프로필 수",
    hasProofMetadata: "증명 메타데이터 있음",
    check: "검사",
    status: "상태",
    detail: "상세",
    routes: "경로",
    links: "링크",
    forms: "폼",
    authSurfaces: "인증 표면",
    blockedUrls: "차단 URL",
    requested: "요청",
    reachable: "접근 가능",
    errors: "오류",
    checked: "확인",
    missing: "누락",
    issues: "이슈",
    present: "존재",
    cookies: "쿠키",
    headers: "헤더",
    cleartext: "평문 전송",
    inspections: "검사 내역",
    exposed: "노출",
    admin: "관리자 표면",
    debug: "디버그 표면",
    risky: "위험 method",
    candidates: "후보",
    count: "개수",
    references: "참조",
    target: "대상",
    category: "분류",
    path: "경로",
    method: "메서드",
    requestedUrl: "요청 URL",
    finalUrl: "최종 URL",
    contentType: "콘텐츠 타입",
    allow: "Allow 헤더",
    redirects: "리다이렉트",
    signal: "신호",
    url: "URL",
    header: "헤더",
    value: "값",
    source: "출처",
    testOrigin: "테스트 Origin",
    testHost: "테스트 Host",
    statusCode: "상태 코드"
  }
};

const evidenceValueLabels = {
  ko: {
    passed: "통과",
    "base-uri not locked to none": "base-uri가 none으로 잠겨 있지 않음",
    "object-src not locked to none": "object-src가 none으로 잠겨 있지 않음",
    "frame-ancestors missing": "frame-ancestors 누락",
    "script-src unsafe-eval": "script-src unsafe-eval 사용",
    "script-src unsafe-inline without nonce/hash": "nonce/hash 없는 script-src unsafe-inline 사용",
    "script-src wildcard": "script-src wildcard 사용",
    "script-src data:": "script-src data: 허용",
    "script-src cleartext source": "script-src에 평문 source 사용",
    hsts_on_http: "HTTP 응답에 HSTS 설정",
    api_docs: "API 문서 노출",
    source_map: "source map 노출",
    directory_listing: "directory listing 노출",
    stack_or_error_detail: "stack trace 또는 상세 오류 노출",
    cleartext_public_websocket: "공개 ws:// WebSocket 참조",
    target_blank_without_noopener: "noopener 없는 새 탭 링크",
    dom_xss_source_to_sink: "DOM XSS source-to-sink 후보",
    client_template_injection: "클라이언트 템플릿 주입 후보",
    prototype_pollution_candidate: "prototype pollution 후보",
    sensitive_browser_storage_key: "민감 브라우저 저장소 키",
    untrusted_host_reflected: "untrusted Host 헤더 반사",
    reflected_untrusted_origin: "untrusted Origin 반사",
    reflected_origin_with_credentials: "credentials와 함께 Origin 반사",
    wildcard_origin_with_credentials: "credentials와 함께 wildcard Origin 허용"
  }
};

function localizeEvidence(value, language, depth = 0) {
  if (language === "en" || value == null || depth > 5) return value;
  const keyLabels = evidenceKeyLabels[language] || {};
  const valueLabels = evidenceValueLabels[language] || {};
  if (typeof value === "string") return valueLabels[value] || value;
  if (typeof value === "number" || typeof value === "boolean") return value;
  if (Array.isArray(value)) return value.map((item) => localizeEvidence(item, language, depth + 1));
  if (typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [
        keyLabels[key] || key,
        localizeEvidence(item, language, depth + 1)
      ])
    );
  }
  return String(value);
}

function buildFallbackChecks(scope, latestScan, auth, language) {
  const t = locale(language);
  const proofStatus = authorizationProofStatus(scope, auth);
  const authorization = criterionFor("aegis.authorization_proof", language);
  const scopeGuard = criterionFor("aegis.scope_guard", language);
  const discovery = criterionFor("aegis.site_discovery", language);
  const scopeStatus = latestScan?.observations?.some((item) => item.check === "scope_guard" && item.status === "passed") ? "PASS" : "NOT_RUN";
  const discoveryStatus = latestScan?.discovery ? "PASS" : "NOT_RUN";
  return [
    {
      id: "aegis.authorization_proof",
      title: authorization.title || "Public target authorization proof is concrete",
      category: authorization.category,
      status: proofStatus.ok ? "PASS" : "WARN",
      passCriteria: authorization.criteria,
      result: proofStatus.ok ? t.statusPass : `${t.statusWarn}: ${authorization.remediation}`,
      evidence: proofStatus,
      remediation: authorization.remediation
    },
    {
      id: "aegis.scope_guard",
      title: scopeGuard.title || "Scope, authorization, safety flags, and execution mode were verified",
      category: scopeGuard.category || "Scope guard",
      status: scopeStatus,
      passCriteria: scopeGuard.criteria,
      result: localizedResult(scopeStatus, language, "Aegis scope guard observation"),
      evidence: latestScan?.observations?.find((item) => item.check === "scope_guard") || {}
    },
    {
      id: "aegis.site_discovery",
      title: discovery.title || "Site discovery map was generated",
      category: discovery.category || "Discovery",
      status: discoveryStatus,
      passCriteria: discovery.criteria,
      result: localizedResult(discoveryStatus, language, "Passive crawler artifact"),
      evidence: {
        routes: latestScan?.discovery?.routes?.length || 0,
        links: latestScan?.discovery?.links?.length || 0,
        forms: latestScan?.discovery?.forms?.length || 0,
        authSurfaces: latestScan?.discovery?.auth_surfaces?.length || 0,
        blockedUrls: latestScan?.discovery?.blocked_urls?.length || 0
      }
    }
  ];
}

function buildTestMatrix(advisory, latestScan, scope, auth, language) {
  const advisoryChecks = (advisory?.findings || []).map((finding) => {
    const meta = criterionFor(finding.id, language);
    const status = statusFromFinding(finding);
    return {
      id: finding.id,
      title: findingTitle(finding, language),
      category: meta.category || "Security",
      status,
      passCriteria: meta.criteria || "The check-specific security expectation is met.",
      result: localizedResult(status, language, finding.passed ? "Passed" : finding.detail || "Review required"),
      evidence: safeEvidence(finding.evidence || {}),
      remediation: meta.remediation || finding.detail || ""
    };
  });

  return [
    ...buildFallbackChecks(scope, latestScan, auth, language),
    ...advisoryChecks
  ];
}

function reportStatus(testMatrix) {
  if (testMatrix.some((item) => item.status === "FAIL")) return "FAIL";
  if (testMatrix.some((item) => item.status === "WARN")) return "WARN";
  if (testMatrix.some((item) => item.status === "PASS")) return "PASS";
  return "NOT_RUN";
}

function buildFindings(testMatrix, advisory) {
  const advisoryById = new Map((advisory?.findings || []).map((finding) => [finding.id, finding]));
  return testMatrix
    .filter((item) => ["WARN", "FAIL"].includes(item.status))
    .map((item) => {
      const source = advisoryById.get(item.id);
      return {
        id: item.id,
        severity: source?.level || (item.status === "FAIL" ? "error" : "warning"),
        title: item.title,
        status: item.status,
        detail: item.result,
        passCriteria: item.passCriteria,
        evidence: item.evidence,
        remediation: item.remediation
      };
    });
}

function uniqueSources(advisory, baseline) {
  const all = [...references, ...(baseline?.sources || []), ...(advisory?.sources || [])];
  const seen = new Set();
  return all.filter((source) => {
    const key = source?.url || source?.name;
    if (!key || seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function buildMethodology(scope, latestScan, advisory, language) {
  if (language === "ko") {
    return [
      "대상 점검 전 aegis.scope.json에서 승인된 범위를 읽습니다.",
      "기본 모드는 passive이며 자격 증명을 추측하지 않고, 폼을 제출하지 않으며, 파괴적 payload를 보내지 않습니다.",
      "사이트 탐색은 허용된 호스트/경로만 따라가고 범위 밖 URL은 차단 목록으로 기록합니다.",
      "실시간 대상 점검은 응답 메타데이터, 헤더, 쿠키, 낮은 영향도의 GET/OPTIONS probe를 사용합니다.",
      "패시브 probe는 일반 민감 파일, API 문서, 관리자/디버그 표면, 위험 HTTP method, ID 포함 route 인벤토리를 포함합니다.",
      "보고서는 증거 요약만 저장하며 HTTP 응답 본문과 민감 값은 제외하거나 마스킹합니다.",
      `최근 스캔: ${latestScan?.scan_id || "미실행"} / 대상 점검: ${advisory?.status || "미실행"} / 프론트엔드: ${scope?.targets?.frontend?.base_url || "미설정"}`
    ];
  }
  if (language === "ja") {
    return [
      "対象チェック前に aegis.scope.json から承認済みスコープを読み取ります。",
      "既定モードは passive で、認証情報推測、フォーム送信、破壊的 payload 送信は行いません。",
      "サイト探索は許可されたホスト/パスのみを辿り、スコープ外 URL を記録します。",
      "ライブ対象チェックはレスポンスメタデータ、ヘッダー、Cookie、低影響の GET/OPTIONS probe を使用します。",
      "パッシブ probe は一般的な機密ファイル、API 文書、管理/デバッグ面、危険 HTTP method、ID 付き route inventory を含みます。",
      "レポートは証跡サマリーのみ保存し、HTTP レスポンス本文と機密値は除外またはマスクします。",
      `最新スキャン: ${latestScan?.scan_id || "未実行"} / 対象診断: ${advisory?.status || "未実行"} / フロントエンド: ${scope?.targets?.frontend?.base_url || "未設定"}`
    ];
  }
  if (language === "zh") {
    return [
      "目标检查前从 aegis.scope.json 读取授权范围。",
      "默认模式为 passive；不会猜测凭据、提交表单或发送破坏性 payload。",
      "站点发现仅跟随允许的主机/路径，并记录被阻止的越界 URL。",
      "实时目标检查使用响应元数据、响应头、Cookie 和低影响 GET/OPTIONS probe。",
      "被动 probe 覆盖常见敏感文件、API 文档、管理/调试界面、危险 HTTP method 和含 ID 的路由清单。",
      "报告仅保存证据摘要；HTTP 响应正文和敏感值会被排除或脱敏。",
      `最近扫描: ${latestScan?.scan_id || "未运行"} / 目标检查: ${advisory?.status || "未运行"} / 前端: ${scope?.targets?.frontend?.base_url || "未设置"}`
    ];
  }
  return [
    "Authorized scope is read from aegis.scope.json before any target check.",
    "The default mode is passive; no credentials are guessed, no forms are submitted, and no destructive payloads are sent.",
    "Site discovery follows only allowed hosts/paths and records blocked out-of-scope URLs.",
    "Live target checks use response metadata, headers, cookies, and low-impact GET/OPTIONS probes.",
    "Passive probes cover common sensitive files, API documentation, admin/debug surfaces, risky HTTP methods, and ID-bearing route inventory.",
    "Reports store evidence summaries only; HTTP response bodies and sensitive values are excluded or redacted.",
    `Latest scan: ${latestScan?.scan_id || "not run"} / advisory: ${advisory?.status || "not run"} / frontend: ${scope?.targets?.frontend?.base_url || "not configured"}`
  ];
}

function buildAiUsage(aiSettings, aiIntegrations) {
  const modelSettings = aiSettings?.aiModelSettings || {};
  const providers = modelSettings.providers || {};
  const configuredProviders = new Set([...(aiIntegrations?.providers || []), ...(aiSettings?.aiProviders || [])]);
  const enabledProviders = Object.entries(providers)
    .filter(([id, provider]) => provider?.enabled || configuredProviders.has(id))
    .map(([id, provider]) => ({
      id,
      label: provider?.label || id,
      type: provider?.providerType || "unknown",
      model: provider?.model || "",
      endpoint: provider?.endpoint || "",
      command: provider?.command || ""
    }));
  return {
    usedInSecurityScan: false,
    usedInPenetrationReport: false,
    defaultProvider: modelSettings.defaultProvider || "codex",
    enabledProviders,
    availableActions: [
      "npm run ai:doctor",
      "npm run ai:report",
      "npm run ai:model:show",
      "npm run ai:model:set",
      "npm run ai:prompt"
    ]
  };
}

function buildReport({ scope, latestScan, advisory, baseline, webSettings, auth, aiSettings, aiIntegrations }) {
  const language = normalizeLanguage(webSettings?.language || "ko");
  const testMatrix = buildTestMatrix(advisory, latestScan, scope, auth, language);
  const findings = buildFindings(testMatrix, advisory);
  const status = reportStatus(testMatrix);
  const safety = scope?.safety || {};
  return {
    command: "penetration-report",
    status,
    language,
    generatedAt: new Date().toISOString(),
    scope: {
      project: scope?.project || latestScan?.project || "unknown",
      environment: scope?.environment || latestScan?.environment || "unknown",
      mode: latestScan?.mode || "passive",
      frontend: scope?.targets?.frontend?.base_url || latestScan?.discovery?.base_url || "",
      backend: scope?.targets?.backend_api?.enabled ? scope?.targets?.backend_api?.base_url || "" : "",
      owner: scope?.authorization?.owner || "unknown",
      proofType: scope?.authorization?.proof_type || "unknown",
      expiresAt: scope?.authorization?.expires_at || "unknown",
      safety: {
        maxRps: safety.max_rps ?? "",
        maxConcurrency: safety.max_concurrency ?? "",
        destructiveTests: Boolean(safety.destructive_tests),
        bruteForce: Boolean(safety.brute_force),
        dataExfiltration: Boolean(safety.data_exfiltration),
        productionActiveScan: Boolean(safety.production_active_scan)
      }
    },
    summary: {
      tests: testMatrix.length,
      passed: testMatrix.filter((item) => item.status === "PASS").length,
      warnings: testMatrix.filter((item) => item.status === "WARN").length,
      errors: testMatrix.filter((item) => item.status === "FAIL").length,
      notRun: testMatrix.filter((item) => item.status === "NOT_RUN").length,
      probes: advisory?.summary?.probes || 0,
      advisoryStatus: advisory?.status || "NOT_RUN"
    },
    methodology: buildMethodology(scope, latestScan, advisory, language),
    aiUsage: buildAiUsage(aiSettings, aiIntegrations),
    testMatrix,
    findings,
    sources: uniqueSources(advisory, baseline),
    artifacts: {
      aegisReport: existsSync(resolve(cwd, ".aegis/reports/aegis-report.html")) ? ".aegis/reports/aegis-report.html" : "",
      advisory: existsSync(resolve(cwd, ".aegis/reports/frontend-advisory.json")) ? ".aegis/reports/frontend-advisory.json" : "",
      latestScan: existsSync(resolve(cwd, ".aegis/latest-scan.json")) ? ".aegis/latest-scan.json" : ""
    }
  };
}

function renderObject(value, language) {
  const displayValue = localizeEvidence(safeEvidence(value), language);
  const text = typeof displayValue === "string" ? displayValue : JSON.stringify(displayValue, null, 2);
  return `<pre>${escapeHtml(text)}</pre>`;
}

function renderHtml(report) {
  const t = translations[report.language] || translations.en;
  const tone = statusClass(report.status);
  const scopeRows = [
    [t.project, report.scope.project],
    [t.environment, report.scope.environment],
    [t.mode, report.scope.mode],
    [t.frontend, report.scope.frontend || "-"],
    [t.backend, report.scope.backend || "-"],
    [t.owner, report.scope.owner],
    [t.proofType, report.scope.proofType],
    [t.expiresAt, report.scope.expiresAt],
    [t.safety, `RPS ${report.scope.safety.maxRps || "-"} / concurrency ${report.scope.safety.maxConcurrency || "-"} / destructive=${report.scope.safety.destructiveTests}`]
  ];

  return `<!doctype html>
<html lang="${escapeHtml(t.lang)}">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(t.title)}</title>
  <style>
    :root { --bg: #f7f8fa; --panel: #ffffff; --text: #191f28; --muted: #6b7684; --line: #e5e8eb; --soft: #f2f4f6; --accent: #3182f6; --ok: #008768; --warn: #b56b00; --danger: #d92d20; }
    * { box-sizing: border-box; }
    body { margin: 0; background: var(--bg); color: var(--text); font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; line-height: 1.5; }
    main { max-width: 1180px; margin: 0 auto; padding: 28px 22px 42px; }
    header { display: grid; gap: 12px; margin-bottom: 18px; }
    h1 { margin: 0; font-size: 28px; letter-spacing: 0; }
    h2 { margin: 0 0 12px; font-size: 18px; letter-spacing: 0; }
    p { margin: 0; }
    .muted { color: var(--muted); }
    .panel { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 18px; margin: 14px 0; }
    .hero { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 18px; align-items: center; }
    .pill { display: inline-flex; align-items: center; border-radius: 999px; padding: 7px 10px; font-size: 13px; font-weight: 800; background: var(--soft); }
    .pill.ok { background: #e6f7f2; color: var(--ok); }
    .pill.warn { background: #fff3dc; color: var(--warn); }
    .pill.danger { background: #fff0ee; color: var(--danger); }
    .grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 10px; }
    .metric { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 14px; }
    .metric span { display: block; color: var(--muted); font-size: 12px; text-transform: uppercase; }
    .metric strong { display: block; font-size: 26px; margin-top: 3px; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th, td { padding: 9px 8px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: top; overflow-wrap: anywhere; }
    th { color: var(--muted); background: #f8fafc; }
    pre { margin: 0; max-height: 260px; overflow: auto; white-space: pre-wrap; background: #0f172a; color: #dbeafe; border-radius: 8px; padding: 10px; font-size: 12px; }
    ul { margin: 0; padding-left: 18px; }
    li + li { margin-top: 6px; }
    a { color: var(--accent); font-weight: 700; text-decoration: none; }
    a:hover { text-decoration: underline; }
    @media (max-width: 780px) { .hero, .grid { grid-template-columns: 1fr; } main { padding: 18px 12px 32px; } }
  </style>
</head>
<body>
  <main>
    <header class="panel hero">
      <div>
        <h1>${escapeHtml(t.title)}</h1>
        <p class="muted">${escapeHtml(report.scope.project)} / ${escapeHtml(report.scope.environment)} / ${escapeHtml(t.generated)} ${escapeHtml(report.generatedAt)}</p>
        <p class="muted">${escapeHtml(t.subtitle)}</p>
      </div>
      <span class="pill ${escapeHtml(tone)}">${escapeHtml(statusLabel(report.status, t))}</span>
    </header>

    <section class="grid" aria-label="${escapeHtml(t.summary)}">
      <div class="metric"><span>${escapeHtml(t.tests)}</span><strong>${escapeHtml(report.summary.tests)}</strong></div>
      <div class="metric"><span>${escapeHtml(t.passed)}</span><strong>${escapeHtml(report.summary.passed)}</strong></div>
      <div class="metric"><span>${escapeHtml(t.warnings)}</span><strong>${escapeHtml(report.summary.warnings)}</strong></div>
      <div class="metric"><span>${escapeHtml(t.probes)}</span><strong>${escapeHtml(report.summary.probes)}</strong></div>
    </section>

    <section class="panel">
      <h2>${escapeHtml(t.scope)}</h2>
      <table><tbody>
        ${scopeRows.map(([label, value]) => `<tr><th>${escapeHtml(label)}</th><td>${escapeHtml(value)}</td></tr>`).join("")}
      </tbody></table>
      <p class="muted" style="margin-top: 10px;">${escapeHtml(t.targetWarning)}</p>
    </section>

    <section class="panel">
      <h2>${escapeHtml(t.methodology)}</h2>
      <ul>${report.methodology.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>
    </section>

    <section class="panel">
      <h2>${escapeHtml(t.aiUsage)}</h2>
      <table><tbody>
        <tr><th>${escapeHtml(t.aiScanUse)}</th><td>${escapeHtml(t.aiNotUsedForScan)}</td></tr>
        <tr><th>${escapeHtml(t.aiReportUse)}</th><td>${escapeHtml(t.aiNotUsedForReport)}</td></tr>
        <tr><th>${escapeHtml(t.aiDefaultProvider)}</th><td>${escapeHtml(report.aiUsage.defaultProvider || "-")}</td></tr>
        <tr><th>${escapeHtml(t.aiEnabledProviders)}</th><td>${escapeHtml(report.aiUsage.enabledProviders.map((provider) => `${provider.label} (${provider.model || provider.type})`).join(", ") || "-")}</td></tr>
        <tr><th>${escapeHtml(t.aiAvailableActions)}</th><td>${escapeHtml(report.aiUsage.availableActions.join(", "))}</td></tr>
      </tbody></table>
      <p class="muted" style="margin-top: 10px;">${escapeHtml(t.aiUsedFor)}</p>
    </section>

    <section class="panel">
      <h2>${escapeHtml(t.tests)}</h2>
      <table>
        <thead><tr><th>${escapeHtml(t.test)}</th><th>${escapeHtml(t.category)}</th><th>${escapeHtml(t.passCriteria)}</th><th>${escapeHtml(t.result)}</th><th>${escapeHtml(t.evidence)}</th></tr></thead>
        <tbody>
          ${report.testMatrix.map((item) => `<tr>
            <td><strong>${escapeHtml(item.title)}</strong><br><span class="pill ${escapeHtml(statusClass(item.status))}">${escapeHtml(statusLabel(item.status, t))}</span><br><span class="muted">${escapeHtml(item.id)}</span></td>
            <td>${escapeHtml(item.category)}</td>
            <td>${escapeHtml(item.passCriteria)}</td>
            <td>${escapeHtml(item.result)}</td>
            <td>${renderObject(item.evidence, report.language)}</td>
          </tr>`).join("")}
        </tbody>
      </table>
    </section>

    <section class="panel">
      <h2>${escapeHtml(t.findings)}</h2>
      ${report.findings.length ? `<table>
        <thead><tr><th>ID</th><th>${escapeHtml(t.result)}</th><th>${escapeHtml(t.passCriteria)}</th><th>${escapeHtml(t.recommendations)}</th><th>${escapeHtml(t.evidence)}</th></tr></thead>
        <tbody>
          ${report.findings.map((finding) => `<tr>
            <td><strong>${escapeHtml(finding.title)}</strong><br><span class="muted">${escapeHtml(finding.id)} / ${escapeHtml(finding.severity)}</span></td>
            <td><span class="pill ${escapeHtml(statusClass(finding.status))}">${escapeHtml(statusLabel(finding.status, t))}</span><br>${escapeHtml(finding.detail)}</td>
            <td>${escapeHtml(finding.passCriteria)}</td>
            <td>${escapeHtml(finding.remediation || "-")}</td>
            <td>${renderObject(finding.evidence, report.language)}</td>
          </tr>`).join("")}
        </tbody>
      </table>` : `<p class="muted">${escapeHtml(t.noFindings)}</p>`}
    </section>

    <section class="panel">
      <h2>${escapeHtml(t.redaction)}</h2>
      <p class="muted">${escapeHtml(t.redactionText)}</p>
    </section>

    <section class="panel">
      <h2>${escapeHtml(t.sources)}</h2>
      <ul>${report.sources.map((source) => `<li><a href="${escapeHtml(source.url)}" target="_blank" rel="noreferrer">${escapeHtml(source.name)}</a></li>`).join("")}</ul>
    </section>
  </main>
</body>
</html>`;
}

async function main() {
  const [scope, latestScan, advisory, baseline, webSettings, auth, aiSettings, aiIntegrations] = await Promise.all([
    readJson("aegis.scope.json", {}),
    readJson(".aegis/latest-scan.json", {}),
    readJson(".aegis/reports/frontend-advisory.json", null),
    readJson(".aigate/security-baseline.json", {}),
    readJson(".aegis/web-settings.json", { language: "ko" }),
    readJson("aegis.auth.json", {}),
    readJson(".aigate/settings.json", {}),
    readJson(".aigate/integrations.json", {})
  ]);
  const report = buildReport({ scope, latestScan, advisory, baseline, webSettings, auth, aiSettings, aiIntegrations });
  await mkdir(dirname(jsonPath), { recursive: true });
  await writeFile(jsonPath, `${JSON.stringify(report, null, 2)}\n`, "utf8");
  await writeFile(htmlPath, renderHtml(report), "utf8");

  const wantsJson = process.argv.includes("--json") || (process.argv.includes("--format") && process.argv[process.argv.indexOf("--format") + 1] === "json");
  if (wantsJson) {
    console.log(JSON.stringify(report, null, 2));
    return;
  }
  console.log(`Penetration report: ${report.status}`);
  console.log(`Tests: ${report.summary.passed}/${report.summary.tests} passed`);
  console.log(`Warnings: ${report.summary.warnings}`);
  console.log(`Report: ${htmlPath}`);
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
