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
    targetWarning: "승인 범위와 소유권을 다시 확인한 뒤 운영 환경에서는 passive 모드만 사용하세요."
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
    targetWarning: "Reconfirm authorization and ownership before testing; use passive mode for production targets."
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
    targetWarning: "検査前に承認範囲と所有権を再確認し、本番環境ではpassiveモードのみ使用してください。"
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
    targetWarning: "测试前请再次确认授权范围和所有权；生产环境仅使用 passive 模式。"
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
  "frontend.headers.powered_by": {
    category: "Fingerprinting",
    criteria: "No checked response exposes X-Powered-By.",
    remediation: "Disable framework disclosure headers in the app server, reverse proxy, or framework config."
  },
  "frontend.headers.framing": {
    category: "Clickjacking",
    criteria: "Every discovered HTML response sets CSP frame-ancestors or X-Frame-Options DENY/SAMEORIGIN.",
    remediation: "Add CSP frame-ancestors or X-Frame-Options to all HTML responses."
  },
  "frontend.headers.auth_cache": {
    category: "Authentication",
    criteria: "Authentication-like pages use Cache-Control: no-store.",
    remediation: "Set Cache-Control: no-store on login, account, password reset, and session pages."
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
  "frontend.cookies.flags": {
    category: "Session",
    criteria: "Session-like cookies use HttpOnly, SameSite, and Secure when applicable.",
    remediation: "Set HttpOnly, SameSite=Lax/Strict, and Secure on session/auth cookies."
  },
  "frontend.forms.autocomplete": {
    category: "Authentication UX",
    criteria: "Authentication fields provide explicit password-manager autocomplete hints.",
    remediation: "Use autocomplete=current-password/new-password for passwords and username/email for login identifiers."
  },
  "frontend.transport.auth_https": {
    category: "Transport",
    criteria: "Authentication surfaces avoid cleartext transport outside loopback hosts.",
    remediation: "Serve authentication/account flows over HTTPS on non-local environments."
  },
  "frontend.content.client_secrets": {
    category: "Information leakage",
    criteria: "Discovered client-side JavaScript and JSON assets do not expose obvious private keys, provider keys, JWT literals, or secret assignments.",
    remediation: "Remove client-side secrets, rotate exposed credentials, and move privileged tokens to server-side storage."
  },
  "frontend.probes.sensitive_files": {
    category: "Exposure",
    criteria: "Common sensitive files, VCS metadata, backup archives, database dumps, and phpinfo pages are not publicly readable.",
    remediation: "Remove exposed files, block dotfiles/backups at the web server, and rotate secrets if exposure is confirmed."
  },
  "frontend.probes.api_docs": {
    category: "API exposure",
    criteria: "OpenAPI, Swagger UI, ReDoc, and similar API docs are absent, authenticated, IP-restricted, or intentionally approved for the environment.",
    remediation: "Disable public API docs outside development or protect them with authentication/IP allowlisting."
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
  "frontend.probes.http_methods": {
    category: "HTTP method exposure",
    criteria: "OPTIONS does not advertise TRACE or unintended state-changing methods such as PUT, DELETE, or PATCH.",
    remediation: "Restrict allowed HTTP methods at the web server/router and disable TRACE."
  },
  "frontend.discovery.object_ids": {
    category: "Authorization review",
    criteria: "ID-bearing routes are inventoried for manual or authenticated BOLA/BFLA review; passive discovery itself does not prove authorization safety.",
    remediation: "Add authenticated role-matrix tests for object-level and function-level authorization."
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

function findingTitle(finding) {
  return finding?.title || criteria[finding?.id]?.category || finding?.id || "Unknown check";
}

function evidenceSummary(evidence) {
  if (!evidence || Object.keys(evidence).length === 0) return "No evidence recorded.";
  const safe = safeEvidence(evidence);
  return JSON.stringify(safe, null, 2);
}

function buildFallbackChecks(scope, latestScan, auth) {
  const proofStatus = authorizationProofStatus(scope, auth);
  return [
    {
      id: "aegis.authorization_proof",
      title: "Public target authorization proof is concrete",
      category: criteria["aegis.authorization_proof"].category,
      status: proofStatus.ok ? "PASS" : "WARN",
      passCriteria: criteria["aegis.authorization_proof"].criteria,
      result: proofStatus.ok ? "Authorization evidence is sufficient for the configured target class." : "Review authorization proof before running public target tests.",
      evidence: proofStatus,
      remediation: criteria["aegis.authorization_proof"].remediation
    },
    {
      id: "aegis.scope_guard",
      title: "Scope, authorization, safety flags, and execution mode were verified",
      category: "Scope guard",
      status: latestScan?.observations?.some((item) => item.check === "scope_guard" && item.status === "passed") ? "PASS" : "NOT_RUN",
      passCriteria: "Scope verification passes before any target request is sent.",
      result: "Aegis scope guard observation",
      evidence: latestScan?.observations?.find((item) => item.check === "scope_guard") || {}
    },
    {
      id: "aegis.site_discovery",
      title: "Site discovery map was generated",
      category: "Discovery",
      status: latestScan?.discovery ? "PASS" : "NOT_RUN",
      passCriteria: "In-scope routes, links, forms, auth surfaces, and blocked URLs are recorded without submitting forms.",
      result: "Passive crawler artifact",
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

function buildTestMatrix(advisory, latestScan, scope, auth) {
  const advisoryChecks = (advisory?.findings || []).map((finding) => {
    const meta = criteria[finding.id] || {};
    const status = statusFromFinding(finding);
    return {
      id: finding.id,
      title: findingTitle(finding),
      category: meta.category || "Security",
      status,
      passCriteria: meta.criteria || "The check-specific security expectation is met.",
      result: finding.passed ? "Passed" : finding.detail || "Review required",
      evidence: safeEvidence(finding.evidence || {}),
      remediation: meta.remediation || finding.detail || ""
    };
  });

  return [
    ...buildFallbackChecks(scope, latestScan, auth),
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
        detail: source?.detail || item.result,
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

function buildMethodology(scope, latestScan, advisory) {
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

function buildReport({ scope, latestScan, advisory, baseline, webSettings, auth }) {
  const language = normalizeLanguage(webSettings?.language || "ko");
  const testMatrix = buildTestMatrix(advisory, latestScan, scope, auth);
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
    methodology: buildMethodology(scope, latestScan, advisory),
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

function renderObject(value) {
  const text = typeof value === "string" ? value : JSON.stringify(safeEvidence(value), null, 2);
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
      <h2>${escapeHtml(t.tests)}</h2>
      <table>
        <thead><tr><th>${escapeHtml(t.test)}</th><th>${escapeHtml(t.category)}</th><th>${escapeHtml(t.passCriteria)}</th><th>${escapeHtml(t.result)}</th><th>${escapeHtml(t.evidence)}</th></tr></thead>
        <tbody>
          ${report.testMatrix.map((item) => `<tr>
            <td><strong>${escapeHtml(item.title)}</strong><br><span class="pill ${escapeHtml(statusClass(item.status))}">${escapeHtml(statusLabel(item.status, t))}</span><br><span class="muted">${escapeHtml(item.id)}</span></td>
            <td>${escapeHtml(item.category)}</td>
            <td>${escapeHtml(item.passCriteria)}</td>
            <td>${escapeHtml(item.result)}</td>
            <td>${renderObject(item.evidence)}</td>
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
            <td>${renderObject(finding.evidence)}</td>
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
  const [scope, latestScan, advisory, baseline, webSettings, auth] = await Promise.all([
    readJson("aegis.scope.json", {}),
    readJson(".aegis/latest-scan.json", {}),
    readJson(".aegis/reports/frontend-advisory.json", null),
    readJson(".aigate/security-baseline.json", {}),
    readJson(".aegis/web-settings.json", { language: "ko" }),
    readJson("aegis.auth.json", {})
  ]);
  const report = buildReport({ scope, latestScan, advisory, baseline, webSettings, auth });
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
