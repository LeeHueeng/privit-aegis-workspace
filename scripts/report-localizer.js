import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";

const cwd = process.cwd();
const htmlPath = resolve(cwd, ".aegis/reports/aegis-report.html");
const jsonPath = resolve(cwd, ".aegis/reports/aegis-report.json");

const translations = {
  ko: {
    lang: "ko",
    title: "Aegis 보안 보고서",
    generated: "생성",
    reviewOk: "검토 완료",
    reviewRecommended: "검토 권장",
    severitySummary: "심각도 요약",
    critical: "치명",
    high: "높음",
    medium: "중간",
    low: "낮음",
    info: "정보",
    scope: "범위 및 승인",
    targetDetails: "검사 대상 정보",
    inspectedAddress: "검사 주소",
    frontendBaseUrl: "프론트엔드 주소",
    backendBaseUrl: "백엔드 API 주소",
    allowedHosts: "허용 호스트",
    allowedPaths: "허용 경로",
    deniedPaths: "차단 경로",
    scanStarted: "스캔 시작",
    scanCompleted: "스캔 완료",
    discoveryConfig: "탐색 설정",
    safetyLimits: "안전 제한",
    owner: "소유자",
    proofType: "증명 유형",
    expiresAt: "만료일",
    unknown: "알 수 없음",
    scanConfig: "스캔 설정",
    latestScan: "최근 스캔",
    mode: "모드",
    target: "대상",
    selectedChecks: "선택된 검사",
    executedChecks: "실행된 검사",
    siteMap: "사이트 탐색 맵",
    routes: "경로",
    links: "링크",
    forms: "폼",
    authSurfaces: "인증 표면",
    blockedUrls: "차단 URL",
    artifact: "증거 파일",
    status: "상태",
    path: "경로",
    depth: "깊이",
    source: "출처",
    findings: "발견 항목",
    id: "ID",
    severity: "심각도",
    titleHeader: "제목",
    recommendedFixes: "권장 조치",
    redactionPolicy: "마스킹 정책",
    noFindings: "최신 스캔 기준 활성 발견 항목이 없습니다.",
    staleNote: "과거 발견 항목은 최신 스캔에서 재현되지 않으면 보고서에서 제외됩니다.",
    redactionText: "Authorization 헤더, 쿠키, 토큰, 비밀번호, API 키, 개인 키, 이메일 주소, 결제 식별자는 보고 전에 마스킹됩니다.",
    footer: "Aegis CLI 보고서 데이터는 로컬 .aegis/ 아래에 저장됩니다.",
    activeFindings: "활성 발견 항목",
    newStatus: "신규",
    resolvedStatus: "해결됨",
    fixedGetFinding: "로그인 유사 폼이 GET을 사용함",
    fixedGetRecommendation: "인증 폼은 POST로 제출하고 자격 증명이나 토큰이 URL에 노출되지 않게 하세요.",
    missingCspFinding: "content-security-policy 헤더 누락",
    missingNosniffFinding: "x-content-type-options 헤더 누락",
    missingCspRecommendation: "애플리케이션 위험도에 맞는 Content-Security-Policy를 설정하세요. 예: script-src, style-src, frame-ancestors 정책을 명시해 XSS와 클릭재킹 영향을 줄입니다.",
    missingNosniffRecommendation: "웹 서버 또는 애플리케이션 게이트웨이에서 X-Content-Type-Options: nosniff 헤더를 설정하세요.",
    frontendTarget: "프론트엔드",
    backendTarget: "백엔드 API",
    databaseTarget: "데이터베이스",
    ciTarget: "CI/CD"
  },
  en: {
    lang: "en",
    title: "Aegis Security Report",
    generated: "generated",
    reviewOk: "Review complete",
    reviewRecommended: "Review recommended",
    severitySummary: "Finding severity summary",
    critical: "Critical",
    high: "High",
    medium: "Medium",
    low: "Low",
    info: "Info",
    scope: "Scope and Authorization",
    targetDetails: "Target Details",
    inspectedAddress: "Inspected address",
    frontendBaseUrl: "Frontend URL",
    backendBaseUrl: "Backend API URL",
    allowedHosts: "Allowed hosts",
    allowedPaths: "Allowed paths",
    deniedPaths: "Denied paths",
    scanStarted: "Scan started",
    scanCompleted: "Scan completed",
    discoveryConfig: "Discovery config",
    safetyLimits: "Safety limits",
    owner: "Owner",
    proofType: "Proof type",
    expiresAt: "Expires at",
    unknown: "unknown",
    scanConfig: "Scan Configuration",
    latestScan: "Latest scan",
    mode: "Mode",
    target: "Target",
    selectedChecks: "Selected checks",
    executedChecks: "Executed checks",
    siteMap: "Site Discovery Map",
    routes: "Routes",
    links: "Links",
    forms: "Forms",
    authSurfaces: "Auth surfaces",
    blockedUrls: "Blocked URLs",
    artifact: "Artifact",
    status: "Status",
    path: "Path",
    depth: "Depth",
    source: "Source",
    findings: "Findings",
    id: "ID",
    severity: "Severity",
    titleHeader: "Title",
    recommendedFixes: "Recommended Fixes",
    redactionPolicy: "Redaction Policy",
    noFindings: "No active findings in the latest scan.",
    staleNote: "Historical findings are excluded from this report when they are no longer reproduced by the latest scan.",
    redactionText: "Authorization headers, cookies, tokens, passwords, API keys, private keys, email addresses, and payment identifiers are redacted before reporting.",
    footer: "Aegis CLI stores report data locally under .aegis/.",
    activeFindings: "Active findings",
    newStatus: "new",
    resolvedStatus: "resolved",
    fixedGetFinding: "Login-like form uses GET",
    fixedGetRecommendation: "Submit authentication forms with POST and avoid placing credentials or tokens in URLs.",
    missingCspFinding: "Missing content-security-policy header",
    missingNosniffFinding: "Missing x-content-type-options header",
    missingCspRecommendation: "Configure Content-Security-Policy according to the application risk profile. For example, define script-src, style-src, and frame-ancestors to reduce XSS and clickjacking impact.",
    missingNosniffRecommendation: "Configure X-Content-Type-Options: nosniff at the web server or application gateway.",
    frontendTarget: "Frontend",
    backendTarget: "Backend API",
    databaseTarget: "Database",
    ciTarget: "CI/CD"
  },
  ja: {
    lang: "ja",
    title: "Aegis セキュリティレポート",
    generated: "生成",
    reviewOk: "確認完了",
    reviewRecommended: "確認推奨",
    severitySummary: "重大度サマリー",
    critical: "重大",
    high: "高",
    medium: "中",
    low: "低",
    info: "情報",
    scope: "スコープと承認",
    targetDetails: "検査対象情報",
    inspectedAddress: "検査アドレス",
    frontendBaseUrl: "フロントエンドURL",
    backendBaseUrl: "バックエンドAPI URL",
    allowedHosts: "許可ホスト",
    allowedPaths: "許可パス",
    deniedPaths: "拒否パス",
    scanStarted: "スキャン開始",
    scanCompleted: "スキャン完了",
    discoveryConfig: "探索設定",
    safetyLimits: "安全制限",
    owner: "所有者",
    proofType: "証明種別",
    expiresAt: "有効期限",
    unknown: "不明",
    scanConfig: "スキャン設定",
    latestScan: "最新スキャン",
    mode: "モード",
    target: "対象",
    selectedChecks: "選択チェック",
    executedChecks: "実行チェック",
    siteMap: "サイト探索マップ",
    routes: "経路",
    links: "リンク",
    forms: "フォーム",
    authSurfaces: "認証面",
    blockedUrls: "ブロックURL",
    artifact: "証跡ファイル",
    status: "状態",
    path: "パス",
    depth: "深度",
    source: "ソース",
    findings: "検出項目",
    id: "ID",
    severity: "重大度",
    titleHeader: "タイトル",
    recommendedFixes: "推奨対応",
    redactionPolicy: "マスキングポリシー",
    noFindings: "最新スキャンでは有効な検出項目はありません。",
    staleNote: "過去の検出項目は、最新スキャンで再現されない場合このレポートから除外されます。",
    redactionText: "Authorization ヘッダー、Cookie、トークン、パスワード、API キー、秘密鍵、メールアドレス、決済識別子は報告前にマスクされます。",
    footer: "Aegis CLI のレポートデータはローカルの .aegis/ 配下に保存されます。",
    activeFindings: "有効な検出項目",
    newStatus: "新規",
    resolvedStatus: "解決済み",
    fixedGetFinding: "ログイン類似フォームが GET を使用しています",
    fixedGetRecommendation: "認証フォームは POST で送信し、認証情報やトークンを URL に含めないでください。",
    missingCspFinding: "content-security-policy ヘッダー不足",
    missingNosniffFinding: "x-content-type-options ヘッダー不足",
    missingCspRecommendation: "アプリケーションのリスクに合わせて Content-Security-Policy を設定してください。例: script-src、style-src、frame-ancestors を明示して XSS やクリックジャッキングの影響を抑えます。",
    missingNosniffRecommendation: "Webサーバーまたはアプリケーションゲートウェイで X-Content-Type-Options: nosniff を設定してください。",
    frontendTarget: "フロントエンド",
    backendTarget: "バックエンドAPI",
    databaseTarget: "データベース",
    ciTarget: "CI/CD"
  },
  zh: {
    lang: "zh",
    title: "Aegis 安全报告",
    generated: "生成",
    reviewOk: "检查完成",
    reviewRecommended: "建议检查",
    severitySummary: "严重程度汇总",
    critical: "严重",
    high: "高",
    medium: "中",
    low: "低",
    info: "信息",
    scope: "范围与授权",
    targetDetails: "检查目标信息",
    inspectedAddress: "检查地址",
    frontendBaseUrl: "前端 URL",
    backendBaseUrl: "后端 API URL",
    allowedHosts: "允许主机",
    allowedPaths: "允许路径",
    deniedPaths: "阻止路径",
    scanStarted: "扫描开始",
    scanCompleted: "扫描完成",
    discoveryConfig: "发现配置",
    safetyLimits: "安全限制",
    owner: "所有者",
    proofType: "证明类型",
    expiresAt: "到期时间",
    unknown: "未知",
    scanConfig: "扫描配置",
    latestScan: "最新扫描",
    mode: "模式",
    target: "目标",
    selectedChecks: "已选检查",
    executedChecks: "已执行检查",
    siteMap: "站点发现图",
    routes: "路由",
    links: "链接",
    forms: "表单",
    authSurfaces: "认证面",
    blockedUrls: "阻止 URL",
    artifact: "证据文件",
    status: "状态",
    path: "路径",
    depth: "深度",
    source: "来源",
    findings: "发现项",
    id: "ID",
    severity: "严重程度",
    titleHeader: "标题",
    recommendedFixes: "建议修复",
    redactionPolicy: "脱敏策略",
    noFindings: "最新扫描中没有有效发现项。",
    staleNote: "历史发现项如果在最新扫描中不再复现，将从本报告中排除。",
    redactionText: "Authorization 头、Cookie、令牌、密码、API 密钥、私钥、邮箱地址和支付标识在报告前会被脱敏。",
    footer: "Aegis CLI 将报告数据保存在本地 .aegis/ 目录下。",
    activeFindings: "有效发现项",
    newStatus: "新建",
    resolvedStatus: "已解决",
    fixedGetFinding: "类似登录的表单使用 GET",
    fixedGetRecommendation: "认证表单应使用 POST 提交，避免凭据或令牌出现在 URL 中。",
    missingCspFinding: "缺少 content-security-policy 响应头",
    missingNosniffFinding: "缺少 x-content-type-options 响应头",
    missingCspRecommendation: "根据应用风险配置 Content-Security-Policy，例如明确 script-src、style-src 和 frame-ancestors，以降低 XSS 与点击劫持影响。",
    missingNosniffRecommendation: "在 Web 服务器或应用网关配置 X-Content-Type-Options: nosniff。",
    frontendTarget: "前端",
    backendTarget: "后端 API",
    databaseTarget: "数据库",
    ciTarget: "CI/CD"
  }
};

async function readJson(file, fallback) {
  try {
    return JSON.parse(await readFile(resolve(cwd, file), "utf8"));
  } catch {
    return fallback;
  }
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function normalizeLanguage(value) {
  const raw = String(value || "").toLowerCase();
  if (raw.startsWith("ko")) return "ko";
  if (raw.startsWith("ja")) return "ja";
  if (raw.startsWith("zh")) return "zh";
  return "en";
}

function severityOrder(severity) {
  return ["critical", "high", "medium", "low", "info"].indexOf(String(severity || "info").toLowerCase());
}

function displaySeverity(severity, t) {
  const key = String(severity || "info").toLowerCase();
  return t[key] || key;
}

function displayStatus(status, t) {
  const key = String(status || "new").toLowerCase();
  if (key === "new") return t.newStatus;
  if (key === "resolved") return t.resolvedStatus;
  return status || t.unknown;
}

function translateFindingTitle(finding, t) {
  if (finding.title === "Login-like form uses GET") return t.fixedGetFinding;
  if (finding.title === "Missing content-security-policy header") return t.missingCspFinding;
  if (finding.title === "Missing x-content-type-options header") return t.missingNosniffFinding;
  return finding.title || t.unknown;
}

function translateRecommendation(value, t) {
  if (value === "Submit authentication forms with POST and avoid placing credentials or tokens in URLs.") {
    return t.fixedGetRecommendation;
  }
  if (value === "Configure content-security-policy according to the application risk profile.") {
    return t.missingCspRecommendation;
  }
  if (value === "Configure x-content-type-options according to the application risk profile.") {
    return t.missingNosniffRecommendation;
  }
  return value;
}

function displayTarget(value, t) {
  const key = String(value || "").toLowerCase();
  if (key === "frontend") return t.frontendTarget;
  if (key === "backend_api") return t.backendTarget;
  if (key === "database") return t.databaseTarget;
  if (key === "ci_cd") return t.ciTarget;
  return value || t.unknown;
}

function listValue(value, fallback = "-") {
  if (Array.isArray(value)) return value.length ? value.join(", ") : fallback;
  if (value == null || value === "") return fallback;
  return String(value);
}

function discoveryConfigText(discovery) {
  const config = discovery?.config || {};
  return [
    `depth=${config.max_depth ?? "-"}`,
    `pages=${config.max_pages ?? "-"}`,
    `forms=${config.include_forms === false ? "false" : "true"}`,
    `redirects=${config.follow_redirects === false ? "false" : "true"}`
  ].join(" / ");
}

function safetyText(scope) {
  const safety = scope?.safety || {};
  return [
    `rps=${safety.max_rps ?? "-"}`,
    `concurrency=${safety.max_concurrency ?? "-"}`,
    `destructive=${Boolean(safety.destructive_tests)}`,
    `bruteForce=${Boolean(safety.brute_force)}`,
    `exfiltration=${Boolean(safety.data_exfiltration)}`
  ].join(" / ");
}

function isGetLoginFindingStillActive(finding, latestScan) {
  if (finding.title !== "Login-like form uses GET") return true;
  const asset = String(finding.asset || "");
  const forms = latestScan?.discovery?.forms || [];
  return forms.some((form) => {
    const method = String(form.method || "get").toLowerCase();
    const urls = [form.page_url, form.action_url].filter(Boolean).map(String);
    return method === "get" && form.auth_like && urls.includes(asset);
  });
}

function activeFindings(allFindings, latestScan) {
  const latestIds = new Set((latestScan?.findings || []).map((finding) => finding.id).filter(Boolean));
  const combined = [...(allFindings || []), ...(latestScan?.findings || [])];
  const byId = new Map();
  for (const finding of combined) {
    if (!finding?.id) continue;
    byId.set(finding.id, finding);
  }
  return [...byId.values()]
    .filter((finding) => latestIds.has(finding.id) || isGetLoginFindingStillActive(finding, latestScan))
    .filter((finding) => !["resolved", "closed", "fixed"].includes(String(finding.status || "").toLowerCase()))
    .sort((a, b) => severityOrder(a.severity) - severityOrder(b.severity) || String(a.id).localeCompare(String(b.id)));
}

function countBySeverity(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const finding of findings) {
    const severity = String(finding.severity || "info").toLowerCase();
    counts[severity in counts ? severity : "info"] += 1;
  }
  return counts;
}

function routeRows(routes, t) {
  if (!routes?.length) {
    return `<tr><td colspan="4" class="empty">${escapeHtml(t.noFindings)}</td></tr>`;
  }
  return routes
    .map(
      (route) => `<tr>
        <td>${escapeHtml(route.status)}</td>
        <td>${escapeHtml(route.path || route.url)}</td>
        <td>${escapeHtml(route.depth ?? 0)}</td>
        <td>${escapeHtml(route.source || "")}</td>
      </tr>`
    )
    .join("\n");
}

function findingsRows(findings, t) {
  if (!findings.length) {
    return `<tr><td colspan="5" class="empty">${escapeHtml(t.noFindings)}</td></tr>`;
  }
  return findings
    .map((finding) => {
      const severity = String(finding.severity || "info").toLowerCase();
      return `<tr>
        <td><code>${escapeHtml(finding.id)}</code></td>
        <td><span class="severity severity-${escapeHtml(severity)}">${escapeHtml(displaySeverity(severity, t))}</span></td>
        <td>${escapeHtml(displayTarget(finding.target_type || finding.target, t))}</td>
        <td>${escapeHtml(translateFindingTitle(finding, t))}</td>
        <td>${escapeHtml(displayStatus(finding.status, t))}</td>
      </tr>`;
    })
    .join("\n");
}

function recommendationList(findings, t) {
  if (!findings.length) {
    return `<p class="empty">${escapeHtml(t.noFindings)}</p><p class="subtle">${escapeHtml(t.staleNote)}</p>`;
  }
  const items = findings.flatMap((finding) => {
    const recommendations = Array.isArray(finding.recommendation) ? finding.recommendation : [finding.recommendation].filter(Boolean);
    return recommendations.map(
      (recommendation) => `<li><strong>${escapeHtml(finding.id)}</strong>: ${escapeHtml(translateRecommendation(recommendation, t))}</li>`
    );
  });
  return `<ul>${items.join("")}</ul>`;
}

function render(report) {
  const { t, scope, latestScan, findings, generatedAt } = report;
  const discovery = latestScan?.discovery || {};
  const auth = scope?.authorization || {};
  const counts = countBySeverity(findings);
  const total = findings.length;
  const badgeTone = total === 0 ? "ok" : counts.critical || counts.high ? "danger" : "warn";
  const badgeText = total === 0 ? t.reviewOk : t.reviewRecommended;
  const generatedText = [scope?.project || latestScan?.project || "privit", scope?.environment || latestScan?.environment || "local", `${t.generated} ${generatedAt}`].join(" / ");
  const frontend = scope?.targets?.frontend || {};
  const backend = scope?.targets?.backend_api || {};
  const inspectedAddress = discovery.base_url || frontend.base_url || latestScan?.target || t.unknown;

  return `<!doctype html>
<html lang="${escapeHtml(t.lang)}" data-aegis-localized="true">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(t.title)}</title>
  <style>
    :root { color-scheme: light; --bg: #f6f7f9; --panel: #ffffff; --text: #1f2937; --muted: #64748b; --line: #d8dee8; --ok: #1f8a5b; --warn: #b7791f; --danger: #c2410c; --accent: #2563eb; }
    * { box-sizing: border-box; }
    body { margin: 0; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: var(--bg); color: var(--text); line-height: 1.55; }
    main { width: min(1180px, calc(100% - 32px)); margin: 0 auto; padding: 28px 0 40px; }
    header { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 16px; align-items: end; border-bottom: 1px solid var(--line); padding-bottom: 18px; margin-bottom: 18px; }
    h1, h2 { margin: 0; letter-spacing: 0; }
    h1 { font-size: 28px; line-height: 1.2; }
    h2 { font-size: 18px; margin-bottom: 12px; }
    p { margin: 0; }
    .subtle { color: var(--muted); font-size: 14px; margin-top: 6px; }
    .badge { justify-self: start; border: 1px solid var(--line); border-radius: 999px; padding: 7px 12px; font-size: 13px; font-weight: 700; background: var(--panel); }
    .badge.ok { color: var(--ok); border-color: #a7d8c1; }
    .badge.warn { color: var(--warn); border-color: #e7c987; }
    .badge.danger { color: var(--danger); border-color: #f2a486; }
    .metrics { display: grid; grid-template-columns: repeat(5, minmax(120px, 1fr)); gap: 12px; margin: 18px 0; }
    .metric, section { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; box-shadow: 0 1px 2px rgba(15, 23, 42, 0.04); }
    .metric { padding: 14px; }
    .metric span { display: block; color: var(--muted); font-size: 12px; text-transform: uppercase; }
    .metric strong { display: block; font-size: 28px; line-height: 1.2; margin-top: 4px; }
    .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
    .target-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; }
    section { padding: 18px; margin-bottom: 14px; }
    dl { display: grid; grid-template-columns: 150px minmax(0, 1fr); gap: 8px 14px; margin: 0; }
    dt { color: var(--muted); }
    dd { margin: 0; min-width: 0; overflow-wrap: anywhere; }
    table { width: 100%; border-collapse: collapse; font-size: 14px; }
    th, td { text-align: left; padding: 10px 8px; border-bottom: 1px solid var(--line); vertical-align: top; }
    th { color: var(--muted); font-weight: 700; background: #f8fafc; }
    code { background: #eef2f7; border-radius: 5px; padding: 2px 5px; }
    ul { margin: 0; padding-left: 20px; }
    .severity { display: inline-block; min-width: 68px; border-radius: 999px; padding: 3px 8px; text-align: center; font-weight: 700; font-size: 12px; color: #ffffff; }
    .severity-critical, .severity-high { background: var(--danger); }
    .severity-medium { background: var(--warn); }
    .severity-low { background: var(--accent); }
    .severity-info { background: var(--muted); }
    .empty { color: var(--muted); text-align: center; padding: 16px; }
    footer { color: var(--muted); font-size: 13px; padding: 8px 0 0; }
    @media (max-width: 980px) { .target-grid { grid-template-columns: 1fr; } }
    @media (max-width: 820px) { main { width: min(100% - 20px, 1180px); padding-top: 18px; } header, .grid, .metrics { grid-template-columns: 1fr; } dl { grid-template-columns: 1fr; } table { display: block; overflow-x: auto; white-space: nowrap; } }
  </style>
</head>
<body>
  <main>
    <header>
      <div>
        <h1>${escapeHtml(t.title)}</h1>
        <p class="subtle">${escapeHtml(generatedText)}</p>
      </div>
      <div class="badge ${badgeTone}">${escapeHtml(badgeText)}</div>
    </header>

    <div class="metrics" aria-label="${escapeHtml(t.severitySummary)}">
      <div class="metric"><span>${escapeHtml(t.critical)}</span><strong>${counts.critical}</strong></div>
      <div class="metric"><span>${escapeHtml(t.high)}</span><strong>${counts.high}</strong></div>
      <div class="metric"><span>${escapeHtml(t.medium)}</span><strong>${counts.medium}</strong></div>
      <div class="metric"><span>${escapeHtml(t.low)}</span><strong>${counts.low}</strong></div>
      <div class="metric"><span>${escapeHtml(t.info)}</span><strong>${counts.info}</strong></div>
    </div>

    <section>
      <h2>${escapeHtml(t.targetDetails)}</h2>
      <div class="target-grid">
        <dl>
          <dt>${escapeHtml(t.inspectedAddress)}</dt><dd>${escapeHtml(inspectedAddress)}</dd>
          <dt>${escapeHtml(t.frontendBaseUrl)}</dt><dd>${escapeHtml(frontend.base_url || "-")}</dd>
          <dt>${escapeHtml(t.backendBaseUrl)}</dt><dd>${escapeHtml(backend.enabled ? backend.base_url || "-" : "-")}</dd>
        </dl>
        <dl>
          <dt>${escapeHtml(t.allowedHosts)}</dt><dd>${escapeHtml(listValue(frontend.allowed_hosts))}</dd>
          <dt>${escapeHtml(t.allowedPaths)}</dt><dd>${escapeHtml(listValue(frontend.allowed_paths))}</dd>
          <dt>${escapeHtml(t.deniedPaths)}</dt><dd>${escapeHtml(listValue(frontend.denied_paths))}</dd>
        </dl>
        <dl>
          <dt>${escapeHtml(t.scanStarted)}</dt><dd>${escapeHtml(latestScan?.started_at || t.unknown)}</dd>
          <dt>${escapeHtml(t.scanCompleted)}</dt><dd>${escapeHtml(latestScan?.completed_at || t.unknown)}</dd>
          <dt>${escapeHtml(t.discoveryConfig)}</dt><dd>${escapeHtml(discoveryConfigText(discovery))}</dd>
          <dt>${escapeHtml(t.safetyLimits)}</dt><dd>${escapeHtml(safetyText(scope))}</dd>
        </dl>
      </div>
    </section>

    <div class="grid">
      <section>
        <h2>${escapeHtml(t.scope)}</h2>
        <dl>
          <dt>${escapeHtml(t.owner)}</dt><dd>${escapeHtml(auth.owner || t.unknown)}</dd>
          <dt>${escapeHtml(t.proofType)}</dt><dd>${escapeHtml(auth.proof_type || t.unknown)}</dd>
          <dt>${escapeHtml(t.expiresAt)}</dt><dd>${escapeHtml(auth.expires_at || t.unknown)}</dd>
        </dl>
      </section>
      <section>
        <h2>${escapeHtml(t.scanConfig)}</h2>
        <dl>
          <dt>${escapeHtml(t.latestScan)}</dt><dd>${escapeHtml(latestScan?.scan_id || t.unknown)}</dd>
          <dt>${escapeHtml(t.mode)}</dt><dd>${escapeHtml(latestScan?.mode || t.unknown)}</dd>
          <dt>${escapeHtml(t.target)}</dt><dd>${escapeHtml(displayTarget(latestScan?.target, t))}</dd>
          <dt>${escapeHtml(t.selectedChecks)}</dt><dd>${escapeHtml(latestScan?.selected_check_count ?? 0)}</dd>
          <dt>${escapeHtml(t.executedChecks)}</dt><dd>${escapeHtml(latestScan?.executed_check_count ?? 0)}</dd>
        </dl>
      </section>
    </div>

    <section>
      <h2>${escapeHtml(t.siteMap)}</h2>
      <dl>
        <dt>${escapeHtml(t.routes)}</dt><dd>${escapeHtml(discovery.routes?.length || 0)}</dd>
        <dt>${escapeHtml(t.links)}</dt><dd>${escapeHtml(discovery.links?.length || 0)}</dd>
        <dt>${escapeHtml(t.forms)}</dt><dd>${escapeHtml(discovery.forms?.length || 0)}</dd>
        <dt>${escapeHtml(t.authSurfaces)}</dt><dd>${escapeHtml(discovery.auth_surfaces?.length || 0)}</dd>
        <dt>${escapeHtml(t.blockedUrls)}</dt><dd>${escapeHtml(discovery.blocked_urls?.length || 0)}</dd>
        <dt>${escapeHtml(t.artifact)}</dt><dd>${escapeHtml(latestScan?.observations?.find((item) => item.artifact_path)?.artifact_path || "")}</dd>
      </dl>
      <table>
        <thead><tr><th>${escapeHtml(t.status)}</th><th>${escapeHtml(t.path)}</th><th>${escapeHtml(t.depth)}</th><th>${escapeHtml(t.source)}</th></tr></thead>
        <tbody>${routeRows(discovery.routes || [], t)}</tbody>
      </table>
    </section>

    <section>
      <h2>${escapeHtml(t.findings)}</h2>
      <table>
        <thead><tr><th>${escapeHtml(t.id)}</th><th>${escapeHtml(t.severity)}</th><th>${escapeHtml(t.target)}</th><th>${escapeHtml(t.titleHeader)}</th><th>${escapeHtml(t.status)}</th></tr></thead>
        <tbody>${findingsRows(findings, t)}</tbody>
      </table>
    </section>

    <section>
      <h2>${escapeHtml(t.recommendedFixes)}</h2>
      ${recommendationList(findings, t)}
    </section>

    <section>
      <h2>${escapeHtml(t.redactionPolicy)}</h2>
      <p>${escapeHtml(t.redactionText)}</p>
    </section>

    <footer>${escapeHtml(t.footer)}</footer>
  </main>
</body>
</html>
`;
}

async function main() {
  const settings = await readJson(".aegis/web-settings.json", { language: "ko" });
  const language = normalizeLanguage(process.argv.find((arg) => arg.startsWith("--lang="))?.split("=")[1] || settings.language);
  const t = translations[language] || translations.ko;
  const scope = await readJson("aegis.scope.json", {});
  const latestScan = await readJson(".aegis/latest-scan.json", {});
  const allFindings = await readJson(".aegis/findings.json", []);
  const findings = activeFindings(allFindings, latestScan);
  const generatedAt = latestScan.completed_at || new Date().toISOString();
  const report = {
    language,
    generatedAt,
    scope,
    latestScan,
    findings,
    summary: countBySeverity(findings)
  };

  await mkdir(dirname(htmlPath), { recursive: true });
  await writeFile(htmlPath, render({ ...report, t }), "utf8");
  await writeFile(jsonPath, `${JSON.stringify(report, null, 2)}\n`, "utf8");

  console.log(`Localized Aegis report (${language}) written to ${htmlPath}`);
  console.log(`Active findings: ${findings.length}`);
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
