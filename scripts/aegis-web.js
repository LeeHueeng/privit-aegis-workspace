import { createServer } from "node:http";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { existsSync, readFileSync } from "node:fs";
import { spawn, spawnSync } from "node:child_process";
import { dirname, extname, resolve } from "node:path";
import { AI_PROVIDER_IDS, buildAiModelReport, normalizeAiModelSettings, normalizeAiRuntimeSettings } from "./ai-models.js";

const cwd = process.cwd();
const port = Number(process.env.AEGIS_WEB_PORT || process.env.PORT || 4317);
const host = process.env.AEGIS_WEB_HOST || "127.0.0.1";

const actions = {
  catalog: ["aegis", ["catalog", "generate"]],
  docs: ["aegis", ["docs", "generate", "--lang", "all"]],
  verify: ["aegis", ["scope", "verify", "--mode", "passive"]],
  plan: ["aegis", ["plan", "--mode", "passive", "--target", "frontend", "--limit", "50"]],
  map: ["aegis", ["run", "--target", "frontend", "--mode", "passive", "--crawl", "true", "--max-depth", "2", "--max-pages", "50"]],
  scan: ["aegis", ["run", "--target", "frontend", "--mode", "passive", "--crawl", "true"]],
  dryRun: ["aegis", ["run", "--target", "frontend", "--mode", "passive", "--dry-run"]],
  report: ["aegis", ["report", "--format", "html"]],
  audit: ["npm", ["run", "security:audit"]],
  hardening: ["npm", ["run", "security:hardening"]],
  targetAdvisory: ["npm", ["run", "security:target"]],
  githubReady: ["node", ["./scripts/github-readiness.js", "--format", "json"]],
  gate: ["aigate", ["test", "--language", "ko"]],
  gateReady: ["aigate", ["git-ready", "--language", "ko"]],
  ai: ["npm", ["run", "ai:integrate"]],
  aiDoctor: ["npm", ["run", "ai:doctor"]],
  aiReport: ["npm", ["run", "ai:report"]],
  aiModelCommands: ["npm", ["run", "ai:model:commands"]],
  aiProviderCheck: ["npm", ["run", "ai:model:check"]],
  ciSecurity: ["npm", ["run", "ci:security"]],
  gitStatus: ["git", ["status", "--short", "--branch"]],
  start: ["npm", ["run", "start:aegis"]]
};

const contentTypes = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".sarif": "application/json; charset=utf-8",
  ".png": "image/png",
  ".svg": "image/svg+xml; charset=utf-8"
};

const webSecurityHeaders = {
  "content-security-policy": [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "connect-src 'self'",
    "frame-src 'self'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'self'"
  ].join("; "),
  "referrer-policy": "strict-origin-when-cross-origin",
  "x-frame-options": "SAMEORIGIN",
  "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=(), fullscreen=(self)",
  "cross-origin-opener-policy": "same-origin"
};

function send(res, status, body, type = "application/json; charset=utf-8") {
  const headers = {
    "content-type": type,
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    ...webSecurityHeaders
  };
  if (process.env.AEGIS_WEB_HSTS === "true") {
    headers["strict-transport-security"] = "max-age=31536000; includeSubDomains";
  }
  res.writeHead(status, headers);
  res.end(body);
}

function json(res, status, value) {
  send(res, status, JSON.stringify(value, null, 2));
}

async function readJsonFile(file, fallback) {
  try {
    return JSON.parse(await readFile(resolve(cwd, file), "utf8"));
  } catch {
    return fallback;
  }
}

async function writeJsonFile(file, value) {
  const absolute = resolve(cwd, file);
  await mkdir(dirname(absolute), { recursive: true });
  await writeFile(absolute, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function countCatalogLines() {
  try {
    return existsSync(resolve(cwd, "catalog/security-checks.jsonl"))
      ? readFileSync(resolve(cwd, "catalog/security-checks.jsonl"), "utf8").trim().split(/\r?\n/).filter(Boolean).length
      : 0;
  } catch {
    return 0;
  }
}

function hostFromUrl(value) {
  try {
    return new URL(value).hostname;
  } catch {
    return "localhost";
  }
}

function splitList(value, fallback = []) {
  if (Array.isArray(value)) {
    return value.map((item) => String(item).trim()).filter(Boolean);
  }
  if (typeof value !== "string") {
    return fallback;
  }
  const items = value.split(",").map((item) => item.trim()).filter(Boolean);
  return items.length ? items : fallback;
}

function boundedNumber(value, fallback, min, max) {
  const number = Number(value ?? fallback);
  if (!Number.isFinite(number)) {
    return fallback;
  }
  return Math.min(Math.max(Math.trunc(number), min), max);
}

function commandInfo(command) {
  const pathResult = spawnSync("sh", ["-lc", `command -v ${command}`], {
    cwd,
    encoding: "utf8",
    timeout: 2000
  });
  const commandPath = pathResult.status === 0 ? pathResult.stdout.trim() : "";
  if (!commandPath) {
    return { installed: false, path: "", version: "" };
  }

  const versionResult = spawnSync(command, ["--version"], {
    cwd,
    encoding: "utf8",
    timeout: 5000
  });
  const version = [versionResult.stdout, versionResult.stderr].filter(Boolean).join(" ").trim();
  return {
    installed: true,
    path: commandPath,
    version
  };
}

function gitInfo() {
  const status = spawnSync("git", ["status", "--short", "--branch"], { cwd, encoding: "utf8", timeout: 5000 });
  const branch = spawnSync("git", ["branch", "--show-current"], { cwd, encoding: "utf8", timeout: 5000 });
  const remote = spawnSync("git", ["remote", "get-url", "origin"], { cwd, encoding: "utf8", timeout: 5000 });
  const statusText = status.status === 0 ? status.stdout.trim() : "";
  return {
    branch: branch.status === 0 ? branch.stdout.trim() : "",
    remote: remote.status === 0 ? remote.stdout.trim() : "",
    status: statusText,
    changedFiles: statusText
      .split(/\r?\n/)
      .filter((line) => line && !line.startsWith("##"))
      .length
  };
}

function buildAiState(integrations, settings) {
  const configured = new Set([...(integrations?.providers || []), ...(settings?.aiProviders || [])]);
  const modelReport = buildAiModelReport(settings?.aiModelSettings);
  const runtimeSettings = normalizeAiRuntimeSettings(settings?.aiRuntimeSettings);
  const providers = AI_PROVIDER_IDS.map((id) => {
    const config = modelReport.providers[id];
    const provider = {
      id,
      label: config.label,
      providerType: config.providerType,
      command: config.command,
      rootFile: config.rootFile,
      sidecarFile: config.sidecarFile
    };
    const enabled = provider.providerType === "cli" ? configured.has(provider.id) || config.enabled : config.enabled;
    const rootReady = provider.rootFile ? existsSync(resolve(cwd, provider.rootFile)) : true;
    const sidecarReady = provider.sidecarFile ? existsSync(resolve(cwd, provider.sidecarFile)) : true;
    const cli = provider.providerType === "cli" ? commandInfo(provider.command) : { installed: true, path: "", version: "" };
    const endpointReady = provider.providerType === "cli" || Boolean(config.endpoint);
    const apiKeyReady = provider.providerType === "cli" || !config.apiKeyEnv || Boolean(process.env[config.apiKeyEnv]);
    const ready = enabled
      ? enabled && rootReady && sidecarReady && cli.installed && endpointReady && apiKeyReady
      : true;
    return {
      ...provider,
      enabled,
      rootReady,
      sidecarReady,
      commandReady: cli.installed,
      commandPath: cli.path,
      version: cli.version,
      model: modelReport.providers[provider.id]?.model || "",
      modelConfig: modelReport.providers[provider.id] || {},
      endpoint: config.endpoint || "",
      apiStyle: config.apiStyle || "",
      apiKeyEnv: config.apiKeyEnv || "",
      endpointReady,
      apiKeyReady,
      commandReference: modelReport.commands[provider.id] || {},
      filesReady: enabled && rootReady && sidecarReady,
      ready,
      status: !enabled ? "disabled" : ready ? "ready" : "check",
      statusTone: !enabled ? "" : ready ? "ok" : "warn"
    };
  });
  const enabledProviders = providers.filter((provider) => provider.enabled);

  return {
    providers,
    modelSettings: modelReport,
    runtimeSettings,
    readyCount: enabledProviders.filter((provider) => provider.ready).length,
    totalCount: enabledProviders.length,
    manifestReady: existsSync(resolve(cwd, ".aigate/integrations.json")),
    settingsReady: existsSync(resolve(cwd, ".aigate/settings.json")),
    requiredCommands: integrations?.requiredCommands || [],
    validationCommands: settings?.qualityCommands || integrations?.validationCommands || []
  };
}

async function state() {
  const scope = await readJsonFile("aegis.scope.json", null);
  const latestScan = await readJsonFile(".aegis/latest-scan.json", null);
  const findings = await readJsonFile(".aegis/findings.json", []);
  const targetAdvisory = await readJsonFile(".aegis/reports/frontend-advisory.json", null);
  const integrations = await readJsonFile(".aigate/integrations.json", null);
  const aiSettings = await readJsonFile(".aigate/settings.json", null);
  const webSettings = await readJsonFile(".aegis/web-settings.json", { language: "ko" });
  const reportPath = resolve(cwd, ".aegis/reports/aegis-report.html");
  return {
    scope,
    latestScan,
    targetAdvisory,
    findings,
    ai: buildAiState(integrations, aiSettings),
    catalogCount: countCatalogLines(),
    reportExists: existsSync(reportPath),
    reports: {
      html: existsSync(reportPath),
      json: existsSync(resolve(cwd, ".aegis/reports/aegis-report.json")),
      sarif: existsSync(resolve(cwd, ".aegis/reports/aegis-report.sarif")),
      junit: existsSync(resolve(cwd, ".aegis/reports/aegis-report.junit.xml"))
    },
    tools: {
      aegis: commandInfo("aegis"),
      aigate: commandInfo("aigate"),
      npm: commandInfo("npm"),
      gh: commandInfo("gh")
    },
    git: gitInfo(),
    webSettings,
    repoRoles: {
      engine: "/Users/hwlee/Documents/privit project",
      workspace: cwd
    },
    reportUrl: "/report",
    generatedAt: new Date().toISOString()
  };
}

async function readRequest(req) {
  const chunks = [];
  for await (const chunk of req) {
    chunks.push(chunk);
  }
  const raw = Buffer.concat(chunks).toString("utf8");
  return raw ? JSON.parse(raw) : {};
}

async function saveScope(payload) {
  const scope = await readJsonFile("aegis.scope.json", {});
  const frontendUrl = payload.frontendUrl || scope.targets?.frontend?.base_url || "http://localhost:3000";
  const backendUrl = payload.backendUrl || scope.targets?.backend_api?.base_url || `${frontendUrl.replace(/\/$/, "")}/api`;

  scope.project = payload.project || scope.project || "privit";
  scope.environment = payload.environment || scope.environment || "local";
  scope.targets ||= {};
  scope.targets.frontend ||= {};
  scope.targets.frontend.enabled = true;
  scope.targets.frontend.base_url = frontendUrl;
  scope.targets.frontend.allowed_hosts = [...new Set([hostFromUrl(frontendUrl), ...(scope.targets.frontend.allowed_hosts || [])])];
  scope.targets.frontend.allowed_paths = splitList(payload.allowedPaths, scope.targets.frontend.allowed_paths || ["/*"]);
  scope.targets.frontend.denied_paths = splitList(payload.deniedPaths, scope.targets.frontend.denied_paths || ["/payments/live/*", "/admin/delete/*"]);
  scope.targets.frontend.discovery ||= {};
  scope.targets.frontend.discovery.enabled = payload.discoveryEnabled !== false;
  scope.targets.frontend.discovery.max_depth = boundedNumber(payload.maxDepth, scope.targets.frontend.discovery.max_depth || 2, 0, 5);
  scope.targets.frontend.discovery.max_pages = boundedNumber(payload.maxPages, scope.targets.frontend.discovery.max_pages || 30, 1, 200);
  scope.targets.frontend.discovery.include_forms = payload.includeForms !== false;
  scope.targets.frontend.discovery.follow_redirects = payload.followRedirects !== false;
  scope.targets.frontend.discovery.sitemap_paths = splitList(payload.sitemapPaths, scope.targets.frontend.discovery.sitemap_paths || ["/robots.txt", "/sitemap.xml"]);
  scope.targets.frontend.discovery.login_indicators = splitList(
    payload.loginIndicators,
    scope.targets.frontend.discovery.login_indicators || ["login", "signin", "sign-in", "auth", "session", "admin", "account"]
  );
  delete scope.targets.frontend.discovery.submit_forms;

  scope.targets.backend_api ||= {};
  scope.targets.backend_api.enabled = Boolean(payload.backendEnabled);
  scope.targets.backend_api.base_url = backendUrl;
  scope.targets.backend_api.allowed_hosts = [...new Set([hostFromUrl(backendUrl), ...(scope.targets.backend_api.allowed_hosts || [])])];
  scope.targets.backend_api.allowed_paths ||= ["/*"];
  scope.targets.ci_cd ||= {};
  scope.targets.ci_cd.enabled = payload.ciEnabled !== false;
  scope.authorization ||= {};
  scope.authorization.owner = payload.owner || scope.authorization.owner || "security@example.com";
  scope.authorization.expires_at = payload.expiresAt || scope.authorization.expires_at;
  scope.safety ||= {};
  scope.safety.max_rps = boundedNumber(payload.maxRps, scope.safety.max_rps || 2, 1, 20);
  scope.safety.max_concurrency = boundedNumber(payload.maxConcurrency, scope.safety.max_concurrency || 3, 1, 20);

  await writeJsonFile("aegis.scope.json", scope);
  return scope;
}

async function saveSettings(payload) {
  const language = ["ko", "en", "ja", "zh"].includes(payload.language) ? payload.language : "ko";
  const settings = { language, updatedAt: new Date().toISOString() };
  await writeJsonFile(".aegis/web-settings.json", settings);
  return settings;
}

async function saveAiSettings(payload) {
  const settings = await readJsonFile(".aigate/settings.json", {});
  const current = normalizeAiModelSettings(settings.aiModelSettings);
  const providers = {};
  for (const id of AI_PROVIDER_IDS) {
    providers[id] = {
      ...current.providers[id],
      ...(payload.providers?.[id] || {})
    };
  }
  settings.aiModelSettings = normalizeAiModelSettings({
    ...current,
    defaultProvider: AI_PROVIDER_IDS.includes(payload.defaultProvider) ? payload.defaultProvider : current.defaultProvider,
    providers,
    updatedAt: new Date().toISOString()
  });
  settings.aiRuntimeSettings = normalizeAiRuntimeSettings({
    ...(payload.runtimeSettings || settings.aiRuntimeSettings || {}),
    updatedAt: new Date().toISOString()
  });
  await writeJsonFile(".aigate/settings.json", settings);
  return {
    ...buildAiModelReport(settings.aiModelSettings),
    runtime: settings.aiRuntimeSettings
  };
}

function runAction(action) {
  const entry = actions[action];
  if (!entry) {
    return Promise.resolve({ ok: false, code: 2, stdout: "", stderr: `Unknown action: ${action}` });
  }
  const [command, args] = entry;
  return new Promise((resolveRun) => {
    const child = spawn(command, args, { cwd, env: process.env });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });
    child.on("close", (code) => {
      resolveRun({ ok: code === 0, code, stdout, stderr, action, command: [command, ...args].join(" ") });
    });
  });
}

function page() {
  return `<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Privit Aegis Console</title>
  <style>
    :root {
      --bg: #f5f7fa;
      --panel: #ffffff;
      --text: #172033;
      --muted: #607086;
      --line: #d8e0ea;
      --accent: #2563eb;
      --ok: #15805f;
      --warn: #b7791f;
      --danger: #c2410c;
      --ink: #0f172a;
      --side: #111827;
    }
    * { box-sizing: border-box; }
    body { margin: 0; background: var(--bg); color: var(--text); font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
    button, input, select { font: inherit; }
    .shell { display: grid; grid-template-columns: 260px minmax(0, 1fr); min-height: 100vh; }
    aside { background: var(--side); color: #e5edf7; padding: 22px 18px; }
    .brand { display: flex; align-items: center; gap: 12px; margin-bottom: 24px; }
    .mark { width: 42px; height: 42px; border-radius: 8px; background: #2563eb; display: grid; place-items: center; color: #eff6ff; font-weight: 900; }
    .brand strong { display: block; font-size: 18px; }
    .brand span { color: #9fb0c7; font-size: 12px; }
    nav { display: grid; gap: 8px; }
    nav button { width: 100%; border: 0; background: transparent; color: #cbd5e1; text-align: left; padding: 10px 12px; border-radius: 7px; cursor: pointer; }
    nav button.active, nav button:hover { background: #253044; color: #ffffff; }
    main { padding: 22px; min-width: 0; }
    header { display: flex; justify-content: space-between; align-items: flex-end; gap: 16px; margin-bottom: 16px; }
    h1 { margin: 0; font-size: 24px; line-height: 1.2; letter-spacing: 0; }
    h2 { margin: 0 0 12px; font-size: 17px; letter-spacing: 0; }
    h3 { margin: 0 0 10px; font-size: 14px; letter-spacing: 0; }
    p { margin: 0; }
    .muted { color: var(--muted); font-size: 13px; }
    .topbar { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; justify-content: flex-end; }
    .status { border: 1px solid var(--line); background: var(--panel); border-radius: 999px; padding: 7px 12px; font-weight: 700; font-size: 13px; }
    .language { width: auto; min-width: 132px; padding: 7px 10px; border-radius: 999px; }
    .grid { display: grid; grid-template-columns: repeat(6, minmax(0, 1fr)); gap: 12px; margin-bottom: 14px; }
    .card, .panel { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; box-shadow: 0 1px 2px rgba(15, 23, 42, 0.04); }
    .card { padding: 14px; min-width: 0; }
    .card span { color: var(--muted); font-size: 12px; text-transform: uppercase; }
    .card strong { display: block; font-size: 25px; margin-top: 4px; overflow-wrap: anywhere; }
    .layout { display: grid; grid-template-columns: minmax(340px, 440px) minmax(0, 1fr); gap: 14px; align-items: start; }
    .panel { padding: 16px; margin-bottom: 14px; }
    form { display: grid; gap: 12px; }
    label { display: grid; gap: 5px; font-weight: 700; font-size: 13px; }
    input, select { width: 100%; border: 1px solid var(--line); border-radius: 7px; padding: 10px 11px; color: var(--text); background: #ffffff; }
    textarea { width: 100%; min-height: 360px; border: 1px solid var(--line); border-radius: 7px; padding: 10px 11px; color: var(--text); background: #ffffff; font: 12px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; line-height: 1.45; resize: vertical; }
    .row { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
    .runtime-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 10px; margin-bottom: 12px; }
    .runtime-switches { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 10px; margin-bottom: 12px; }
    .switch { display: flex; align-items: center; gap: 8px; font-weight: 700; }
    .switch input { width: auto; }
    .actions { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 9px; }
    .actions button, .primary { border: 0; border-radius: 7px; padding: 10px 11px; cursor: pointer; background: #e8eef8; color: var(--ink); font-weight: 800; min-height: 42px; }
    .primary { background: var(--accent); color: #ffffff; }
    .actions button:hover, .primary:hover { filter: brightness(0.97); }
    iframe { width: 100%; height: 650px; border: 1px solid var(--line); border-radius: 8px; background: #ffffff; }
    pre { min-height: 190px; max-height: 380px; overflow: auto; background: #0f172a; color: #dbeafe; border-radius: 8px; padding: 12px; white-space: pre-wrap; font-size: 13px; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th, td { text-align: left; padding: 9px 7px; border-bottom: 1px solid var(--line); vertical-align: top; overflow-wrap: anywhere; }
    th { color: var(--muted); background: #f8fafc; }
    .ai-list, .list { display: grid; gap: 10px; }
    .line-item { display: grid; grid-template-columns: 112px minmax(0, 1fr) auto; gap: 10px; align-items: center; border: 1px solid var(--line); border-radius: 8px; padding: 10px; }
    .line-item strong { font-size: 14px; }
    .line-item span { color: var(--muted); font-size: 12px; overflow-wrap: anywhere; }
    .model-card { border: 1px solid var(--line); border-radius: 8px; padding: 12px; display: grid; gap: 10px; }
    .model-card header { margin: 0; align-items: center; }
    .model-card-meta { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; justify-content: flex-end; }
    .docs-link { color: var(--accent); font-size: 12px; font-weight: 800; text-decoration: none; }
    .docs-link:hover { text-decoration: underline; }
    .model-card code { display: block; background: #eef2f7; border-radius: 6px; padding: 7px 8px; overflow-wrap: anywhere; font-size: 12px; }
    .pill { border-radius: 999px; padding: 4px 8px; font-size: 12px; font-weight: 800; background: #eef2f7; white-space: nowrap; }
    .pill.ok { background: #e5f7ef; color: var(--ok); }
    .pill.warn { background: #fff7e6; color: var(--warn); }
    .hidden { display: none; }
    .ok { color: var(--ok); }
    .warn { color: var(--warn); }
    .danger { color: var(--danger); }
    @media (max-width: 1120px) {
      .grid { grid-template-columns: repeat(3, minmax(0, 1fr)); }
    }
    @media (max-width: 980px) {
      .shell, .layout, .runtime-grid, .runtime-switches { grid-template-columns: 1fr; }
      aside { position: static; }
      .actions { grid-template-columns: 1fr 1fr; }
    }
    @media (max-width: 620px) {
      main { padding: 14px; }
      header { align-items: flex-start; flex-direction: column; }
      .topbar { justify-content: flex-start; }
      .grid, .row, .actions, .line-item { grid-template-columns: 1fr; }
      iframe { height: 520px; }
    }
  </style>
</head>
<body>
  <div class="shell">
    <aside>
      <div class="brand">
        <div class="mark">A</div>
        <div><strong>Aegis Console</strong><span>Privit local security</span></div>
      </div>
      <nav>
        <button class="active" data-view="dashboard" data-i18n="navDashboard">Dashboard</button>
        <button data-view="scope" data-i18n="navScope">Scope</button>
        <button data-view="discovery" data-i18n="navDiscovery">Discovery</button>
        <button data-view="ai" data-i18n="navAi">AI</button>
        <button data-view="updates" data-i18n="navUpdates">Updates</button>
        <button data-view="report" data-i18n="navReport">Report</button>
        <button data-view="logs" data-i18n="navLogs">Logs</button>
      </nav>
    </aside>
    <main>
      <header>
        <div>
          <h1 data-i18n="title">Privit Aegis Console</h1>
          <p class="muted" id="subtitle">Loading</p>
        </div>
        <div class="topbar">
          <select id="language-select" class="language" aria-label="Language">
            <option value="ko">한국어</option>
            <option value="en">English</option>
            <option value="ja">日本語</option>
            <option value="zh">中文</option>
          </select>
          <div class="status" id="status">Ready</div>
        </div>
      </header>

      <section id="dashboard-view">
        <div class="grid">
          <div class="card"><span data-i18n="metricCatalog">Catalog</span><strong id="catalog-count">0</strong></div>
          <div class="card"><span data-i18n="metricFindings">Findings</span><strong id="finding-count">0</strong></div>
          <div class="card"><span data-i18n="metricRoutes">Routes</span><strong id="route-count">0</strong></div>
          <div class="card"><span data-i18n="metricForms">Forms</span><strong id="form-count">0</strong></div>
          <div class="card"><span data-i18n="metricAuth">Auth</span><strong id="auth-count">0</strong></div>
          <div class="card"><span data-i18n="metricAi">AI</span><strong id="ai-count">0/3</strong></div>
        </div>
        <div class="layout">
          <div class="panel">
            <h2 data-i18n="actions">Actions</h2>
            <div class="actions">
              <button data-action="catalog" data-i18n="actionCatalog">Catalog</button>
              <button data-action="docs" data-i18n="actionDocs">Docs</button>
              <button data-action="verify" data-i18n="actionVerify">Verify</button>
              <button data-action="plan" data-i18n="actionPlan">Plan</button>
              <button data-action="map" data-i18n="actionMap">Map</button>
              <button data-action="scan" data-i18n="actionScan">Scan</button>
              <button data-action="dryRun" data-i18n="actionDryRun">Dry Run</button>
              <button data-action="report" data-i18n="actionReport">Report</button>
              <button data-action="gate" data-i18n="actionGate">AIGate</button>
              <button class="primary" data-action="start" data-i18n="actionStart">Start All</button>
            </div>
          </div>
          <div class="panel">
            <h2 data-i18n="latestRun">Latest Run</h2>
            <pre id="latest-summary">No run yet.</pre>
          </div>
        </div>
      </section>

      <section id="scope-view" class="hidden">
        <div class="panel">
          <h2 data-i18n="scopeSettings">Scope Settings</h2>
          <form id="scope-form">
            <div class="row">
              <label><span data-i18n="project">Project</span><input name="project"></label>
              <label><span data-i18n="environment">Environment</span>
                <select name="environment">
                  <option value="local">local</option>
                  <option value="development">development</option>
                  <option value="staging">staging</option>
                  <option value="production_passive_only">production_passive_only</option>
                </select>
              </label>
            </div>
            <label><span data-i18n="frontendUrl">Frontend URL</span><input name="frontendUrl"></label>
            <label><span data-i18n="backendUrl">Backend API URL</span><input name="backendUrl"></label>
            <div class="row">
              <label><span data-i18n="owner">Owner Email</span><input name="owner"></label>
              <label><span data-i18n="expiresAt">Authorization Expires</span><input name="expiresAt" type="date"></label>
            </div>
            <div class="row">
              <label><span data-i18n="allowedPaths">Allowed Paths</span><input name="allowedPaths"></label>
              <label><span data-i18n="deniedPaths">Denied Paths</span><input name="deniedPaths"></label>
            </div>
            <div class="row">
              <label><span data-i18n="maxRps">Max RPS</span><input name="maxRps" type="number" min="1" max="20"></label>
              <label><span data-i18n="maxConcurrency">Max Concurrency</span><input name="maxConcurrency" type="number" min="1" max="20"></label>
            </div>
            <div class="row">
              <label class="switch"><input name="backendEnabled" type="checkbox"> <span data-i18n="backendApi">Backend API</span></label>
              <label class="switch"><input name="ciEnabled" type="checkbox"> <span data-i18n="ciCd">CI/CD</span></label>
            </div>
            <button class="primary" type="submit" data-i18n="saveScope">Save Scope</button>
          </form>
        </div>
      </section>

      <section id="discovery-view" class="hidden">
        <div class="layout">
          <div class="panel">
            <h2 data-i18n="discoverySettings">Discovery Settings</h2>
            <form id="discovery-form">
              <div class="row">
                <label><span data-i18n="maxDepth">Max Depth</span><input name="maxDepth" type="number" min="0" max="5"></label>
                <label><span data-i18n="maxPages">Max Pages</span><input name="maxPages" type="number" min="1" max="200"></label>
              </div>
              <label><span data-i18n="sitemapPaths">Sitemap Paths</span><input name="sitemapPaths"></label>
              <label><span data-i18n="loginIndicators">Login Indicators</span><input name="loginIndicators"></label>
              <div class="row">
                <label class="switch"><input name="discoveryEnabled" type="checkbox"> <span data-i18n="discoveryEnabled">Discovery</span></label>
                <label class="switch"><input name="includeForms" type="checkbox"> <span data-i18n="includeForms">Form Inventory</span></label>
              </div>
              <label class="switch"><input name="followRedirects" type="checkbox"> <span data-i18n="followRedirects">Follow Redirects</span></label>
              <button class="primary" type="submit" data-i18n="saveDiscovery">Save Discovery</button>
            </form>
          </div>
          <div class="panel">
            <h2 data-i18n="siteMap">Site Map</h2>
            <table>
              <thead><tr><th>Status</th><th>Path</th><th>Depth</th><th>Source</th></tr></thead>
              <tbody id="route-table"></tbody>
            </table>
          </div>
        </div>
      </section>

      <section id="ai-view" class="hidden">
        <div class="layout">
          <div class="panel">
            <h2 data-i18n="providers">Providers</h2>
            <div id="ai-providers" class="ai-list"></div>
          </div>
          <div class="panel">
            <h2 data-i18n="aiModels">AI Models</h2>
            <form id="ai-model-form">
              <label><span data-i18n="defaultProvider">Default Provider</span>
                <select name="defaultProvider" id="default-provider-select"></select>
              </label>
              <div id="ai-model-settings" class="ai-list"></div>
              <button class="primary" type="submit" data-i18n="saveAiModels">Save AI Models</button>
            </form>
          </div>
        </div>
        <div class="layout">
          <div class="panel">
            <h2 data-i18n="aiGate">AI Gate</h2>
            <div class="actions">
              <button data-action="ai" data-i18n="actionAiSetup">AI Setup</button>
              <button data-action="aiDoctor" data-i18n="actionAiDoctor">AI Doctor</button>
              <button data-action="aiReport" data-i18n="actionAiReport">AI Report</button>
              <button data-action="aiModelCommands" data-i18n="actionAiModelCommands">Model Commands</button>
              <button data-action="aiProviderCheck" data-i18n="actionAiProviderCheck">Provider Check</button>
            </div>
          </div>
          <div class="panel">
            <h2 data-i18n="aiCommandReference">Command Reference</h2>
            <pre id="ai-summary">Loading</pre>
          </div>
        </div>
        <div class="panel">
          <h2 data-i18n="aiRuntimeSettings">AI Runtime Settings</h2>
          <div class="runtime-grid">
            <label><span data-i18n="aiProfile">Profile</span><input name="runtime.profile" form="ai-model-form"></label>
            <label><span data-i18n="aiLocale">Locale</span><input name="runtime.locale" form="ai-model-form"></label>
            <label><span data-i18n="aiTemperature">Temperature</span><input name="runtime.response.temperature" form="ai-model-form" type="number" min="0" max="2" step="0.01"></label>
            <label><span data-i18n="aiTopP">Top P</span><input name="runtime.response.topP" form="ai-model-form" type="number" min="0" max="1" step="0.01"></label>
            <label><span data-i18n="aiMaxOutputTokens">Max Output Tokens</span><input name="runtime.response.maxOutputTokens" form="ai-model-form" type="number" min="1"></label>
            <label><span data-i18n="aiMaxInputTokens">Max Input Tokens</span><input name="runtime.context.maxInputTokens" form="ai-model-form" type="number" min="1"></label>
            <label><span data-i18n="aiFileBudgetTokens">File Budget Tokens</span><input name="runtime.context.fileBudgetTokens" form="ai-model-form" type="number" min="1"></label>
            <label><span data-i18n="aiOutputFormat">Output Format</span><input name="runtime.response.outputFormat" form="ai-model-form"></label>
            <label><span data-i18n="aiMaxTurns">Max Turns</span><input name="runtime.execution.maxTurns" form="ai-model-form" type="number" min="1" max="200"></label>
            <label><span data-i18n="aiTimeoutMs">Timeout Ms</span><input name="runtime.execution.timeoutMs" form="ai-model-form" type="number" min="1000"></label>
            <label><span data-i18n="aiParallelism">Parallelism</span><input name="runtime.execution.parallelism" form="ai-model-form" type="number" min="1" max="20"></label>
            <label><span data-i18n="aiBudgetPerRun">Budget / Run</span><input name="runtime.cost.budgetUsdPerRun" form="ai-model-form" type="number" min="0" step="0.01"></label>
            <label><span data-i18n="aiDailyBudget">Daily Budget</span><input name="runtime.cost.dailyBudgetUsd" form="ai-model-form" type="number" min="0" step="0.01"></label>
            <label><span data-i18n="aiMinAigateScore">Min AIGate Score</span><input name="runtime.quality.minAigateScore" form="ai-model-form" type="number" min="0" max="100"></label>
            <label><span data-i18n="aiMemoryMode">Memory Mode</span><input name="runtime.context.memoryMode" form="ai-model-form"></label>
            <label><span data-i18n="aiHandoffLanguage">Handoff Language</span><input name="runtime.handoff.defaultLanguage" form="ai-model-form"></label>
          </div>
          <div class="runtime-switches">
            <label class="switch"><input name="runtime.tools.allowNetwork" form="ai-model-form" type="checkbox"> <span data-i18n="aiAllowNetwork">Network</span></label>
            <label class="switch"><input name="runtime.tools.allowPackageInstall" form="ai-model-form" type="checkbox"> <span data-i18n="aiAllowPackageInstall">Package Install</span></label>
            <label class="switch"><input name="runtime.cost.preferLocalWhenAvailable" form="ai-model-form" type="checkbox"> <span data-i18n="aiPreferLocal">Prefer Local</span></label>
            <label class="switch"><input name="runtime.security.promptInjectionGuard" form="ai-model-form" type="checkbox"> <span data-i18n="aiPromptGuard">Prompt Guard</span></label>
            <label class="switch"><input name="runtime.security.redactSecrets" form="ai-model-form" type="checkbox"> <span data-i18n="aiRedactSecrets">Redact Secrets</span></label>
            <label class="switch"><input name="runtime.security.storePrompts" form="ai-model-form" type="checkbox"> <span data-i18n="aiStorePrompts">Store Prompts</span></label>
            <label class="switch"><input name="runtime.security.storeResponses" form="ai-model-form" type="checkbox"> <span data-i18n="aiStoreResponses">Store Responses</span></label>
            <label class="switch"><input name="runtime.quality.requireTests" form="ai-model-form" type="checkbox"> <span data-i18n="aiRequireTests">Require Tests</span></label>
          </div>
          <h3 data-i18n="aiAdvancedJson">Advanced JSON</h3>
          <textarea id="ai-runtime-json" name="runtimeJson" form="ai-model-form"></textarea>
        </div>
      </section>

      <section id="updates-view" class="hidden">
        <div class="layout">
          <div class="panel">
            <h2 data-i18n="updates">Updates</h2>
            <div class="actions">
              <button data-action="audit" data-i18n="actionAudit">npm audit</button>
              <button data-action="hardening" data-i18n="actionHardening">Hardening</button>
              <button data-action="targetAdvisory" data-i18n="actionTargetAdvisory">Target Advisory</button>
              <button data-action="githubReady" data-i18n="actionGithubReady">GitHub Ready</button>
              <button data-action="gateReady" data-i18n="actionGateReady">Gate Ready</button>
              <button data-action="gitStatus" data-i18n="actionGitStatus">Git Status</button>
              <button data-action="ciSecurity" data-i18n="actionCiSecurity">CI Security</button>
            </div>
          </div>
          <div class="panel">
            <h2 data-i18n="repositoryRoles">Repository Roles</h2>
            <pre id="repo-summary">Loading</pre>
          </div>
        </div>
        <div class="panel">
          <h2 data-i18n="toolchain">Toolchain</h2>
          <div id="toolchain-list" class="list"></div>
        </div>
      </section>

      <section id="report-view" class="hidden">
        <iframe id="report-frame" title="Aegis report"></iframe>
      </section>

      <section id="logs-view" class="hidden">
        <div class="panel">
          <h2 data-i18n="commandOutput">Command Output</h2>
          <pre id="log-output">No command output yet.</pre>
        </div>
      </section>
    </main>
  </div>

  <script>
    const stateUrl = "/api/state";
    const scopeForm = document.querySelector("#scope-form");
    const discoveryForm = document.querySelector("#discovery-form");
    const aiModelForm = document.querySelector("#ai-model-form");
    const languageSelect = document.querySelector("#language-select");
    let currentState = null;
    let language = localStorage.getItem("aegis.language") || "ko";

    const messages = {
      ko: {
        navDashboard: "대시보드", navScope: "범위", navDiscovery: "탐색", navAi: "AI", navUpdates: "업데이트", navReport: "보고서", navLogs: "로그",
        title: "Privit Aegis 콘솔", metricCatalog: "카탈로그", metricFindings: "취약점", metricRoutes: "경로", metricForms: "폼", metricAuth: "인증", metricAi: "AI",
        actions: "작업", actionCatalog: "카탈로그", actionDocs: "문서", actionVerify: "검증", actionPlan: "계획", actionMap: "사이트맵", actionScan: "스캔", actionDryRun: "드라이런", actionReport: "보고서", actionGate: "AIGate", actionStart: "전체 실행",
        latestRun: "최근 실행", scopeSettings: "범위 설정", project: "프로젝트", environment: "환경", frontendUrl: "프론트 URL", backendUrl: "백엔드 API URL", owner: "소유자 이메일", expiresAt: "승인 만료일", allowedPaths: "허용 경로", deniedPaths: "차단 경로", maxRps: "최대 RPS", maxConcurrency: "최대 동시성", backendApi: "백엔드 API", ciCd: "CI/CD", saveScope: "범위 저장",
        discoverySettings: "탐색 설정", maxDepth: "최대 깊이", maxPages: "최대 페이지", sitemapPaths: "사이트맵 경로", loginIndicators: "로그인 지표", discoveryEnabled: "탐색", includeForms: "폼 수집", followRedirects: "리다이렉트 추적", saveDiscovery: "탐색 저장", siteMap: "사이트맵",
        providers: "프로바이더", aiModels: "AI 모델", aiRuntimeSettings: "AI 런타임 설정", defaultProvider: "기본 프로바이더", saveAiModels: "AI 모델 저장", aiGate: "AI 게이트", aiCommandReference: "명령어 참고", actionAiSetup: "AI 설정", actionAiDoctor: "AI 점검", actionAiReport: "AI 보고서", actionAiModelCommands: "모델 명령어", actionAiProviderCheck: "프로바이더 점검", modelDocs: "모델 문서",
        aiProfile: "프로필", aiLocale: "언어", aiTemperature: "온도", aiTopP: "Top P", aiMaxOutputTokens: "최대 출력 토큰", aiMaxInputTokens: "최대 입력 토큰", aiFileBudgetTokens: "파일 토큰 예산", aiOutputFormat: "출력 형식", aiMaxTurns: "최대 턴", aiTimeoutMs: "타임아웃 ms", aiParallelism: "병렬성", aiBudgetPerRun: "실행당 예산", aiDailyBudget: "일일 예산", aiMinAigateScore: "최소 AIGate 점수", aiMemoryMode: "메모리 모드", aiHandoffLanguage: "전달 언어", aiAllowNetwork: "네트워크", aiAllowPackageInstall: "패키지 설치", aiPreferLocal: "로컬 우선", aiPromptGuard: "프롬프트 방어", aiRedactSecrets: "시크릿 마스킹", aiStorePrompts: "프롬프트 저장", aiStoreResponses: "응답 저장", aiRequireTests: "테스트 필수", aiAdvancedJson: "고급 JSON",
        model: "모델", providerType: "유형", enabledProvider: "사용", endpoint: "API/로컬 엔드포인트", healthUrl: "헬스 URL", apiStyle: "API 방식", apiKeyEnv: "키 환경변수", effort: "추론 강도", approvalMode: "승인 모드", permissionMode: "권한 모드", sandbox: "샌드박스", outputFormat: "출력 형식", fallbackModel: "대체 모델", extraArgs: "추가 인자", disabled: "비활성", check: "확인 필요",
        updates: "업데이트", actionAudit: "npm audit", actionHardening: "하드닝 검사", actionTargetAdvisory: "대상 점검", actionGithubReady: "GitHub 준비", actionGateReady: "Gate Ready", actionGitStatus: "Git 상태", actionCiSecurity: "CI 보안", repositoryRoles: "레포 역할", toolchain: "툴체인", commandOutput: "명령 출력",
        ready: "준비", reportReady: "보고서 준비", running: "실행 중", passed: "통과", failed: "실패", saved: "저장됨"
      },
      en: {
        navDashboard: "Dashboard", navScope: "Scope", navDiscovery: "Discovery", navAi: "AI", navUpdates: "Updates", navReport: "Report", navLogs: "Logs",
        title: "Privit Aegis Console", metricCatalog: "Catalog", metricFindings: "Findings", metricRoutes: "Routes", metricForms: "Forms", metricAuth: "Auth", metricAi: "AI",
        actions: "Actions", actionCatalog: "Catalog", actionDocs: "Docs", actionVerify: "Verify", actionPlan: "Plan", actionMap: "Site Map", actionScan: "Scan", actionDryRun: "Dry Run", actionReport: "Report", actionGate: "AIGate", actionStart: "Start All",
        latestRun: "Latest Run", scopeSettings: "Scope Settings", project: "Project", environment: "Environment", frontendUrl: "Frontend URL", backendUrl: "Backend API URL", owner: "Owner Email", expiresAt: "Authorization Expires", allowedPaths: "Allowed Paths", deniedPaths: "Denied Paths", maxRps: "Max RPS", maxConcurrency: "Max Concurrency", backendApi: "Backend API", ciCd: "CI/CD", saveScope: "Save Scope",
        discoverySettings: "Discovery Settings", maxDepth: "Max Depth", maxPages: "Max Pages", sitemapPaths: "Sitemap Paths", loginIndicators: "Login Indicators", discoveryEnabled: "Discovery", includeForms: "Form Inventory", followRedirects: "Follow Redirects", saveDiscovery: "Save Discovery", siteMap: "Site Map",
        providers: "Providers", aiModels: "AI Models", aiRuntimeSettings: "AI Runtime Settings", defaultProvider: "Default Provider", saveAiModels: "Save AI Models", aiGate: "AI Gate", aiCommandReference: "Command Reference", actionAiSetup: "AI Setup", actionAiDoctor: "AI Doctor", actionAiReport: "AI Report", actionAiModelCommands: "Model Commands", actionAiProviderCheck: "Provider Check", modelDocs: "Model Docs",
        aiProfile: "Profile", aiLocale: "Locale", aiTemperature: "Temperature", aiTopP: "Top P", aiMaxOutputTokens: "Max Output Tokens", aiMaxInputTokens: "Max Input Tokens", aiFileBudgetTokens: "File Budget Tokens", aiOutputFormat: "Output Format", aiMaxTurns: "Max Turns", aiTimeoutMs: "Timeout Ms", aiParallelism: "Parallelism", aiBudgetPerRun: "Budget / Run", aiDailyBudget: "Daily Budget", aiMinAigateScore: "Min AIGate Score", aiMemoryMode: "Memory Mode", aiHandoffLanguage: "Handoff Language", aiAllowNetwork: "Network", aiAllowPackageInstall: "Package Install", aiPreferLocal: "Prefer Local", aiPromptGuard: "Prompt Guard", aiRedactSecrets: "Redact Secrets", aiStorePrompts: "Store Prompts", aiStoreResponses: "Store Responses", aiRequireTests: "Require Tests", aiAdvancedJson: "Advanced JSON",
        model: "Model", providerType: "Type", enabledProvider: "Enabled", endpoint: "API/Local Endpoint", healthUrl: "Health URL", apiStyle: "API Style", apiKeyEnv: "Key Env", effort: "Effort", approvalMode: "Approval Mode", permissionMode: "Permission Mode", sandbox: "Sandbox", outputFormat: "Output Format", fallbackModel: "Fallback Model", extraArgs: "Extra Args", disabled: "Disabled", check: "Check",
        updates: "Updates", actionAudit: "npm audit", actionHardening: "Hardening", actionTargetAdvisory: "Target Advisory", actionGithubReady: "GitHub Ready", actionGateReady: "Gate Ready", actionGitStatus: "Git Status", actionCiSecurity: "CI Security", repositoryRoles: "Repository Roles", toolchain: "Toolchain", commandOutput: "Command Output",
        ready: "Ready", reportReady: "Report ready", running: "Running", passed: "Passed", failed: "Failed", saved: "Saved"
      },
      ja: {
        navDashboard: "ダッシュボード", navScope: "スコープ", navDiscovery: "探索", navAi: "AI", navUpdates: "更新", navReport: "レポート", navLogs: "ログ",
        title: "Privit Aegis コンソール", metricCatalog: "カタログ", metricFindings: "検出", metricRoutes: "経路", metricForms: "フォーム", metricAuth: "認証", metricAi: "AI",
        actions: "操作", actionCatalog: "カタログ", actionDocs: "ドキュメント", actionVerify: "検証", actionPlan: "計画", actionMap: "サイトマップ", actionScan: "スキャン", actionDryRun: "ドライラン", actionReport: "レポート", actionGate: "AIGate", actionStart: "全実行",
        latestRun: "最新実行", scopeSettings: "スコープ設定", project: "プロジェクト", environment: "環境", frontendUrl: "フロントURL", backendUrl: "バックエンドAPI URL", owner: "所有者メール", expiresAt: "承認期限", allowedPaths: "許可パス", deniedPaths: "拒否パス", maxRps: "最大RPS", maxConcurrency: "最大同時実行", backendApi: "バックエンドAPI", ciCd: "CI/CD", saveScope: "スコープ保存",
        discoverySettings: "探索設定", maxDepth: "最大深度", maxPages: "最大ページ", sitemapPaths: "サイトマップパス", loginIndicators: "ログイン指標", discoveryEnabled: "探索", includeForms: "フォーム収集", followRedirects: "リダイレクト追跡", saveDiscovery: "探索保存", siteMap: "サイトマップ",
        providers: "プロバイダー", aiModels: "AIモデル", aiRuntimeSettings: "AIランタイム設定", defaultProvider: "既定プロバイダー", saveAiModels: "AIモデル保存", aiGate: "AIゲート", aiCommandReference: "コマンド参照", actionAiSetup: "AI設定", actionAiDoctor: "AI診断", actionAiReport: "AIレポート", actionAiModelCommands: "モデルコマンド", actionAiProviderCheck: "プロバイダー診断", modelDocs: "モデル文書",
        aiProfile: "プロファイル", aiLocale: "ロケール", aiTemperature: "温度", aiTopP: "Top P", aiMaxOutputTokens: "最大出力トークン", aiMaxInputTokens: "最大入力トークン", aiFileBudgetTokens: "ファイルトークン予算", aiOutputFormat: "出力形式", aiMaxTurns: "最大ターン", aiTimeoutMs: "タイムアウト ms", aiParallelism: "並列数", aiBudgetPerRun: "実行予算", aiDailyBudget: "日次予算", aiMinAigateScore: "最小AIGateスコア", aiMemoryMode: "メモリモード", aiHandoffLanguage: "引き継ぎ言語", aiAllowNetwork: "ネットワーク", aiAllowPackageInstall: "パッケージ導入", aiPreferLocal: "ローカル優先", aiPromptGuard: "プロンプト防御", aiRedactSecrets: "秘密マスク", aiStorePrompts: "プロンプト保存", aiStoreResponses: "応答保存", aiRequireTests: "テスト必須", aiAdvancedJson: "詳細JSON",
        model: "モデル", providerType: "種類", enabledProvider: "有効", endpoint: "API/ローカルエンドポイント", healthUrl: "ヘルスURL", apiStyle: "API方式", apiKeyEnv: "キー環境変数", effort: "推論強度", approvalMode: "承認モード", permissionMode: "権限モード", sandbox: "サンドボックス", outputFormat: "出力形式", fallbackModel: "フォールバックモデル", extraArgs: "追加引数", disabled: "無効", check: "確認",
        updates: "更新", actionAudit: "npm audit", actionHardening: "ハードニング診断", actionTargetAdvisory: "対象診断", actionGithubReady: "GitHub準備", actionGateReady: "Gate Ready", actionGitStatus: "Git状態", actionCiSecurity: "CIセキュリティ", repositoryRoles: "リポジトリ役割", toolchain: "ツールチェーン", commandOutput: "コマンド出力",
        ready: "準備完了", reportReady: "レポート準備完了", running: "実行中", passed: "成功", failed: "失敗", saved: "保存済み"
      },
      zh: {
        navDashboard: "仪表盘", navScope: "范围", navDiscovery: "发现", navAi: "AI", navUpdates: "更新", navReport: "报告", navLogs: "日志",
        title: "Privit Aegis 控制台", metricCatalog: "目录", metricFindings: "发现项", metricRoutes: "路由", metricForms: "表单", metricAuth: "认证", metricAi: "AI",
        actions: "操作", actionCatalog: "目录", actionDocs: "文档", actionVerify: "验证", actionPlan: "计划", actionMap: "站点图", actionScan: "扫描", actionDryRun: "试运行", actionReport: "报告", actionGate: "AIGate", actionStart: "全部运行",
        latestRun: "最近运行", scopeSettings: "范围设置", project: "项目", environment: "环境", frontendUrl: "前端 URL", backendUrl: "后端 API URL", owner: "所有者邮箱", expiresAt: "授权到期", allowedPaths: "允许路径", deniedPaths: "拒绝路径", maxRps: "最大 RPS", maxConcurrency: "最大并发", backendApi: "后端 API", ciCd: "CI/CD", saveScope: "保存范围",
        discoverySettings: "发现设置", maxDepth: "最大深度", maxPages: "最大页面", sitemapPaths: "站点图路径", loginIndicators: "登录指标", discoveryEnabled: "发现", includeForms: "表单清单", followRedirects: "跟随重定向", saveDiscovery: "保存发现", siteMap: "站点图",
        providers: "提供方", aiModels: "AI 模型", aiRuntimeSettings: "AI 运行时设置", defaultProvider: "默认提供方", saveAiModels: "保存 AI 模型", aiGate: "AI 网关", aiCommandReference: "命令参考", actionAiSetup: "AI 设置", actionAiDoctor: "AI 检查", actionAiReport: "AI 报告", actionAiModelCommands: "模型命令", actionAiProviderCheck: "提供方检查", modelDocs: "模型文档",
        aiProfile: "配置", aiLocale: "语言", aiTemperature: "温度", aiTopP: "Top P", aiMaxOutputTokens: "最大输出令牌", aiMaxInputTokens: "最大输入令牌", aiFileBudgetTokens: "文件令牌预算", aiOutputFormat: "输出格式", aiMaxTurns: "最大轮次", aiTimeoutMs: "超时 ms", aiParallelism: "并行数", aiBudgetPerRun: "单次预算", aiDailyBudget: "每日预算", aiMinAigateScore: "最低 AIGate 分数", aiMemoryMode: "记忆模式", aiHandoffLanguage: "交接语言", aiAllowNetwork: "网络", aiAllowPackageInstall: "包安装", aiPreferLocal: "优先本地", aiPromptGuard: "提示防护", aiRedactSecrets: "密钥脱敏", aiStorePrompts: "保存提示", aiStoreResponses: "保存响应", aiRequireTests: "要求测试", aiAdvancedJson: "高级 JSON",
        model: "模型", providerType: "类型", enabledProvider: "启用", endpoint: "API/本地端点", healthUrl: "健康 URL", apiStyle: "API 样式", apiKeyEnv: "密钥环境变量", effort: "推理强度", approvalMode: "审批模式", permissionMode: "权限模式", sandbox: "沙箱", outputFormat: "输出格式", fallbackModel: "备用模型", extraArgs: "额外参数", disabled: "已禁用", check: "需检查",
        updates: "更新", actionAudit: "npm audit", actionHardening: "加固检查", actionTargetAdvisory: "目标检查", actionGithubReady: "GitHub 就绪", actionGateReady: "Gate Ready", actionGitStatus: "Git 状态", actionCiSecurity: "CI 安全", repositoryRoles: "仓库角色", toolchain: "工具链", commandOutput: "命令输出",
        ready: "就绪", reportReady: "报告就绪", running: "运行中", passed: "通过", failed: "失败", saved: "已保存"
      }
    };

    function t(key) {
      return messages[language]?.[key] || messages.en[key] || key;
    }

    function escapeHtml(value) {
      return String(value ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
    }

    function applyI18n() {
      document.documentElement.lang = language;
      languageSelect.value = language;
      for (const el of document.querySelectorAll("[data-i18n]")) {
        el.textContent = t(el.dataset.i18n);
      }
      setStatus(currentState?.reportExists ? t("reportReady") : t("ready"), currentState?.reportExists ? "ok" : "");
    }

    function view(name) {
      for (const section of document.querySelectorAll("main > section")) section.classList.add("hidden");
      document.querySelector("#" + name + "-view").classList.remove("hidden");
      for (const button of document.querySelectorAll("nav button")) button.classList.toggle("active", button.dataset.view === name);
      if (name === "report") document.querySelector("#report-frame").src = "/report?ts=" + Date.now();
    }

    function setStatus(text, tone) {
      const el = document.querySelector("#status");
      el.textContent = text;
      el.className = "status " + (tone || "");
    }

    function payloadFromForms() {
      const payload = Object.fromEntries(new FormData(scopeForm).entries());
      Object.assign(payload, Object.fromEntries(new FormData(discoveryForm).entries()));
      payload.backendEnabled = scopeForm.backendEnabled.checked;
      payload.ciEnabled = scopeForm.ciEnabled.checked;
      payload.discoveryEnabled = discoveryForm.discoveryEnabled.checked;
      payload.includeForms = discoveryForm.includeForms.checked;
      payload.followRedirects = discoveryForm.followRedirects.checked;
      return payload;
    }

    function fillForms(scope) {
      if (!scope) return;
      const discovery = scope.targets?.frontend?.discovery || {};
      scopeForm.project.value = scope.project || "";
      scopeForm.environment.value = scope.environment || "local";
      scopeForm.frontendUrl.value = scope.targets?.frontend?.base_url || "";
      scopeForm.backendUrl.value = scope.targets?.backend_api?.base_url || "";
      scopeForm.owner.value = scope.authorization?.owner || "";
      scopeForm.expiresAt.value = scope.authorization?.expires_at || "";
      scopeForm.allowedPaths.value = (scope.targets?.frontend?.allowed_paths || ["/*"]).join(", ");
      scopeForm.deniedPaths.value = (scope.targets?.frontend?.denied_paths || []).join(", ");
      scopeForm.maxRps.value = scope.safety?.max_rps || 2;
      scopeForm.maxConcurrency.value = scope.safety?.max_concurrency || 3;
      scopeForm.backendEnabled.checked = Boolean(scope.targets?.backend_api?.enabled);
      scopeForm.ciEnabled.checked = Boolean(scope.targets?.ci_cd?.enabled);
      discoveryForm.discoveryEnabled.checked = discovery.enabled !== false;
      discoveryForm.maxDepth.value = discovery.max_depth ?? 2;
      discoveryForm.maxPages.value = discovery.max_pages ?? 30;
      discoveryForm.includeForms.checked = discovery.include_forms !== false;
      discoveryForm.followRedirects.checked = discovery.follow_redirects !== false;
      discoveryForm.sitemapPaths.value = (discovery.sitemap_paths || ["/robots.txt", "/sitemap.xml"]).join(", ");
      discoveryForm.loginIndicators.value = (discovery.login_indicators || ["login", "signin", "sign-in", "auth", "session", "admin", "account"]).join(", ");
    }

    function getPathValue(root, path, fallback = "") {
      return path.split(".").reduce((current, part) => current?.[part], root) ?? fallback;
    }

    function setPathValue(root, path, value) {
      const parts = path.split(".");
      let target = root;
      for (const part of parts.slice(0, -1)) {
        target[part] ||= {};
        target = target[part];
      }
      target[parts.at(-1)] = value;
    }

    function fillRuntimeControls(runtimeSettings) {
      for (const input of document.querySelectorAll('[name^="runtime."]')) {
        const path = input.name.replace(/^runtime\./, "");
        const value = getPathValue(runtimeSettings, path, input.type === "checkbox" ? false : "");
        if (input.type === "checkbox") {
          input.checked = Boolean(value);
        } else {
          input.value = value;
        }
      }
      document.querySelector("#ai-runtime-json").value = JSON.stringify(runtimeSettings, null, 2);
    }

    function renderAi(ai) {
      const providers = ai.providers || [];
      const modelSettings = ai.modelSettings || { defaultProvider: "codex", providers: {}, commands: {} };
      const runtimeSettings = ai.runtimeSettings || {};
      document.querySelector("#ai-count").textContent = (ai.readyCount || 0) + "/" + (ai.totalCount || 3);
      document.querySelector("#ai-providers").innerHTML = providers.map((provider) => \`
        <div class="line-item">
          <strong>\${escapeHtml(provider.label)}</strong>
          <span>\${escapeHtml(provider.providerType || "cli")} / \${escapeHtml(provider.model || "-")} / \${escapeHtml(provider.endpoint || provider.rootFile || "-")} / \${escapeHtml(provider.command)} \${escapeHtml(provider.version || "")}</span>
          <span class="pill \${escapeHtml(provider.statusTone || "")}">\${escapeHtml(t(provider.status || (provider.ready ? "ready" : "check")))}</span>
        </div>
      \`).join("");
      document.querySelector("#default-provider-select").innerHTML = providers.map((provider) =>
        \`<option value="\${escapeHtml(provider.id)}" \${modelSettings.defaultProvider === provider.id ? "selected" : ""}>\${escapeHtml(provider.label)}</option>\`
      ).join("");
      document.querySelector("#ai-model-settings").innerHTML = providers.map((provider) => {
        const config = modelSettings.providers?.[provider.id] || provider.modelConfig || {};
        const commands = modelSettings.commands?.[provider.id] || provider.commandReference || {};
        const presets = config.presets || [];
        const datalistId = "models-" + provider.id;
        return \`
          <div class="model-card" data-provider="\${escapeHtml(provider.id)}">
            <header>
              <h3>\${escapeHtml(provider.label)}</h3>
              <div class="model-card-meta">
                <a class="docs-link" href="\${escapeHtml(config.docsUrl || "#")}" target="_blank" rel="noreferrer" data-i18n="modelDocs">\${t("modelDocs")}</a>
                <span class="pill">\${escapeHtml(config.providerType || "cli")}</span>
                <span class="pill \${escapeHtml(provider.statusTone || "")}">\${escapeHtml(t(provider.status || "check"))}</span>
              </div>
            </header>
            <label class="switch"><input name="\${provider.id}.enabled" type="checkbox" \${config.enabled ? "checked" : ""}> <span data-i18n="enabledProvider">\${t("enabledProvider")}</span></label>
            <datalist id="\${datalistId}">
              \${presets.map((model) => \`<option value="\${escapeHtml(model)}"></option>\`).join("")}
            </datalist>
            <div class="row">
              <label><span data-i18n="model">\${t("model")}</span><input name="\${provider.id}.model" list="\${datalistId}" value="\${escapeHtml(config.model || "")}"></label>
              <label><span data-i18n="providerType">\${t("providerType")}</span><input name="\${provider.id}.providerType" value="\${escapeHtml(config.providerType || "")}" disabled></label>
            </div>
            <div class="row">
              <label><span data-i18n="endpoint">\${t("endpoint")}</span><input name="\${provider.id}.endpoint" value="\${escapeHtml(config.endpoint || "")}"></label>
              <label><span data-i18n="healthUrl">\${t("healthUrl")}</span><input name="\${provider.id}.healthUrl" value="\${escapeHtml(config.healthUrl || "")}"></label>
            </div>
            <div class="row">
              <label><span data-i18n="apiStyle">\${t("apiStyle")}</span><input name="\${provider.id}.apiStyle" value="\${escapeHtml(config.apiStyle || "")}"></label>
              <label><span data-i18n="apiKeyEnv">\${t("apiKeyEnv")}</span><input name="\${provider.id}.apiKeyEnv" value="\${escapeHtml(config.apiKeyEnv || "")}"></label>
            </div>
            <div class="row">
              <label><span data-i18n="effort">\${t("effort")}</span><input name="\${provider.id}.effort" value="\${escapeHtml(config.effort || "")}"></label>
              <label><span data-i18n="outputFormat">\${t("outputFormat")}</span><input name="\${provider.id}.outputFormat" value="\${escapeHtml(config.outputFormat || "")}"></label>
            </div>
            <div class="row">
              <label><span data-i18n="approvalMode">\${t("approvalMode")}</span><input name="\${provider.id}.approvalMode" value="\${escapeHtml(config.approvalMode || "")}"></label>
              <label><span data-i18n="permissionMode">\${t("permissionMode")}</span><input name="\${provider.id}.permissionMode" value="\${escapeHtml(config.permissionMode || "")}"></label>
            </div>
            <div class="row">
              <label><span data-i18n="sandbox">\${t("sandbox")}</span><input name="\${provider.id}.sandbox" value="\${escapeHtml(config.sandbox || "")}"></label>
              <label><span data-i18n="fallbackModel">\${t("fallbackModel")}</span><input name="\${provider.id}.fallbackModel" value="\${escapeHtml(config.fallbackModel || "")}"></label>
            </div>
            <label><span data-i18n="extraArgs">\${t("extraArgs")}</span><input name="\${provider.id}.extraArgs" value="\${escapeHtml(config.extraArgs || "")}"></label>
            <code>\${escapeHtml(commands.interactive || "")}</code>
            <code>\${escapeHtml(commands.headless || "")}</code>
          </div>
        \`;
      }).join("");
      document.querySelector("#ai-summary").textContent = JSON.stringify({
        manifest: ai.manifestReady ? "ready" : "missing",
        settings: ai.settingsReady ? "ready" : "missing",
        defaultProvider: modelSettings.defaultProvider,
        providers: providers.filter((provider) => provider.enabled).map((provider) => provider.id),
        models: Object.fromEntries(providers.map((provider) => [provider.id, modelSettings.providers?.[provider.id]?.model || ""])),
        enabled: Object.fromEntries(providers.map((provider) => [provider.id, Boolean(modelSettings.providers?.[provider.id]?.enabled)])),
        endpoints: Object.fromEntries(providers.map((provider) => [provider.id, modelSettings.providers?.[provider.id]?.endpoint || ""])),
        docs: Object.fromEntries(providers.map((provider) => [provider.id, modelSettings.providers?.[provider.id]?.docsUrl || ""])),
        commands: modelSettings.commands || {},
        validation: ai.validationCommands || [],
        required: ai.requiredCommands || [],
        runtime: {
          profile: runtimeSettings.profile,
          locale: runtimeSettings.locale,
          temperature: runtimeSettings.response?.temperature,
          maxInputTokens: runtimeSettings.context?.maxInputTokens,
          maxOutputTokens: runtimeSettings.response?.maxOutputTokens,
          allowNetwork: runtimeSettings.tools?.allowNetwork,
          preferLocal: runtimeSettings.cost?.preferLocalWhenAvailable,
          minAigateScore: runtimeSettings.quality?.minAigateScore
        }
      }, null, 2);
      fillRuntimeControls(runtimeSettings);
    }

    function aiPayloadFromForm() {
      const formData = new FormData(aiModelForm);
      const providers = {};
      const runtimeSettings = JSON.parse(document.querySelector("#ai-runtime-json").value || "{}");
      for (const card of document.querySelectorAll(".model-card")) {
        const provider = card.dataset.provider;
        providers[provider] = {
          enabled: Boolean(card.querySelector(\`input[name="\${provider}.enabled"]\`)?.checked)
        };
      }
      for (const input of document.querySelectorAll('[name^="runtime."]')) {
        const path = input.name.replace(/^runtime\./, "");
        setPathValue(runtimeSettings, path, input.type === "checkbox" ? Boolean(input.checked) : input.value);
      }
      for (const [key, value] of formData.entries()) {
        if (key === "defaultProvider" || key === "runtimeJson" || key.startsWith("runtime.")) continue;
        const [provider, field] = key.split(".");
        providers[provider] ||= {};
        if (field === "enabled") continue;
        providers[provider][field] = value;
      }
      return {
        defaultProvider: formData.get("defaultProvider"),
        providers,
        runtimeSettings
      };
    }

    function renderToolchain(data) {
      const tools = data.tools || {};
      document.querySelector("#toolchain-list").innerHTML = Object.entries(tools).map(([name, tool]) => \`
        <div class="line-item">
          <strong>\${escapeHtml(name)}</strong>
          <span>\${escapeHtml(tool.version || tool.path || "missing")}</span>
          <span class="pill \${tool.installed ? "ok" : "warn"}">\${tool.installed ? "Ready" : "Missing"}</span>
        </div>
      \`).join("");
    }

    function renderRoutes(discovery) {
      const routes = discovery?.routes || [];
      document.querySelector("#route-table").innerHTML = routes.length ? routes.slice(0, 40).map((route) => \`
        <tr><td>\${escapeHtml(route.status)}</td><td>\${escapeHtml(route.path || route.url)}</td><td>\${escapeHtml(route.depth ?? 0)}</td><td>\${escapeHtml(route.source || "")}</td></tr>
      \`).join("") : '<tr><td colspan="4" class="muted">No routes</td></tr>';
    }

    function renderState(data) {
      currentState = data;
      const scope = data.scope || {};
      const scan = data.latestScan || {};
      const discovery = scan.discovery || {};
      const targetAdvisory = data.targetAdvisory || {};
      document.querySelector("#subtitle").textContent = [scope.project || "privit", scope.environment || "local", scope.targets?.frontend?.base_url || ""].filter(Boolean).join(" / ");
      document.querySelector("#catalog-count").textContent = data.catalogCount || 0;
      document.querySelector("#finding-count").textContent = (data.findings || []).length;
      document.querySelector("#route-count").textContent = discovery.routes?.length || 0;
      document.querySelector("#form-count").textContent = discovery.forms?.length || 0;
      document.querySelector("#auth-count").textContent = discovery.auth_surfaces?.length || 0;
      document.querySelector("#latest-summary").textContent = JSON.stringify({
        scan_id: scan.scan_id || "not run",
        target: scan.target || "frontend",
        mode: scan.mode || "passive",
        selected_checks: scan.selected_check_count || 0,
        executed_checks: scan.executed_check_count || 0,
        findings: (data.findings || []).length,
        discovery: {
          routes: discovery.routes?.length || 0,
          forms: discovery.forms?.length || 0,
          auth_surfaces: discovery.auth_surfaces?.length || 0,
          blocked_urls: discovery.blocked_urls?.length || 0
        },
        target_advisory: {
          status: targetAdvisory.status || "not run",
          checked: targetAdvisory.summary?.targets || 0,
          warnings: targetAdvisory.summary?.warnings || 0
        }
      }, null, 2);
      document.querySelector("#repo-summary").textContent = JSON.stringify({
        engine_repo: data.repoRoles?.engine,
        workspace_repo: data.repoRoles?.workspace,
        current_remote: data.git?.remote,
        current_branch: data.git?.branch,
        changed_files: data.git?.changedFiles
      }, null, 2);
      fillForms(scope);
      renderAi(data.ai || {});
      renderToolchain(data);
      renderRoutes(discovery);
      language = localStorage.getItem("aegis.language") || data.webSettings?.language || language;
      applyI18n();
    }

    async function refresh() {
      const res = await fetch(stateUrl);
      renderState(await res.json());
    }

    async function run(action) {
      setStatus(t("running") + " " + action, "warn");
      const res = await fetch("/api/action", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ action })
      });
      const data = await res.json();
      document.querySelector("#log-output").textContent = "$ " + (data.command || action) + "\\n\\n" + (data.stdout || "") + (data.stderr ? "\\n[stderr]\\n" + data.stderr : "");
      setStatus(data.ok ? t("passed") : t("failed"), data.ok ? "ok" : "danger");
      await refresh();
      if (["report", "start", "scan", "map"].includes(action)) document.querySelector("#report-frame").src = "/report?ts=" + Date.now();
    }

    async function saveScope() {
      await fetch("/api/scope", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(payloadFromForms())
      });
      setStatus(t("saved"), "ok");
      await refresh();
    }

    document.querySelectorAll("nav button").forEach((button) => button.addEventListener("click", () => view(button.dataset.view)));
    document.querySelectorAll("[data-action]").forEach((button) => button.addEventListener("click", () => run(button.dataset.action)));
    scopeForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      await saveScope();
    });
    discoveryForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      await saveScope();
    });
    aiModelForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      try {
        await fetch("/api/ai-settings", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(aiPayloadFromForm())
        });
        setStatus(t("saved"), "ok");
        await refresh();
      } catch (error) {
        setStatus(error.message, "danger");
      }
    });
    languageSelect.addEventListener("change", async () => {
      language = languageSelect.value;
      localStorage.setItem("aegis.language", language);
      applyI18n();
      await fetch("/api/settings", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ language })
      });
    });

    applyI18n();
    refresh();
  </script>
</body>
</html>`;
}

async function handle(req, res) {
  const url = new URL(req.url, `http://${req.headers.host}`);
  try {
    if (req.method === "GET" && url.pathname === "/") return send(res, 200, page(), "text/html; charset=utf-8");
    if (req.method === "GET" && url.pathname === "/api/state") return json(res, 200, await state());
    if (req.method === "POST" && url.pathname === "/api/scope") return json(res, 200, await saveScope(await readRequest(req)));
    if (req.method === "POST" && url.pathname === "/api/settings") return json(res, 200, await saveSettings(await readRequest(req)));
    if (req.method === "POST" && url.pathname === "/api/ai-settings") return json(res, 200, await saveAiSettings(await readRequest(req)));
    if (req.method === "POST" && url.pathname === "/api/action") {
      const body = await readRequest(req);
      return json(res, 200, await runAction(body.action));
    }
    if (req.method === "GET" && url.pathname === "/report") {
      const file = resolve(cwd, ".aegis/reports/aegis-report.html");
      if (!existsSync(file)) return send(res, 404, "<h1>Report not generated</h1>", "text/html; charset=utf-8");
      return send(res, 200, await readFile(file, "utf8"), contentTypes[extname(file)] || "text/plain; charset=utf-8");
    }
    return json(res, 404, { error: "not_found" });
  } catch (error) {
    return json(res, 500, { error: error.message });
  }
}

createServer(handle).listen(port, host, () => {
  console.log(`Aegis web console: http://${host}:${port}`);
});
