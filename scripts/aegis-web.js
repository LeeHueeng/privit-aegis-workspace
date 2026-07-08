import { createServer } from "node:http";
import { readFile, writeFile } from "node:fs/promises";
import { existsSync, readFileSync } from "node:fs";
import { spawn, spawnSync } from "node:child_process";
import { extname, resolve } from "node:path";

const cwd = process.cwd();
const port = Number(process.env.AEGIS_WEB_PORT || process.env.PORT || 4317);
const host = process.env.AEGIS_WEB_HOST || "127.0.0.1";

const actions = {
  catalog: ["aegis", ["catalog", "generate"]],
  docs: ["aegis", ["docs", "generate", "--lang", "all"]],
  verify: ["aegis", ["scope", "verify", "--mode", "passive"]],
  plan: ["aegis", ["plan", "--mode", "passive", "--target", "frontend", "--limit", "25"]],
  scan: ["aegis", ["run", "--target", "frontend", "--mode", "passive", "--dry-run"]],
  report: ["aegis", ["report", "--format", "html"]],
  gate: ["aigate", ["test", "--language", "ko"]],
  ai: ["npm", ["run", "ai:integrate"]],
  aiDoctor: ["npm", ["run", "ai:doctor"]],
  aiReport: ["npm", ["run", "ai:report"]],
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

function send(res, status, body, type = "application/json; charset=utf-8") {
  res.writeHead(status, {
    "content-type": type,
    "cache-control": "no-store"
  });
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

function buildAiState(integrations, settings) {
  const configured = new Set([...(integrations?.providers || []), ...(settings?.aiProviders || [])]);
  const providers = [
    { id: "codex", label: "Codex", command: "codex", rootFile: "AGENTS.md" },
    { id: "gemini", label: "Gemini", command: "gemini", rootFile: "GEMINI.md" },
    { id: "claude", label: "Claude", command: "claude", rootFile: "CLAUDE.md" }
  ].map((provider) => {
    const sidecarFile = `.aigate/integrations/${provider.id}.md`;
    const enabled = configured.has(provider.id);
    const rootReady = existsSync(resolve(cwd, provider.rootFile));
    const sidecarReady = existsSync(resolve(cwd, sidecarFile));
    const cli = commandInfo(provider.command);
    return {
      ...provider,
      enabled,
      sidecarFile,
      rootReady,
      sidecarReady,
      commandReady: cli.installed,
      commandPath: cli.path,
      version: cli.version,
      filesReady: enabled && rootReady && sidecarReady,
      ready: enabled && rootReady && sidecarReady && cli.installed
    };
  });

  return {
    providers,
    readyCount: providers.filter((provider) => provider.ready).length,
    totalCount: providers.length,
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
  const integrations = await readJsonFile(".aigate/integrations.json", null);
  const aiSettings = await readJsonFile(".aigate/settings.json", null);
  const reportPath = resolve(cwd, ".aegis/reports/aegis-report.html");
  return {
    scope,
    latestScan,
    findings,
    ai: buildAiState(integrations, aiSettings),
    catalogCount: countCatalogLines(),
    reportExists: existsSync(reportPath),
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
  scope.targets.frontend.allowed_paths = payload.allowedPaths?.split(",").map((item) => item.trim()).filter(Boolean) || scope.targets.frontend.allowed_paths || ["/*"];
  scope.targets.frontend.denied_paths = payload.deniedPaths?.split(",").map((item) => item.trim()).filter(Boolean) || scope.targets.frontend.denied_paths || ["/payments/live/*", "/admin/delete/*"];
  scope.targets.backend_api ||= {};
  scope.targets.backend_api.enabled = Boolean(payload.backendEnabled);
  scope.targets.backend_api.base_url = backendUrl;
  scope.targets.backend_api.allowed_hosts = [...new Set([hostFromUrl(backendUrl), ...(scope.targets.backend_api.allowed_hosts || [])])];
  scope.targets.backend_api.allowed_paths ||= ["/*"];
  scope.targets.ci_cd ||= {};
  scope.targets.ci_cd.enabled = payload.ciEnabled !== false;
  scope.authorization ||= {};
  scope.authorization.owner = payload.owner || scope.authorization.owner || "security@example.com";
  scope.safety ||= {};
  scope.safety.max_rps = Number(payload.maxRps || scope.safety.max_rps || 2);
  scope.safety.max_concurrency = Number(payload.maxConcurrency || scope.safety.max_concurrency || 3);

  await writeFile(resolve(cwd, "aegis.scope.json"), `${JSON.stringify(scope, null, 2)}\n`, "utf8");
  return scope;
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
      resolveRun({ ok: code === 0, code, stdout, stderr, action });
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
    }
    * { box-sizing: border-box; }
    body { margin: 0; background: var(--bg); color: var(--text); font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
    button, input, select { font: inherit; }
    .shell { display: grid; grid-template-columns: 260px minmax(0, 1fr); min-height: 100vh; }
    aside { background: #111827; color: #e5edf7; padding: 22px 18px; }
    .brand { display: flex; align-items: center; gap: 12px; margin-bottom: 24px; }
    .brand svg { width: 42px; height: 42px; flex: 0 0 auto; }
    .brand strong { display: block; font-size: 18px; }
    .brand span { color: #9fb0c7; font-size: 12px; }
    nav { display: grid; gap: 8px; }
    nav button { width: 100%; border: 0; background: transparent; color: #cbd5e1; text-align: left; padding: 10px 12px; border-radius: 7px; cursor: pointer; }
    nav button.active, nav button:hover { background: #253044; color: #ffffff; }
    main { padding: 22px; min-width: 0; }
    header { display: flex; justify-content: space-between; align-items: flex-end; gap: 16px; margin-bottom: 16px; }
    h1 { margin: 0; font-size: 24px; line-height: 1.2; letter-spacing: 0; }
    h2 { margin: 0 0 12px; font-size: 17px; letter-spacing: 0; }
    p { margin: 0; }
    .muted { color: var(--muted); font-size: 13px; }
    .status { border: 1px solid var(--line); background: var(--panel); border-radius: 999px; padding: 7px 12px; font-weight: 700; font-size: 13px; }
    .grid { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 12px; margin-bottom: 14px; }
    .card, .panel { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; box-shadow: 0 1px 2px rgba(15, 23, 42, 0.04); }
    .card { padding: 14px; }
    .card span { color: var(--muted); font-size: 12px; text-transform: uppercase; }
    .card strong { display: block; font-size: 26px; margin-top: 4px; }
    .layout { display: grid; grid-template-columns: minmax(340px, 440px) minmax(0, 1fr); gap: 14px; align-items: start; }
    .panel { padding: 16px; margin-bottom: 14px; }
    form { display: grid; gap: 12px; }
    label { display: grid; gap: 5px; font-weight: 700; font-size: 13px; }
    input, select { width: 100%; border: 1px solid var(--line); border-radius: 7px; padding: 10px 11px; color: var(--text); background: #ffffff; }
    .row { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
    .switch { display: flex; align-items: center; gap: 8px; font-weight: 700; }
    .switch input { width: auto; }
    .actions { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 9px; }
    .actions button, .primary { border: 0; border-radius: 7px; padding: 10px 11px; cursor: pointer; background: #e8eef8; color: var(--ink); font-weight: 800; }
    .primary { background: var(--accent); color: #ffffff; }
    .actions button:hover, .primary:hover { filter: brightness(0.97); }
    iframe { width: 100%; height: 620px; border: 1px solid var(--line); border-radius: 8px; background: #ffffff; }
    pre { min-height: 190px; max-height: 340px; overflow: auto; background: #0f172a; color: #dbeafe; border-radius: 8px; padding: 12px; white-space: pre-wrap; font-size: 13px; }
    .ai-list { display: grid; gap: 10px; }
    .ai-provider { display: grid; grid-template-columns: 92px minmax(0, 1fr) auto; gap: 10px; align-items: center; border: 1px solid var(--line); border-radius: 8px; padding: 10px; }
    .ai-provider strong { font-size: 14px; }
    .ai-provider span { color: var(--muted); font-size: 12px; overflow-wrap: anywhere; }
    .pill { border-radius: 999px; padding: 4px 8px; font-size: 12px; font-weight: 800; background: #eef2f7; }
    .pill.ok { background: #e5f7ef; color: var(--ok); }
    .pill.warn { background: #fff7e6; color: var(--warn); }
    .hidden { display: none; }
    .ok { color: var(--ok); }
    .warn { color: var(--warn); }
    .danger { color: var(--danger); }
    @media (max-width: 980px) {
      .shell, .layout, .grid { grid-template-columns: 1fr; }
      aside { position: static; }
      .actions { grid-template-columns: 1fr 1fr; }
    }
    @media (max-width: 560px) {
      main { padding: 14px; }
      header { align-items: flex-start; flex-direction: column; }
      .row, .actions { grid-template-columns: 1fr; }
      iframe { height: 520px; }
    }
  </style>
</head>
<body>
  <div class="shell">
    <aside>
      <div class="brand">
        <svg viewBox="0 0 64 64" role="img" aria-label="Aegis mark">
          <rect x="8" y="8" width="48" height="48" rx="12" fill="#2563eb"/>
          <path d="M32 16l16 7v10c0 10-6.5 18-16 21-9.5-3-16-11-16-21V23l16-7z" fill="#eff6ff"/>
          <path d="M32 22l10 4v7c0 6-3.8 11.5-10 14-6.2-2.5-10-8-10-14v-7l10-4z" fill="#15805f"/>
        </svg>
        <div><strong>Aegis Console</strong><span>Privit local security</span></div>
      </div>
      <nav>
        <button class="active" data-view="dashboard">Dashboard</button>
        <button data-view="settings">Settings</button>
        <button data-view="ai">AI</button>
        <button data-view="report">Report</button>
        <button data-view="logs">Logs</button>
      </nav>
    </aside>
    <main>
      <header>
        <div>
          <h1>Privit Aegis Console</h1>
          <p class="muted" id="subtitle">Loading</p>
        </div>
        <div class="status" id="status">Ready</div>
      </header>

      <section id="dashboard-view">
        <div class="grid">
          <div class="card"><span>Catalog</span><strong id="catalog-count">0</strong></div>
          <div class="card"><span>Findings</span><strong id="finding-count">0</strong></div>
          <div class="card"><span>Checks</span><strong id="check-count">0</strong></div>
          <div class="card"><span>Mode</span><strong id="scan-mode">-</strong></div>
          <div class="card"><span>AI</span><strong id="ai-count">0/3</strong></div>
        </div>
        <div class="layout">
          <div class="panel">
            <h2>Actions</h2>
            <div class="actions">
              <button data-action="catalog">Catalog</button>
              <button data-action="docs">Docs</button>
              <button data-action="verify">Verify</button>
              <button data-action="plan">Plan</button>
              <button data-action="scan">Scan</button>
              <button data-action="report">Report</button>
              <button data-action="gate">AIGate</button>
              <button data-action="ai">AI Setup</button>
              <button data-action="aiDoctor">AI Doctor</button>
              <button data-action="aiReport">AI Report</button>
              <button class="primary" data-action="start">Start All</button>
            </div>
          </div>
          <div class="panel">
            <h2>Latest Run</h2>
            <pre id="latest-summary">No run yet.</pre>
          </div>
        </div>
      </section>

      <section id="settings-view" class="hidden">
        <div class="panel">
          <h2>Scope Settings</h2>
          <form id="scope-form">
            <div class="row">
              <label>Project <input name="project"></label>
              <label>Environment
                <select name="environment">
                  <option value="local">local</option>
                  <option value="development">development</option>
                  <option value="staging">staging</option>
                  <option value="production_passive_only">production_passive_only</option>
                </select>
              </label>
            </div>
            <label>Frontend URL <input name="frontendUrl"></label>
            <label>Backend API URL <input name="backendUrl"></label>
            <label>Owner Email <input name="owner"></label>
            <div class="row">
              <label>Allowed Paths <input name="allowedPaths"></label>
              <label>Denied Paths <input name="deniedPaths"></label>
            </div>
            <div class="row">
              <label>Max RPS <input name="maxRps" type="number" min="1"></label>
              <label>Max Concurrency <input name="maxConcurrency" type="number" min="1"></label>
            </div>
            <div class="row">
              <label class="switch"><input name="backendEnabled" type="checkbox"> Backend API</label>
              <label class="switch"><input name="ciEnabled" type="checkbox"> CI/CD</label>
            </div>
            <button class="primary" type="submit">Save Scope</button>
          </form>
        </div>
      </section>

      <section id="ai-view" class="hidden">
        <div class="layout">
          <div class="panel">
            <h2>Providers</h2>
            <div id="ai-providers" class="ai-list"></div>
          </div>
          <div class="panel">
            <h2>AI Gate</h2>
            <pre id="ai-summary">Loading</pre>
          </div>
        </div>
      </section>

      <section id="report-view" class="hidden">
        <iframe id="report-frame" title="Aegis report"></iframe>
      </section>

      <section id="logs-view" class="hidden">
        <div class="panel">
          <h2>Command Output</h2>
          <pre id="log-output">No command output yet.</pre>
        </div>
      </section>
    </main>
  </div>

  <script>
    const stateUrl = "/api/state";
    const form = document.querySelector("#scope-form");
    let currentState = null;

    function escapeHtml(value) {
      return String(value ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
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

    function fillForm(scope) {
      if (!scope) return;
      form.project.value = scope.project || "";
      form.environment.value = scope.environment || "local";
      form.frontendUrl.value = scope.targets?.frontend?.base_url || "";
      form.backendUrl.value = scope.targets?.backend_api?.base_url || "";
      form.owner.value = scope.authorization?.owner || "";
      form.allowedPaths.value = (scope.targets?.frontend?.allowed_paths || ["/*"]).join(", ");
      form.deniedPaths.value = (scope.targets?.frontend?.denied_paths || []).join(", ");
      form.maxRps.value = scope.safety?.max_rps || 2;
      form.maxConcurrency.value = scope.safety?.max_concurrency || 3;
      form.backendEnabled.checked = Boolean(scope.targets?.backend_api?.enabled);
      form.ciEnabled.checked = Boolean(scope.targets?.ci_cd?.enabled);
    }

    function renderAi(ai) {
      const providers = ai.providers || [];
      document.querySelector("#ai-count").textContent = (ai.readyCount || 0) + "/" + (ai.totalCount || 3);
      document.querySelector("#ai-providers").innerHTML = providers.map((provider) => \`
        <div class="ai-provider">
          <strong>\${escapeHtml(provider.label)}</strong>
          <span>\${escapeHtml(provider.rootFile)} / \${escapeHtml(provider.sidecarFile)} / \${escapeHtml(provider.command)} \${escapeHtml(provider.version || "missing")}</span>
          <span class="pill \${provider.ready ? "ok" : "warn"}">\${provider.ready ? "Ready" : "Check"}</span>
        </div>
      \`).join("");
      document.querySelector("#ai-summary").textContent = JSON.stringify({
        manifest: ai.manifestReady ? "ready" : "missing",
        settings: ai.settingsReady ? "ready" : "missing",
        providers: providers.filter((provider) => provider.enabled).map((provider) => provider.id),
        cli: providers.reduce((acc, provider) => ({ ...acc, [provider.id]: provider.commandReady ? provider.version : "missing" }), {}),
        validation: ai.validationCommands || [],
        required: ai.requiredCommands || []
      }, null, 2);
    }

    function renderState(data) {
      currentState = data;
      const scope = data.scope || {};
      const scan = data.latestScan || {};
      document.querySelector("#subtitle").textContent = [scope.project || "privit", scope.environment || "local", scope.targets?.frontend?.base_url || ""].filter(Boolean).join(" / ");
      document.querySelector("#catalog-count").textContent = data.catalogCount || 0;
      document.querySelector("#finding-count").textContent = (data.findings || []).length;
      document.querySelector("#check-count").textContent = scan.selected_check_count || 0;
      document.querySelector("#scan-mode").textContent = scan.mode || "passive";
      document.querySelector("#latest-summary").textContent = JSON.stringify({
        scan_id: scan.scan_id || "not run",
        target: scan.target || "frontend",
        selected_checks: scan.selected_check_count || 0,
        executed_checks: scan.executed_check_count || 0,
        findings: (data.findings || []).length,
        ai: (data.ai?.providers || []).filter((provider) => provider.ready).map((provider) => provider.id)
      }, null, 2);
      fillForm(scope);
      renderAi(data.ai || {});
      setStatus(data.reportExists ? "Report ready" : "Ready", data.reportExists ? "ok" : "");
    }

    async function refresh() {
      const res = await fetch(stateUrl);
      renderState(await res.json());
    }

    async function run(action) {
      setStatus("Running " + action, "warn");
      const res = await fetch("/api/action", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ action })
      });
      const data = await res.json();
      document.querySelector("#log-output").textContent = "$ " + action + "\\n\\n" + (data.stdout || "") + (data.stderr ? "\\n[stderr]\\n" + data.stderr : "");
      setStatus(data.ok ? "Passed" : "Failed", data.ok ? "ok" : "danger");
      await refresh();
      if (action === "report" || action === "start") document.querySelector("#report-frame").src = "/report?ts=" + Date.now();
    }

    document.querySelectorAll("nav button").forEach((button) => button.addEventListener("click", () => view(button.dataset.view)));
    document.querySelectorAll("[data-action]").forEach((button) => button.addEventListener("click", () => run(button.dataset.action)));
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const payload = Object.fromEntries(new FormData(form).entries());
      payload.backendEnabled = form.backendEnabled.checked;
      payload.ciEnabled = form.ciEnabled.checked;
      await fetch("/api/scope", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(payload)
      });
      setStatus("Saved", "ok");
      await refresh();
    });

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
