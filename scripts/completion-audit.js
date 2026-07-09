import { readFileSync, existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";

const cwd = process.cwd();

function readJson(file, fallback) {
  try {
    return JSON.parse(readFileSync(resolve(cwd, file), "utf8"));
  } catch {
    return fallback;
  }
}

function readText(file) {
  try {
    return readFileSync(resolve(cwd, file), "utf8");
  } catch {
    return "";
  }
}

function runJson(command, args) {
  const result = spawnSync(command, args, {
    cwd,
    encoding: "utf8",
    timeout: 20000
  });
  if (result.status !== 0) {
    return { ok: false, error: (result.stderr || result.stdout || "").trim() };
  }
  try {
    return { ok: true, value: JSON.parse(result.stdout.match(/\{[\s\S]*\}$/)?.[0] || result.stdout) };
  } catch (error) {
    return { ok: false, error: error.message };
  }
}

function add(checks, area, id, ok, detail, evidence = {}, external = false) {
  checks.push({
    area,
    id,
    status: ok ? "pass" : external ? "blocked_external" : "todo",
    ok,
    detail,
    evidence
  });
}

function hasScripts(packageJson, names) {
  const scripts = packageJson.scripts || {};
  return names.every((name) => Boolean(scripts[name]));
}

function failedFindingIds(report) {
  return (report?.findings || [])
    .filter((finding) => !finding.passed)
    .map((finding) => finding.id);
}

function main() {
  const packageJson = readJson("package.json", {});
  const policy = readJson("aegis.policy.json", {});
  const aiSettings = readJson(".aigate/settings.json", {});
  const targetAdvisory = readJson(".aegis/reports/frontend-advisory.json", null);
  const penetrationReport = readJson(".aegis/reports/penetration-report.json", null);
  const hardening = readJson(".aegis/reports/security-hardening.json", null);
  const webSource = readText("scripts/aegis-web.js");
  const webSettings = readJson(".aegis/web-settings.json", { language: "ko" });
  const reportHtml = readText(".aegis/reports/aegis-report.html");
  const checks = [];

  add(
    checks,
    "cli",
    "core_commands",
    hasScripts(packageJson, [
      "web",
      "security:map",
      "security:target",
      "security:penetration",
      "security:hardening",
      "github:ready",
      "ai:model:set",
      "ci:security"
    ]),
    "CLI exposes web, crawl, target advisory, hardening, GitHub readiness, AI model, and CI commands."
  );

  const locales = policy.localization?.supported_locales || [];
  add(
    checks,
    "i18n",
    "policy_locales",
    ["ko-KR", "ja-JP", "zh-CN", "en-US"].every((locale) => locales.includes(locale)),
    "Security policy supports Korean, Japanese, Chinese, and English.",
    { locales }
  );
  add(
    checks,
    "i18n",
    "web_locales",
    ["value=\"ko\"", "value=\"en\"", "value=\"ja\"", "value=\"zh\""].every((needle) => webSource.includes(needle)),
    "Web console exposes Korean, English, Japanese, and Chinese selectors."
  );

  const providerConfig = aiSettings.aiModelSettings?.providers || {};
  add(
    checks,
    "ai",
    "providers",
    ["codex", "gemini", "claude", "local", "api"].every((provider) => Boolean(providerConfig[provider])),
    "AI settings include CLI providers plus local AI and direct API providers.",
    { providers: Object.keys(providerConfig) }
  );
  add(
    checks,
    "ai",
    "runtime_controls",
    Boolean(aiSettings.aiRuntimeSettings?.security?.promptInjectionGuard && aiSettings.aiRuntimeSettings?.security?.redactSecrets),
    "AI runtime settings include prompt-injection guard and secret redaction."
  );

  add(
    checks,
    "web",
    "actions",
    ["targetAdvisory", "penetrationReport", "aiProviderCheck", "gitStatus"].every((needle) => webSource.includes(needle)),
    "Web console includes target advisory, penetration report, AI provider check, and git status actions."
  );
  add(
    checks,
    "web",
    "aigate_separation",
    [
      'data-action="gate"',
      'data-action="gateReady"',
      'data-action="githubReady"',
      'data-action="ciSecurity"',
      'data-action="completionAudit"',
      '["aigate"',
      "github-readiness.js",
      "ci:security"
    ].every((needle) => !webSource.includes(needle)),
    "Web console leaves AIGate, GitHub readiness, and CI security checks to git/CI workflows."
  );

  add(
    checks,
    "security",
    "target_advisory",
    ["PASS", "WARN"].includes(targetAdvisory?.status) && Number(targetAdvisory?.summary?.errors || 0) === 0,
    "Live target advisory runs and has no blocking errors.",
    { status: targetAdvisory?.status, summary: targetAdvisory?.summary }
  );
  add(
    checks,
    "security",
    "passive_probes",
    Number(targetAdvisory?.summary?.probes || 0) > 0,
    "Target advisory includes passive probes plus DNS/CNAME takeover fingerprints, Host header reflection, reverse tabnabbing, CORS, CSP quality, cookie scope, framework fingerprinting, redirect/HPP parameter inventory, client bundle leakage, DOM XSS, Web Messaging, resource manipulation, client template injection, prototype pollution, browser storage, WebSocket, JWT, XSSI JSON, cloud storage references, backup/extension exposure, directory listings, source maps, API docs, admin/debug surfaces, metafiles, error disclosure, HTTP methods, header misconfiguration, and TLS posture.",
    { probes: targetAdvisory?.summary?.probes, contentReviews: targetAdvisory?.summary?.contentReviews }
  );
  const hardeningFailedIds = failedFindingIds(hardening);
  const hardeningBlockedByScope = hardening?.status === "FAIL" && hardeningFailedIds.every((id) => id === "scope.local.loopback");
  add(
    checks,
    "security",
    "hardening",
    ["PASS", "WARN"].includes(hardening?.status),
    hardeningBlockedByScope
      ? "Hardening is blocked by the current local scope pointing at external hosts; confirm authorization or switch back to loopback."
      : "OWASP/GitHub hardening report is generated and has no blocking errors.",
    { status: hardening?.status, summary: hardening?.summary, failed: hardeningFailedIds },
    hardeningBlockedByScope
  );
  add(
    checks,
    "security",
    "reports",
    existsSync(resolve(cwd, ".aegis/reports/aegis-report.html")) && existsSync(resolve(cwd, ".aegis/reports/frontend-advisory.json")),
    "HTML and frontend advisory reports exist."
  );
  add(
    checks,
    "security",
    "penetration_report",
    existsSync(resolve(cwd, ".aegis/reports/penetration-report.html")) && Boolean(penetrationReport?.testMatrix?.length),
    "Penetration report exists and documents executed checks with pass criteria.",
    { status: penetrationReport?.status, summary: penetrationReport?.summary }
  );
  add(
    checks,
    "security",
    "localized_report",
    reportHtml.includes('data-aegis-localized="true"') && reportHtml.includes(`lang="${webSettings.language || "ko"}"`),
    "HTML report is localized with the current web-console language.",
    { language: webSettings.language || "ko" }
  );

  const githubReady = runJson("node", ["./scripts/github-readiness.js", "--format", "json"]);
  const githubValue = githubReady.value || {};
  const githubCodeOk = Boolean(githubValue.checks?.ghAuth?.ok && githubValue.checks?.aigate?.ok);
  add(
    checks,
    "github",
    "local_readiness",
    githubCodeOk,
    "Local GitHub readiness and AIGate checks can run.",
    { status: githubValue.status, score: githubValue.checks?.aigate?.score }
  );
  add(
    checks,
    "github",
    "ci_secret",
    Boolean(githubValue.checks?.aegisCliToken?.ok),
    "GitHub repository secret AEGIS_CLI_SSH_KEY or AEGIS_CLI_TOKEN is configured.",
    { detail: githubValue.checks?.aegisCliToken?.detail },
    true
  );
  add(
    checks,
    "github",
    "server_enforcement",
    Boolean(githubValue.checks?.branchProtection?.ok),
    "GitHub branch protection or ruleset requires the AIGate check.",
    { detail: githubValue.checks?.branchProtection?.detail },
    true
  );

  const todos = checks.filter((check) => check.status === "todo");
  const external = checks.filter((check) => check.status === "blocked_external");
  const report = {
    command: "completion-audit",
    status: todos.length ? "TODO" : external.length ? "BLOCKED_EXTERNAL" : "PASS",
    generatedAt: new Date().toISOString(),
    summary: {
      total: checks.length,
      passed: checks.filter((check) => check.ok).length,
      todo: todos.length,
      blockedExternal: external.length
    },
    checks,
    nextSteps: [
      ...todos.map((check) => check.detail),
      ...external.map((check) => check.detail)
    ]
  };

  const json = process.argv.includes("--json") || process.argv.includes("--format") && process.argv[process.argv.indexOf("--format") + 1] === "json";
  if (json) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    console.log(`Completion audit: ${report.status}`);
    console.log(`Passed: ${report.summary.passed}/${report.summary.total}`);
    console.log(`TODO: ${report.summary.todo}`);
    console.log(`External blockers: ${report.summary.blockedExternal}`);
    for (const check of checks.filter((item) => !item.ok)) {
      console.log(`- [${check.status}] ${check.area}.${check.id}: ${check.detail}`);
    }
  }

  if (todos.length) {
    process.exit(1);
  }
}

main();
