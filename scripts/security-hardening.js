import { mkdir, readFile, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";

const cwd = process.cwd();
const reportPath = resolve(cwd, ".aegis/reports/security-hardening.json");

async function readJson(file, fallback) {
  try {
    return JSON.parse(await readFile(resolve(cwd, file), "utf8"));
  } catch {
    return fallback;
  }
}

async function readText(file, fallback = "") {
  try {
    return await readFile(resolve(cwd, file), "utf8");
  } catch {
    return fallback;
  }
}

function hasFullShaActionReference(value) {
  return /^[^@\s]+@[a-f0-9]{40}$/i.test(value.trim());
}

function addFinding(findings, level, id, title, passed, detail, evidence = {}) {
  findings.push({
    level,
    id,
    title,
    status: passed ? "pass" : level === "warning" ? "warn" : "fail",
    passed,
    detail,
    evidence
  });
}

function inspectScope(findings, baseline, scope) {
  const safety = scope?.safety || {};
  for (const flag of baseline.scope?.requiredFalseSafetyFlags || []) {
    addFinding(
      findings,
      "error",
      `scope.${flag}`,
      `Scope safety flag ${flag} is disabled`,
      safety[flag] === false,
      `${flag} must stay false for this authorized passive workspace.`,
      { value: safety[flag] }
    );
  }

  const frontend = scope?.targets?.frontend || {};
  const discovery = frontend.discovery || {};
  const maxDepth = Number(discovery.max_depth ?? 0);
  const maxPages = Number(discovery.max_pages ?? 0);
  addFinding(
    findings,
    "error",
    "scope.discovery.depth",
    "Passive discovery depth is bounded",
    Number.isFinite(maxDepth) && maxDepth <= baseline.scope.maxPassiveDepth,
    `max_depth should be <= ${baseline.scope.maxPassiveDepth}.`,
    { value: discovery.max_depth }
  );
  addFinding(
    findings,
    "error",
    "scope.discovery.pages",
    "Passive discovery page count is bounded",
    Number.isFinite(maxPages) && maxPages <= baseline.scope.maxPassivePages,
    `max_pages should be <= ${baseline.scope.maxPassivePages}.`,
    { value: discovery.max_pages }
  );

  const baseUrl = String(frontend.base_url || "");
  const allowedHosts = frontend.allowed_hosts || [];
  const isLocal = scope?.environment === "local";
  const loopbackOnly = allowedHosts.every((host) => ["localhost", "127.0.0.1", "::1"].includes(host));
  addFinding(
    findings,
    "error",
    "scope.local.loopback",
    "Local scope stays on loopback hosts",
    !isLocal || (baseUrl.startsWith("http://localhost") || baseUrl.startsWith("http://127.0.0.1")) && loopbackOnly,
    "Local scans should not drift to external hosts unless scope is explicitly changed.",
    { baseUrl, allowedHosts }
  );
}

function inspectWebConsole(findings, baseline, source) {
  addFinding(
    findings,
    "error",
    "web.host.default",
    "Web console defaults to loopback",
    source.includes(`process.env.AEGIS_WEB_HOST || "${baseline.webConsole.requiredDefaultHost}"`),
    "The local console should bind to 127.0.0.1 by default.",
    { requiredDefaultHost: baseline.webConsole.requiredDefaultHost }
  );

  const lower = source.toLowerCase();
  for (const header of baseline.webConsole.requiredHeaders || []) {
    addFinding(
      findings,
      "error",
      `web.header.${header}`,
      `Web console sends ${header}`,
      lower.includes(`"${header}"`),
      "Local report pages should use browser security headers as defense in depth.",
      { header }
    );
  }
}

function inspectGithubActions(findings, baseline, workflow) {
  const lower = workflow.toLowerCase();
  addFinding(
    findings,
    "error",
    "github.no_pull_request_target",
    "Workflow avoids pull_request_target",
    !lower.includes("pull_request_target"),
    "pull_request_target exposes a larger trust boundary and is not needed here."
  );
  addFinding(
    findings,
    "error",
    "github.permissions.contents_read",
    "Workflow uses read-only contents permission",
    /permissions:\s*\n(?:\s+\w[\w-]*:\s*\w+\s*\n)*\s+contents:\s*read\b/i.test(workflow),
    "GITHUB_TOKEN should default to the minimum repository read permission."
  );
  addFinding(
    findings,
    "error",
    "github.timeout",
    "Workflow job has an explicit timeout",
    /\btimeout-minutes:\s*\d+\b/i.test(workflow),
    "Security jobs should have a bounded runtime."
  );
  addFinding(
    findings,
    "error",
    "github.checkout.persist_credentials",
    "Checkout does not persist credentials",
    /uses:\s*actions\/checkout@[\w.-]+\s*\n\s*with:\s*\n(?:\s+\S.*\n)*\s+persist-credentials:\s*false\b/i.test(workflow),
    "The checkout token should not remain in local git config after checkout."
  );

  const actionRefs = [...workflow.matchAll(/uses:\s*([^\s#]+)/g)].map((match) => match[1]);
  const tagPinned = actionRefs.filter((ref) => !hasFullShaActionReference(ref));
  addFinding(
    findings,
    "warning",
    "github.actions.sha_pinning",
    "Third-party actions are pinned to commit SHAs",
    tagPinned.length === 0,
    "Tag-pinned actions are easier to update, but commit SHA pinning gives stronger supply-chain integrity.",
    { tagPinned }
  );
}

function inspectLatestScan(findings, baseline, latestScan) {
  const discovery = latestScan?.discovery;
  if (!discovery) {
    addFinding(
      findings,
      "warning",
      "scan.discovery.missing",
      "Latest passive discovery is available",
      false,
      "Run npm run security:map before hardening review to include route and form evidence."
    );
    return;
  }

  const forms = discovery.forms || [];
  const authGetForms = forms.filter((form) => form.auth_like && String(form.method || "get").toLowerCase() === "get");
  addFinding(
    findings,
    "warning",
    "scan.auth_forms.post",
    "Authentication-like forms submit with POST",
    authGetForms.length === 0,
    "Authentication forms should not place credentials in URLs, browser history, proxies, or logs.",
    { count: authGetForms.length, pages: authGetForms.map((form) => form.page_url) }
  );

  const stateChangingForms = forms.filter((form) => !["get", "head", "options"].includes(String(form.method || "get").toLowerCase()));
  const withoutCsrf = stateChangingForms.filter((form) => {
    const controls = form.controls || [];
    return !controls.some((control) => /csrf|xsrf|token/i.test(`${control.name || ""} ${control.id || ""}`));
  });
  addFinding(
    findings,
    "warning",
    "scan.csrf.tokens",
    "State-changing forms expose an anti-CSRF token",
    withoutCsrf.length === 0,
    "State-changing cookie-authenticated form flows should include CSRF protection.",
    { count: withoutCsrf.length, pages: withoutCsrf.map((form) => form.page_url) }
  );

  const routeCount = discovery.routes?.length || 0;
  addFinding(
    findings,
    "info",
    "scan.discovery.inventory",
    "Passive discovery inventory captured",
    routeCount > 0,
    "Route, link, form, and auth-surface inventory is available for review.",
    {
      routes: routeCount,
      forms: forms.length,
      authSurfaces: discovery.auth_surfaces?.length || 0,
      blockedUrls: discovery.blocked_urls?.length || 0
    }
  );
}

function parseArgs(argv) {
  const flags = new Set(argv.slice(2));
  return {
    json: flags.has("--json") || argv.includes("--format") && argv[argv.indexOf("--format") + 1] === "json",
    strict: flags.has("--strict") || process.env.SECURITY_HARDENING_STRICT === "true"
  };
}

async function main() {
  const options = parseArgs(process.argv);
  const baseline = await readJson(".aigate/security-baseline.json", {});
  const scope = await readJson("aegis.scope.json", {});
  const latestScan = await readJson(".aegis/latest-scan.json", null);
  const webSource = await readText("scripts/aegis-web.js");
  const workflow = await readText(".github/workflows/ci.yml");
  const findings = [];

  inspectScope(findings, baseline, scope);
  inspectWebConsole(findings, baseline, webSource);
  inspectGithubActions(findings, baseline, workflow);
  inspectLatestScan(findings, baseline, latestScan);

  const errors = findings.filter((finding) => finding.level === "error" && !finding.passed);
  const warnings = findings.filter((finding) => finding.level === "warning" && !finding.passed);
  const report = {
    command: "security-hardening",
    status: errors.length || options.strict && warnings.length ? "FAIL" : warnings.length ? "WARN" : "PASS",
    generatedAt: new Date().toISOString(),
    profile: baseline.profile || "default",
    sources: baseline.sources || [],
    summary: {
      total: findings.length,
      passed: findings.filter((finding) => finding.passed).length,
      errors: errors.length,
      warnings: warnings.length,
      strict: options.strict
    },
    findings
  };

  await mkdir(dirname(reportPath), { recursive: true });
  await writeFile(reportPath, `${JSON.stringify(report, null, 2)}\n`, "utf8");

  if (options.json) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    console.log(`Security hardening: ${report.status}`);
    console.log(`Profile: ${report.profile}`);
    console.log(`Passed: ${report.summary.passed}/${report.summary.total}`);
    console.log(`Errors: ${report.summary.errors}`);
    console.log(`Warnings: ${report.summary.warnings}`);
    console.log(`Report: ${reportPath}`);
    for (const finding of findings.filter((item) => !item.passed)) {
      console.log(`- [${finding.level}] ${finding.id}: ${finding.detail}`);
    }
  }

  if (errors.length || options.strict && warnings.length) {
    process.exit(1);
  }
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
