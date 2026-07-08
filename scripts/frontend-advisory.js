import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";

const cwd = process.cwd();
const reportPath = resolve(cwd, ".aegis/reports/frontend-advisory.json");
const USER_AGENT = "Privit-Aegis-Frontend-Advisory/0.1";

async function readJson(file, fallback) {
  try {
    return JSON.parse(await readFile(resolve(cwd, file), "utf8"));
  } catch {
    return fallback;
  }
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

function isLoopback(hostname) {
  return ["localhost", "127.0.0.1", "::1"].includes(hostname);
}

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function globMatches(pathname, pattern) {
  if (!pattern || pattern === "/*") return true;
  const regex = new RegExp(`^${escapeRegex(pattern).replace(/\\\*/g, ".*")}$`);
  return regex.test(pathname);
}

function isAllowedUrl(url, scope) {
  const frontend = scope?.targets?.frontend || {};
  const allowedHosts = new Set(frontend.allowed_hosts || []);
  const allowedPaths = frontend.allowed_paths?.length ? frontend.allowed_paths : ["/*"];
  const deniedPaths = frontend.denied_paths || [];
  try {
    const parsed = new URL(url);
    const hostAllowed = allowedHosts.size === 0 || allowedHosts.has(parsed.hostname);
    const pathAllowed = allowedPaths.some((pattern) => globMatches(parsed.pathname, pattern));
    const pathDenied = deniedPaths.some((pattern) => globMatches(parsed.pathname, pattern));
    return hostAllowed && pathAllowed && !pathDenied;
  } catch {
    return false;
  }
}

function looksLikeAsset(url) {
  try {
    return /\.(?:avif|bmp|css|gif|ico|jpe?g|js|map|png|svg|webp|woff2?|ttf)(?:$|\?)/i.test(new URL(url).pathname);
  } catch {
    return false;
  }
}

function looksLikeHtmlRoute(route) {
  const contentType = String(route.content_type || "").toLowerCase();
  if (contentType.includes("text/html")) return true;
  if (looksLikeAsset(route.url)) return false;
  return Number(route.depth || 0) <= 1;
}

function authHints(scope) {
  return scope?.targets?.frontend?.discovery?.login_indicators || [
    "login",
    "signin",
    "sign-in",
    "auth",
    "session",
    "admin",
    "account"
  ];
}

function isAuthLikeUrl(url, scope, discovery) {
  const lower = url.toLowerCase();
  const formUrls = new Set(
    (discovery?.forms || [])
      .filter((form) => form.auth_like)
      .flatMap((form) => [form.page_url, form.action_url])
      .filter(Boolean)
  );
  if (formUrls.has(url)) return true;
  return authHints(scope).some((hint) => lower.includes(String(hint).toLowerCase()));
}

function unique(values) {
  return [...new Set(values.filter(Boolean))];
}

function buildTargets(scope, latestScan, baseline) {
  const discovery = latestScan?.discovery || {};
  const frontend = scope?.targets?.frontend || {};
  const maxPages = Number(baseline?.frontendAdvisory?.maxHeaderAuditPages || 20);
  const candidates = [
    frontend.base_url,
    ...(discovery.routes || []).filter(looksLikeHtmlRoute).map((route) => route.url),
    ...(discovery.forms || []).flatMap((form) => [form.page_url, form.action_url]),
    ...(discovery.auth_surfaces || []).map((surface) => surface.url)
  ];

  return unique(candidates)
    .filter((url) => isAllowedUrl(url, scope))
    .filter((url) => !looksLikeAsset(url))
    .slice(0, Math.max(1, maxPages));
}

function normalizeHeaders(rawHeaders) {
  const headers = {};
  for (const [name, value] of Object.entries(rawHeaders || {})) {
    headers[name.toLowerCase()] = Array.isArray(value) ? value.join(", ") : String(value || "");
  }
  return headers;
}

function requestHeaders(url, redirects = 0) {
  return new Promise((resolveRequest) => {
    let parsed;
    try {
      parsed = new URL(url);
    } catch (error) {
      resolveRequest({ ok: false, url, finalUrl: url, error: error.message, headers: {}, setCookies: [] });
      return;
    }

    const client = parsed.protocol === "https:" ? httpsRequest : httpRequest;
    const req = client(
      parsed,
      {
        method: "GET",
        timeout: 7000,
        headers: {
          "user-agent": USER_AGENT,
          accept: "text/html,application/xhtml+xml,application/json;q=0.8,*/*;q=0.5"
        }
      },
      (res) => {
        const status = res.statusCode || 0;
        const location = res.headers.location;
        res.resume();
        res.on("end", async () => {
          if ([301, 302, 303, 307, 308].includes(status) && location && redirects < 5) {
            const nextUrl = new URL(location, parsed).toString();
            resolveRequest(await requestHeaders(nextUrl, redirects + 1));
            return;
          }
          resolveRequest({
            ok: true,
            url,
            finalUrl: parsed.toString(),
            status,
            headers: normalizeHeaders(res.headers),
            setCookies: Array.isArray(res.headers["set-cookie"]) ? res.headers["set-cookie"] : [],
            redirects
          });
        });
      }
    );

    req.on("timeout", () => {
      req.destroy(new Error("request timed out"));
    });
    req.on("error", (error) => {
      resolveRequest({ ok: false, url, finalUrl: url, error: error.message, headers: {}, setCookies: [] });
    });
    req.end();
  });
}

function isHtmlResponse(response) {
  const contentType = String(response.headers?.["content-type"] || "").toLowerCase();
  if (contentType.includes("text/html")) return true;
  return !looksLikeAsset(response.finalUrl || response.url);
}

function hasNoStore(value) {
  return /\bno-store\b/i.test(String(value || ""));
}

function headerValue(response, name) {
  return String(response.headers?.[name] || "");
}

function evaluateHeaders(findings, responses, scope, discovery) {
  const reachable = responses.filter((response) => response.ok);
  const htmlResponses = reachable.filter(isHtmlResponse);
  const checkHeader = (id, title, header, applies, validate, detail) => {
    const targets = reachable.filter(applies);
    const missing = targets.filter((response) => !validate(headerValue(response, header)));
    addFinding(findings, "warning", id, title, missing.length === 0, detail, {
      checked: targets.length,
      missing: missing.map((response) => response.finalUrl || response.url)
    });
  };

  addFinding(
    findings,
    "warning",
    "frontend.reachable",
    "Configured frontend URLs are reachable",
    reachable.length > 0 && responses.every((response) => response.ok),
    "The advisory can only verify live headers when the configured frontend is running.",
    {
      requested: responses.length,
      reachable: reachable.length,
      errors: responses.filter((response) => !response.ok).map((response) => ({ url: response.url, error: response.error }))
    }
  );

  checkHeader(
    "frontend.headers.csp",
    "HTML responses send Content-Security-Policy",
    "content-security-policy",
    (response) => isHtmlResponse(response),
    Boolean,
    "CSP helps reduce XSS and client-side injection impact on discovered HTML pages."
  );
  checkHeader(
    "frontend.headers.nosniff",
    "Responses send X-Content-Type-Options: nosniff",
    "x-content-type-options",
    () => true,
    (value) => /\bnosniff\b/i.test(value),
    "nosniff reduces MIME confusion attacks across HTML and static assets."
  );
  checkHeader(
    "frontend.headers.referrer",
    "HTML responses send a safe Referrer-Policy",
    "referrer-policy",
    (response) => isHtmlResponse(response),
    (value) => Boolean(value) && !/\bunsafe-url\b/i.test(value),
    "A restrictive referrer policy limits accidental leakage of paths and query data."
  );
  checkHeader(
    "frontend.headers.permissions",
    "HTML responses send Permissions-Policy",
    "permissions-policy",
    (response) => isHtmlResponse(response),
    Boolean,
    "Permissions-Policy disables unused browser capabilities such as camera, microphone, and geolocation."
  );

  const poweredByPresent = reachable.filter((response) => headerValue(response, "x-powered-by"));
  addFinding(
    findings,
    "warning",
    "frontend.headers.powered_by",
    "Responses do not expose X-Powered-By",
    poweredByPresent.length === 0,
    "Framework disclosure headers add avoidable fingerprinting detail.",
    { present: poweredByPresent.map((response) => response.finalUrl || response.url) }
  );

  const framingMissing = htmlResponses.filter((response) => {
    const csp = headerValue(response, "content-security-policy");
    const xfo = headerValue(response, "x-frame-options");
    return !/\bframe-ancestors\b/i.test(csp) && !/\b(?:deny|sameorigin)\b/i.test(xfo);
  });
  addFinding(
    findings,
    "warning",
    "frontend.headers.framing",
    "HTML responses protect against clickjacking",
    framingMissing.length === 0,
    "Use CSP frame-ancestors or X-Frame-Options on HTML pages.",
    { missing: framingMissing.map((response) => response.finalUrl || response.url) }
  );

  const authResponses = htmlResponses.filter((response) => isAuthLikeUrl(response.finalUrl || response.url, scope, discovery));
  const cacheMissing = authResponses.filter((response) => !hasNoStore(headerValue(response, "cache-control")));
  addFinding(
    findings,
    "warning",
    "frontend.headers.auth_cache",
    "Authentication-like pages use Cache-Control: no-store",
    cacheMissing.length === 0,
    "Auth and account pages should avoid browser/proxy storage of sensitive responses.",
    { checked: authResponses.length, missing: cacheMissing.map((response) => response.finalUrl || response.url) }
  );

  const httpsResponses = reachable.filter((response) => {
    const parsed = new URL(response.finalUrl || response.url);
    return parsed.protocol === "https:" && !isLoopback(parsed.hostname);
  });
  const hstsMissing = httpsResponses.filter((response) => !headerValue(response, "strict-transport-security"));
  addFinding(
    findings,
    "info",
    "frontend.headers.hsts",
    "HTTPS non-loopback responses send HSTS",
    hstsMissing.length === 0,
    "HSTS is expected on real HTTPS environments; local HTTP targets are skipped.",
    { checked: httpsResponses.length, missing: hstsMissing.map((response) => response.finalUrl || response.url) }
  );
}

function cookieName(cookie) {
  return String(cookie || "").split("=")[0].trim();
}

function cookieFlags(cookie) {
  return String(cookie || "")
    .split(";")
    .slice(1)
    .map((part) => part.trim().toLowerCase());
}

function evaluateCookies(findings, responses) {
  const cookieEvidence = [];
  for (const response of responses.filter((item) => item.ok)) {
    const parsed = new URL(response.finalUrl || response.url);
    for (const cookie of response.setCookies || []) {
      const name = cookieName(cookie);
      const flags = cookieFlags(cookie);
      const sensitive = /(?:session|auth|jwt|sid|access|refresh|token)/i.test(name) && !/(?:csrf|xsrf)/i.test(name);
      const sameSiteNone = flags.some((flag) => flag === "samesite=none");
      const missing = [];
      if (!flags.some((flag) => flag.startsWith("samesite"))) missing.push("SameSite");
      if (sensitive && !flags.includes("httponly")) missing.push("HttpOnly");
      if ((parsed.protocol === "https:" || sameSiteNone) && !flags.includes("secure")) missing.push("Secure");
      if (missing.length) {
        cookieEvidence.push({ url: response.finalUrl || response.url, name, missing });
      }
    }
  }

  addFinding(
    findings,
    "warning",
    "frontend.cookies.flags",
    "Cookies use defensive attributes",
    cookieEvidence.length === 0,
    "Session-like cookies should use HttpOnly, SameSite, and Secure when applicable.",
    { cookies: cookieEvidence }
  );
}

function evaluateForms(findings, discovery) {
  const authForms = (discovery?.forms || []).filter((form) => form.auth_like);
  const autocompleteIssues = [];
  for (const form of authForms) {
    for (const control of form.controls || []) {
      const type = String(control.type || "").toLowerCase();
      const autocomplete = String(control.autocomplete || "").toLowerCase();
      if (type === "password" && !["current-password", "new-password"].includes(autocomplete)) {
        autocompleteIssues.push({ page: form.page_url, field: control.name || control.id || "password", expected: "current-password or new-password" });
      }
      if (["email", "text"].includes(type) && /user|email|account|login/i.test(`${control.name || ""} ${control.id || ""}`)) {
        const allowed = type === "email" ? ["email", "username"] : ["username", "email", "organization"];
        if (!allowed.includes(autocomplete)) {
          autocompleteIssues.push({ page: form.page_url, field: control.name || control.id || type, expected: allowed.join(" or ") });
        }
      }
    }
  }

  addFinding(
    findings,
    "warning",
    "frontend.forms.autocomplete",
    "Authentication fields use explicit autocomplete hints",
    autocompleteIssues.length === 0,
    "Explicit autocomplete values improve password-manager behavior and reduce credential reuse friction.",
    { issues: autocompleteIssues }
  );
}

function parseArgs(argv) {
  const flags = new Set(argv.slice(2));
  return {
    json: flags.has("--json") || (argv.includes("--format") && argv[argv.indexOf("--format") + 1] === "json")
  };
}

async function main() {
  const options = parseArgs(process.argv);
  const [scope, latestScan, baseline] = await Promise.all([
    readJson("aegis.scope.json", {}),
    readJson(".aegis/latest-scan.json", {}),
    readJson(".aigate/security-baseline.json", {})
  ]);
  const discovery = latestScan?.discovery || {};
  const targets = buildTargets(scope, latestScan, baseline);
  const responses = [];
  for (const target of targets) {
    responses.push(await requestHeaders(target));
  }

  const findings = [];
  evaluateHeaders(findings, responses, scope, discovery);
  evaluateCookies(findings, responses);
  evaluateForms(findings, discovery);

  const warnings = findings.filter((finding) => finding.level === "warning" && !finding.passed);
  const errors = findings.filter((finding) => finding.level === "error" && !finding.passed);
  const report = {
    command: "frontend-advisory",
    status: errors.length ? "FAIL" : warnings.length ? "WARN" : "PASS",
    generatedAt: new Date().toISOString(),
    target: scope?.targets?.frontend?.base_url || "",
    sources: baseline.sources || [],
    summary: {
      targets: targets.length,
      reachable: responses.filter((response) => response.ok).length,
      total: findings.length,
      passed: findings.filter((finding) => finding.passed).length,
      warnings: warnings.length,
      errors: errors.length
    },
    responses: responses.map((response) => ({
      url: response.url,
      finalUrl: response.finalUrl,
      status: response.status,
      ok: response.ok,
      error: response.error,
      headers: {
        "cache-control": response.headers?.["cache-control"] || "",
        "content-security-policy": response.headers?.["content-security-policy"] || "",
        "permissions-policy": response.headers?.["permissions-policy"] || "",
        "referrer-policy": response.headers?.["referrer-policy"] || "",
        "strict-transport-security": response.headers?.["strict-transport-security"] || "",
        "x-content-type-options": response.headers?.["x-content-type-options"] || "",
        "x-frame-options": response.headers?.["x-frame-options"] || "",
        "x-powered-by": response.headers?.["x-powered-by"] || ""
      },
      setCookieCount: response.setCookies?.length || 0
    })),
    findings
  };

  await mkdir(dirname(reportPath), { recursive: true });
  await writeFile(reportPath, `${JSON.stringify(report, null, 2)}\n`, "utf8");

  if (options.json) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    console.log(`Frontend advisory: ${report.status}`);
    console.log(`Target: ${report.target || "not configured"}`);
    console.log(`Checked: ${report.summary.reachable}/${report.summary.targets}`);
    console.log(`Passed: ${report.summary.passed}/${report.summary.total}`);
    console.log(`Warnings: ${report.summary.warnings}`);
    console.log(`Report: ${reportPath}`);
    for (const finding of findings.filter((item) => !item.passed)) {
      console.log(`- [${finding.level}] ${finding.id}: ${finding.detail}`);
    }
  }

  if (errors.length) {
    process.exit(1);
  }
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
