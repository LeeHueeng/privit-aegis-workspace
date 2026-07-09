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

function targetScope(scope, targetName = "frontend") {
  return scope?.targets?.[targetName] || {};
}

function isAllowedUrl(url, scope, targetName = "frontend") {
  const target = targetScope(scope, targetName);
  const allowedHosts = new Set(target.allowed_hosts || []);
  const allowedPaths = target.allowed_paths?.length ? target.allowed_paths : ["/*"];
  const deniedPaths = target.denied_paths || [];
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

function requestHeaders(url, redirects = 0, options = {}, originalUrl = url) {
  return new Promise((resolveRequest) => {
    let parsed;
    try {
      parsed = new URL(url);
    } catch (error) {
      resolveRequest({ ok: false, requestedUrl: originalUrl, url, finalUrl: url, error: error.message, headers: {}, setCookies: [] });
      return;
    }

    const client = parsed.protocol === "https:" ? httpsRequest : httpRequest;
    const method = String(options.method || "GET").toUpperCase();
    const maxBodyBytes = Number(options.maxBodyBytes || 0);
    const extraHeaders = options.headers || {};
    const req = client(
      parsed,
      {
        method,
        timeout: 7000,
        headers: {
          "user-agent": USER_AGENT,
          accept: "text/html,application/xhtml+xml,application/json;q=0.8,*/*;q=0.5",
          ...extraHeaders
        }
      },
      (res) => {
        const status = res.statusCode || 0;
        const location = res.headers.location;
        const chunks = [];
        let received = 0;
        if (!maxBodyBytes) {
          res.resume();
        } else {
          res.on("data", (chunk) => {
            if (received >= maxBodyBytes) return;
            const remaining = maxBodyBytes - received;
            const slice = chunk.length > remaining ? chunk.subarray(0, remaining) : chunk;
            chunks.push(slice);
            received += slice.length;
          });
        }
        res.on("end", async () => {
          if ([301, 302, 303, 307, 308].includes(status) && location && redirects < 5) {
            const nextUrl = new URL(location, parsed).toString();
            resolveRequest(await requestHeaders(nextUrl, redirects + 1, options, originalUrl));
            return;
          }
          resolveRequest({
            ok: true,
            requestedUrl: originalUrl,
            url,
            finalUrl: parsed.toString(),
            method,
            status,
            headers: normalizeHeaders(res.headers),
            setCookies: Array.isArray(res.headers["set-cookie"]) ? res.headers["set-cookie"] : [],
            bodyPreview: maxBodyBytes ? Buffer.concat(chunks).toString("utf8") : "",
            redirects
          });
        });
      }
    );

    req.on("timeout", () => {
      req.destroy(new Error("request timed out"));
    });
    req.on("error", (error) => {
      resolveRequest({ ok: false, requestedUrl: originalUrl, url, finalUrl: url, method, error: error.message, headers: {}, setCookies: [] });
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

function parseCspDirectives(policy) {
  const directives = {};
  for (const part of String(policy || "").split(";")) {
    const tokens = part.trim().split(/\s+/).filter(Boolean);
    if (!tokens.length) continue;
    directives[tokens[0].toLowerCase()] = tokens.slice(1).map((token) => token.toLowerCase());
  }
  return directives;
}

function cspQualityIssues(policy) {
  const directives = parseCspDirectives(policy);
  if (!Object.keys(directives).length) return [];
  const issues = [];
  const script = directives["script-src"] || directives["default-src"] || [];
  const object = directives["object-src"] || [];
  const base = directives["base-uri"] || [];
  const frameAncestors = directives["frame-ancestors"] || [];
  const hasNonceOrHash = script.some((token) => /^'(?:nonce-|sha)/.test(token));

  if (script.includes("'unsafe-eval'")) issues.push("script-src unsafe-eval");
  if (script.includes("'unsafe-inline'") && !hasNonceOrHash) issues.push("script-src unsafe-inline without nonce/hash");
  if (script.includes("*")) issues.push("script-src wildcard");
  if (script.includes("data:")) issues.push("script-src data:");
  if (script.includes("http:")) issues.push("script-src cleartext source");
  if (!object.length || !object.includes("'none'")) issues.push("object-src not locked to none");
  if (!base.length || !base.includes("'none'")) issues.push("base-uri not locked to none");
  if (!frameAncestors.length) issues.push("frame-ancestors missing");
  return issues;
}

function corsIssues(response, testOrigin) {
  const allowOrigin = headerValue(response, "access-control-allow-origin");
  const allowCredentials = /\btrue\b/i.test(headerValue(response, "access-control-allow-credentials"));
  if (!allowOrigin) return [];
  const issues = [];
  if (allowOrigin === "*" && allowCredentials) issues.push("wildcard_origin_with_credentials");
  if (allowOrigin === testOrigin && allowCredentials) issues.push("reflected_origin_with_credentials");
  if (allowOrigin === testOrigin && !allowCredentials) issues.push("reflected_untrusted_origin");
  if (/^https?:\/\/\*/i.test(allowOrigin)) issues.push("wildcard_subdomain_origin");
  return issues;
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

  const cspQuality = htmlResponses
    .map((response) => ({
      url: response.finalUrl || response.url,
      issues: cspQualityIssues(headerValue(response, "content-security-policy"))
    }))
    .filter((item) => item.issues.length);
  addFinding(
    findings,
    "warning",
    "frontend.headers.csp_quality",
    "Content-Security-Policy avoids weak directives",
    cspQuality.length === 0,
    "OWASP WSTG recommends reviewing CSP meaningfully, not only checking that the header exists.",
    { checked: htmlResponses.filter((response) => headerValue(response, "content-security-policy")).length, issues: cspQuality }
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

async function evaluateCors(findings, scope) {
  const testOrigin = "https://aegis.invalid";
  const targets = targetBaseUrls(scope)
    .map((target) => ({ ...target, url: target.baseUrl }))
    .filter((target) => isAllowedUrl(target.url, scope, target.targetName));
  const checks = [];
  for (const target of targets) {
    const getResponse = await requestHeaders(target.url, 0, {
      method: "GET",
      headers: { origin: testOrigin }
    });
    const optionsResponse = await requestHeaders(target.url, 0, {
      method: "OPTIONS",
      headers: {
        origin: testOrigin,
        "access-control-request-method": "GET"
      }
    });
    checks.push({ target, response: getResponse, phase: "GET" });
    checks.push({ target, response: optionsResponse, phase: "OPTIONS" });
  }

  const issues = checks.flatMap(({ target, response, phase }) => corsIssues(response, testOrigin).map((signal) => ({
    target: target.targetName,
    phase,
    requestedUrl: response.requestedUrl || target.url,
    finalUrl: response.finalUrl || response.url,
    status: response.status || 0,
    allowOrigin: headerValue(response, "access-control-allow-origin"),
    allowCredentials: headerValue(response, "access-control-allow-credentials"),
    signal
  })));

  addFinding(
    findings,
    "warning",
    "frontend.headers.cors",
    "CORS does not trust arbitrary origins",
    issues.length === 0,
    "OWASP WSTG CORS testing checks whether untrusted origins are reflected or allowed with credentials.",
    { checked: checks.length, testOrigin, issues }
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

function configuredProbePaths(baseline, key, fallback) {
  const values = baseline?.frontendAdvisory?.passiveProbes?.[key];
  return Array.isArray(values) && values.length ? values : fallback;
}

function configuredNumber(baseline, key, fallback) {
  const value = Number(baseline?.frontendAdvisory?.[key]);
  return Number.isFinite(value) ? value : fallback;
}

function urlForPath(baseUrl, path) {
  try {
    return new URL(path, baseUrl).toString();
  } catch {
    return "";
  }
}

function targetBaseUrls(scope) {
  const targets = [];
  const frontend = targetScope(scope, "frontend");
  if (frontend.enabled !== false && frontend.base_url) {
    targets.push({ targetName: "frontend", baseUrl: frontend.base_url });
  }
  const backend = targetScope(scope, "backend_api");
  if (backend.enabled && backend.base_url) {
    targets.push({ targetName: "backend_api", baseUrl: backend.base_url });
  }
  return targets;
}

function probeFactory(scope, targetName, baseUrl, category, paths, method = "GET") {
  return paths
    .map((path) => ({ targetName, category, path, method, url: urlForPath(baseUrl, path) }))
    .filter((probe) => probe.url && isAllowedUrl(probe.url, scope, targetName));
}

function discoveredSourceMapPaths(latestScan) {
  const paths = [];
  for (const route of latestScan?.discovery?.routes || []) {
    try {
      const parsed = new URL(route.url);
      if (/\.map$/i.test(parsed.pathname)) paths.push(parsed.pathname);
      if (/\.js$/i.test(parsed.pathname)) paths.push(`${parsed.pathname}.map`);
    } catch {
      // Ignore malformed discovery entries.
    }
  }
  return unique(paths);
}

function buildPassiveProbes(scope, latestScan, baseline) {
  const probeConfig = baseline?.frontendAdvisory?.passiveProbes || {};
  const sensitiveFiles = configuredProbePaths(baseline, "sensitiveFiles", [
    "/.env",
    "/.git/config",
    "/.svn/entries",
    "/config.json",
    "/backup.zip",
    "/db.sql",
    "/phpinfo.php"
  ]);
  const apiDocs = configuredProbePaths(baseline, "apiDocs", [
    "/openapi.json",
    "/swagger.json",
    "/swagger-ui",
    "/swagger-ui/index.html",
    "/api-docs",
    "/redoc"
  ]);
  const adminPaths = configuredProbePaths(baseline, "adminPaths", [
    "/admin",
    "/admin/login",
    "/dashboard",
    "/manage",
    "/console"
  ]);
  const debugPaths = configuredProbePaths(baseline, "debugPaths", [
    "/debug",
    "/actuator",
    "/actuator/env",
    "/metrics",
    "/health",
    "/server-status",
    "/_next/webpack-hmr"
  ]);
  const sourceMapPaths = unique([
    ...configuredProbePaths(baseline, "sourceMaps", [
      "/main.js.map",
      "/app.js.map",
      "/static/js/main.js.map",
      "/_next/static/chunks/main.js.map"
    ]),
    ...discoveredSourceMapPaths(latestScan)
  ]);

  const routeMethodPaths = unique([
    "/",
    "/api",
    ...(latestScan?.discovery?.routes || [])
      .filter((route) => Number(route.depth || 0) <= 1)
      .map((route) => route.path || "")
  ]).slice(0, Number(probeConfig.maxMethodTargets || 12));

  const probes = [];
  for (const target of targetBaseUrls(scope)) {
    probes.push(...probeFactory(scope, target.targetName, target.baseUrl, "sensitiveFiles", sensitiveFiles));
    probes.push(...probeFactory(scope, target.targetName, target.baseUrl, "apiDocs", apiDocs));
    probes.push(...probeFactory(scope, target.targetName, target.baseUrl, "adminPaths", adminPaths));
    probes.push(...probeFactory(scope, target.targetName, target.baseUrl, "debugPaths", debugPaths));
    probes.push(...probeFactory(scope, target.targetName, target.baseUrl, "sourceMaps", sourceMapPaths));
    probes.push(...probeFactory(scope, target.targetName, target.baseUrl, "httpMethods", routeMethodPaths, "OPTIONS"));
  }

  return probes.slice(0, Number(probeConfig.maxProbeRequests || 60));
}

function responseText(response) {
  return String(response.bodyPreview || "").slice(0, 4096);
}

function isSuccessStatus(response) {
  return response.ok && response.status >= 200 && response.status < 300;
}

function isLoginLikeBody(response) {
  const text = responseText(response).toLowerCase();
  return /(?:login|sign in|signin|password|csrf|session|forgot password)/i.test(text);
}

function contentType(response) {
  return headerValue(response, "content-type").toLowerCase();
}

function sensitiveSignal(probe, response) {
  if (!isSuccessStatus(response)) return "";
  const text = responseText(response);
  const type = contentType(response);
  const path = probe.path.toLowerCase();
  if (path === "/.env" && /(?:^|\n)[A-Z0-9_]{2,}=.{1,}/.test(text) && !/<html/i.test(text)) return "dotenv";
  if (path === "/.git/config" && /\[(?:core|remote|branch)\]/i.test(text)) return "git_config";
  if (path === "/.svn/entries" && /(?:dir|file|\d{4}-\d{2}-\d{2})/i.test(text) && !/<html/i.test(text)) return "svn_entries";
  if (path.endsWith(".json") && type.includes("application/json")) return "json_config";
  if (path.endsWith(".sql") && /(?:create table|insert into|mysqldump|postgresql)/i.test(text)) return "database_dump";
  if (path.endsWith(".zip") && /(?:application\/zip|application\/octet-stream)/i.test(type)) return "archive";
  if (path.endsWith("phpinfo.php") && /php version|phpinfo\(\)/i.test(text)) return "phpinfo";
  return "";
}

function apiDocsSignal(response) {
  if (!isSuccessStatus(response) || isLoginLikeBody(response)) return "";
  const text = responseText(response);
  const type = contentType(response);
  if (type.includes("application/json") && /"(?:openapi|swagger)"\s*:/.test(text)) return "openapi_json";
  if (/swagger ui|redoc|openapi|api documentation/i.test(text)) return "api_docs";
  return "";
}

function sourceMapSignal(response) {
  if (!isSuccessStatus(response)) return "";
  const text = responseText(response);
  const type = contentType(response);
  if ((type.includes("json") || /\.map(?:$|\?)/i.test(response.finalUrl || response.url)) && /"version"\s*:\s*\d/.test(text) && /"mappings"\s*:/.test(text)) {
    return "source_map";
  }
  return "";
}

function exposedRouteSignal(scope, discovery, probe, response) {
  if (!isSuccessStatus(response)) return "";
  const finalUrl = response.finalUrl || response.url;
  if (isAuthLikeUrl(finalUrl, scope, discovery) || isLoginLikeBody(response)) return "";
  if (contentType(response).includes("text/html") && /<title>\s*(?:404|not found)/i.test(responseText(response))) return "";
  return `${response.status}`;
}

function methodSignal(response) {
  const allow = headerValue(response, "allow");
  if (!allow) return "";
  const methods = allow.split(",").map((method) => method.trim().toUpperCase()).filter(Boolean);
  const risky = methods.filter((method) => ["TRACE", "PUT", "DELETE", "PATCH"].includes(method));
  return risky.length ? risky.join(",") : "";
}

function probeEvidence(probe, response, signal) {
  return {
    target: probe.targetName,
    category: probe.category,
    path: probe.path,
    method: response.method || probe.method,
    requestedUrl: response.requestedUrl || probe.url,
    finalUrl: response.finalUrl || response.url,
    status: response.status || 0,
    contentType: headerValue(response, "content-type"),
    allow: headerValue(response, "allow"),
    redirects: response.redirects || 0,
    signal
  };
}

function objectIdentifierEvidence(discovery) {
  const queryIdLike = /[?&](?:id|userId|accountId|tenantId|orderId)=/i;
  const segmentIdLike = (path) => String(path || "")
    .split("/")
    .some((segment) => /^\d{2,}$/.test(segment) || /^[0-9a-f]{8,}$/i.test(segment));
  return (discovery?.routes || [])
    .filter((route) => queryIdLike.test(route.url || "") || segmentIdLike(route.path || ""))
    .slice(0, 20)
    .map((route) => ({ path: route.path || route.url, status: route.status, depth: route.depth }));
}

function contentReviewTargets(scope, latestScan, baseline) {
  const maxAssets = configuredNumber(baseline, "maxContentReviewAssets", 12);
  const routes = latestScan?.discovery?.routes || [];
  return unique(
    routes
      .map((route) => route.url)
      .filter((url) => /\.(?:js|mjs|json)(?:$|\?)/i.test(String(url || "")))
      .filter((url) => isAllowedUrl(url, scope, "frontend"))
  ).slice(0, Math.max(0, maxAssets));
}

function clientSecretSignals(response) {
  if (!isSuccessStatus(response)) return [];
  const text = responseText(response);
  const patterns = [
    ["private_key", /-----BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY-----/i],
    ["aws_access_key", /\bAKIA[0-9A-Z]{16}\b/],
    ["google_api_key", /\bAIza[0-9A-Za-z_-]{20,}\b/],
    ["jwt_literal", /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/],
    ["secret_assignment", /\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|password|secret)\b\s*[:=]\s*["'][^"']{8,}["']/i]
  ];
  return patterns.filter(([, pattern]) => pattern.test(text)).map(([name]) => name);
}

async function evaluateClientContentLeakage(findings, scope, latestScan, baseline) {
  const targets = contentReviewTargets(scope, latestScan, baseline);
  const reviews = [];
  for (const url of targets) {
    const response = await requestHeaders(url, 0, { method: "GET", maxBodyBytes: 8192 });
    const signals = clientSecretSignals(response);
    reviews.push({
      url,
      finalUrl: response.finalUrl || response.url,
      status: response.status || 0,
      contentType: headerValue(response, "content-type"),
      signals,
      ok: response.ok
    });
  }
  const exposures = reviews.filter((review) => review.signals.length);
  addFinding(
    findings,
    "warning",
    "frontend.content.client_secrets",
    "Client-side bundles do not expose obvious secrets",
    exposures.length === 0,
    "OWASP WSTG information leakage review includes frontend JavaScript and public content. This check stores signal names only, not secret values.",
    { checked: reviews.length, exposed: exposures }
  );
  return reviews;
}

function evaluateTransport(findings, discovery) {
  const authUrls = unique(
    (discovery?.forms || [])
      .filter((form) => form.auth_like)
      .flatMap((form) => [form.page_url, form.action_url])
  );
  const cleartext = authUrls.filter((url) => {
    try {
      const parsed = new URL(url);
      return parsed.protocol !== "https:" && !isLoopback(parsed.hostname);
    } catch {
      return false;
    }
  });
  addFinding(
    findings,
    "warning",
    "frontend.transport.auth_https",
    "Authentication surfaces avoid cleartext transport outside loopback",
    cleartext.length === 0,
    "Login and account flows should use HTTPS on non-local targets.",
    { cleartext }
  );
}

async function evaluatePassiveProbes(findings, scope, latestScan, baseline) {
  const discovery = latestScan?.discovery || {};
  const probes = buildPassiveProbes(scope, latestScan, baseline);
  const probeResponses = [];
  for (const probe of probes) {
    probeResponses.push({
      probe,
      response: await requestHeaders(probe.url, 0, {
        method: probe.method,
        maxBodyBytes: probe.method === "GET" ? 4096 : 0
      })
    });
  }

  const sensitiveExposures = [];
  const apiDocExposures = [];
  const adminExposures = [];
  const debugExposures = [];
  const sourceMapExposures = [];
  const riskyMethods = [];
  for (const { probe, response } of probeResponses) {
    if (probe.category === "sensitiveFiles") {
      const signal = sensitiveSignal(probe, response);
      if (signal) sensitiveExposures.push(probeEvidence(probe, response, signal));
    } else if (probe.category === "apiDocs") {
      const signal = apiDocsSignal(response);
      if (signal) apiDocExposures.push(probeEvidence(probe, response, signal));
    } else if (probe.category === "adminPaths") {
      const signal = exposedRouteSignal(scope, discovery, probe, response);
      if (signal) adminExposures.push(probeEvidence(probe, response, signal));
    } else if (probe.category === "debugPaths") {
      const signal = exposedRouteSignal(scope, discovery, probe, response);
      if (signal) debugExposures.push(probeEvidence(probe, response, signal));
    } else if (probe.category === "sourceMaps") {
      const signal = sourceMapSignal(response);
      if (signal) sourceMapExposures.push(probeEvidence(probe, response, signal));
    } else if (probe.category === "httpMethods") {
      const signal = methodSignal(response);
      if (signal) riskyMethods.push(probeEvidence(probe, response, signal));
    }
  }

  addFinding(
    findings,
    "warning",
    "frontend.probes.sensitive_files",
    "Common sensitive files are not publicly readable",
    sensitiveExposures.length === 0,
    "Passive probes check for exposed dotenv, VCS metadata, config, archive, dump, and phpinfo files without storing response bodies.",
    { checked: probes.filter((probe) => probe.category === "sensitiveFiles").length, exposed: sensitiveExposures }
  );
  addFinding(
    findings,
    "warning",
    "frontend.probes.api_docs",
    "API documentation is not anonymously exposed",
    apiDocExposures.length === 0,
    "OpenAPI, Swagger, ReDoc, and API docs endpoints should be intentionally published or access controlled.",
    { checked: probes.filter((probe) => probe.category === "apiDocs").length, exposed: apiDocExposures }
  );
  addFinding(
    findings,
    "warning",
    "frontend.probes.admin_debug",
    "Admin and debug surfaces are absent or require authentication",
    adminExposures.length === 0 && debugExposures.length === 0,
    "Admin consoles, debug endpoints, metrics, actuator, server-status, and framework hot-reload endpoints should not be anonymously available.",
    { admin: adminExposures, debug: debugExposures }
  );
  addFinding(
    findings,
    "warning",
    "frontend.probes.source_maps",
    "Production source maps are not publicly exposed",
    sourceMapExposures.length === 0,
    "Source maps can disclose source paths, internal comments, and client-side implementation details.",
    { checked: probes.filter((probe) => probe.category === "sourceMaps").length, exposed: sourceMapExposures }
  );
  addFinding(
    findings,
    "warning",
    "frontend.probes.http_methods",
    "OPTIONS does not advertise risky HTTP methods",
    riskyMethods.length === 0,
    "TRACE and unintended state-changing methods expand the attack surface when exposed anonymously.",
    { checked: probes.filter((probe) => probe.category === "httpMethods").length, risky: riskyMethods }
  );

  const objectIds = objectIdentifierEvidence(discovery);
  addFinding(
    findings,
    "info",
    "frontend.discovery.object_ids",
    "Object identifier routes are inventoried for BOLA/BFLA review",
    true,
    "OWASP API testing should review ID-bearing routes manually or with authenticated role matrices; this passive check records candidates only.",
    { candidates: objectIds, count: objectIds.length }
  );

  return probeResponses.map(({ probe, response }) => ({
    ...probeEvidence(probe, response, ""),
    ok: response.ok,
    error: response.error || ""
  }));
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
  await evaluateCors(findings, scope);
  evaluateCookies(findings, responses);
  evaluateForms(findings, discovery);
  evaluateTransport(findings, discovery);
  const contentReviews = await evaluateClientContentLeakage(findings, scope, latestScan, baseline);
  const probes = await evaluatePassiveProbes(findings, scope, latestScan, baseline);

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
      probes: probes.length,
      contentReviews: contentReviews.length,
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
        "access-control-allow-origin": response.headers?.["access-control-allow-origin"] || "",
        "access-control-allow-credentials": response.headers?.["access-control-allow-credentials"] || "",
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
    contentReviews,
    probes,
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
