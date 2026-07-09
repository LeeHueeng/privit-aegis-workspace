import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { connect as tlsConnect } from "node:tls";
import { resolveCname } from "node:dns/promises";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { isIP } from "node:net";
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

function isPublicNonLoopbackUrl(url) {
  try {
    const parsed = new URL(url);
    return ["http:", "https:"].includes(parsed.protocol) && !isLoopback(parsed.hostname);
  } catch {
    return false;
  }
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

const ATTACK_SURFACE_RULES = [
  {
    id: "xss_html",
    label: "XSS / HTML injection",
    review: "OWASP WSTG reflected, stored, DOM XSS, and HTML injection",
    patterns: [/\b(q|query|search|keyword|message|comment|content|html|body|description|title|name|bio|profile|return)\b/i]
  },
  {
    id: "sql_nosql_orm",
    label: "SQL / NoSQL / ORM injection",
    review: "OWASP WSTG SQL, NoSQL, and ORM injection",
    patterns: [/\b(id|ids|filter|where|sort|order|group|select|query|search|userId|accountId|tenantId|orderId|limit|offset)\b/i]
  },
  {
    id: "ldap_xml_xpath",
    label: "LDAP / XML / XPath / XXE",
    review: "OWASP WSTG LDAP, XML, XPath, and parser injection",
    patterns: [/\b(ldap|dn|uid|cn|member|group|filter|xml|xpath|xslt|soap|saml|assertion|wsdl|xsl)\b/i]
  },
  {
    id: "ssrf_fetch",
    label: "SSRF / URL fetch",
    review: "OWASP WSTG SSRF and server-side fetch review",
    patterns: [/\b(url|uri|link|target|callback|webhook|endpoint|feed|avatar|image|proxy|fetch|redirect|return|continue|dest|destination)\b/i]
  },
  {
    id: "file_path",
    label: "Path traversal / LFI / RFI",
    review: "OWASP WSTG local and remote file inclusion",
    patterns: [/\b(file|path|dir|folder|template|page|view|include|download|upload|import|export|filename|document|attachment)\b/i]
  },
  {
    id: "command_code_template",
    label: "Command / code / template injection",
    review: "OWASP WSTG command, code, and server-side template injection",
    patterns: [/\b(cmd|command|exec|process|shell|script|code|template|expression|render|debug|eval|function)\b/i]
  },
  {
    id: "http_header",
    label: "HTTP splitting / smuggling / host header",
    review: "OWASP WSTG HTTP response splitting, request smuggling, and host header injection",
    patterns: [/\b(header|host|forwarded|referer|origin|next|return|continue|callback|location)\b/i]
  },
  {
    id: "authz_mass_assignment",
    label: "BOLA / BFLA / mass assignment",
    review: "OWASP API Top 10 object, function, and property authorization",
    patterns: [/\b(role|admin|isAdmin|enabled|disabled|status|plan|price|credit|balance|permission|scope|owner|tenant|org|organization|account|user|record|object)\b/i]
  },
  {
    id: "upload_business_logic",
    label: "File upload / business logic",
    review: "OWASP WSTG malicious and unexpected file upload review",
    patterns: [/\b(upload|file|attachment|avatar|image|photo|document|import|media|multipart)\b/i]
  },
  {
    id: "graphql_api",
    label: "GraphQL / API schema review",
    review: "OWASP API and GraphQL endpoint authorization/introspection review",
    patterns: [/\b(graphql|graphiql|query|mutation|operationName|variables|schema|api)\b/i]
  }
];

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
          if (options.followRedirects !== false && [301, 302, 303, 307, 308].includes(status) && location && redirects < 5) {
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

function attrValue(tag, name) {
  const pattern = new RegExp(`\\b${escapeRegex(name)}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, "i");
  const match = String(tag || "").match(pattern);
  return match ? match[1] || match[2] || match[3] || "" : "";
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

function serverHeaderLooksDetailed(value) {
  const header = String(value || "");
  return /\b[a-z][\w.-]*\/\d[\w.-]*/i.test(header);
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

function headerMisconfigurationIssues(response) {
  const issues = [];
  const crossDomainPolicy = headerValue(response, "x-permitted-cross-domain-policies");
  const xFrameOptions = headerValue(response, "x-frame-options");
  const hsts = headerValue(response, "strict-transport-security");
  const finalUrl = response.finalUrl || response.url;

  if (crossDomainPolicy && !/\bnone\b/i.test(crossDomainPolicy)) {
    issues.push({ url: finalUrl, header: "x-permitted-cross-domain-policies", value: crossDomainPolicy, signal: "permissive_cross_domain_policy" });
  }
  if (headerValue(response, "public-key-pins") || headerValue(response, "public-key-pins-report-only")) {
    issues.push({ url: finalUrl, header: "public-key-pins", signal: "deprecated_hpkp" });
  }
  if (/\ballow-from\b/i.test(xFrameOptions)) {
    issues.push({ url: finalUrl, header: "x-frame-options", value: xFrameOptions, signal: "obsolete_allow_from" });
  }
  try {
    const parsed = new URL(finalUrl);
    if (parsed.protocol === "http:" && hsts) {
      issues.push({ url: finalUrl, header: "strict-transport-security", signal: "hsts_on_http" });
    }
  } catch {
    // Ignore malformed response URLs in optional header placement checks.
  }
  return issues;
}

function firstHeaderToken(value) {
  return String(value || "").split(";")[0].trim().toLowerCase();
}

function crossOriginIsolationEvidence(response) {
  const finalUrl = response.finalUrl || response.url;
  const headerNames = [
    "cross-origin-opener-policy",
    "cross-origin-embedder-policy",
    "cross-origin-embedder-policy-report-only",
    "cross-origin-resource-policy"
  ];
  const headers = Object.fromEntries(
    headerNames
      .map((name) => [name, headerValue(response, name)])
      .filter(([, value]) => value)
  );
  return {
    url: finalUrl,
    status: response.status || 0,
    headers,
    missing: headerNames.filter((name) => !headers[name])
  };
}

function crossOriginIsolationIssues(response) {
  const finalUrl = response.finalUrl || response.url;
  const headerChecks = [
    {
      header: "cross-origin-opener-policy",
      allowed: new Set(["same-origin", "same-origin-allow-popups", "unsafe-none"]),
      weak: new Set(["unsafe-none"])
    },
    {
      header: "cross-origin-embedder-policy",
      allowed: new Set(["require-corp", "credentialless", "unsafe-none"]),
      weak: new Set(["unsafe-none"])
    },
    {
      header: "cross-origin-embedder-policy-report-only",
      allowed: new Set(["require-corp", "credentialless", "unsafe-none"]),
      weak: new Set(["unsafe-none"])
    },
    {
      header: "cross-origin-resource-policy",
      allowed: new Set(["same-origin", "same-site", "cross-origin"]),
      weak: new Set()
    }
  ];
  const issues = [];
  for (const check of headerChecks) {
    const raw = headerValue(response, check.header);
    if (!raw) continue;
    const value = firstHeaderToken(raw);
    if (!check.allowed.has(value)) {
      issues.push({ url: finalUrl, header: check.header, value: raw, signal: "invalid_cross_origin_policy_value" });
    } else if (check.weak.has(value)) {
      issues.push({ url: finalUrl, header: check.header, value: raw, signal: "explicit_unsafe_none" });
    }
  }
  return issues;
}

function splitPolicyDirectives(value) {
  return String(value || "")
    .split(/,(?=\s*[a-z][a-z0-9-]*\s*=)/i)
    .map((part) => part.trim())
    .filter(Boolean);
}

function permissionsPolicyDirectives(value) {
  const directives = [];
  for (const part of splitPolicyDirectives(value)) {
    const match = part.match(/^([a-z][a-z0-9-]*)\s*=\s*(.+)$/i);
    if (match) {
      directives.push({ feature: match[1].toLowerCase(), value: match[2].trim() });
    } else {
      directives.push({ feature: "", value: part, malformed: true });
    }
  }
  return directives;
}

function permissionsPolicyIssues(response) {
  const finalUrl = response.finalUrl || response.url;
  const policy = headerValue(response, "permissions-policy");
  const sensitiveFeatures = new Set([
    "accelerometer",
    "bluetooth",
    "camera",
    "clipboard-read",
    "display-capture",
    "geolocation",
    "gyroscope",
    "hid",
    "local-fonts",
    "magnetometer",
    "microphone",
    "payment",
    "serial",
    "usb"
  ]);
  const issues = [];
  for (const directive of permissionsPolicyDirectives(policy)) {
    if (directive.malformed) {
      issues.push({ url: finalUrl, feature: "", value: directive.value.slice(0, 160), signal: "malformed_permissions_policy_directive" });
      continue;
    }
    const value = directive.value.toLowerCase();
    if (sensitiveFeatures.has(directive.feature) && /(?:^|[\s(])\*(?:[\s)]|$)/.test(value)) {
      issues.push({ url: finalUrl, feature: directive.feature, value: directive.value.slice(0, 160), signal: "sensitive_browser_feature_allows_wildcard" });
    }
  }
  return issues;
}

function cspReportOnlyEvidence(response) {
  const policy = headerValue(response, "content-security-policy-report-only");
  return {
    url: response.finalUrl || response.url,
    status: response.status || 0,
    present: Boolean(policy),
    hasReportEndpoint: /\b(?:report-to|report-uri)\b/i.test(policy),
    issues: cspQualityIssues(policy),
    policyPreview: policy.slice(0, 240)
  };
}

function frameworkFingerprintEvidence(response) {
  const finalUrl = response.finalUrl || response.url;
  const headerNames = [
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
    "x-runtime",
    "x-rack-cache",
    "x-redirect-by",
    "x-nextjs-cache",
    "x-drupal-cache",
    "x-varnish",
    "x-laravel"
  ];
  const headers = headerNames
    .map((name) => ({ url: finalUrl, header: name, value: headerValue(response, name) }))
    .filter((item) => item.value);
  const cookiePatterns = [
    ["php", /^PHPSESSID$/i],
    ["java", /^JSESSIONID$/i],
    ["aspnet", /^ASP\.NET_SessionId$/i],
    ["rails", /^_.*_session$/i],
    ["laravel", /^laravel_session$/i],
    ["express", /^connect\.sid$/i],
    ["play", /^PLAY_SESSION$/i],
    ["cakephp", /^CAKEPHP$/i]
  ];
  const cookies = [];
  for (const cookie of response.setCookies || []) {
    const name = cookieName(cookie);
    const match = cookiePatterns.find(([, pattern]) => pattern.test(name));
    if (match) cookies.push({ url: finalUrl, name, signal: match[0] });
  }
  return { headers, cookies };
}

function reverseTabnabbingIssues(response) {
  if (!isSuccessStatus(response) || !isHtmlResponse(response)) return [];
  const finalUrl = response.finalUrl || response.url;
  const issues = [];
  for (const match of clientCodeText(response).matchAll(/<a\b[^>]*\btarget\s*=\s*(?:"_blank"|'_blank'|_blank)[^>]*>/gi)) {
    const tag = match[0];
    const rel = attrValue(tag, "rel").toLowerCase();
    if (/\bnoopener\b|\bnoreferrer\b/i.test(rel)) continue;
    issues.push({
      url: finalUrl,
      href: attrValue(tag, "href").slice(0, 200),
      signal: "target_blank_without_noopener"
    });
  }
  return issues.slice(0, 20);
}

function sameOriginUrl(a, b) {
  try {
    return new URL(a).origin === new URL(b).origin;
  } catch {
    return false;
  }
}

function externalSubresourceIntegrityIssues(response) {
  if (!isSuccessStatus(response) || !isHtmlResponse(response)) return [];
  const baseUrl = response.finalUrl || response.url;
  const issues = [];
  const html = clientCodeText(response);
  for (const match of html.matchAll(/<script\b[^>]*\bsrc\b[^>]*>/gi)) {
    const tag = match[0];
    const src = attrValue(tag, "src");
    if (!src) continue;
    try {
      const url = new URL(src, baseUrl).toString();
      if (!/^https?:\/\//i.test(url) || sameOriginUrl(url, baseUrl)) continue;
      if (!attrValue(tag, "integrity")) {
        issues.push({ url: baseUrl, resource: url.slice(0, 240), tag: "script", signal: "external_script_without_sri" });
      }
    } catch {
      // Ignore malformed resource references in passive HTML inventory.
    }
  }
  for (const match of html.matchAll(/<link\b[^>]*\bhref\b[^>]*>/gi)) {
    const tag = match[0];
    const rel = attrValue(tag, "rel").toLowerCase();
    if (!/\b(?:stylesheet|preload|modulepreload)\b/.test(rel)) continue;
    const href = attrValue(tag, "href");
    if (!href) continue;
    try {
      const url = new URL(href, baseUrl).toString();
      if (!/^https?:\/\//i.test(url) || sameOriginUrl(url, baseUrl)) continue;
      if (!attrValue(tag, "integrity")) {
        issues.push({ url: baseUrl, resource: url.slice(0, 240), tag: "link", rel, signal: "external_stylesheet_without_sri" });
      }
    } catch {
      // Ignore malformed resource references in passive HTML inventory.
    }
  }
  return issues.slice(0, 30);
}

function mixedContentIssues(response) {
  if (!isSuccessStatus(response) || !isHtmlResponse(response)) return [];
  const baseUrl = response.finalUrl || response.url;
  try {
    if (new URL(baseUrl).protocol !== "https:") return [];
  } catch {
    return [];
  }
  const issues = [];
  const html = clientCodeText(response);
  for (const match of html.matchAll(/<(script|link|iframe|img|form)\b[^>]*(?:\bsrc\b|\bhref\b|\baction\b)[^>]*>/gi)) {
    const tag = match[0];
    const tagName = match[1].toLowerCase();
    const value = attrValue(tag, "src") || attrValue(tag, "href") || attrValue(tag, "action");
    if (!value) continue;
    try {
      const url = new URL(value, baseUrl);
      if (url.protocol !== "http:" || isLoopback(url.hostname)) continue;
      issues.push({ url: baseUrl, resource: url.toString().slice(0, 240), tag: tagName, signal: "http_subresource_on_https_page" });
    } catch {
      // Ignore malformed resource references in passive HTML inventory.
    }
  }
  return issues.slice(0, 30);
}

function rateLimitHeaders(response) {
  const names = [
    "ratelimit-limit",
    "ratelimit-remaining",
    "ratelimit-reset",
    "retry-after",
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-ratelimit-reset"
  ];
  return Object.fromEntries(
    names
      .map((name) => [name, headerValue(response, name)])
      .filter(([, value]) => value)
  );
}

function rateLimitEvidence(response, extra = {}) {
  return {
    url: response.finalUrl || response.url,
    status: response.status || 0,
    headers: rateLimitHeaders(response),
    ...extra
  };
}

function cacheControlProtected(value) {
  const header = String(value || "");
  if (/\bpublic\b/i.test(header)) return false;
  return /\b(?:no-store|no-cache|private|max-age=0|s-maxage=0)\b/i.test(header);
}

function authApiHeaderEvidence(probe, response, signal) {
  return {
    target: probe.targetName,
    path: probe.path,
    requestedUrl: response.requestedUrl || probe.url,
    finalUrl: response.finalUrl || response.url,
    status: response.status || 0,
    contentType: contentType(response),
    cacheControl: headerValue(response, "cache-control"),
    xContentTypeOptions: headerValue(response, "x-content-type-options"),
    signal
  };
}

function numericCacheDirective(value, name) {
  const match = String(value || "").match(new RegExp(`\\b${escapeRegex(name)}\\s*=\\s*(\\d+)`, "i"));
  return match ? Number(match[1]) : null;
}

function cacheControlAllowsSharedStorage(value) {
  const header = String(value || "");
  if (!header || /\b(?:no-store|no-cache|private)\b/i.test(header)) return false;
  if (/\bpublic\b/i.test(header)) return true;
  const sMaxAge = numericCacheDirective(header, "s-maxage");
  if (typeof sMaxAge === "number" && sMaxAge > 0) return true;
  const maxAge = numericCacheDirective(header, "max-age");
  return typeof maxAge === "number" && maxAge > 0;
}

function cacheLayerHeaders(response) {
  const names = [
    "age",
    "cdn-cache-control",
    "cf-cache-status",
    "surrogate-control",
    "via",
    "x-cache",
    "x-cache-hits",
    "x-served-by",
    "x-varnish",
    "x-vercel-cache",
    "x-nextjs-cache"
  ];
  return Object.fromEntries(
    names
      .map((name) => [name, headerValue(response, name)])
      .filter(([, value]) => value)
  );
}

function cacheDeceptionRouteEvidence(response, scope, discovery) {
  if (!isSuccessStatus(response) || !isHtmlResponse(response)) return null;
  const finalUrl = response.finalUrl || response.url;
  let parsed;
  try {
    parsed = new URL(finalUrl);
  } catch {
    return null;
  }
  const path = parsed.pathname;
  const dynamicPath = /(?:account|admin|billing|cart|checkout|dashboard|inbox|me|orders?|payment|profile|session|settings|user|wallet)/i.test(path);
  const hasQuery = parsed.searchParams && [...parsed.searchParams.keys()].length > 0;
  const authLike = isAuthLikeUrl(finalUrl, scope, discovery);
  if (!dynamicPath && !hasQuery && !authLike) return null;

  const cacheControl = headerValue(response, "cache-control");
  const layers = cacheLayerHeaders(response);
  const sharedCacheable = cacheControlAllowsSharedStorage(cacheControl);
  const unprotectedBehindCache = Boolean(Object.keys(layers).length) && !cacheControlProtected(cacheControl);
  const signal = sharedCacheable
    ? "cacheable_dynamic_html"
    : unprotectedBehindCache
      ? "dynamic_html_behind_cache_without_no_store"
      : "dynamic_html_cache_review_candidate";

  return {
    url: finalUrl,
    status: response.status || 0,
    path,
    authLike,
    hasQuery,
    cacheControl,
    cacheHeaders: layers,
    signal,
    issue: sharedCacheable || unprotectedBehindCache
  };
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
  const deprecatedFeaturePolicy = htmlResponses
    .map((response) => ({
      url: response.finalUrl || response.url,
      value: headerValue(response, "feature-policy")
    }))
    .filter((item) => item.value);
  addFinding(
    findings,
    "warning",
    "frontend.headers.feature_policy_deprecated",
    "HTML responses use Permissions-Policy instead of deprecated Feature-Policy",
    deprecatedFeaturePolicy.length === 0,
    "Feature-Policy is the deprecated predecessor of Permissions-Policy and should be migrated to the current header syntax.",
    { checked: htmlResponses.length, present: deprecatedFeaturePolicy }
  );
  const permissionsIssues = htmlResponses.flatMap(permissionsPolicyIssues);
  addFinding(
    findings,
    "warning",
    "frontend.headers.permissions_policy_quality",
    "Permissions-Policy avoids wildcard access to sensitive browser features",
    permissionsIssues.length === 0,
    "Permissions-Policy should apply least privilege to camera, microphone, geolocation, payment, USB, serial, HID, clipboard, and display-capture features.",
    { checked: htmlResponses.filter((response) => headerValue(response, "permissions-policy")).length, issues: permissionsIssues }
  );

  const isolationEvidence = htmlResponses.map(crossOriginIsolationEvidence);
  const isolationPresent = isolationEvidence.filter((item) => Object.keys(item.headers).length);
  addFinding(
    findings,
    "info",
    "frontend.headers.cross_origin_isolation",
    "Cross-origin isolation headers are inventoried",
    true,
    "COOP, COEP, COEP-Report-Only, and CORP are defense-in-depth browser isolation headers. Missing values are informational because rollout depends on application embedding requirements.",
    {
      checked: htmlResponses.length,
      present: isolationPresent,
      missing: isolationEvidence
        .filter((item) => !Object.keys(item.headers).length)
        .map((item) => item.url)
    }
  );

  const isolationIssues = htmlResponses.flatMap(crossOriginIsolationIssues);
  addFinding(
    findings,
    "warning",
    "frontend.headers.cross_origin_isolation_values",
    "Cross-origin isolation headers avoid weak or invalid values",
    isolationIssues.length === 0,
    "MDN and OWASP guidance treats COOP/COEP/CORP as browser isolation controls; explicit unsafe-none or unknown values should be reviewed.",
    { checked: isolationPresent.length, issues: isolationIssues }
  );

  const cspReportOnly = htmlResponses.map(cspReportOnlyEvidence);
  addFinding(
    findings,
    "info",
    "frontend.headers.csp_report_only",
    "CSP Report-Only policies are inventoried",
    true,
    "Content-Security-Policy-Report-Only helps trial CSP changes without enforcement. The report records whether a reporting directive is present and reuses CSP quality signals for review.",
    {
      checked: htmlResponses.length,
      present: cspReportOnly.filter((item) => item.present),
      missing: cspReportOnly.filter((item) => !item.present).map((item) => item.url)
    }
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

  const serverVersionPresent = reachable
    .map((response) => ({
      url: response.finalUrl || response.url,
      server: headerValue(response, "server")
    }))
    .filter((item) => serverHeaderLooksDetailed(item.server));
  addFinding(
    findings,
    "warning",
    "frontend.headers.server_version",
    "Responses do not expose precise Server versions",
    serverVersionPresent.length === 0,
    "OWASP WSTG web server fingerprinting notes that server/version banners can help attackers target known version-specific issues.",
    { present: serverVersionPresent }
  );

  const headerMisconfigurations = reachable.flatMap(headerMisconfigurationIssues);
  addFinding(
    findings,
    "warning",
    "frontend.headers.misconfiguration",
    "Security headers avoid deprecated or overly permissive directives",
    headerMisconfigurations.length === 0,
    "OWASP WSTG recommends checking for permissive cross-domain policy headers, obsolete X-Frame-Options directives, deprecated HPKP, and misplaced HSTS.",
    { checked: reachable.length, issues: headerMisconfigurations }
  );

  const frameworkSignals = reachable.map(frameworkFingerprintEvidence);
  const frameworkHeaders = frameworkSignals.flatMap((item) => item.headers);
  const frameworkCookies = frameworkSignals.flatMap((item) => item.cookies);
  addFinding(
    findings,
    "warning",
    "frontend.fingerprint.framework_markers",
    "Responses avoid framework-identifying headers and cookie names",
    frameworkHeaders.length === 0 && frameworkCookies.length === 0,
    "OWASP WSTG framework fingerprinting checks headers, cookies, source, files, and error markers that reveal application components.",
    { checked: reachable.length, headers: frameworkHeaders, cookies: frameworkCookies }
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

  const tabnabbingIssues = htmlResponses.flatMap(reverseTabnabbingIssues);
  addFinding(
    findings,
    "warning",
    "frontend.content.reverse_tabnabbing",
    "External new-tab links use rel=noopener or noreferrer",
    tabnabbingIssues.length === 0,
    "OWASP WSTG reverse tabnabbing testing reviews target=_blank links that omit opener isolation.",
    { checked: htmlResponses.length, issues: tabnabbingIssues }
  );

  const sriIssues = htmlResponses.flatMap(externalSubresourceIntegrityIssues);
  addFinding(
    findings,
    "warning",
    "frontend.content.subresource_integrity",
    "External scripts and styles use Subresource Integrity",
    sriIssues.length === 0,
    "Subresource Integrity helps detect unexpected changes in third-party scripts and styles loaded by discovered HTML pages.",
    { checked: htmlResponses.length, issues: sriIssues }
  );

  const mixedContent = htmlResponses.flatMap(mixedContentIssues);
  addFinding(
    findings,
    "warning",
    "frontend.content.mixed_content",
    "HTTPS pages avoid cleartext subresources and form actions",
    mixedContent.length === 0,
    "HTTPS pages should not load active resources or submit forms over cleartext HTTP because that weakens transport guarantees.",
    { checked: htmlResponses.filter((response) => {
      try {
        return new URL(response.finalUrl || response.url).protocol === "https:";
      } catch {
        return false;
      }
    }).length, issues: mixedContent }
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

  const cacheDeceptionCandidates = htmlResponses
    .map((response) => cacheDeceptionRouteEvidence(response, scope, discovery))
    .filter(Boolean);
  addFinding(
    findings,
    "info",
    "frontend.cache.deception_candidates",
    "Dynamic HTML routes are inventoried for web cache deception review",
    true,
    "OWASP path-confusion and web-cache-deception testing starts by identifying dynamic pages where caches and origins may disagree about whether a response is static or user-specific.",
    { checked: htmlResponses.length, candidates: cacheDeceptionCandidates }
  );
  const cacheDeceptionIssues = cacheDeceptionCandidates.filter((item) => item.issue);
  addFinding(
    findings,
    "warning",
    "frontend.cache.dynamic_route_shared_cache",
    "Dynamic or authentication-like HTML routes avoid shared-cache storage",
    cacheDeceptionIssues.length === 0,
    "Dynamic HTML routes with account, session, admin, billing, checkout, profile, or query-bearing content should avoid public/shared caching to reduce web cache deception risk.",
    { checked: cacheDeceptionCandidates.length, issues: cacheDeceptionIssues }
  );

  const authRateLimitSignals = authResponses.map((response) => rateLimitEvidence(response));
  addFinding(
    findings,
    "info",
    "frontend.headers.auth_rate_limit",
    "Authentication-like pages are inventoried for rate-limit headers",
    true,
    "Rate-limit headers are not required to prove throttling, but visible Retry-After or RateLimit headers help reviewers confirm brute-force and abuse-control posture.",
    {
      checked: authRateLimitSignals.length,
      present: authRateLimitSignals.filter((item) => Object.keys(item.headers).length),
      missing: authRateLimitSignals.filter((item) => !Object.keys(item.headers).length).map((item) => item.url)
    }
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

function cookieAttribute(cookie, name) {
  const prefix = `${String(name || "").toLowerCase()}=`;
  const part = String(cookie || "")
    .split(";")
    .slice(1)
    .map((item) => item.trim())
    .find((item) => item.toLowerCase().startsWith(prefix));
  return part ? part.slice(prefix.length).trim() : "";
}

function isSensitiveCookieName(name) {
  return /(?:session|auth|jwt|sid|access|refresh|token)/i.test(name) && !/(?:csrf|xsrf)/i.test(name);
}

function evaluateCookies(findings, responses) {
  const cookieEvidence = [];
  const scopeEvidence = [];
  for (const response of responses.filter((item) => item.ok)) {
    const parsed = new URL(response.finalUrl || response.url);
    for (const cookie of response.setCookies || []) {
      const name = cookieName(cookie);
      const flags = cookieFlags(cookie);
      const sensitive = isSensitiveCookieName(name);
      const sameSiteNone = flags.some((flag) => flag === "samesite=none");
      const missing = [];
      if (!flags.some((flag) => flag.startsWith("samesite"))) missing.push("SameSite");
      if (sensitive && !flags.includes("httponly")) missing.push("HttpOnly");
      if ((parsed.protocol === "https:" || sameSiteNone) && !flags.includes("secure")) missing.push("Secure");
      if (missing.length) {
        cookieEvidence.push({ url: response.finalUrl || response.url, name, missing });
      }
      if (sensitive) {
        const domain = cookieAttribute(cookie, "domain");
        const path = cookieAttribute(cookie, "path");
        const scope = [];
        const normalizedDomain = domain.replace(/^\./, "").toLowerCase();
        if (domain && normalizedDomain !== parsed.hostname.toLowerCase()) scope.push("broad Domain");
        if (path === "/") scope.push("Path=/");
        if (scope.length) scopeEvidence.push({ url: response.finalUrl || response.url, name, scope, domain, path });
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
  addFinding(
    findings,
    "warning",
    "frontend.cookies.scope",
    "Sensitive cookies avoid broad Domain and Path scope",
    scopeEvidence.length === 0,
    "OWASP WSTG cookie testing checks Domain and Path scope because loose scoping can expose session cookies to sibling applications or subdomains.",
    { cookies: scopeEvidence }
  );
}

function formMethod(form) {
  return String(form?.method || "get").toUpperCase();
}

function formControls(form) {
  return Array.isArray(form?.controls) ? form.controls : [];
}

function formControlText(control) {
  return [
    control?.tag,
    control?.type,
    control?.name,
    control?.id,
    control?.autocomplete
  ].filter(Boolean).join(" ");
}

function isStateChangingForm(form) {
  return !["GET", "HEAD", "OPTIONS"].includes(formMethod(form));
}

function isCsrfControl(control) {
  return /(?:csrf|xsrf|authenticity|requestverificationtoken|anti[-_]?forgery|_token|csrfmiddlewaretoken)/i.test(formControlText(control));
}

function isSensitiveControl(control) {
  return /(?:password|passwd|pwd|secret|token|session|auth|jwt|email|phone|tel|credential|otp|mfa)/i.test(formControlText(control));
}

function normalizeFormAction(form) {
  const action = form?.action_url || form?.page_url || "";
  try {
    return new URL(action, form?.page_url || undefined).toString();
  } catch {
    return action;
  }
}

function formEvidence(form, extra = {}) {
  return {
    page: form.page_url || "",
    action: normalizeFormAction(form),
    method: formMethod(form),
    authLike: Boolean(form.auth_like),
    controls: formControls(form).slice(0, 12).map((control) => ({
      tag: control.tag || "",
      type: control.type || "",
      name: control.name || "",
      autocomplete: control.autocomplete || ""
    })),
    ...extra
  };
}

function isAllowedFormAction(actionUrl, scope) {
  return isAllowedUrl(actionUrl, scope, "frontend") || isAllowedUrl(actionUrl, scope, "backend_api");
}

function evaluateForms(findings, discovery, scope) {
  const forms = discovery?.forms || [];
  const authForms = forms.filter((form) => form.auth_like);
  const autocompleteIssues = [];
  for (const form of authForms) {
    for (const control of formControls(form)) {
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

  const authGetForms = authForms.filter((form) => formMethod(form) === "GET");
  addFinding(
    findings,
    "warning",
    "frontend.forms.auth_get_method",
    "Authentication-like forms avoid GET submissions",
    authGetForms.length === 0,
    "GET form submissions can place credentials, reset data, or tokens into URLs, browser history, proxy logs, and referrer headers.",
    { forms: authGetForms.map((form) => formEvidence(form)) }
  );

  const stateChangingForms = forms.filter(isStateChangingForm);
  const csrfMissing = stateChangingForms.filter((form) => !formControls(form).some(isCsrfControl));
  addFinding(
    findings,
    "warning",
    "frontend.forms.csrf_tokens",
    "State-changing forms expose anti-CSRF token candidates",
    csrfMissing.length === 0,
    "Passive form inventory checks whether POST/PUT/PATCH/DELETE-like forms contain CSRF token fields before any active submission testing.",
    { checked: stateChangingForms.length, missing: csrfMissing.map((form) => formEvidence(form)) }
  );

  const externalActions = forms
    .map((form) => ({ form, action: normalizeFormAction(form) }))
    .filter(({ action }) => action && /^https?:\/\//i.test(action) && !isAllowedFormAction(action, scope))
    .map(({ form, action }) => formEvidence(form, { action }));
  addFinding(
    findings,
    "warning",
    "frontend.forms.external_actions",
    "Forms submit only to in-scope targets",
    externalActions.length === 0,
    "Unexpected external form actions can leak credentials or workflow data to unapproved origins.",
    { forms: externalActions }
  );

  const insecureSensitiveActions = forms
    .filter((form) => form.auth_like || isStateChangingForm(form) || formControls(form).some(isSensitiveControl))
    .map((form) => ({ form, action: normalizeFormAction(form) }))
    .filter(({ action }) => {
      try {
        const parsed = new URL(action);
        return parsed.protocol === "http:" && !isLoopback(parsed.hostname);
      } catch {
        return false;
      }
    })
    .map(({ form, action }) => formEvidence(form, { action }));
  addFinding(
    findings,
    "warning",
    "frontend.forms.sensitive_cleartext_action",
    "Sensitive forms avoid cleartext non-loopback submissions",
    insecureSensitiveActions.length === 0,
    "Authentication, state-changing, and sensitive forms should not submit over cleartext HTTP outside local loopback environments.",
    { forms: insecureSensitiveActions }
  );

  const fileUploadForms = forms
    .filter((form) => formControls(form).some((control) => String(control.type || "").toLowerCase() === "file"))
    .map((form) => formEvidence(form));
  addFinding(
    findings,
    "info",
    "frontend.forms.file_upload_inventory",
    "File upload forms are inventoried for controlled testing",
    true,
    "Upload controls are recorded so authorized testers can review file type validation, malware scanning, storage paths, and authorization.",
    { count: fileUploadForms.length, forms: fileUploadForms }
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
  const backupFiles = configuredProbePaths(baseline, "backupFiles", [
    "/.DS_Store",
    "/backup.tar.gz",
    "/backup.tgz",
    "/backup.sql",
    "/database.sql.gz",
    "/site.zip",
    "/www.zip",
    "/config.php.bak",
    "/config.php~",
    "/application.properties.bak",
    "/application.yml.bak",
    "/web.config.bak"
  ]);
  const sensitiveExtensions = configuredProbePaths(baseline, "sensitiveExtensions", [
    "/index.inc",
    "/config.inc",
    "/settings.inc",
    "/global.asa",
    "/web.config",
    "/app.config",
    "/application.properties",
    "/application.yml",
    "/WEB-INF/web.xml",
    "/WEB-INF/classes/application.properties",
    "/composer.lock",
    "/package-lock.json"
  ]);
  const apiDocs = configuredProbePaths(baseline, "apiDocs", [
    "/openapi.json",
    "/swagger.json",
    "/swagger-ui",
    "/swagger-ui/index.html",
    "/api-docs",
    "/redoc"
  ]);
  const apiVersionPaths = configuredProbePaths(baseline, "apiVersionPaths", [
    "/api/v1",
    "/api/v1/",
    "/api/v1/users",
    "/api/v1/auth",
    "/api/v2",
    "/api/v2/",
    "/v1",
    "/v1/",
    "/v2",
    "/v2/",
    "/rest/v1",
    "/rest/v2"
  ]);
  const legacyApiPaths = configuredProbePaths(baseline, "legacyApiPaths", [
    "/api/v0",
    "/v0",
    "/api/legacy",
    "/legacy",
    "/api/old",
    "/old",
    "/api/beta",
    "/beta",
    "/api/internal",
    "/internal/api"
  ]);
  const graphqlEndpoints = configuredProbePaths(baseline, "graphqlEndpoints", [
    "/graphql",
    "/graphiql",
    "/graphql/playground",
    "/api/graphql",
    "/v1/graphql"
  ]);
  const uploadPaths = configuredProbePaths(baseline, "uploadPaths", [
    "/upload",
    "/uploads",
    "/files/upload",
    "/api/upload",
    "/api/uploads",
    "/attachments",
    "/import",
    "/export"
  ]);
  const identityEndpoints = configuredProbePaths(baseline, "identityEndpoints", [
    "/.well-known/openid-configuration",
    "/.well-known/jwks.json",
    "/oauth/authorize",
    "/oauth/token",
    "/oauth2/authorize",
    "/oauth2/token",
    "/auth/realms/master/.well-known/openid-configuration"
  ]);
  const oauthCallbackPaths = configuredProbePaths(baseline, "oauthCallbackPaths", [
    "/callback",
    "/auth/callback",
    "/oauth/callback",
    "/oauth2/callback",
    "/oidc/callback",
    "/sso/callback",
    "/login/callback",
    "/signin/callback",
    "/signin-oidc",
    "/api/auth/callback",
    "/api/oauth/callback",
    "/saml/acs"
  ]);
  const authApiPaths = configuredProbePaths(baseline, "authApiPaths", [
    "/api/me",
    "/api/user",
    "/api/users",
    "/api/users/me",
    "/api/profile",
    "/api/account",
    "/api/session",
    "/api/auth/session",
    "/api/auth/me",
    "/api/admin/users",
    "/users/me",
    "/profile",
    "/account"
  ]);
  const accountRecoveryPaths = configuredProbePaths(baseline, "accountRecoveryPaths", [
    "/.well-known/change-password",
    "/change-password",
    "/account/change-password",
    "/settings/password",
    "/forgot-password",
    "/reset-password",
    "/password/forgot",
    "/password/reset",
    "/api/auth/forgot-password",
    "/api/auth/reset-password"
  ]);
  const logoutPaths = configuredProbePaths(baseline, "logoutPaths", [
    "/logout",
    "/log-out",
    "/signout",
    "/sign-out",
    "/sign_out",
    "/session/logout",
    "/session/signout",
    "/sessions/destroy",
    "/auth/logout",
    "/auth/signout",
    "/api/logout",
    "/api/auth/logout",
    "/api/auth/signout"
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
  const metafiles = configuredProbePaths(baseline, "metafiles", [
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml"
  ]);
  const mobileAssociationFiles = configuredProbePaths(baseline, "mobileAssociationFiles", [
    "/.well-known/assetlinks.json",
    "/assetlinks.json",
    "/.well-known/apple-app-site-association",
    "/apple-app-site-association"
  ]);
  const errorPages = configuredProbePaths(baseline, "errorPages", [
    "/.aegis-error-probe-404"
  ]);
  const directoryListings = configuredProbePaths(baseline, "directoryListings", [
    "/uploads/",
    "/files/",
    "/backup/",
    "/backups/",
    "/download/",
    "/downloads/",
    "/assets/",
    "/static/"
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
    probes.push(...probeFactory(scope, target.targetName, target.baseUrl, "backupFiles", backupFiles));
    probes.push(...probeFactory(scope, target.targetName, target.baseUrl, "sensitiveExtensions", sensitiveExtensions));
    probes.push(...probeFactory(scope, target.targetName, target.baseUrl, "apiDocs", apiDocs));
    probes.push(...probeFactory(scope, target.targetName, target.baseUrl, "apiVersionPaths", apiVersionPaths));
    probes.push(...probeFactory(scope, target.targetName, target.baseUrl, "legacyApiPaths", legacyApiPaths));
    probes.push(...probeFactory(scope, target.targetName, target.baseUrl, "graphqlEndpoints", graphqlEndpoints));
    probes.push(...probeFactory(scope, target.targetName, target.baseUrl, "uploadPaths", uploadPaths));
    probes.push(...probeFactory(scope, target.targetName, target.baseUrl, "identityEndpoints", identityEndpoints));
    probes.push(...probeFactory(scope, target.targetName, target.baseUrl, "oauthCallbackPaths", oauthCallbackPaths));
    probes.push(...probeFactory(scope, target.targetName, target.baseUrl, "authApiPaths", authApiPaths));
    probes.push(...probeFactory(scope, target.targetName, target.baseUrl, "accountRecoveryPaths", accountRecoveryPaths));
    probes.push(...probeFactory(scope, target.targetName, target.baseUrl, "logoutPaths", logoutPaths));
    probes.push(...probeFactory(scope, target.targetName, target.baseUrl, "adminPaths", adminPaths));
    probes.push(...probeFactory(scope, target.targetName, target.baseUrl, "debugPaths", debugPaths));
    probes.push(...probeFactory(scope, target.targetName, target.baseUrl, "metafiles", metafiles));
    probes.push(...probeFactory(scope, target.targetName, target.baseUrl, "mobileAssociationFiles", mobileAssociationFiles));
    probes.push(...probeFactory(scope, target.targetName, target.baseUrl, "errorPages", errorPages));
    probes.push(...probeFactory(scope, target.targetName, target.baseUrl, "directoryListings", directoryListings));
    probes.push(...probeFactory(scope, target.targetName, target.baseUrl, "sourceMaps", sourceMapPaths));
    probes.push(...probeFactory(scope, target.targetName, target.baseUrl, "httpMethods", routeMethodPaths, "OPTIONS"));
  }

  return probes.slice(0, Number(probeConfig.maxProbeRequests || 150));
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

function isSoftNotFoundResponse(response) {
  const text = responseText(response);
  if (!contentType(response).includes("text/html")) return false;
  return /<title>\s*(?:404|not found|page not found)/i.test(text)
    || /\b(?:404 not found|page not found|not found|does not exist)\b/i.test(text);
}

function sensitiveContentSignal(text) {
  const value = String(text || "");
  if (/-----BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY-----/i.test(value)) return "private_key";
  if (/\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|password|passwd|pwd|secret)\b\s*[:=]/i.test(value)) return "secret_marker";
  if (/\b(?:spring\.datasource|jdbc:|database_url|connectionstring|db_password|mysql|postgresql)\b/i.test(value)) return "database_config";
  if (/<\?(?:php|=)|<%|package\s+[\w.]+;|import\s+java\./i.test(value)) return "source_code";
  return "";
}

function backupFileSignal(probe, response) {
  if (!isSuccessStatus(response) || isLoginLikeBody(response) || isSoftNotFoundResponse(response)) return "";
  const path = probe.path.toLowerCase();
  const type = contentType(response);
  const text = responseText(response);
  if (path === "/.ds_store" && /Bud1/.test(text)) return "macos_ds_store";
  if (/\.(?:zip|tar\.gz|tgz|gz|rar|7z)$/i.test(path) && /(?:application\/(?:zip|gzip|x-gzip|x-tar|octet-stream)|binary)/i.test(type)) {
    return "backup_archive";
  }
  if (/\.sql(?:\.gz)?$/i.test(path) && /(?:create table|insert into|mysqldump|postgresql|dump completed)/i.test(text)) {
    return "database_dump";
  }
  const contentSignal = sensitiveContentSignal(text);
  if (contentSignal) return contentSignal;
  if (/\.(?:bak|old|orig|tmp|swp)$|~$/i.test(path) && !type.includes("text/html")) return "backup_copy";
  return "";
}

function sensitiveExtensionSignal(probe, response) {
  if (!isSuccessStatus(response) || isLoginLikeBody(response) || isSoftNotFoundResponse(response)) return "";
  const path = probe.path.toLowerCase();
  const type = contentType(response);
  const text = responseText(response);
  const contentSignal = sensitiveContentSignal(text);
  if (contentSignal) return contentSignal;
  if (/\/web-inf\//i.test(path)) return "java_web_inf";
  if (/\.(?:asa|inc|config|properties|ya?ml)$/i.test(path) && !type.includes("text/html")) return "sensitive_extension";
  if (/(?:composer|package-lock)\.json$/i.test(path) && /"(?:packages|dependencies|lockfileVersion)"\s*[:{]/i.test(text)) {
    return "dependency_manifest";
  }
  return "";
}

function directoryListingSignal(response) {
  if (!isSuccessStatus(response) || isLoginLikeBody(response)) return "";
  const text = responseText(response);
  if (/<title>\s*Index of\s+\//i.test(text)) return "index_of";
  if (/\bParent Directory\b/i.test(text) && /<a\s+href=/i.test(text)) return "parent_directory";
  if (/\bDirectory listing for\s+\//i.test(text)) return "directory_listing";
  if (/\[To Parent Directory\]/i.test(text)) return "iis_directory_listing";
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

function apiVersionSignal(probe, response) {
  if (!response.ok || isLoginLikeBody(response) || isSoftNotFoundResponse(response)) return "";
  if (response.status >= 400) return "";
  const type = contentType(response);
  const path = String(probe.path || "").toLowerCase();
  if (type.includes("json")) return "versioned_api_json";
  if (/\/(?:api\/)?v\d+(?:\/|$)/i.test(path) && !type.includes("text/html")) return "versioned_api_response";
  if (/\/(?:api\/)?v\d+(?:\/|$)/i.test(path) && response.status >= 300 && response.status < 400) return "versioned_api_redirect";
  return "";
}

function legacyApiSignal(probe, response) {
  if (!response.ok || isLoginLikeBody(response) || isSoftNotFoundResponse(response)) return "";
  if (response.status >= 400) return "";
  const type = contentType(response);
  const path = String(probe.path || "").toLowerCase();
  if (!/(?:v0|legacy|old|beta|internal)/i.test(path)) return "";
  if (type.includes("json")) return "legacy_api_json";
  if (!type.includes("text/html")) return "legacy_api_response";
  if (response.status >= 300 && response.status < 400) return "legacy_api_redirect";
  return "";
}

function graphqlSignal(response) {
  if (!isSuccessStatus(response) || isLoginLikeBody(response) || isSoftNotFoundResponse(response)) return "";
  const text = responseText(response);
  const type = contentType(response);
  const finalUrl = response.finalUrl || response.url || "";
  if (/graphiql|graphql playground|apollo sandbox|graphql voyager/i.test(text)) return "graphql_ide";
  if (type.includes("json") && /"errors"\s*:\s*\[/.test(text) && /graphql|query|mutation/i.test(text)) return "graphql_json_error";
  if (/graphql/i.test(text) && /(?:query|mutation|operationName|__schema|schema)/i.test(text)) return "graphql_endpoint";
  if (/\/graphql(?:$|[/?#])/i.test(finalUrl)) return "graphql_reachable";
  return "";
}

function uploadSurfaceSignal(probe, response) {
  if (!isSuccessStatus(response) || isLoginLikeBody(response) || isSoftNotFoundResponse(response)) return "";
  const text = responseText(response);
  const type = contentType(response);
  const path = String(probe.path || "").toLowerCase();
  if (/<input\b[^>]*\btype=["']?file["']?/i.test(text)) return "upload_form";
  if (/multipart\/form-data|dropzone|filepond|uppy|upload/i.test(text)) return "upload_ui";
  if (/\/(?:upload|uploads|files|attachments?|import|export)(?:\/|$)/i.test(path) && !type.includes("text/html")) {
    return "file_endpoint";
  }
  if (/\/(?:upload|uploads|files|attachments?|import|export)(?:\/|$)/i.test(path)) return "upload_surface";
  return "";
}

function identityMetadataSignal(probe, response) {
  if (!isSuccessStatus(response) || isLoginLikeBody(response) || isSoftNotFoundResponse(response)) return "";
  const text = responseText(response);
  const type = contentType(response);
  const path = String(probe.path || "").toLowerCase();
  if (path.includes("openid-configuration") && type.includes("json") && /"(?:issuer|authorization_endpoint|jwks_uri)"\s*:/.test(text)) {
    return "openid_configuration";
  }
  if (path.includes("jwks") && type.includes("json") && /"keys"\s*:\s*\[/.test(text)) return "jwks_metadata";
  if (/\/oauth2?\/(?:authorize|token)(?:$|[/?#])/i.test(path) && !isSoftNotFoundResponse(response)) return "oauth_endpoint";
  return "";
}

function unauthenticatedUserApiSignal(probe, response) {
  if (!isSuccessStatus(response) || isLoginLikeBody(response) || isSoftNotFoundResponse(response)) return "";
  const text = responseText(response);
  const type = contentType(response);
  const path = String(probe.path || "").toLowerCase();
  if (type.includes("json") && /"(?:email|username|user(Name)?|account|profile|role|roles|permissions|tenant|organization|session|userId|accountId)"\s*:/i.test(text)) {
    return "user_or_session_json";
  }
  if (type.includes("json") && /\[(?:\s*\{[\s\S]{0,300}"(?:id|email|username|role)"\s*:)/i.test(text)) {
    return "user_collection_json";
  }
  if (/\/(?:api\/)?(?:me|user|users|profile|account|session)(?:\/|$)/i.test(path) && type.includes("json") && text.trim().startsWith("{")) {
    return "auth_api_json";
  }
  return "";
}

function accountRecoverySignal(probe, response) {
  if (!response.ok || isSoftNotFoundResponse(response)) return "";
  const path = String(probe.path || "").toLowerCase();
  if (response.status >= 200 && response.status < 400 && path.includes(".well-known/change-password")) {
    return response.redirects ? "well_known_change_password_redirect" : "well_known_change_password";
  }
  if (response.status >= 200 && response.status < 400 && /(?:change|forgot|reset)[-_]?(?:password|pass)|password\/(?:forgot|reset)/i.test(path)) {
    return response.redirects ? "account_recovery_redirect" : "account_recovery_route";
  }
  return "";
}

function oauthCallbackSignal(probe, response) {
  if (!response.ok || isSoftNotFoundResponse(response)) return "";
  const path = String(probe.path || "").toLowerCase();
  if (!/(?:callback|signin-oidc|saml\/acs)/i.test(path)) return "";
  const finalPath = (() => {
    try {
      return new URL(response.finalUrl || response.url || probe.url).pathname.toLowerCase();
    } catch {
      return "";
    }
  })();
  if (response.redirects && /\/(?:login|signin|sign-in|auth)(?:\/|$)/i.test(finalPath)) {
    return "oauth_callback_rejects_missing_or_anonymous_request";
  }
  if (response.status >= 200 && response.status < 400) return response.redirects ? "oauth_callback_redirect" : "oauth_callback_route";
  if ([400, 401, 403, 405].includes(response.status)) return "oauth_callback_rejects_missing_or_anonymous_request";
  return "";
}

function referrerPolicyProtected(value) {
  const policy = String(value || "").toLowerCase();
  return /\b(?:no-referrer|same-origin|strict-origin|strict-origin-when-cross-origin)\b/.test(policy) && !/\bunsafe-url\b/.test(policy);
}

function urlWithRedactedParameters(value) {
  const raw = String(value || "");
  if (!raw) return "";
  try {
    const parsed = new URL(raw, "https://aegis.invalid");
    const keys = unique([...parsed.searchParams.keys()]);
    parsed.search = keys.map((key) => `${encodeURIComponent(key)}=[redacted]`).join("&");
    parsed.hash = parsed.hash ? "#[redacted]" : "";
    const output = raw.startsWith("/") ? `${parsed.pathname}${parsed.search}${parsed.hash}` : parsed.toString();
    return output.slice(0, 240);
  } catch {
    return raw.split(/[?#]/)[0].slice(0, 240);
  }
}

function oauthCallbackEvidence(probe, response, signal) {
  return {
    target: probe.targetName,
    path: probe.path,
    requestedUrl: response.requestedUrl || probe.url,
    finalUrl: response.finalUrl || response.url,
    status: response.status || 0,
    signal,
    contentType: contentType(response),
    cacheControl: headerValue(response, "cache-control"),
    referrerPolicy: headerValue(response, "referrer-policy"),
    location: urlWithRedactedParameters(headerValue(response, "location"))
  };
}

function logoutRouteSignal(probe, response) {
  if (!response.ok || isSoftNotFoundResponse(response)) return "";
  const path = String(probe.path || "").toLowerCase();
  if (!/(?:logout|log-out|signout|sign-out|sign_out|sessions?\/destroy)/i.test(path)) return "";
  if (response.status >= 200 && response.status < 400) return response.redirects ? "logout_redirect" : "logout_route";
  if (response.status === 401 || response.status === 403) return "logout_requires_auth";
  if (response.status === 405) return "logout_requires_non_get_method";
  return "";
}

function clearSiteDataDirectives(value) {
  return String(value || "")
    .split(",")
    .map((part) => part.trim().replace(/^"|"$/g, "").toLowerCase())
    .filter(Boolean);
}

function cookieClearsValue(cookie) {
  const value = String(cookie || "");
  if (/\bmax-age\s*=\s*0\b/i.test(value)) return true;
  const expires = value.match(/\bexpires\s*=\s*([^;]+)/i);
  if (!expires) return false;
  const time = Date.parse(expires[1]);
  return Number.isFinite(time) && time <= Date.now();
}

function logoutCleanupEvidence(probe, response, signal) {
  const clearSiteData = headerValue(response, "clear-site-data");
  const clearedCookies = (response.setCookies || [])
    .filter(cookieClearsValue)
    .map(cookieName)
    .filter(Boolean);
  return {
    target: probe.targetName,
    path: probe.path,
    requestedUrl: response.requestedUrl || probe.url,
    finalUrl: response.finalUrl || response.url,
    status: response.status || 0,
    signal,
    cacheControl: headerValue(response, "cache-control"),
    clearSiteData,
    clearSiteDataDirectives: clearSiteDataDirectives(clearSiteData),
    clearedCookies
  };
}

function securityTxtEvidence(probe, response) {
  const text = responseText(response);
  const present = isSuccessStatus(response) && !isSoftNotFoundResponse(response) && /(?:^|\n)\s*Contact\s*:/im.test(text);
  return {
    target: probe.targetName,
    path: probe.path,
    requestedUrl: response.requestedUrl || probe.url,
    finalUrl: response.finalUrl || response.url,
    status: response.status || 0,
    contentType: contentType(response),
    present,
    contactPresent: /(?:^|\n)\s*Contact\s*:/im.test(text),
    expiresPresent: /(?:^|\n)\s*Expires\s*:/im.test(text),
    policyPresent: /(?:^|\n)\s*Policy\s*:/im.test(text),
    preferredLanguagesPresent: /(?:^|\n)\s*Preferred-Languages\s*:/im.test(text)
  };
}

function mobileAssociationSignal(probe, response) {
  if (!isSuccessStatus(response) || isSoftNotFoundResponse(response)) return "";
  const path = String(probe.path || "").toLowerCase();
  const text = responseText(response);
  const type = contentType(response);
  if (path.endsWith("assetlinks.json") && (type.includes("json") || /"namespace"\s*:\s*"android_app"|"sha256_cert_fingerprints"/i.test(text))) {
    return "android_assetlinks";
  }
  if (path.endsWith("apple-app-site-association") && (type.includes("json") || /"applinks"\s*:|"appIDs?"\s*:/i.test(text))) {
    return "apple_app_site_association";
  }
  return "";
}

function parseJsonPreview(text) {
  try {
    return JSON.parse(String(text || ""));
  } catch {
    return null;
  }
}

function mobileAssociationEvidence(probe, response, signal) {
  const text = responseText(response);
  const parsed = parseJsonPreview(text);
  const evidence = {
    target: probe.targetName,
    path: probe.path,
    requestedUrl: response.requestedUrl || probe.url,
    finalUrl: response.finalUrl || response.url,
    status: response.status || 0,
    signal,
    contentType: contentType(response),
    relationCount: 0,
    appIdentifierCount: 0,
    packageCount: 0,
    pathPatternCount: 0,
    broadPathPatterns: [],
    parseableJson: Boolean(parsed)
  };
  if (!parsed) return evidence;

  if (Array.isArray(parsed)) {
    evidence.relationCount = parsed.length;
    const packages = [];
    for (const item of parsed) {
      if (item?.target?.package_name) packages.push(item.target.package_name);
    }
    evidence.packageCount = unique(packages).length;
    evidence.androidNamespaces = unique(parsed.map((item) => item?.target?.namespace)).filter(Boolean);
    return evidence;
  }

  const details = Array.isArray(parsed?.applinks?.details) ? parsed.applinks.details : [];
  const appIds = [];
  const pathPatterns = [];
  for (const detail of details) {
    if (detail?.appID) appIds.push(detail.appID);
    if (Array.isArray(detail?.appIDs)) appIds.push(...detail.appIDs);
    if (Array.isArray(detail?.paths)) pathPatterns.push(...detail.paths);
    if (Array.isArray(detail?.components)) {
      for (const component of detail.components) {
        if (component?.["/"]) pathPatterns.push(component["/"]);
      }
    }
  }
  evidence.relationCount = details.length;
  evidence.appIdentifierCount = unique(appIds).length;
  evidence.pathPatternCount = pathPatterns.length;
  evidence.broadPathPatterns = unique(pathPatterns.filter((pattern) => ["*", "/*", "/"].includes(String(pattern || "").trim()))).slice(0, 10);
  return evidence;
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

function metafileSignal(probe, response) {
  if (!isSuccessStatus(response)) return "";
  const path = String(probe.path || "").toLowerCase();
  const text = responseText(response);
  const sensitivePath = /(?:admin|internal|private|backup|debug|manage|console|secret|token|config|staging)/i;
  if (path.endsWith("/robots.txt")) {
    const disallowLines = text.split(/\r?\n/).filter((line) => /^\s*disallow\s*:/i.test(line));
    if (disallowLines.some((line) => sensitivePath.test(line))) return "robots_sensitive_disallow";
  }
  if (path.endsWith("/sitemap.xml") && /<loc>[^<]*(?:admin|internal|private|backup|debug|manage|console|secret|token|config|staging)/i.test(text)) {
    return "sitemap_sensitive_path";
  }
  if (path.endsWith("/crossdomain.xml") && /<allow-access-from\b[^>]*\bdomain=["']\*["']/i.test(text)) {
    return "permissive_crossdomain_policy";
  }
  if (path.endsWith("/clientaccesspolicy.xml") && /<domain\b[^>]*\buri=["']\*["']/i.test(text)) {
    return "permissive_crossdomain_policy";
  }
  return "";
}

function errorDisclosureSignal(response) {
  if (!response.ok || response.status < 400) return "";
  const text = responseText(response);
  if (!text) return "";
  const patterns = [
    /\bstack trace\b/i,
    /\btraceback \(most recent call last\)/i,
    /\b(?:nullpointerexception|runtimeexception|illegalargumentexception)\b/i,
    /\bjava\.lang\.[a-z]+exception\b/i,
    /\borg\.springframework\./i,
    /\bat\s+[\w.$<>]+\([^)]*:\d+\)/,
    /\b(?:sql syntax|mysql|postgresql|ora-\d{5}|sqliteexception)\b/i,
    /\b(?:warning|fatal error):\s+.+\s+on line\s+\d+/i,
    /\b(?:express|next\.js|django|rails|laravel)\b.{0,80}\b(?:error|exception)\b/i
  ];
  return patterns.some((pattern) => pattern.test(text)) ? "stack_or_error_detail" : "";
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

function redirectParameterEvidence(discovery) {
  const redirectParam = /^(?:next|url|uri|redirect|redirect_uri|return|returnurl|return_url|continue|callback|target|to|dest|destination|forward|goto|return_to)$/i;
  const candidates = [];
  const inspectUrl = (source, url, status = undefined) => {
    if (!url) return;
    try {
      const parsed = new URL(url);
      for (const key of parsed.searchParams.keys()) {
        if (redirectParam.test(key)) {
          candidates.push({ source, path: parsed.pathname, parameter: key, status });
        }
      }
    } catch {
      // Ignore non-URL form actions in passive redirect-parameter inventory.
    }
  };
  for (const route of discovery?.routes || []) {
    inspectUrl("route", route.url, route.status);
  }
  for (const form of discovery?.forms || []) {
    inspectUrl("form_page", form.page_url);
    inspectUrl("form_action", form.action_url);
  }
  return candidates.slice(0, 30);
}

function externalRedirectDestinationEvidence(discovery) {
  const redirectParam = /^(?:next|url|uri|redirect|redirect_uri|return|returnurl|return_url|continue|callback|target|to|dest|destination|forward|goto|return_to)$/i;
  const candidates = [];
  const inspectUrl = (source, url, status = undefined, baseUrl = undefined) => {
    if (!url) return;
    let parsed;
    try {
      parsed = baseUrl ? new URL(url, baseUrl) : new URL(url);
    } catch {
      return;
    }
    for (const key of unique([...parsed.searchParams.keys()])) {
      if (!redirectParam.test(key)) continue;
      const rawValue = String(parsed.searchParams.get(key) || "").trim();
      if (!/^(?:https?:)?\/\//i.test(rawValue)) continue;
      try {
        const destination = new URL(rawValue, parsed);
        if (!["http:", "https:"].includes(destination.protocol)) continue;
        if (destination.origin === parsed.origin) continue;
        candidates.push({
          source,
          path: parsed.pathname,
          parameter: key,
          status,
          sourceHost: parsed.hostname,
          destinationHost: destination.hostname,
          destinationProtocol: destination.protocol.replace(":", ""),
          signal: destination.protocol === "http:" ? "external_cleartext_redirect_destination" : "external_redirect_destination"
        });
      } catch {
        // Ignore malformed redirect parameter values in passive inventory.
      }
    }
  };
  for (const route of discovery?.routes || []) {
    inspectUrl("route", route.url, route.status);
  }
  for (const form of discovery?.forms || []) {
    inspectUrl("form_page", form.page_url);
    inspectUrl("form_action", form.action_url, undefined, form.page_url);
  }
  return candidates.slice(0, 30);
}

function duplicateParameterEvidence(discovery) {
  const candidates = [];
  const inspectUrl = (source, url, status = undefined) => {
    if (!url) return;
    try {
      const parsed = new URL(url);
      const counts = new Map();
      for (const key of parsed.searchParams.keys()) {
        counts.set(key, (counts.get(key) || 0) + 1);
      }
      for (const [parameter, count] of counts.entries()) {
        if (count > 1) candidates.push({ source, path: parsed.pathname, parameter, count, status });
      }
    } catch {
      // Ignore malformed discovery URLs in passive HPP inventory.
    }
  };
  for (const route of discovery?.routes || []) {
    inspectUrl("route", route.url, route.status);
  }
  for (const form of discovery?.forms || []) {
    inspectUrl("form_page", form.page_url);
    inspectUrl("form_action", form.action_url);
  }
  return candidates.slice(0, 30);
}

function urlParameterEntries(url, baseUrl = undefined) {
  if (!url) return [];
  try {
    const parsed = baseUrl ? new URL(url, baseUrl) : new URL(url);
    const entries = [];
    for (const key of unique([...parsed.searchParams.keys()])) {
      entries.push({ location: "query", path: parsed.pathname, parameter: key });
    }
    const fragment = parsed.hash.replace(/^#/, "");
    if (fragment) {
      const queryStart = fragment.indexOf("?");
      const paramText = queryStart >= 0 ? fragment.slice(queryStart + 1) : fragment;
      const fragmentPath = queryStart >= 0 ? fragment.slice(0, queryStart) : "";
      if (paramText.includes("=")) {
        for (const key of unique([...new URLSearchParams(paramText).keys()])) {
          entries.push({
            location: "fragment",
            path: parsed.pathname,
            fragmentPath: fragmentPath || undefined,
            parameter: key
          });
        }
      }
    }
    return entries;
  } catch {
    return [];
  }
}

function sensitiveUrlParameterEvidence(discovery) {
  const sensitiveParam = /^(?:access[_-]?token|refresh[_-]?token|id[_-]?token|token|jwt|session|sid|auth|authorization|password|passwd|pwd|secret|api[_-]?key|apikey|key|credential|otp|mfa|code)$/i;
  const candidates = [];
  const inspectUrl = (source, url, status = undefined, baseUrl = undefined) => {
    for (const entry of urlParameterEntries(url, baseUrl)) {
      if (sensitiveParam.test(entry.parameter)) {
        candidates.push({ source, ...entry, status });
      }
    }
  };
  for (const route of discovery?.routes || []) {
    inspectUrl("route", route.url, route.status);
  }
  for (const form of discovery?.forms || []) {
    inspectUrl("form_page", form.page_url);
    inspectUrl("form_action", form.action_url, undefined, form.page_url);
  }
  return candidates.slice(0, 30);
}

function authFlowTokenEvidence(discovery) {
  const authParam = /^(?:access[_-]?token|refresh[_-]?token|id[_-]?token|token|jwt|code|otp|mfa|ticket|reset[_-]?token|invite[_-]?token|verification[_-]?token)$/i;
  const flowPath = /(?:reset|forgot|password|verify|verification|activate|activation|invite|invitation|magic|callback|oauth|oidc|sso|auth|login|signin|mfa|otp)/i;
  const candidates = [];
  const classify = (entry) => {
    const context = `${entry.path || ""} ${entry.fragmentPath || ""} ${entry.parameter || ""}`;
    if (/(?:oauth|oidc|sso|callback|access[_-]?token|id[_-]?token|refresh[_-]?token|\bcode\b)/i.test(context)) return "oauth_or_sso";
    if (/(?:reset|forgot|password|reset[_-]?token)/i.test(context)) return "password_reset";
    if (/(?:verify|verification|activate|activation|verification[_-]?token)/i.test(context)) return "verification";
    if (/(?:invite|invitation|invite[_-]?token)/i.test(context)) return "invitation";
    if (/(?:magic|otp|mfa|ticket)/i.test(context)) return "magic_link_or_mfa";
    return "auth_flow";
  };
  const inspectUrl = (source, url, status = undefined, baseUrl = undefined) => {
    for (const entry of urlParameterEntries(url, baseUrl)) {
      const context = `${entry.path || ""} ${entry.fragmentPath || ""}`;
      if (!authParam.test(entry.parameter) || !flowPath.test(`${context} ${entry.parameter}`)) continue;
      candidates.push({ source, ...entry, flow: classify(entry), status });
    }
  };
  for (const route of discovery?.routes || []) {
    inspectUrl("route", route.url, route.status);
  }
  for (const form of discovery?.forms || []) {
    inspectUrl("form_page", form.page_url);
    inspectUrl("form_action", form.action_url, undefined, form.page_url);
  }
  return candidates.slice(0, 30);
}

function oauthAuthorizationRequestEvidence(discovery) {
  const candidates = [];
  const inspectUrl = (source, url, status = undefined, baseUrl = undefined) => {
    if (!url) return;
    try {
      const parsed = baseUrl ? new URL(url, baseUrl) : new URL(url);
      const params = parsed.searchParams;
      const parameterNames = unique([...params.keys()]);
      const pathLooksOauth = /\/(?:oauth2?|oidc|sso|auth)\/(?:authorize|login|connect)|\/authorize(?:$|[/?#])/i.test(parsed.pathname);
      const hasOauthParams = parameterNames.some((key) => /^(?:client_id|redirect_uri|response_type|scope|state|nonce|code_challenge|code_challenge_method|response_mode)$/i.test(key));
      if (!pathLooksOauth && !hasOauthParams) return;

      const signals = [];
      const responseType = String(params.get("response_type") || "").toLowerCase();
      const responseMode = String(params.get("response_mode") || "").toLowerCase();
      const redirectUri = String(params.get("redirect_uri") || "");
      if (/\b(?:token|id_token)\b/.test(responseType)) signals.push("implicit_response_type");
      if (responseType && !params.has("state")) signals.push("state_not_observed");
      if (responseType.includes("code") && !params.has("code_challenge")) signals.push("pkce_not_observed");
      if (responseMode && responseMode !== "form_post" && /\b(?:token|id_token)\b/.test(responseType)) signals.push("response_mode_not_form_post");
      try {
        if (redirectUri) {
          const redirect = new URL(redirectUri);
          if (redirect.protocol === "http:" && !isLoopback(redirect.hostname)) signals.push("cleartext_redirect_uri");
        }
      } catch {
        if (redirectUri) signals.push("unparseable_redirect_uri");
      }

      candidates.push({
        source,
        path: parsed.pathname,
        status,
        parameters: parameterNames.filter((key) => /^(?:client_id|redirect_uri|response_type|scope|state|nonce|code_challenge|code_challenge_method|response_mode)$/i.test(key)),
        signals
      });
    } catch {
      // Ignore malformed OAuth authorization request candidates.
    }
  };
  for (const route of discovery?.routes || []) {
    inspectUrl("route", route.url, route.status);
  }
  for (const form of discovery?.forms || []) {
    inspectUrl("form_page", form.page_url);
    inspectUrl("form_action", form.action_url, undefined, form.page_url);
  }
  return candidates.slice(0, 30);
}

function pathFromUrl(url, baseUrl = undefined) {
  try {
    return (baseUrl ? new URL(url, baseUrl) : new URL(url)).pathname;
  } catch {
    return String(url || "").split(/[?#]/)[0].slice(0, 160);
  }
}

function normalizedInputName(value) {
  return String(value || "")
    .replace(/\[\]/g, "")
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .replace(/[\[\].:-]+/g, "_")
    .toLowerCase();
}

function massAssignmentFieldRisk(name) {
  const normalized = normalizedInputName(name);
  const parts = normalized.split(/[_\s-]+/).filter(Boolean);
  if (!parts.length) return "";
  if (parts.includes("isadmin") || parts.includes("admin") || parts.includes("superuser") || parts.includes("root")) {
    return "privilege_escalation_property";
  }
  if (parts.some((part) => ["role", "roles", "permission", "permissions", "scope", "scopes", "privilege", "privileges"].includes(part))) {
    return "authorization_property";
  }
  if (parts.some((part) => ["tenant", "tenantid", "organization", "organizationid", "orgid", "owner", "ownerid"].includes(part))) {
    return "tenancy_or_ownership_property";
  }
  if (parts.some((part) => ["enabled", "disabled", "active", "verified", "emailverified", "locked", "status"].includes(part))) {
    return "account_state_property";
  }
  if (parts.some((part) => ["plan", "price", "credit", "balance", "quota", "billing"].includes(part))) {
    return "billing_or_entitlement_property";
  }
  return "";
}

function massAssignmentFieldEvidence(discovery) {
  const candidates = [];
  const inspectName = (source, name, context = {}) => {
    const risk = massAssignmentFieldRisk(name);
    if (!risk) return;
    candidates.push({
      source,
      path: context.path || "",
      action: context.action || "",
      method: context.method || "GET",
      field: name,
      type: context.type || "",
      risk
    });
  };
  const inspectUrl = (source, url, status = undefined, method = "GET", baseUrl = undefined) => {
    for (const entry of urlParameterEntries(url, baseUrl)) {
      const risk = massAssignmentFieldRisk(entry.parameter);
      if (!risk) continue;
      candidates.push({
        source,
        location: entry.location,
        path: entry.path,
        parameter: entry.parameter,
        method,
        status,
        risk
      });
    }
  };

  for (const route of discovery?.routes || []) {
    inspectUrl("route", route.url, route.status, "GET");
  }
  for (const form of discovery?.forms || []) {
    const method = String(form.method || "GET").toUpperCase();
    const pagePath = pathFromUrl(form.page_url);
    const actionPath = pathFromUrl(form.action_url || form.page_url, form.page_url);
    inspectUrl("form_page", form.page_url, undefined, method);
    inspectUrl("form_action", form.action_url, undefined, method, form.page_url);
    for (const control of form.controls || []) {
      inspectName("form_field", control.name || control.id || "", {
        path: pagePath,
        action: actionPath,
        method,
        type: control.type || ""
      });
    }
  }
  return candidates.slice(0, 40);
}

function ssrfParameterRisk(name, path = "", method = "GET", type = "") {
  const normalized = normalizedInputName(name);
  const context = `${normalized} ${path} ${method} ${type}`.toLowerCase();
  if (!normalized) return "";
  if (/(?:^|_)(?:webhook|callback|endpoint|proxy|fetch|remote|feed)(?:_|$)/.test(normalized)) {
    return "server_side_fetch_parameter";
  }
  if (/(?:^|_)(?:image|avatar|file|document|attachment|media)(?:_|$)/.test(normalized) && /(?:url|uri|link|remote)/.test(normalized)) {
    return "remote_media_fetch_parameter";
  }
  if (/(?:^|_)(?:url|uri|link|target|source|dest|destination)(?:_|$)/.test(normalized)) {
    if (/(?:import|export|fetch|proxy|webhook|callback|avatar|image|media|upload|download|render|preview|integrations?|connectors?)/.test(context)) {
      return "url_fetch_candidate";
    }
    return "navigation_or_redirect_parameter";
  }
  if (String(type || "").toLowerCase() === "url") {
    return /(?:import|fetch|proxy|webhook|callback|avatar|image|media|upload|download|render|preview)/.test(context)
      ? "url_input_control"
      : "navigation_or_redirect_parameter";
  }
  return "";
}

function ssrfParameterEvidence(discovery) {
  const candidates = [];
  const inspectEntry = (source, entry, context = {}) => {
    const name = entry.parameter || context.field || "";
    const risk = ssrfParameterRisk(name, entry.path || context.path || "", context.method || "GET", context.type || "");
    if (!risk) return;
    candidates.push({
      source,
      location: entry.location || context.location || "",
      path: entry.path || context.path || "",
      action: context.action || "",
      parameter: entry.parameter || undefined,
      field: context.field || undefined,
      method: context.method || "GET",
      status: context.status,
      type: context.type || "",
      risk
    });
  };
  const inspectUrl = (source, url, status = undefined, method = "GET", baseUrl = undefined) => {
    for (const entry of urlParameterEntries(url, baseUrl)) {
      inspectEntry(source, entry, { method, status });
    }
  };

  for (const route of discovery?.routes || []) {
    inspectUrl("route", route.url, route.status, "GET");
  }
  for (const form of discovery?.forms || []) {
    const method = String(form.method || "GET").toUpperCase();
    const pagePath = pathFromUrl(form.page_url);
    const actionPath = pathFromUrl(form.action_url || form.page_url, form.page_url);
    inspectUrl("form_page", form.page_url, undefined, method);
    inspectUrl("form_action", form.action_url, undefined, method, form.page_url);
    for (const control of form.controls || []) {
      const field = control.name || control.id || "";
      inspectEntry("form_field", {}, {
        field,
        path: pagePath,
        action: actionPath,
        method,
        type: control.type || ""
      });
    }
  }
  return candidates.slice(0, 40);
}

function inputAttackSurfaceCandidates(discovery) {
  const candidates = [];
  const pushRoutePath = (route) => {
    const path = route.path || route.url || "";
    if (!path) return;
    candidates.push({
      source: "route_path",
      method: "GET",
      path,
      status: route.status
    });
  };
  const inspectUrl = (source, url, status = undefined, method = "GET", baseUrl = undefined) => {
    if (!url) return;
    try {
      const parsed = baseUrl ? new URL(url, baseUrl) : new URL(url);
      candidates.push({
        source,
        method,
        path: parsed.pathname,
        status
      });
      for (const key of unique([...parsed.searchParams.keys()])) {
        candidates.push({
          source: `${source}_query`,
          method,
          path: parsed.pathname,
          parameter: key,
          status
        });
      }
    } catch {
      // Discovery may contain intentionally relative form actions.
    }
  };
  for (const route of discovery?.routes || []) {
    pushRoutePath(route);
    inspectUrl("route", route.url, route.status, "GET");
  }
  for (const form of discovery?.forms || []) {
    const method = String(form.method || "GET").toUpperCase();
    inspectUrl("form_page", form.page_url, undefined, method);
    inspectUrl("form_action", form.action_url, undefined, method, form.page_url);
    for (const control of form.controls || []) {
      const field = control.name || control.id || control.type || "";
      if (!field) continue;
      candidates.push({
        source: "form_field",
        method,
        path: (() => {
          try {
            return new URL(form.page_url).pathname;
          } catch {
            return form.page_url || "";
          }
        })(),
        action: form.action_url || "",
        field,
        type: control.type || ""
      });
    }
  }
  return candidates.slice(0, 400);
}

function attackSurfaceText(candidate) {
  return [
    candidate.path,
    candidate.action,
    candidate.parameter,
    candidate.field,
    candidate.type,
    candidate.source,
    candidate.method
  ].filter(Boolean).join(" ");
}

function attackSurfaceEvidence(discovery) {
  const candidates = inputAttackSurfaceCandidates(discovery);
  const categories = [];
  for (const rule of ATTACK_SURFACE_RULES) {
    const matches = candidates.filter((candidate) => rule.patterns.some((pattern) => pattern.test(attackSurfaceText(candidate))));
    if (!matches.length) continue;
    categories.push({
      id: rule.id,
      label: rule.label,
      review: rule.review,
      count: matches.length,
      samples: matches.slice(0, 10)
    });
  }
  return {
    totalCandidates: candidates.length,
    categories,
    coverage: ATTACK_SURFACE_RULES.map((rule) => ({ id: rule.id, label: rule.label, matched: categories.some((item) => item.id === rule.id) }))
  };
}

function isClientReviewAsset(url) {
  try {
    return /\.(?:js|mjs|json)(?:$|\?)/i.test(new URL(url).pathname);
  } catch {
    return false;
  }
}

function extractClientReviewAssets(response) {
  if (!isSuccessStatus(response) || !isHtmlResponse(response)) return [];
  const baseUrl = response.finalUrl || response.url;
  const assets = [];
  for (const match of clientCodeText(response).matchAll(/<(?:script|link)\b[^>]*(?:\bsrc\b|\bhref\b)[^>]*>/gi)) {
    const tag = match[0];
    const asset = attrValue(tag, "src") || attrValue(tag, "href");
    if (!asset) continue;
    try {
      const url = new URL(asset, baseUrl).toString();
      if (isClientReviewAsset(url)) assets.push(url);
    } catch {
      // Ignore malformed asset references from partially captured HTML.
    }
  }
  return unique(assets).slice(0, 30);
}

function contentReviewTargets(scope, latestScan, baseline, responses = []) {
  const maxAssets = configuredNumber(baseline, "maxContentReviewAssets", 12);
  const routes = latestScan?.discovery?.routes || [];
  return unique(
    [
      ...routes.map((route) => route.url).filter(isClientReviewAsset),
      ...responses.flatMap(extractClientReviewAssets)
    ]
      .filter((url) => isAllowedUrl(url, scope, "frontend"))
  ).slice(0, Math.max(0, maxAssets));
}

function clientSecretSignals(response) {
  if (!isSuccessStatus(response)) return [];
  const text = clientCodeText(response);
  const patterns = [
    ["private_key", /-----BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY-----/i],
    ["aws_access_key", /\bAKIA[0-9A-Z]{16}\b/],
    ["google_api_key", /\bAIza[0-9A-Za-z_-]{20,}\b/],
    ["jwt_literal", /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/],
    ["secret_assignment", /\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|password|secret)\b\s*[:=]\s*["'][^"']{8,}["']/i]
  ];
  return patterns.filter(([, pattern]) => pattern.test(text)).map(([name]) => name);
}

function clientCodeText(response) {
  return String(response.bodyPreview || "").slice(0, 16384);
}

function clientBehaviorSignals(response) {
  if (!isSuccessStatus(response)) return [];
  const text = clientCodeText(response);
  const signals = [];
  const clientInput = String.raw`(?:location\.(?:href|search|hash)|document\.(?:URL|documentURI|referrer)|URLSearchParams|searchParams|window\.name)`;
  const domSink = String.raw`(?:innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval|setTimeout|setInterval|Function\s*\()`;
  const domPattern = new RegExp(`${domSink}[\\s\\S]{0,260}${clientInput}|${clientInput}[\\s\\S]{0,260}${domSink}`, "i");
  const templatePattern = new RegExp(String.raw`(?:dangerouslySetInnerHTML|v-html|ng-bind-html|x-html)[\s\S]{0,260}${clientInput}|\{\{[^}]{0,180}${clientInput}[^}]{0,180}\}\}`, "i");
  if (/postMessage\s*\([^)]*,\s*["']\*["']/i.test(text)) signals.push("postmessage_wildcard_target");
  if (/addEventListener\s*\(\s*["']message["']/i.test(text) && !/(?:^|[.\s])origin\b|event\.origin|e\.origin/i.test(text)) {
    signals.push("message_listener_without_origin_check");
  }
  if (domPattern.test(text)) signals.push("dom_xss_source_to_sink");
  if (templatePattern.test(text)) signals.push("client_template_injection");
  if (/(?:__proto__|constructor\s*\[\s*["']prototype["']\s*\]|constructor\.prototype)/i.test(text)
    && /(?:URLSearchParams|location\.(?:search|hash)|qs\.parse|queryString\.parse|JSON\.parse|merge|assign|defaultsDeep|cloneDeep)/i.test(text)) {
    signals.push("prototype_pollution_candidate");
  }
  if (/(?:window\.)?location(?:\.(?:href|assign|replace))?\s*(?:=|\()\s*[^;]{0,220}(?:URLSearchParams|location\.(?:search|hash)|document\.(?:URL|location))/is.test(text)) {
    signals.push("client_redirect_from_url");
  }
  if (/(?:iframe|script|img|link|audio|video)\.src\s*=\s*[^;]{0,220}(?:URLSearchParams|location\.|searchParams)/is.test(text)
    || /createElement\(\s*["'](?:script|iframe)["']\)[\s\S]{0,300}\.src\s*=/i.test(text)) {
    signals.push("resource_url_from_client_input");
  }
  if (/(?:localStorage|sessionStorage)\.setItem\(\s*["'][^"']*(?:token|secret|password|jwt|auth|session)[^"']*/i.test(text)) {
    signals.push("sensitive_browser_storage_key");
  }
  if (/document\.write\s*\([^)]*(?:location|document\.URL|URLSearchParams)/i.test(text)) {
    signals.push("document_write_from_url");
  }
  return unique(signals);
}

function cloudStorageReferences(response) {
  if (!isSuccessStatus(response)) return [];
  const text = clientCodeText(response);
  const providers = [
    ["aws_s3", /(?:^|\.)s3(?:[-.][a-z0-9-]+)?\.amazonaws\.com$|(?:^|\.)s3-website[-.][a-z0-9-]+\.amazonaws\.com$/i],
    ["google_cloud_storage", /(?:^|\.)storage\.googleapis\.com$/i],
    ["azure_blob", /(?:^|\.)blob\.core\.windows\.net$/i],
    ["firebase_storage", /(?:^|\.)firebasestorage\.googleapis\.com$/i],
    ["digitalocean_spaces", /(?:^|\.)digitaloceanspaces\.com$/i],
    ["cloudflare_r2", /(?:^|\.)r2\.dev$/i]
  ];
  const refs = [];
  for (const match of text.matchAll(/https?:\/\/([a-z0-9.-]+)(?::\d+)?\/[^\s"'<>)]*/gi)) {
    const host = match[1].toLowerCase();
    const provider = providers.find(([, pattern]) => pattern.test(host));
    if (provider) refs.push({ host, provider: provider[0] });
  }
  return [...new Map(refs.map((ref) => [`${ref.provider}:${ref.host}`, ref])).values()].slice(0, 20);
}

function decodeBase64UrlJson(value) {
  try {
    const normalized = String(value || "").replace(/-/g, "+").replace(/_/g, "/");
    const padding = "=".repeat((4 - (normalized.length % 4)) % 4);
    return JSON.parse(Buffer.from(`${normalized}${padding}`, "base64").toString("utf8"));
  } catch {
    return null;
  }
}

function jwtLiteralEvidence(response) {
  if (!isSuccessStatus(response)) return [];
  const seen = new Set();
  const tokens = [];
  for (const match of clientCodeText(response).matchAll(/\b(eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*)\b/g)) {
    const token = match[1];
    if (seen.has(token)) continue;
    seen.add(token);
    const [headerPart, payloadPart, signaturePart = ""] = token.split(".");
    const header = decodeBase64UrlJson(headerPart) || {};
    const payload = decodeBase64UrlJson(payloadPart) || {};
    const alg = String(header.alg || "");
    const signals = [];
    if (!alg) signals.push("missing_alg");
    if (/^none$/i.test(alg)) signals.push("unsigned_alg_none");
    if (!signaturePart) signals.push("empty_signature");
    tokens.push({
      url: response.finalUrl || response.url,
      alg,
      typ: String(header.typ || ""),
      kidPresent: Boolean(header.kid),
      payloadClaims: Object.keys(payload).filter((key) => /^(?:iss|sub|aud|exp|nbf|iat|jti|role|scope|email)$/i.test(key)).slice(0, 12),
      signals
    });
  }
  return tokens.slice(0, 20);
}

function websocketReferences(response) {
  if (!isSuccessStatus(response)) return [];
  const refs = [];
  const text = clientCodeText(response);
  for (const match of text.matchAll(/\b(wss?:\/\/[^\s"'`),;]+)\b/gi)) {
    try {
      const parsed = new URL(match[1]);
      const signal = parsed.protocol === "ws:" && !isLoopback(parsed.hostname) ? "cleartext_public_websocket" : "websocket_endpoint";
      refs.push({
        url: response.finalUrl || response.url,
        endpointHost: parsed.hostname,
        scheme: parsed.protocol.replace(":", ""),
        signal
      });
    } catch {
      // Ignore malformed WebSocket-like strings from minified bundles.
    }
  }
  return [...new Map(refs.map((ref) => [`${ref.scheme}:${ref.endpointHost}:${ref.signal}`, ref])).values()].slice(0, 20);
}

function xssiJsonEvidence(response) {
  if (!isSuccessStatus(response)) return null;
  const finalUrl = response.finalUrl || response.url;
  const type = contentType(response);
  if (!type.includes("json") && !/\.json(?:$|\?)/i.test(finalUrl)) return null;
  const text = clientCodeText(response).trimStart();
  if (!text) return null;
  const hasAntiXssiPrefix = /^\)\]\}',?\s*\n/.test(text) || /^while\s*\(\s*1\s*\)\s*;/.test(text) || /^for\s*\(\s*;;\s*\)\s*;/.test(text);
  const topLevelArray = text.startsWith("[");
  const topLevelObject = text.startsWith("{");
  if (!topLevelArray && !topLevelObject) return null;
  return {
    url: finalUrl,
    contentType: type,
    topLevel: topLevelArray ? "array" : "object",
    hasAntiXssiPrefix,
    nosniff: /\bnosniff\b/i.test(headerValue(response, "x-content-type-options"))
  };
}

async function evaluateClientContentLeakage(findings, scope, latestScan, baseline, responses = []) {
  const targets = contentReviewTargets(scope, latestScan, baseline, responses);
  const reviews = [];
  for (const url of targets) {
    const response = await requestHeaders(url, 0, { method: "GET", maxBodyBytes: 16384 });
    const signals = clientSecretSignals(response);
    const behaviorSignals = clientBehaviorSignals(response);
    const cloudStorage = cloudStorageReferences(response);
    const jwtLiterals = jwtLiteralEvidence(response);
    const websockets = websocketReferences(response);
    const xssiJson = xssiJsonEvidence(response);
    reviews.push({
      url,
      finalUrl: response.finalUrl || response.url,
      status: response.status || 0,
      contentType: headerValue(response, "content-type"),
      signals,
      behaviorSignals,
      cloudStorage,
      jwtLiterals,
      websockets,
      xssiJson,
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
  const webMessaging = reviews
    .filter((review) => review.behaviorSignals.includes("postmessage_wildcard_target") || review.behaviorSignals.includes("message_listener_without_origin_check"))
    .map((review) => ({ url: review.url, finalUrl: review.finalUrl, status: review.status, signals: review.behaviorSignals.filter((signal) => signal.includes("message")) }));
  addFinding(
    findings,
    "warning",
    "frontend.content.web_messaging",
    "Client-side bundles avoid risky Web Messaging patterns",
    webMessaging.length === 0,
    "OWASP WSTG Web Messaging testing reviews postMessage target origins and message event origin validation.",
    { checked: reviews.length, exposed: webMessaging }
  );
  const domXss = reviews
    .filter((review) => review.behaviorSignals.includes("dom_xss_source_to_sink"))
    .map((review) => ({ url: review.url, finalUrl: review.finalUrl, status: review.status, signals: ["dom_xss_source_to_sink"] }));
  addFinding(
    findings,
    "warning",
    "frontend.content.dom_xss",
    "Client-side bundles avoid DOM XSS source-to-sink patterns",
    domXss.length === 0,
    "OWASP WSTG DOM XSS testing reviews client-side sources such as location data flowing into HTML/script execution sinks.",
    { checked: reviews.length, exposed: domXss }
  );
  const clientRedirects = reviews
    .filter((review) => review.behaviorSignals.includes("client_redirect_from_url") || review.behaviorSignals.includes("document_write_from_url"))
    .map((review) => ({ url: review.url, finalUrl: review.finalUrl, status: review.status, signals: review.behaviorSignals.filter((signal) => ["client_redirect_from_url", "document_write_from_url"].includes(signal)) }));
  addFinding(
    findings,
    "warning",
    "frontend.content.client_redirects",
    "Client-side bundles avoid URL-controlled redirects and document writes",
    clientRedirects.length === 0,
    "OWASP WSTG client-side URL redirect testing reviews code paths where URL-controlled values influence navigation.",
    { checked: reviews.length, exposed: clientRedirects }
  );
  const resourceManipulation = reviews
    .filter((review) => review.behaviorSignals.includes("resource_url_from_client_input"))
    .map((review) => ({ url: review.url, finalUrl: review.finalUrl, status: review.status, signals: ["resource_url_from_client_input"] }));
  addFinding(
    findings,
    "warning",
    "frontend.content.resource_manipulation",
    "Client-side bundles avoid URL-controlled resource loading",
    resourceManipulation.length === 0,
    "OWASP WSTG client-side resource manipulation testing reviews whether URL-controlled input can choose scripts, iframes, or other resources.",
    { checked: reviews.length, exposed: resourceManipulation }
  );
  const templateInjection = reviews
    .filter((review) => review.behaviorSignals.includes("client_template_injection"))
    .map((review) => ({ url: review.url, finalUrl: review.finalUrl, status: review.status, signals: ["client_template_injection"] }));
  addFinding(
    findings,
    "warning",
    "frontend.content.template_injection",
    "Client-side template sinks avoid URL-controlled input",
    templateInjection.length === 0,
    "OWASP WSTG client-side template injection testing reviews framework template sinks that can interpret user-controlled data.",
    { checked: reviews.length, exposed: templateInjection }
  );
  const prototypePollution = reviews
    .filter((review) => review.behaviorSignals.includes("prototype_pollution_candidate"))
    .map((review) => ({ url: review.url, finalUrl: review.finalUrl, status: review.status, signals: ["prototype_pollution_candidate"] }));
  addFinding(
    findings,
    "warning",
    "frontend.content.prototype_pollution",
    "Client-side bundles avoid prototype-pollution candidate flows",
    prototypePollution.length === 0,
    "OWASP WSTG prototype pollution testing starts by identifying structured input that can influence object keys such as __proto__ or constructor.prototype.",
    { checked: reviews.length, exposed: prototypePollution }
  );
  const browserStorage = reviews
    .filter((review) => review.behaviorSignals.includes("sensitive_browser_storage_key"))
    .map((review) => ({ url: review.url, finalUrl: review.finalUrl, status: review.status, signals: ["sensitive_browser_storage_key"] }));
  addFinding(
    findings,
    "warning",
    "frontend.content.browser_storage",
    "Client-side bundles avoid storing sensitive keys in browser storage",
    browserStorage.length === 0,
    "OWASP WSTG browser storage testing looks for authentication tokens, session identifiers, or sensitive business data in localStorage/sessionStorage.",
    { checked: reviews.length, exposed: browserStorage }
  );
  const websocketIssues = reviews
    .filter((review) => review.websockets.some((item) => item.signal === "cleartext_public_websocket"))
    .map((review) => ({ url: review.url, finalUrl: review.finalUrl, status: review.status, references: review.websockets.filter((item) => item.signal === "cleartext_public_websocket") }));
  addFinding(
    findings,
    "warning",
    "frontend.content.websockets",
    "Client-side bundles avoid cleartext public WebSocket endpoints",
    websocketIssues.length === 0,
    "OWASP WSTG WebSocket testing includes reviewing whether WebSocket endpoints are protected consistently with the parent application transport.",
    { checked: reviews.length, exposed: websocketIssues, references: reviews.flatMap((review) => review.websockets).slice(0, 20) }
  );
  const jwtWeak = reviews
    .flatMap((review) => review.jwtLiterals.map((token) => ({ ...token, assetUrl: review.url, finalUrl: review.finalUrl })))
    .filter((token) => token.signals.length);
  addFinding(
    findings,
    "warning",
    "frontend.content.jwt_algorithms",
    "JWT literals do not advertise unsigned or malformed algorithms",
    jwtWeak.length === 0,
    "OWASP WSTG JWT testing starts by decoding token headers and checking for unsigned, malformed, or unexpected algorithms before deeper authenticated validation.",
    { checked: reviews.reduce((count, review) => count + review.jwtLiterals.length, 0), weak: jwtWeak }
  );
  const xssiCandidates = reviews
    .filter((review) => review.xssiJson)
    .map((review) => review.xssiJson);
  addFinding(
    findings,
    "info",
    "frontend.content.xssi_json",
    "JSON assets are inventoried for XSSI review",
    true,
    "OWASP WSTG Cross Site Script Inclusion testing reviews JSON-like responses that may be loadable through script inclusion across origins.",
    { checked: reviews.length, candidates: xssiCandidates }
  );
  const cloudStorage = reviews
    .filter((review) => review.cloudStorage.length)
    .map((review) => ({ url: review.url, finalUrl: review.finalUrl, status: review.status, references: review.cloudStorage }));
  addFinding(
    findings,
    "info",
    "frontend.content.cloud_storage_refs",
    "Cloud storage references are inventoried for access-control review",
    true,
    "OWASP WSTG cloud storage testing starts by identifying storage endpoints whose access controls should be manually verified.",
    { checked: reviews.length, references: cloudStorage }
  );
  return reviews;
}

function evaluateTransport(findings, scope, discovery) {
  const targetCleartext = targetBaseUrls(scope)
    .map((target) => ({ target: target.targetName, url: target.baseUrl }))
    .filter((target) => isAllowedUrl(target.url, scope, target.target))
    .filter((target) => {
      try {
        const parsed = new URL(target.url);
        return parsed.protocol === "http:" && isPublicNonLoopbackUrl(target.url);
      } catch {
        return false;
      }
    });
  addFinding(
    findings,
    "warning",
    "frontend.transport.public_https",
    "Public non-loopback targets use HTTPS",
    targetCleartext.length === 0,
    "OWASP WSTG weak transport testing expects public application traffic to avoid cleartext HTTP.",
    { cleartext: targetCleartext }
  );

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

function inspectTlsTarget(target) {
  return new Promise((resolveInspection) => {
    let parsed;
    try {
      parsed = new URL(target.baseUrl);
    } catch (error) {
      resolveInspection({ target: target.targetName, url: target.baseUrl, ok: false, error: error.message });
      return;
    }
    if (parsed.protocol !== "https:" || isLoopback(parsed.hostname)) {
      resolveInspection({ target: target.targetName, url: target.baseUrl, skipped: true });
      return;
    }

    const host = parsed.hostname;
    const port = Number(parsed.port || 443);
    const socket = tlsConnect({
      host,
      port,
      servername: isIP(host) ? undefined : host,
      timeout: 7000,
      rejectUnauthorized: false
    });

    const finish = (result) => {
      socket.removeAllListeners();
      if (!socket.destroyed) socket.destroy();
      resolveInspection(result);
    };

    socket.once("secureConnect", () => {
      const certificate = socket.getPeerCertificate() || {};
      const validTo = certificate.valid_to || "";
      const validFrom = certificate.valid_from || "";
      const validToMs = Date.parse(validTo);
      const daysRemaining = Number.isFinite(validToMs) ? Math.ceil((validToMs - Date.now()) / 86400000) : null;
      finish({
        target: target.targetName,
        url: target.baseUrl,
        host,
        port,
        ok: true,
        protocol: socket.getProtocol(),
        authorized: socket.authorized,
        authorizationError: socket.authorizationError ? String(socket.authorizationError) : "",
        validFrom,
        validTo,
        daysRemaining,
        subject: certificate.subject?.CN || "",
        issuer: certificate.issuer?.CN || ""
      });
    });
    socket.once("timeout", () => finish({ target: target.targetName, url: target.baseUrl, host, port, ok: false, error: "TLS handshake timed out" }));
    socket.once("error", (error) => finish({ target: target.targetName, url: target.baseUrl, host, port, ok: false, error: error.message }));
  });
}

async function evaluateTls(findings, scope) {
  const targets = targetBaseUrls(scope)
    .filter((target) => isAllowedUrl(target.baseUrl, scope, target.targetName))
    .filter((target) => {
      try {
        const parsed = new URL(target.baseUrl);
        return parsed.protocol === "https:" && isPublicNonLoopbackUrl(target.baseUrl);
      } catch {
        return false;
      }
    });
  const inspections = [];
  for (const target of targets) {
    inspections.push(await inspectTlsTarget(target));
  }
  const weak = inspections.filter((item) => {
    if (!item.ok) return true;
    if (!["TLSv1.2", "TLSv1.3"].includes(item.protocol)) return true;
    if (item.authorized !== true) return true;
    if (!item.validTo) return true;
    if (typeof item.daysRemaining !== "number" || item.daysRemaining < 14) return true;
    return false;
  });
  addFinding(
    findings,
    "warning",
    "frontend.transport.tls_certificate",
    "Public HTTPS targets present valid modern TLS certificates",
    weak.length === 0,
    "OWASP WSTG weak transport testing includes certificate validity and TLS configuration review for public HTTPS services.",
    { checked: inspections.length, issues: weak, inspections }
  );
}

function takeoverProviderForCname(cname) {
  const value = String(cname || "").replace(/\.$/, "").toLowerCase();
  const providers = [
    ["github-pages", /(?:^|\.)github\.io$/],
    ["github-fastly", /(?:^|\.)github\.map\.fastly\.net$/],
    ["aws-s3", /(?:^|\.)s3(?:[-.][a-z0-9-]+)?\.amazonaws\.com$|(?:^|\.)s3-website[-.][a-z0-9-]+\.amazonaws\.com$/],
    ["azure", /(?:^|\.)(?:azurewebsites\.net|cloudapp\.net|trafficmanager\.net)$/],
    ["heroku", /(?:^|\.)herokuapp\.com$/],
    ["netlify", /(?:^|\.)netlify\.app$/],
    ["vercel", /(?:^|\.)vercel\.app$/],
    ["cloudflare-pages", /(?:^|\.)pages\.dev$/],
    ["readme", /(?:^|\.)readme\.io$/]
  ];
  const match = providers.find(([, pattern]) => pattern.test(value));
  return match ? match[0] : "";
}

function takeoverFingerprintSignals(response) {
  if (!response.ok) return [];
  const text = responseText(response);
  const patterns = [
    ["github-pages", /There isn't a GitHub Pages site here/i],
    ["aws-s3", /(?:NoSuchBucket|The specified bucket does not exist)/i],
    ["heroku", /No such app/i],
    ["azure", /(?:404 Web Site not found|The resource you are looking for has been removed)/i],
    ["fastly", /Fastly error:\s*unknown domain/i],
    ["netlify", /Not Found - Request ID:/i],
    ["cloudflare-pages", /(?:project not found|deployment_not_found)/i],
    ["readme", /Project doesnt exist/i]
  ];
  return patterns.filter(([, pattern]) => pattern.test(text)).map(([provider]) => provider);
}

async function inspectCnameTarget(target) {
  let parsed;
  try {
    parsed = new URL(target.baseUrl);
  } catch (error) {
    return { target: target.targetName, url: target.baseUrl, ok: false, error: error.message, cnames: [] };
  }
  if (!isPublicNonLoopbackUrl(target.baseUrl)) {
    return { target: target.targetName, url: target.baseUrl, host: parsed.hostname, skipped: true, cnames: [] };
  }

  let cnames = [];
  try {
    cnames = await resolveCname(parsed.hostname);
  } catch (error) {
    if (!["ENODATA", "ENOTFOUND", "ENOTIMP", "ENOTSUP"].includes(error.code)) {
      return { target: target.targetName, url: target.baseUrl, host: parsed.hostname, ok: false, error: error.code || error.message, cnames: [] };
    }
  }
  const providers = unique(cnames.map(takeoverProviderForCname));
  const response = providers.length
    ? await requestHeaders(target.baseUrl, 0, { method: "GET", maxBodyBytes: 4096 })
    : null;
  const fingerprints = response ? takeoverFingerprintSignals(response) : [];
  const issues = providers
    .filter((provider) => fingerprints.includes(provider) || (provider === "github-fastly" && fingerprints.includes("github-pages")))
    .map((provider) => ({
      target: target.targetName,
      host: parsed.hostname,
      cname: cnames.find((cname) => takeoverProviderForCname(cname) === provider) || cnames[0],
      provider,
      status: response?.status || 0,
      signal: "dangling_cname_fingerprint"
    }));
  return {
    target: target.targetName,
    url: target.baseUrl,
    host: parsed.hostname,
    ok: true,
    cnames,
    providers,
    responseStatus: response?.status || 0,
    issues
  };
}

async function evaluateDns(findings, scope, baseline) {
  const maxTargets = configuredNumber(baseline, "maxDnsAuditTargets", 12);
  const targets = targetBaseUrls(scope)
    .filter((target) => isAllowedUrl(target.baseUrl, scope, target.targetName))
    .slice(0, Math.max(1, maxTargets));
  const inspections = [];
  for (const target of targets) {
    inspections.push(await inspectCnameTarget(target));
  }
  const issues = inspections.flatMap((item) => item.issues || []);
  addFinding(
    findings,
    "warning",
    "frontend.dns.dangling_cname",
    "Public target hostnames do not show dangling CNAME takeover fingerprints",
    issues.length === 0,
    "OWASP WSTG subdomain takeover testing checks DNS CNAME records and known third-party unclaimed-resource fingerprints before manual validation.",
    { checked: inspections.length, issues, inspections }
  );
}

function hostHeaderIssue(response, testHost) {
  if (!response.ok) return null;
  const lowerHost = testHost.toLowerCase();
  const reflectedHeaders = ["location", "content-location", "refresh"]
    .map((name) => ({ header: name, value: headerValue(response, name) }))
    .filter((item) => item.value.toLowerCase().includes(lowerHost));
  const bodyReflected = responseText(response).toLowerCase().includes(lowerHost);
  if (!reflectedHeaders.length && !bodyReflected) return null;
  return {
    status: response.status || 0,
    reflectedHeaders,
    bodyReflected,
    signal: "untrusted_host_reflected"
  };
}

async function evaluateHostHeader(findings, scope, baseline) {
  const testHost = "aegis.invalid";
  const maxTargets = configuredNumber(baseline, "maxHostHeaderAuditTargets", 8);
  const targets = targetBaseUrls(scope)
    .filter((target) => isAllowedUrl(target.baseUrl, scope, target.targetName))
    .slice(0, Math.max(1, maxTargets));
  const variants = [
    { name: "host", headers: { host: testHost } },
    { name: "x-forwarded-host", headers: { "x-forwarded-host": testHost } },
    { name: "x-original-host", headers: { "x-original-host": testHost } },
    { name: "forwarded", headers: { forwarded: `host=${testHost};proto=https` } }
  ];
  const checks = [];
  const issues = [];
  for (const target of targets) {
    for (const variant of variants) {
      const response = await requestHeaders(target.baseUrl, 0, {
        method: "GET",
        followRedirects: false,
        maxBodyBytes: 4096,
        headers: variant.headers
      });
      const issue = hostHeaderIssue(response, testHost);
      const evidence = {
        target: target.targetName,
        url: target.baseUrl,
        variant: variant.name,
        status: response.status || 0,
        ok: response.ok,
        error: response.error || "",
        location: headerValue(response, "location"),
        contentLocation: headerValue(response, "content-location"),
        refresh: headerValue(response, "refresh")
      };
      checks.push(evidence);
      if (issue) issues.push({ ...evidence, ...issue });
    }
  }
  addFinding(
    findings,
    "warning",
    "frontend.headers.host_injection",
    "Responses do not reflect untrusted Host-style headers",
    issues.length === 0,
    "OWASP WSTG host header injection testing checks whether attacker-supplied Host-style headers influence redirects, links, or security-sensitive response content.",
    { checked: checks.length, testHost, issues }
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
  const backupExposures = [];
  const extensionExposures = [];
  const apiDocExposures = [];
  const apiVersionSurfaces = [];
  const legacyApiExposures = [];
  const graphqlExposures = [];
  const uploadSurfaces = [];
  const identityMetadata = [];
  const oauthCallbackSurfaces = [];
  const unauthenticatedUserApis = [];
  const accountRecoverySurfaces = [];
  const logoutSurfaces = [];
  const adminExposures = [];
  const debugExposures = [];
  const metafileExposures = [];
  const mobileAssociationFiles = [];
  const errorDisclosures = [];
  const directoryListingExposures = [];
  const sourceMapExposures = [];
  const riskyMethods = [];
  for (const { probe, response } of probeResponses) {
    if (probe.category === "sensitiveFiles") {
      const signal = sensitiveSignal(probe, response);
      if (signal) sensitiveExposures.push(probeEvidence(probe, response, signal));
    } else if (probe.category === "backupFiles") {
      const signal = backupFileSignal(probe, response);
      if (signal) backupExposures.push(probeEvidence(probe, response, signal));
    } else if (probe.category === "sensitiveExtensions") {
      const signal = sensitiveExtensionSignal(probe, response);
      if (signal) extensionExposures.push(probeEvidence(probe, response, signal));
    } else if (probe.category === "apiDocs") {
      const signal = apiDocsSignal(response);
      if (signal) apiDocExposures.push(probeEvidence(probe, response, signal));
    } else if (probe.category === "apiVersionPaths") {
      const signal = apiVersionSignal(probe, response);
      if (signal) apiVersionSurfaces.push(probeEvidence(probe, response, signal));
    } else if (probe.category === "legacyApiPaths") {
      const signal = legacyApiSignal(probe, response);
      if (signal) legacyApiExposures.push(probeEvidence(probe, response, signal));
    } else if (probe.category === "graphqlEndpoints") {
      const signal = graphqlSignal(response);
      if (signal) graphqlExposures.push(probeEvidence(probe, response, signal));
    } else if (probe.category === "uploadPaths") {
      const signal = uploadSurfaceSignal(probe, response);
      if (signal) uploadSurfaces.push(probeEvidence(probe, response, signal));
    } else if (probe.category === "identityEndpoints") {
      const signal = identityMetadataSignal(probe, response);
      if (signal) identityMetadata.push(probeEvidence(probe, response, signal));
    } else if (probe.category === "oauthCallbackPaths") {
      const signal = oauthCallbackSignal(probe, response);
      if (signal) oauthCallbackSurfaces.push(oauthCallbackEvidence(probe, response, signal));
    } else if (probe.category === "authApiPaths") {
      const signal = unauthenticatedUserApiSignal(probe, response);
      if (signal) unauthenticatedUserApis.push(probeEvidence(probe, response, signal));
    } else if (probe.category === "accountRecoveryPaths") {
      const signal = accountRecoverySignal(probe, response);
      if (signal) accountRecoverySurfaces.push(probeEvidence(probe, response, signal));
    } else if (probe.category === "logoutPaths") {
      const signal = logoutRouteSignal(probe, response);
      if (signal) logoutSurfaces.push(logoutCleanupEvidence(probe, response, signal));
    } else if (probe.category === "adminPaths") {
      const signal = exposedRouteSignal(scope, discovery, probe, response);
      if (signal) adminExposures.push(probeEvidence(probe, response, signal));
    } else if (probe.category === "debugPaths") {
      const signal = exposedRouteSignal(scope, discovery, probe, response);
      if (signal) debugExposures.push(probeEvidence(probe, response, signal));
    } else if (probe.category === "metafiles") {
      const signal = metafileSignal(probe, response);
      if (signal) metafileExposures.push(probeEvidence(probe, response, signal));
    } else if (probe.category === "mobileAssociationFiles") {
      const signal = mobileAssociationSignal(probe, response);
      if (signal) mobileAssociationFiles.push(mobileAssociationEvidence(probe, response, signal));
    } else if (probe.category === "errorPages") {
      const signal = errorDisclosureSignal(response);
      if (signal) errorDisclosures.push(probeEvidence(probe, response, signal));
    } else if (probe.category === "directoryListings") {
      const signal = directoryListingSignal(response);
      if (signal) directoryListingExposures.push(probeEvidence(probe, response, signal));
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
    "frontend.probes.backup_files",
    "Old backup and unreferenced files are not publicly readable",
    backupExposures.length === 0,
    "OWASP WSTG warns that old backups, editor copies, snapshots, and archives can expose source code, credentials, logs, or hidden functionality.",
    { checked: probes.filter((probe) => probe.category === "backupFiles").length, exposed: backupExposures }
  );
  addFinding(
    findings,
    "warning",
    "frontend.probes.sensitive_extensions",
    "Sensitive server-side extensions and config files are not publicly served",
    extensionExposures.length === 0,
    "OWASP WSTG file-extension testing checks whether server-side include, config, source, and dependency files are exposed through the web server.",
    { checked: probes.filter((probe) => probe.category === "sensitiveExtensions").length, exposed: extensionExposures }
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
    "info",
    "frontend.probes.api_versions",
    "Versioned API routes are inventoried",
    true,
    "OWASP API reconnaissance recommends inventorying deployed API versions because older versions may retain vulnerabilities fixed in newer implementations.",
    { checked: probes.filter((probe) => probe.category === "apiVersionPaths").length, routes: apiVersionSurfaces }
  );
  addFinding(
    findings,
    "warning",
    "frontend.probes.legacy_api_versions",
    "Legacy, beta, internal, and v0 API routes are not anonymously exposed",
    legacyApiExposures.length === 0,
    "Deprecated or internal API versions expand attack surface and should be retired, authenticated, or explicitly approved for the environment.",
    { checked: probes.filter((probe) => probe.category === "legacyApiPaths").length, exposed: legacyApiExposures }
  );
  addFinding(
    findings,
    "info",
    "frontend.probes.graphql",
    "GraphQL endpoints are inventoried for schema and authorization review",
    true,
    "OWASP API testing treats GraphQL endpoints as API attack surface that should be reviewed for introspection exposure, operation authorization, and object-level access controls.",
    { checked: probes.filter((probe) => probe.category === "graphqlEndpoints").length, endpoints: graphqlExposures }
  );
  const graphqlSchemaExposureIssues = graphqlExposures
    .filter((item) => ["graphql_ide", "graphql_endpoint", "graphql_json_error"].includes(item.signal))
    .map((item) => ({ ...item, signal: `${item.signal}_requires_access_control_review` }));
  addFinding(
    findings,
    "warning",
    "frontend.probes.graphql_schema_exposure",
    "GraphQL IDE and schema-like signals are not anonymously exposed",
    graphqlSchemaExposureIssues.length === 0,
    "OWASP GraphQL testing treats public IDEs, schema hints, and verbose GraphQL errors as signals for introspection and authorization review.",
    { checked: graphqlExposures.length, issues: graphqlSchemaExposureIssues }
  );
  addFinding(
    findings,
    "info",
    "frontend.probes.upload_surfaces",
    "Upload and import/export surfaces are inventoried for file-handling review",
    true,
    "OWASP WSTG file-upload testing starts by identifying upload, import, export, and attachment surfaces before controlled authenticated testing.",
    { checked: probes.filter((probe) => probe.category === "uploadPaths").length, surfaces: uploadSurfaces }
  );
  addFinding(
    findings,
    "info",
    "frontend.probes.identity_metadata",
    "OIDC, OAuth, and JWKS metadata endpoints are inventoried",
    true,
    "Identity metadata can be intentionally public, but discovered issuer, JWKS, authorization, and token endpoints should be reviewed for scope, audience, and key-rotation posture.",
    { checked: probes.filter((probe) => probe.category === "identityEndpoints").length, endpoints: identityMetadata }
  );
  addFinding(
    findings,
    "info",
    "frontend.probes.oauth_callback_routes",
    "OAuth, OIDC, SSO, and SAML callback routes are inventoried",
    true,
    "Passive probes request common callback paths without credentials or authorization parameters, then record status, cache-control, and Referrer-Policy for redirect-flow review.",
    { checked: probes.filter((probe) => probe.category === "oauthCallbackPaths").length, routes: oauthCallbackSurfaces }
  );
  const oauthCallbackSensitiveResponses = oauthCallbackSurfaces.filter((item) =>
    ["oauth_callback_route", "oauth_callback_redirect"].includes(item.signal)
  );
  const oauthCallbackCacheIssues = oauthCallbackSensitiveResponses
    .filter((item) => !cacheControlProtected(item.cacheControl))
    .map((item) => ({ ...item, signal: "missing_private_or_no_store_cache_control" }));
  addFinding(
    findings,
    "warning",
    "frontend.probes.oauth_callback_cache",
    "OAuth and SSO callback responses avoid browser/shared-cache storage",
    oauthCallbackCacheIssues.length === 0,
    "OAuth callback responses may process authorization codes or tokens and should use no-store/private/no-cache style cache controls.",
    { checked: oauthCallbackSensitiveResponses.length, issues: oauthCallbackCacheIssues }
  );
  const oauthCallbackReferrerIssues = oauthCallbackSensitiveResponses
    .filter((item) => !referrerPolicyProtected(item.referrerPolicy))
    .map((item) => ({ ...item, signal: "missing_restrictive_referrer_policy" }));
  addFinding(
    findings,
    "warning",
    "frontend.probes.oauth_callback_referrer",
    "OAuth and SSO callback responses use restrictive Referrer-Policy",
    oauthCallbackReferrerIssues.length === 0,
    "OWASP OAuth testing notes that authorization codes or tokens in URLs can leak through referrer headers; callback responses should use no-referrer, same-origin, or strict-origin style policies.",
    { checked: oauthCallbackSensitiveResponses.length, issues: oauthCallbackReferrerIssues }
  );
  addFinding(
    findings,
    "warning",
    "frontend.probes.unauthenticated_user_api",
    "User, account, and session APIs are not anonymously readable",
    unauthenticatedUserApis.length === 0,
    "Passive probes check common user/session API paths for anonymously reachable JSON that appears to expose identities, roles, permissions, tenants, or session state.",
    { checked: probes.filter((probe) => probe.category === "authApiPaths").length, exposed: unauthenticatedUserApis }
  );
  addFinding(
    findings,
    "info",
    "frontend.probes.account_recovery",
    "Account recovery and password-change routes are inventoried",
    true,
    "Passive probes check common forgot/reset/change-password routes and the well-known change-password URL without submitting credentials or tokens.",
    { checked: probes.filter((probe) => probe.category === "accountRecoveryPaths").length, routes: accountRecoverySurfaces }
  );
  addFinding(
    findings,
    "info",
    "frontend.probes.logout_routes",
    "Logout and sign-out routes are inventoried for session cleanup review",
    true,
    "Passive probes request common logout/sign-out paths without cookies or form submissions, then record cache-control, Clear-Site-Data, and cookie-clearing signals for review.",
    { checked: probes.filter((probe) => probe.category === "logoutPaths").length, routes: logoutSurfaces }
  );
  const logoutCacheIssues = logoutSurfaces
    .filter((item) => ["logout_route", "logout_redirect"].includes(item.signal))
    .filter((item) => !cacheControlProtected(item.cacheControl))
    .map((item) => ({ ...item, signal: "missing_private_or_no_store_cache_control" }));
  addFinding(
    findings,
    "warning",
    "frontend.probes.logout_cache",
    "Logout and sign-out responses avoid browser/shared-cache storage",
    logoutCacheIssues.length === 0,
    "OWASP browser-cache guidance recommends no-store style cache controls around authentication state changes and logout flows.",
    {
      checked: logoutSurfaces.filter((item) => ["logout_route", "logout_redirect"].includes(item.signal)).length,
      issues: logoutCacheIssues
    }
  );
  const authApiRateLimitSignals = probeResponses
    .filter(({ probe }) => probe.category === "authApiPaths")
    .map(({ probe, response }) => rateLimitEvidence(response, { target: probe.targetName, path: probe.path }));
  addFinding(
    findings,
    "info",
    "frontend.probes.auth_api_rate_limit",
    "Auth and session API probes are inventoried for rate-limit headers",
    true,
    "Visible Retry-After or RateLimit headers are useful evidence for abuse-control review, though absence of these headers does not prove throttling is missing.",
    {
      checked: authApiRateLimitSignals.length,
      present: authApiRateLimitSignals.filter((item) => Object.keys(item.headers).length),
      missing: authApiRateLimitSignals.filter((item) => !Object.keys(item.headers).length).map((item) => ({ target: item.target, path: item.path, status: item.status }))
    }
  );
  const authApiJsonResponses = probeResponses.filter(({ probe, response }) =>
    probe.category === "authApiPaths"
    && isSuccessStatus(response)
    && !isSoftNotFoundResponse(response)
    && contentType(response).includes("json")
  );
  const authApiCacheIssues = authApiJsonResponses
    .filter(({ response }) => !cacheControlProtected(headerValue(response, "cache-control")))
    .map(({ probe, response }) => authApiHeaderEvidence(probe, response, "missing_private_or_no_store_cache_control"));
  addFinding(
    findings,
    "warning",
    "frontend.probes.auth_api_cache",
    "Auth and session API JSON responses avoid shared-cache exposure",
    authApiCacheIssues.length === 0,
    "User, account, and session JSON should use private/no-store/no-cache style cache controls and avoid public caching.",
    { checked: authApiJsonResponses.length, issues: authApiCacheIssues }
  );
  const authApiNosniffIssues = authApiJsonResponses
    .filter(({ response }) => !/\bnosniff\b/i.test(headerValue(response, "x-content-type-options")))
    .map(({ probe, response }) => authApiHeaderEvidence(probe, response, "missing_x_content_type_options_nosniff"));
  addFinding(
    findings,
    "warning",
    "frontend.probes.auth_api_nosniff",
    "Auth and session API JSON responses use nosniff",
    authApiNosniffIssues.length === 0,
    "JSON API responses should use X-Content-Type-Options: nosniff to reduce MIME confusion risks.",
    { checked: authApiJsonResponses.length, issues: authApiNosniffIssues }
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
    "frontend.probes.metafiles",
    "Webserver metafiles do not disclose sensitive paths or permissive cross-domain policy",
    metafileExposures.length === 0,
    "OWASP WSTG information gathering includes reviewing robots, sitemap, security.txt, and legacy cross-domain policy files for information leakage.",
    { checked: probes.filter((probe) => probe.category === "metafiles").length, exposed: metafileExposures }
  );
  const securityTxtChecks = probeResponses
    .filter(({ probe }) => probe.category === "metafiles" && String(probe.path || "").endsWith("/security.txt"))
    .map(({ probe, response }) => securityTxtEvidence(probe, response));
  addFinding(
    findings,
    "info",
    "frontend.probes.security_txt",
    "Security contact metadata is inventoried",
    true,
    "RFC 9116 security.txt helps vulnerability reporters find the right contact and policy; this passive check records presence and common fields only.",
    { checked: securityTxtChecks.length, files: securityTxtChecks }
  );
  addFinding(
    findings,
    "info",
    "frontend.probes.mobile_association_files",
    "Mobile app link association files are inventoried",
    true,
    "OWASP MASTG deep-link testing includes verifying Android App Links and iOS Universal Links association files before testing app-side handlers.",
    { checked: probes.filter((probe) => probe.category === "mobileAssociationFiles").length, files: mobileAssociationFiles }
  );
  const mobileAssociationIssues = mobileAssociationFiles
    .filter((item) => !item.parseableJson || item.broadPathPatterns.length)
    .map((item) => ({
      ...item,
      signal: !item.parseableJson ? "association_file_not_parseable_json" : "broad_universal_link_path_scope"
    }));
  addFinding(
    findings,
    "warning",
    "frontend.probes.mobile_deep_link_scope",
    "Mobile deep-link association files are parseable and avoid broad wildcard scopes",
    mobileAssociationIssues.length === 0,
    "Universal/App Link association files should be valid JSON and use the narrowest practical path scope so mobile apps do not claim unintended web paths.",
    { checked: mobileAssociationFiles.length, issues: mobileAssociationIssues }
  );
  addFinding(
    findings,
    "warning",
    "frontend.probes.error_disclosure",
    "Error responses do not expose stack traces or framework internals",
    errorDisclosures.length === 0,
    "OWASP WSTG error handling tests look for stack traces, framework details, SQL errors, and other implementation clues in error responses.",
    { checked: probes.filter((probe) => probe.category === "errorPages").length, exposed: errorDisclosures }
  );
  addFinding(
    findings,
    "warning",
    "frontend.probes.directory_listing",
    "Directory listing is not enabled on common public directories",
    directoryListingExposures.length === 0,
    "OWASP WSTG old/unreferenced file testing calls out directory listing as a common way to enumerate forgotten content.",
    { checked: probes.filter((probe) => probe.category === "directoryListings").length, exposed: directoryListingExposures }
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

  const massAssignmentFields = massAssignmentFieldEvidence(discovery);
  addFinding(
    findings,
    "warning",
    "frontend.discovery.mass_assignment_fields",
    "Sensitive authorization and account fields are not client-controlled",
    massAssignmentFields.length === 0,
    "OWASP mass-assignment testing starts by identifying client-controlled fields that look like roles, permissions, tenancy, billing, status, or ownership properties.",
    { candidates: massAssignmentFields, count: massAssignmentFields.length }
  );

  const redirectParams = redirectParameterEvidence(discovery);
  addFinding(
    findings,
    "info",
    "frontend.discovery.redirect_parameters",
    "Redirect-like URL parameters are inventoried for open redirect review",
    true,
    "OWASP WSTG client-side URL redirect testing starts by identifying parameters that control URLs or paths; this passive check records candidates only.",
    { candidates: redirectParams, count: redirectParams.length }
  );
  const externalRedirectDestinations = externalRedirectDestinationEvidence(discovery);
  addFinding(
    findings,
    "warning",
    "frontend.discovery.redirect_external_destinations",
    "Redirect-like parameters do not carry external destinations in discovered URLs",
    externalRedirectDestinations.length === 0,
    "OWASP unvalidated redirect testing reviews URL parameters that can send users to untrusted external destinations; this passive check records destination hosts only.",
    { candidates: externalRedirectDestinations, count: externalRedirectDestinations.length }
  );

  const duplicateParams = duplicateParameterEvidence(discovery);
  addFinding(
    findings,
    "info",
    "frontend.discovery.duplicate_parameters",
    "Duplicate URL parameters are inventoried for HTTP Parameter Pollution review",
    true,
    "OWASP WSTG HTTP Parameter Pollution testing reviews how applications interpret repeated parameters; this passive check records observed candidates only.",
    { candidates: duplicateParams, count: duplicateParams.length }
  );

  const ssrfParameters = ssrfParameterEvidence(discovery);
  addFinding(
    findings,
    "info",
    "frontend.discovery.ssrf_url_parameters",
    "Server-side fetch URL parameters are inventoried for SSRF review",
    true,
    "OWASP SSRF testing begins by identifying URL, webhook, callback, proxy, fetch, feed, and remote-media inputs; this passive check stores names only.",
    { candidates: ssrfParameters, count: ssrfParameters.length }
  );
  const ssrfReviewIssues = ssrfParameters.filter((item) =>
    item.risk !== "navigation_or_redirect_parameter"
    || String(item.method || "GET").toUpperCase() !== "GET"
  );
  addFinding(
    findings,
    "warning",
    "frontend.discovery.ssrf_fetch_inputs",
    "Remote-fetch inputs are reviewed before server-side use",
    ssrfReviewIssues.length === 0,
    "Inputs that can make the server fetch remote URLs should enforce allowlists, private-network blocking, redirect limits, and response-size controls.",
    { checked: ssrfParameters.length, issues: ssrfReviewIssues }
  );

  const sensitiveUrlParams = sensitiveUrlParameterEvidence(discovery);
  addFinding(
    findings,
    "warning",
    "frontend.discovery.sensitive_url_parameters",
    "Sensitive values are not passed through URL query or fragment parameters",
    sensitiveUrlParams.length === 0,
    "Tokens, passwords, API keys, and session identifiers in URL query strings or fragments can leak through logs, browser history, referrer headers, and shared links.",
    { candidates: sensitiveUrlParams, count: sensitiveUrlParams.length }
  );

  const authFlowTokens = authFlowTokenEvidence(discovery);
  addFinding(
    findings,
    "info",
    "frontend.discovery.auth_flow_token_urls",
    "Authentication-flow URL tokens are inventoried for leakage review",
    true,
    "Password reset, verification, invitation, magic-link, OAuth, and SSO flows sometimes carry token-like parameters in URLs; passive discovery records parameter names only so reviewers can assess leakage risk.",
    { candidates: authFlowTokens, count: authFlowTokens.length }
  );

  const oauthAuthorizationRequests = oauthAuthorizationRequestEvidence(discovery);
  addFinding(
    findings,
    "info",
    "frontend.discovery.oauth_authorization_requests",
    "OAuth and OIDC authorization requests are inventoried",
    true,
    "Discovered authorization URLs are reviewed for parameter names such as response_type, redirect_uri, state, nonce, code_challenge, and response_mode without storing values.",
    { candidates: oauthAuthorizationRequests, count: oauthAuthorizationRequests.length }
  );
  const oauthAuthorizationIssues = oauthAuthorizationRequests
    .filter((item) => (item.signals || []).some((signal) => ["implicit_response_type", "cleartext_redirect_uri", "response_mode_not_form_post"].includes(signal)))
    .map((item) => ({ ...item, signals: item.signals.filter((signal) => ["implicit_response_type", "cleartext_redirect_uri", "response_mode_not_form_post"].includes(signal)) }));
  addFinding(
    findings,
    "warning",
    "frontend.discovery.oauth_authorization_request_hardening",
    "OAuth authorization request URLs avoid risky response and redirect modes",
    oauthAuthorizationIssues.length === 0,
    "OWASP OAuth testing and OAuth security guidance recommend avoiding implicit token responses, cleartext redirect URIs, and URL-carried token response modes where form_post or server-side state is available.",
    { checked: oauthAuthorizationRequests.length, issues: oauthAuthorizationIssues }
  );

  const attackSurfaces = attackSurfaceEvidence(discovery);
  addFinding(
    findings,
    "info",
    "frontend.discovery.attack_surface_matrix",
    "Input and API attack surfaces are mapped to OWASP review families",
    true,
    "OWASP WSTG input validation and OWASP API testing begin by identifying entry points; this passive matrix classifies discovered routes, parameters, and fields without sending exploit payloads.",
    attackSurfaces
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
    responses.push(await requestHeaders(target, 0, { maxBodyBytes: 16384 }));
  }

  const findings = [];
  evaluateHeaders(findings, responses, scope, discovery);
  await evaluateCors(findings, scope);
  await evaluateHostHeader(findings, scope, baseline);
  evaluateCookies(findings, responses);
  evaluateForms(findings, discovery, scope);
  evaluateTransport(findings, scope, discovery);
  await evaluateTls(findings, scope);
  await evaluateDns(findings, scope, baseline);
  const contentReviews = await evaluateClientContentLeakage(findings, scope, latestScan, baseline, responses);
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
        "x-powered-by": response.headers?.["x-powered-by"] || "",
        "x-permitted-cross-domain-policies": response.headers?.["x-permitted-cross-domain-policies"] || "",
        "public-key-pins": response.headers?.["public-key-pins"] || "",
        "public-key-pins-report-only": response.headers?.["public-key-pins-report-only"] || "",
        "x-aspnet-version": response.headers?.["x-aspnet-version"] || "",
        "x-aspnetmvc-version": response.headers?.["x-aspnetmvc-version"] || "",
        "x-generator": response.headers?.["x-generator"] || "",
        "x-runtime": response.headers?.["x-runtime"] || "",
        "x-redirect-by": response.headers?.["x-redirect-by"] || "",
        server: response.headers?.server || ""
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
