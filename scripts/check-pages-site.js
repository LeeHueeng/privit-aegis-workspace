import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

const cwd = process.cwd();

const requiredFiles = [
  "README.md",
  "README.ko.md",
  "README.ja.md",
  "README.zh-CN.md",
  "SUPPORT.md",
  "aegis.scope.example.json",
  "docs/LANGUAGES.md",
  "docs/SHOWCASE.md",
  "docs/EXAMPLES.md",
  "docs/ARCHITECTURE.md",
  "docs/DETECTION_MATRIX.md",
  "docs/FAQ.md",
  "docs/PRIVACY_AND_DATA.md",
  "docs/THREAT_MODEL.md",
  "docs/SAFE_SCOPE_TEMPLATE.md",
  "docs/RELEASE_PROCESS.md",
  "docs/LAUNCH_CHECKLIST.md",
  "docs/github-pages.md",
  "docs/ROADMAP.md",
  "docs/assets/aegis-readme-preview.svg",
  "docs/pages/index.html",
  "docs/pages/styles.css",
  "docs/pages/site.js",
  "docs/pages/assets/aegis-workflow.svg"
];

function read(file) {
  return readFileSync(resolve(cwd, file), "utf8");
}

const failures = [];

for (const file of requiredFiles) {
  if (!existsSync(resolve(cwd, file))) {
    failures.push(`Missing required documentation file: ${file}`);
  }
}

if (failures.length === 0) {
  const rootReadme = read("README.md");
  const languageIndex = read("docs/LANGUAGES.md");
  const indexHtml = read("docs/pages/index.html");
  const siteJs = read("docs/pages/site.js");

  const readmeLinks = [
    "README.ko.md",
    "README.ja.md",
    "README.zh-CN.md",
    "GitHub Pages",
    "docs/SHOWCASE.md",
    "docs/EXAMPLES.md",
    "docs/ARCHITECTURE.md",
    "docs/DETECTION_MATRIX.md",
    "docs/FAQ.md",
    "docs/PRIVACY_AND_DATA.md",
    "docs/THREAT_MODEL.md",
    "docs/SAFE_SCOPE_TEMPLATE.md",
    "docs/RELEASE_PROCESS.md"
  ];
  for (const link of readmeLinks) {
    if (!rootReadme.includes(link)) {
      failures.push(`README.md is missing language or Pages link: ${link}`);
    }
  }

  for (const locale of ["Korean", "English", "Japanese", "Chinese"]) {
    if (!languageIndex.includes(locale)) {
      failures.push(`docs/LANGUAGES.md is missing locale row: ${locale}`);
    }
  }

  for (const lang of ["ko", "en", "ja", "zh"]) {
    if (!indexHtml.includes(`data-lang="${lang}"`)) {
      failures.push(`GitHub Pages site is missing language button: ${lang}`);
    }
    if (!siteJs.includes(`${lang}: {`)) {
      failures.push(`GitHub Pages translations are missing language block: ${lang}`);
    }
  }

  for (const anchor of ["#overview", "#workflow", "#checks", "#reports", "#ai", "#start"]) {
    if (!indexHtml.includes(anchor)) {
      failures.push(`GitHub Pages navigation is missing anchor: ${anchor}`);
    }
  }

  if (!indexHtml.includes("docs/EXAMPLES.md")) {
    failures.push("GitHub Pages site is missing the examples link.");
  }

  const safeScope = JSON.parse(read("aegis.scope.example.json"));
  const frontend = safeScope.targets?.frontend || {};
  const allowedHosts = frontend.allowed_hosts || [];
  const safeHosts = allowedHosts.every((host) => ["localhost", "127.0.0.1"].includes(host));
  const safety = safeScope.safety || {};
  const disabledFlags = ["destructive_tests", "brute_force", "data_exfiltration", "persistence", "production_active_scan"]
    .every((flag) => safety[flag] === false);
  if (safeScope.environment !== "local") {
    failures.push("aegis.scope.example.json must use local environment.");
  }
  if (!String(frontend.base_url || "").startsWith("http://localhost")) {
    failures.push("aegis.scope.example.json frontend must point at localhost.");
  }
  if (!safeHosts || allowedHosts.length !== 2) {
    failures.push("aegis.scope.example.json allowed_hosts must contain only localhost and 127.0.0.1.");
  }
  if (!disabledFlags) {
    failures.push("aegis.scope.example.json must disable all destructive safety flags.");
  }
}

if (failures.length) {
  console.error(JSON.stringify({ status: "FAIL", failures }, null, 2));
  process.exit(1);
}

console.log(JSON.stringify({ status: "PASS", checkedFiles: requiredFiles.length }, null, 2));
