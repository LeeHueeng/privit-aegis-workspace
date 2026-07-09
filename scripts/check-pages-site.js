import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

const cwd = process.cwd();

const requiredFiles = [
  "README.md",
  "README.ko.md",
  "README.ja.md",
  "README.zh-CN.md",
  "docs/LANGUAGES.md",
  "docs/SHOWCASE.md",
  "docs/EXAMPLES.md",
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

  const readmeLinks = ["README.ko.md", "README.ja.md", "README.zh-CN.md", "GitHub Pages", "docs/SHOWCASE.md", "docs/EXAMPLES.md"];
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
}

if (failures.length) {
  console.error(JSON.stringify({ status: "FAIL", failures }, null, 2));
  process.exit(1);
}

console.log(JSON.stringify({ status: "PASS", checkedFiles: requiredFiles.length }, null, 2));
