import { existsSync, readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { buildAiModelReport } from "./ai-models.js";

const cwd = process.cwd();

function readJsonFile(file, fallback) {
  try {
    return JSON.parse(readFileSync(resolve(cwd, file), "utf8"));
  } catch {
    return fallback;
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
  return {
    installed: true,
    path: commandPath,
    version: [versionResult.stdout, versionResult.stderr].filter(Boolean).join(" ").trim()
  };
}

const integrations = readJsonFile(".aigate/integrations.json", {});
const settings = readJsonFile(".aigate/settings.json", {});
const modelReport = buildAiModelReport(settings.aiModelSettings);
const configured = new Set([...(integrations.providers || []), ...(settings.aiProviders || [])]);
const providers = [
  { id: "codex", label: "Codex", command: "codex", rootFile: "AGENTS.md" },
  { id: "gemini", label: "Gemini", command: "gemini", rootFile: "GEMINI.md" },
  { id: "claude", label: "Claude", command: "claude", rootFile: "CLAUDE.md" }
].map((provider) => {
  const sidecarFile = `.aigate/integrations/${provider.id}.md`;
  const cli = commandInfo(provider.command);
  const enabled = configured.has(provider.id);
  const rootReady = existsSync(resolve(cwd, provider.rootFile));
  const sidecarReady = existsSync(resolve(cwd, sidecarFile));
  return {
    ...provider,
    model: modelReport.providers[provider.id]?.model || "",
    commandReference: modelReport.commands[provider.id] || {},
    enabled,
    rootReady,
    sidecarReady,
    commandReady: cli.installed,
    commandPath: cli.path,
    version: cli.version,
    ready: enabled && rootReady && sidecarReady && cli.installed
  };
});

const result = {
  command: "ai-doctor",
  status: providers.every((provider) => provider.ready) ? "READY" : "WARN",
  readyCount: providers.filter((provider) => provider.ready).length,
  totalCount: providers.length,
  providers,
  defaultProvider: modelReport.defaultProvider,
  modelSettings: modelReport.providers,
  commandReference: modelReport.commands,
  validationCommands: settings.qualityCommands || integrations.validationCommands || [],
  next: providers.every((provider) => provider.ready)
    ? "Run npm run ai:report for the current AI handoff."
    : "Install missing provider CLIs or regenerate integration files with npm run ai:integrate."
};

console.log(JSON.stringify(result, null, 2));
