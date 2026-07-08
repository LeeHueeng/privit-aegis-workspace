import { existsSync, readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { AI_PROVIDER_IDS, buildAiModelReport, normalizeAiRuntimeSettings } from "./ai-models.js";

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
const runtimeSettings = normalizeAiRuntimeSettings(settings.aiRuntimeSettings);
const configured = new Set([...(integrations.providers || []), ...(settings.aiProviders || [])]);
const providers = AI_PROVIDER_IDS.map((id) => {
  const modelConfig = modelReport.providers[id];
  const provider = {
    id,
    label: modelConfig.label,
    providerType: modelConfig.providerType,
    command: modelConfig.command,
    rootFile: modelConfig.rootFile,
    sidecarFile: modelConfig.sidecarFile
  };
  const cli = provider.providerType === "cli" ? commandInfo(provider.command) : { installed: true, path: "", version: "" };
  const enabled = provider.providerType === "cli" ? configured.has(provider.id) || modelConfig.enabled : modelConfig.enabled;
  const rootReady = provider.rootFile ? existsSync(resolve(cwd, provider.rootFile)) : true;
  const sidecarReady = provider.sidecarFile ? existsSync(resolve(cwd, provider.sidecarFile)) : true;
  const endpointReady = provider.providerType === "cli" || Boolean(modelConfig.endpoint);
  const apiKeyReady = provider.providerType === "cli" || !modelConfig.apiKeyEnv || Boolean(process.env[modelConfig.apiKeyEnv]);
  const ready = enabled
    ? rootReady && sidecarReady && cli.installed && endpointReady && apiKeyReady
    : true;
  return {
    ...provider,
    model: modelReport.providers[provider.id]?.model || "",
    endpoint: modelConfig.endpoint || "",
    apiStyle: modelConfig.apiStyle || "",
    apiKeyEnv: modelConfig.apiKeyEnv || "",
    apiKeyReady,
    endpointReady,
    commandReference: modelReport.commands[provider.id] || {},
    enabled,
    rootReady,
    sidecarReady,
    commandReady: cli.installed,
    commandPath: cli.path,
    version: cli.version,
    ready,
    status: !enabled ? "DISABLED" : ready ? "READY" : "WARN"
  };
});
const enabledProviders = providers.filter((provider) => provider.enabled);
const activeProviders = enabledProviders.length ? enabledProviders : providers;

const result = {
  command: "ai-doctor",
  status: activeProviders.every((provider) => provider.ready) ? "READY" : "WARN",
  readyCount: enabledProviders.filter((provider) => provider.ready).length,
  totalCount: enabledProviders.length,
  providers,
  defaultProvider: modelReport.defaultProvider,
  modelSettings: modelReport.providers,
  runtimeSettings,
  commandReference: modelReport.commands,
  validationCommands: settings.qualityCommands || integrations.validationCommands || [],
  next: providers.every((provider) => provider.ready)
    ? "Run npm run ai:report for the current AI handoff."
    : "Install missing provider CLIs or regenerate integration files with npm run ai:integrate."
};

console.log(JSON.stringify(result, null, 2));
