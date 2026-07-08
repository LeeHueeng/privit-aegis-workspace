import { readFile, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const AI_PROVIDER_IDS = ["codex", "gemini", "claude", "local", "api"];

export const DEFAULT_AI_MODEL_SETTINGS = {
  version: 1,
  defaultProvider: "codex",
  providers: {
    codex: {
      label: "Codex",
      providerType: "cli",
      enabled: true,
      command: "codex",
      rootFile: "AGENTS.md",
      sidecarFile: ".aigate/integrations/codex.md",
      model: "gpt-5.5",
      modelFlag: "--model",
      effort: "high",
      approvalMode: "on-request",
      permissionMode: "",
      sandbox: "workspace-write",
      outputFormat: "text",
      fallbackModel: "",
      extraArgs: "",
      endpoint: "",
      healthUrl: "",
      apiStyle: "cli",
      apiKeyEnv: "OPENAI_API_KEY",
      docsUrl: "https://developers.openai.com/codex/models",
      presets: ["gpt-5.5", "gpt-5.3-codex-spark", "gpt-5", "o3"]
    },
    gemini: {
      label: "Gemini",
      providerType: "cli",
      enabled: true,
      command: "gemini",
      rootFile: "GEMINI.md",
      sidecarFile: ".aigate/integrations/gemini.md",
      model: "gemini-3.1-pro-preview",
      modelFlag: "--model",
      effort: "",
      approvalMode: "default",
      permissionMode: "",
      sandbox: "",
      outputFormat: "text",
      fallbackModel: "",
      extraArgs: "",
      endpoint: "",
      healthUrl: "",
      apiStyle: "cli",
      apiKeyEnv: "GEMINI_API_KEY",
      docsUrl: "https://ai.google.dev/gemini-api/docs/models",
      presets: ["gemini-3.1-pro-preview", "gemini-3.1-flash-lite", "gemini-2.5-pro", "gemini-2.5-flash"]
    },
    claude: {
      label: "Claude",
      providerType: "cli",
      enabled: true,
      command: "claude",
      rootFile: "CLAUDE.md",
      sidecarFile: ".aigate/integrations/claude.md",
      model: "sonnet",
      modelFlag: "--model",
      effort: "high",
      approvalMode: "",
      permissionMode: "manual",
      sandbox: "",
      outputFormat: "text",
      fallbackModel: "",
      extraArgs: "",
      endpoint: "",
      healthUrl: "",
      apiStyle: "cli",
      apiKeyEnv: "ANTHROPIC_API_KEY",
      docsUrl: "https://docs.anthropic.com/en/docs/claude-code/model-config",
      presets: ["sonnet", "opus", "haiku", "fable", "claude-fable-5", "claude-opus-4-8", "claude-sonnet-5", "claude-haiku-4-5"]
    },
    local: {
      label: "Local AI",
      providerType: "local",
      enabled: false,
      command: "curl",
      rootFile: "",
      sidecarFile: "",
      model: "llama3.1:8b",
      modelFlag: "--model",
      effort: "",
      approvalMode: "",
      permissionMode: "",
      sandbox: "",
      outputFormat: "json",
      fallbackModel: "",
      extraArgs: "",
      endpoint: "http://127.0.0.1:11434/v1/chat/completions",
      healthUrl: "http://127.0.0.1:11434/api/tags",
      apiStyle: "openai-chat",
      apiKeyEnv: "",
      docsUrl: "https://github.com/ollama/ollama/blob/main/docs/api.md",
      presets: ["llama3.1:8b", "qwen3.5:8b", "gemma4:9b", "gpt-oss:20b"]
    },
    api: {
      label: "Direct API",
      providerType: "api",
      enabled: false,
      command: "curl",
      rootFile: "",
      sidecarFile: "",
      model: "gpt-5.5",
      modelFlag: "--model",
      effort: "",
      approvalMode: "",
      permissionMode: "",
      sandbox: "",
      outputFormat: "json",
      fallbackModel: "",
      extraArgs: "",
      endpoint: "https://api.openai.com/v1/responses",
      healthUrl: "",
      apiStyle: "openai-responses",
      apiKeyEnv: "OPENAI_API_KEY",
      docsUrl: "https://developers.openai.com/api/reference/resources/responses/methods/create",
      presets: ["gpt-5.5", "gpt-5.4", "gpt-5.4-mini", "gpt-5.3-codex-spark"]
    }
  }
};

function cleanString(value, fallback = "") {
  if (value === undefined || value === null) {
    return fallback;
  }
  return String(value).trim();
}

function cleanBoolean(value, fallback = false) {
  if (value === undefined || value === null || value === "") {
    return fallback;
  }
  if (typeof value === "boolean") {
    return value;
  }
  const normalized = String(value).trim().toLowerCase();
  if (["1", "true", "yes", "on", "enable", "enabled"].includes(normalized)) {
    return true;
  }
  if (["0", "false", "no", "off", "disable", "disabled"].includes(normalized)) {
    return false;
  }
  return fallback;
}

function shellQuote(value) {
  return `"${String(value).replace(/(["\\$`])/g, "\\$1")}"`;
}

function shellQuoteWithEnv(value) {
  return `"${String(value).replace(/(["\\`])/g, "\\$1")}"`;
}

function apiPayload(provider) {
  if (provider.apiStyle === "openai-responses") {
    return JSON.stringify({ model: provider.model, input: "<prompt>" });
  }
  return JSON.stringify({
    model: provider.model,
    messages: [{ role: "user", content: "<prompt>" }],
    stream: false
  });
}

function providerConfigCommand(providerId, provider) {
  const parts = [
    "npm run ai:model:set --",
    "--provider",
    providerId,
    "--model",
    shellQuote(provider.model)
  ];
  if (provider.endpoint) parts.push("--endpoint", shellQuote(provider.endpoint));
  if (provider.apiStyle && provider.apiStyle !== "cli") parts.push("--api-style", shellQuote(provider.apiStyle));
  if (provider.apiKeyEnv) parts.push("--api-key-env", shellQuote(provider.apiKeyEnv));
  if (provider.healthUrl) parts.push("--health-url", shellQuote(provider.healthUrl));
  return parts.join(" ");
}

function buildApiCommand(provider) {
  const endpoint = provider.endpoint || "<endpoint>";
  const headers = [`-H ${shellQuote("Content-Type: application/json")}`];
  if (provider.apiKeyEnv) {
    headers.push(`-H ${shellQuoteWithEnv(`Authorization: Bearer $${provider.apiKeyEnv}`)}`);
  }
  const payload = apiPayload(provider);
  return `curl -sS ${shellQuote(endpoint)} ${headers.join(" ")} -d ${shellQuote(payload)}`;
}

export function normalizeAiModelSettings(input = {}) {
  const providers = {};
  for (const id of AI_PROVIDER_IDS) {
    const defaults = DEFAULT_AI_MODEL_SETTINGS.providers[id];
    const configured = input.providers?.[id] || {};
    providers[id] = {
      ...defaults,
      ...configured,
      label: defaults.label,
      providerType: defaults.providerType,
      command: cleanString(configured.command, defaults.command),
      rootFile: defaults.rootFile,
      sidecarFile: defaults.sidecarFile,
      modelFlag: defaults.modelFlag,
      enabled: cleanBoolean(configured.enabled, defaults.enabled),
      apiKeyEnv: cleanString(configured.apiKeyEnv, defaults.apiKeyEnv),
      docsUrl: defaults.docsUrl,
      presets: Array.from(new Set([...(configured.presets || []), ...defaults.presets])).filter(Boolean),
      model: cleanString(configured.model, defaults.model),
      effort: cleanString(configured.effort, defaults.effort),
      approvalMode: cleanString(configured.approvalMode, defaults.approvalMode),
      permissionMode: cleanString(configured.permissionMode, defaults.permissionMode),
      sandbox: cleanString(configured.sandbox, defaults.sandbox),
      outputFormat: cleanString(configured.outputFormat, defaults.outputFormat),
      fallbackModel: cleanString(configured.fallbackModel, defaults.fallbackModel),
      extraArgs: cleanString(configured.extraArgs, defaults.extraArgs),
      endpoint: cleanString(configured.endpoint, defaults.endpoint),
      healthUrl: cleanString(configured.healthUrl, defaults.healthUrl),
      apiStyle: cleanString(configured.apiStyle, defaults.apiStyle)
    };
  }

  const defaultProvider = AI_PROVIDER_IDS.includes(input.defaultProvider) ? input.defaultProvider : DEFAULT_AI_MODEL_SETTINGS.defaultProvider;
  return {
    version: 1,
    defaultProvider,
    providers,
    updatedAt: input.updatedAt || null
  };
}

export function buildProviderCommandReference(providerId, provider) {
  if (provider.providerType === "local" || provider.providerType === "api") {
    return {
      interactive: provider.healthUrl ? `curl -sS ${shellQuote(provider.healthUrl)}` : `test -n "$${provider.apiKeyEnv || "API_KEY"}"`,
      headless: buildApiCommand(provider),
      config: providerConfigCommand(providerId, provider),
      inSession: "Use the generated API command or configure this provider as the default.",
      health: provider.healthUrl ? `curl -sS ${shellQuote(provider.healthUrl)}` : `test -n "$${provider.apiKeyEnv || "API_KEY"}"`
    };
  }

  const modelArg = `${provider.modelFlag} ${shellQuote(provider.model)}`;
  const extra = provider.extraArgs ? ` ${provider.extraArgs}` : "";

  if (providerId === "codex") {
    const sandbox = provider.sandbox ? ` --sandbox ${shellQuote(provider.sandbox)}` : "";
    const approval = provider.approvalMode ? ` --ask-for-approval ${shellQuote(provider.approvalMode)}` : "";
    return {
      interactive: `codex ${modelArg}${sandbox}${approval}${extra}`,
      headless: `codex exec ${modelArg}${sandbox}${approval}${extra} ${shellQuote("<prompt>")}`,
      config: `codex -c model=${shellQuote(provider.model)}`,
      inSession: `/model ${provider.model}`
    };
  }

  if (providerId === "gemini") {
    const approval = provider.approvalMode ? ` --approval-mode ${shellQuote(provider.approvalMode)}` : "";
    const output = provider.outputFormat ? ` --output-format ${shellQuote(provider.outputFormat)}` : "";
    return {
      interactive: `gemini ${modelArg}${approval}${extra}`,
      headless: `gemini ${modelArg}${approval}${output}${extra} --prompt ${shellQuote("<prompt>")}`,
      config: `gemini ${modelArg}`,
      inSession: "/model"
    };
  }

  const effort = provider.effort ? ` --effort ${shellQuote(provider.effort)}` : "";
  const permission = provider.permissionMode ? ` --permission-mode ${shellQuote(provider.permissionMode)}` : "";
  const output = provider.outputFormat ? ` --output-format ${shellQuote(provider.outputFormat)}` : "";
  const fallback = provider.fallbackModel ? ` --fallback-model ${shellQuote(provider.fallbackModel)}` : "";
  return {
    interactive: `claude ${modelArg}${effort}${permission}${extra}`,
    headless: `claude ${modelArg}${effort}${permission}${output}${fallback}${extra} --print ${shellQuote("<prompt>")}`,
    config: `claude ${modelArg}`,
    inSession: "/model"
  };
}

export function buildAiModelReport(aiModelSettings) {
  const normalized = normalizeAiModelSettings(aiModelSettings);
  return {
    ...normalized,
    commands: Object.fromEntries(
      AI_PROVIDER_IDS.map((id) => [id, buildProviderCommandReference(id, normalized.providers[id])])
    )
  };
}

async function probeUrl(url) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 2500);
  try {
    const response = await fetch(url, { method: "GET", signal: controller.signal });
    return {
      ok: response.ok,
      status: response.status,
      detail: response.ok ? "reachable" : `HTTP ${response.status}`
    };
  } catch (error) {
    return {
      ok: false,
      status: 0,
      detail: error.name === "AbortError" ? "timeout" : error.message
    };
  } finally {
    clearTimeout(timer);
  }
}

async function checkProviders(settings, providerId = "") {
  const report = buildAiModelReport(settings);
  const ids = providerId ? [providerId] : AI_PROVIDER_IDS;
  const checks = {};
  for (const id of ids) {
    if (!AI_PROVIDER_IDS.includes(id)) {
      throw new Error(`Unsupported provider: ${id}`);
    }
    const provider = report.providers[id];
    const envPresent = provider.providerType === "cli" ? true : provider.apiKeyEnv ? Boolean(process.env[provider.apiKeyEnv]) : true;
    const apiKeyReady = provider.providerType === "cli" ? true : envPresent;
    const endpointConfigured = provider.providerType === "cli" || Boolean(provider.endpoint);
    const health = provider.providerType === "local" && provider.healthUrl
      ? await probeUrl(provider.healthUrl)
      : { ok: true, status: 0, detail: "not required" };
    checks[id] = {
      label: provider.label,
      providerType: provider.providerType,
      enabled: provider.enabled,
      model: provider.model,
      endpoint: provider.endpoint,
      healthUrl: provider.healthUrl,
      apiStyle: provider.apiStyle,
      apiKeyEnv: provider.apiKeyEnv,
      apiKeyPresent: envPresent,
      endpointConfigured,
      health,
      ready: !provider.enabled || (endpointConfigured && apiKeyReady && health.ok),
      commandReference: report.commands[id]
    };
  }
  return checks;
}

function parseArgs(argv) {
  const args = argv.slice(2);
  const flags = {};
  const positionals = [];
  for (let index = 0; index < args.length; index += 1) {
    const token = args[index];
    if (!token.startsWith("--")) {
      positionals.push(token);
      continue;
    }
    const [rawKey, inlineValue] = token.slice(2).split(/=(.*)/s, 2);
    const key = rawKey;
    if (inlineValue !== undefined) {
      flags[key] = inlineValue;
      continue;
    }
    const next = args[index + 1];
    if (!next || next.startsWith("--")) {
      flags[key] = true;
      continue;
    }
    flags[key] = next;
    index += 1;
  }
  return { positionals, flags };
}

async function readSettings(cwd) {
  const file = resolve(cwd, ".aigate/settings.json");
  if (!existsSync(file)) {
    return {};
  }
  return JSON.parse(await readFile(file, "utf8"));
}

async function writeSettings(cwd, settings) {
  await writeFile(resolve(cwd, ".aigate/settings.json"), `${JSON.stringify(settings, null, 2)}\n`, "utf8");
}

async function main(argv = process.argv, cwd = process.cwd()) {
  const { positionals, flags } = parseArgs(argv);
  const command = positionals[0] || "show";
  const settings = await readSettings(cwd);
  const current = normalizeAiModelSettings(settings.aiModelSettings);

  if (command === "commands") {
    console.log(JSON.stringify(buildAiModelReport(current).commands, null, 2));
    return;
  }

  if (command === "check") {
    console.log(JSON.stringify(await checkProviders(settings.aiModelSettings, cleanString(flags.provider, "")), null, 2));
    return;
  }

  if (command === "set") {
    const provider = cleanString(flags.provider, current.defaultProvider);
    if (!AI_PROVIDER_IDS.includes(provider)) {
      throw new Error(`Unsupported provider: ${provider}`);
    }
    const next = normalizeAiModelSettings({
      ...current,
      defaultProvider: flags["default-provider"] ? cleanString(flags["default-provider"], current.defaultProvider) : current.defaultProvider,
      providers: {
        ...current.providers,
        [provider]: {
          ...current.providers[provider],
          enabled: flags.enable ? true : flags.disable ? false : cleanBoolean(flags.enabled, current.providers[provider].enabled),
          model: cleanString(flags.model, current.providers[provider].model),
          effort: cleanString(flags.effort, current.providers[provider].effort),
          approvalMode: cleanString(flags["approval-mode"], current.providers[provider].approvalMode),
          permissionMode: cleanString(flags["permission-mode"], current.providers[provider].permissionMode),
          sandbox: cleanString(flags.sandbox, current.providers[provider].sandbox),
          outputFormat: cleanString(flags["output-format"], current.providers[provider].outputFormat),
          fallbackModel: cleanString(flags["fallback-model"], current.providers[provider].fallbackModel),
          extraArgs: cleanString(flags["extra-args"], current.providers[provider].extraArgs),
          endpoint: cleanString(flags.endpoint, current.providers[provider].endpoint),
          healthUrl: cleanString(flags["health-url"], current.providers[provider].healthUrl),
          apiStyle: cleanString(flags["api-style"], current.providers[provider].apiStyle),
          apiKeyEnv: cleanString(flags["api-key-env"], current.providers[provider].apiKeyEnv)
        }
      },
      updatedAt: new Date().toISOString()
    });
    settings.aiModelSettings = next;
    await writeSettings(cwd, settings);
    console.log(JSON.stringify(buildAiModelReport(next), null, 2));
    return;
  }

  console.log(JSON.stringify(buildAiModelReport(current), null, 2));
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error(error.message);
    process.exit(error.exitCode || 1);
  });
}
