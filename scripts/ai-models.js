import { readFile, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const AI_PROVIDER_IDS = ["codex", "gemini", "claude"];

export const DEFAULT_AI_MODEL_SETTINGS = {
  version: 1,
  defaultProvider: "codex",
  providers: {
    codex: {
      label: "Codex",
      command: "codex",
      model: "gpt-5.5",
      modelFlag: "--model",
      effort: "high",
      approvalMode: "on-request",
      permissionMode: "",
      sandbox: "workspace-write",
      outputFormat: "text",
      fallbackModel: "",
      extraArgs: "",
      apiKeyEnv: "OPENAI_API_KEY",
      docsUrl: "https://developers.openai.com/codex/models",
      presets: ["gpt-5.5", "gpt-5.3-codex-spark", "gpt-5", "o3"]
    },
    gemini: {
      label: "Gemini",
      command: "gemini",
      model: "gemini-3.1-pro-preview",
      modelFlag: "--model",
      effort: "",
      approvalMode: "default",
      permissionMode: "",
      sandbox: "",
      outputFormat: "text",
      fallbackModel: "",
      extraArgs: "",
      apiKeyEnv: "GEMINI_API_KEY",
      docsUrl: "https://ai.google.dev/gemini-api/docs/models",
      presets: ["gemini-3.1-pro-preview", "gemini-3.1-flash-lite", "gemini-2.5-pro", "gemini-2.5-flash"]
    },
    claude: {
      label: "Claude",
      command: "claude",
      model: "sonnet",
      modelFlag: "--model",
      effort: "high",
      approvalMode: "",
      permissionMode: "manual",
      sandbox: "",
      outputFormat: "text",
      fallbackModel: "",
      extraArgs: "",
      apiKeyEnv: "ANTHROPIC_API_KEY",
      docsUrl: "https://docs.anthropic.com/en/docs/claude-code/model-config",
      presets: ["sonnet", "opus", "haiku", "fable", "claude-fable-5", "claude-opus-4-8", "claude-sonnet-5", "claude-haiku-4-5"]
    }
  }
};

function cleanString(value, fallback = "") {
  if (value === undefined || value === null) {
    return fallback;
  }
  return String(value).trim();
}

function shellQuote(value) {
  return `"${String(value).replace(/(["\\$`])/g, "\\$1")}"`;
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
      command: defaults.command,
      modelFlag: defaults.modelFlag,
      apiKeyEnv: defaults.apiKeyEnv,
      docsUrl: defaults.docsUrl,
      presets: Array.from(new Set([...(configured.presets || []), ...defaults.presets])).filter(Boolean),
      model: cleanString(configured.model, defaults.model),
      effort: cleanString(configured.effort, defaults.effort),
      approvalMode: cleanString(configured.approvalMode, defaults.approvalMode),
      permissionMode: cleanString(configured.permissionMode, defaults.permissionMode),
      sandbox: cleanString(configured.sandbox, defaults.sandbox),
      outputFormat: cleanString(configured.outputFormat, defaults.outputFormat),
      fallbackModel: cleanString(configured.fallbackModel, defaults.fallbackModel),
      extraArgs: cleanString(configured.extraArgs, defaults.extraArgs)
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
          model: cleanString(flags.model, current.providers[provider].model),
          effort: cleanString(flags.effort, current.providers[provider].effort),
          approvalMode: cleanString(flags["approval-mode"], current.providers[provider].approvalMode),
          permissionMode: cleanString(flags["permission-mode"], current.providers[provider].permissionMode),
          sandbox: cleanString(flags.sandbox, current.providers[provider].sandbox),
          outputFormat: cleanString(flags["output-format"], current.providers[provider].outputFormat),
          fallbackModel: cleanString(flags["fallback-model"], current.providers[provider].fallbackModel),
          extraArgs: cleanString(flags["extra-args"], current.providers[provider].extraArgs)
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
