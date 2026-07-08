# AI Integration

Privit Aegis is wired for these AI assistants:

- Codex: `AGENTS.md`, `.aigate/integrations/codex.md`
- Gemini: `GEMINI.md`, `.aigate/integrations/gemini.md`
- Claude: `CLAUDE.md`, `.aigate/integrations/claude.md`

Shared validation commands:

```sh
npm run ci:aegis
npm run gate:ready
```

AI handoff commands:

```sh
npm run ai:doctor
npm run ai:report
npm run ai:prompt
npm run ai:model:show
npm run ai:model:commands
npm run ai:model:check
npm run ai:settings:show
```

Provider-specific prompt files:

```sh
npm run ai:prompt:codex
npm run ai:prompt:gemini
npm run ai:prompt:claude
```

Model settings are stored in `.aigate/settings.json` under `aiModelSettings`.
Use the web console AI tab or the CLI helper:

```sh
npm run ai:model:set -- --provider codex --model gpt-5.5
npm run ai:model:set -- --provider gemini --model gemini-3.1-pro-preview
npm run ai:model:set -- --provider claude --model sonnet --effort high
```

Runtime settings are stored under `aiRuntimeSettings`. These control shared AI
behavior across CLI, web console, local AI, and direct API providers:

```sh
npm run ai:settings:show
npm run ai:settings:set -- --profile secure-balanced --temperature 0.2 --max-output-tokens 8192 --max-input-tokens 128000 --allow-network false --allow-package-install false --budget-usd 2 --daily-budget-usd 10 --min-aigate-score 89 --language ko
```

The runtime profile includes response shaping, context budgets, tool permission
defaults, prompt-injection and secret-redaction guards, cost budgets, audit-log
retention, AIGate score thresholds, and handoff language. The web console AI tab
exposes the common fields and keeps the full advanced JSON editable.

Local and direct API providers are available but disabled by default. They store
only endpoint and environment-variable names, never secret values:

```sh
npm run ai:model:set -- --provider local --enable --model llama3.1:8b --endpoint http://127.0.0.1:11434/v1/chat/completions --health-url http://127.0.0.1:11434/api/tags --api-style openai-chat
npm run ai:model:set -- --provider api --enable --model gpt-5.5 --endpoint https://api.openai.com/v1/responses --api-style openai-responses --api-key-env OPENAI_API_KEY
npm run ai:model:check
```

Reference commands generated from the current settings:

```sh
codex --model "gpt-5.5"
gemini --model "gemini-3.1-pro-preview"
claude --model "sonnet" --effort "high"
curl -sS "http://127.0.0.1:11434/v1/chat/completions" -H "Content-Type: application/json" -d "{\"model\":\"llama3.1:8b\",\"messages\":[{\"role\":\"user\",\"content\":\"<prompt>\"}],\"stream\":false}"
curl -sS "https://api.openai.com/v1/responses" -H "Content-Type: application/json" -H "Authorization: Bearer $OPENAI_API_KEY" -d "{\"model\":\"gpt-5.5\",\"input\":\"<prompt>\"}"
```

Model reference pages:

- Codex: https://developers.openai.com/codex/models
- Gemini: https://ai.google.dev/gemini-api/docs/models
- Claude Code: https://docs.anthropic.com/en/docs/claude-code/model-config
- Local/Ollama API: https://github.com/ollama/ollama/blob/main/docs/api.md
- OpenAI Responses API: https://developers.openai.com/api/reference/resources/responses/methods/create

The assistants must keep Aegis runs passive unless the scope file explicitly
allows a stronger mode. Generated `.aegis/` artifacts stay local unless a
reviewer requests a specific evidence bundle.
