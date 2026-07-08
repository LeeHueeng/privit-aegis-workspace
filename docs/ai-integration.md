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

Reference commands generated from the current settings:

```sh
codex --model "gpt-5.5"
gemini --model "gemini-3.1-pro-preview"
claude --model "sonnet" --effort "high"
```

Model reference pages:

- Codex: https://developers.openai.com/codex/models
- Gemini: https://ai.google.dev/gemini-api/docs/models
- Claude Code: https://docs.anthropic.com/en/docs/claude-code/model-config

The assistants must keep Aegis runs passive unless the scope file explicitly
allows a stronger mode. Generated `.aegis/` artifacts stay local unless a
reviewer requests a specific evidence bundle.
