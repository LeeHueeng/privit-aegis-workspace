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
```

Provider-specific prompt files:

```sh
npm run ai:prompt:codex
npm run ai:prompt:gemini
npm run ai:prompt:claude
```

The assistants must keep Aegis runs passive unless the scope file explicitly
allows a stronger mode. Generated `.aegis/` artifacts stay local unless a
reviewer requests a specific evidence bundle.
