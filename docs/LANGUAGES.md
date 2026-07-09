# Multilingual Documentation

Privit Aegis keeps public entry points in four languages so contributors can
understand the project before they install anything.

| Language | README | Human Guide | Agent Guide |
| --- | --- | --- | --- |
| Korean | [`README.ko.md`](../README.ko.md) | [`docs/ko-KR/HUMAN_SECURITY_GUIDE.md`](./ko-KR/HUMAN_SECURITY_GUIDE.md) | [`docs/ko-KR/AGENT_SECURITY_CHECKS.md`](./ko-KR/AGENT_SECURITY_CHECKS.md) |
| English | [`README.md`](../README.md) | [`docs/en-US/HUMAN_SECURITY_GUIDE.md`](./en-US/HUMAN_SECURITY_GUIDE.md) | [`docs/en-US/AGENT_SECURITY_CHECKS.md`](./en-US/AGENT_SECURITY_CHECKS.md) |
| Japanese | [`README.ja.md`](../README.ja.md) | [`docs/ja-JP/HUMAN_SECURITY_GUIDE.md`](./ja-JP/HUMAN_SECURITY_GUIDE.md) | [`docs/ja-JP/AGENT_SECURITY_CHECKS.md`](./ja-JP/AGENT_SECURITY_CHECKS.md) |
| Chinese | [`README.zh-CN.md`](../README.zh-CN.md) | [`docs/zh-CN/HUMAN_SECURITY_GUIDE.md`](./zh-CN/HUMAN_SECURITY_GUIDE.md) | [`docs/zh-CN/AGENT_SECURITY_CHECKS.md`](./zh-CN/AGENT_SECURITY_CHECKS.md) |

## Translation Rules

- Keep security meaning exact before making prose sound natural.
- Preserve command names, file paths, environment variables, and finding IDs.
- Prefer short sentences for report and CLI language because findings are read
  under pressure.
- If a detection rule changes, update the English and Korean copy first, then
  mirror the same behavior in Japanese and Chinese.

## Markdown Support

Localized Markdown files are intentionally kept at the repository root when they
are first-entry documents. Deeper guides live under locale folders such as
`docs/ko-KR` and `docs/ja-JP`. The GitHub Pages site links to every language
entry point and mirrors the same navigation model.
