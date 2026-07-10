# Repository Roles

Privit Aegis uses two public repositories on purpose. The split keeps the CLI
engine reusable while letting this repository focus on the web console,
localized reporting, GitHub Pages, AI settings, and Privit-specific workflow.

## Repositories

| Repository | Role | Audience |
| --- | --- | --- |
| [`privit-project`](https://github.com/LeeHueeng/privit-project) | Reusable Aegis CLI engine | CLI users, package consumers, engine contributors |
| [`privit-aegis-workspace`](https://github.com/LeeHueeng/privit-aegis-workspace) | Privit security testing workspace | Web-console users, reviewers, maintainers, demo visitors |

## Why Not Merge Them?

- The CLI engine can stay small, installable, and npm-ready.
- The workspace can evolve richer UX, reports, screenshots, Pages content, and
  project-specific settings without bloating the CLI package.
- CI can pin the engine by commit SHA, making upgrades explicit and reviewable.
- Issues are easier to route: command/scanner bugs go to the engine; web console
  and report UX go to the workspace.

## How They Connect

GitHub Actions installs the public CLI engine from a pinned commit:

```sh
npm install -g "git+https://github.com/LeeHueeng/privit-project.git#<commit-sha>"
```

Local development can use the same GitHub install, or link the package when
working on engine changes:

```sh
cd privit-project
npm link

cd ../privit-aegis-workspace
npm link aegis-security-cli
```

## Where to Contribute

- CLI command behavior, catalog generation, report writers, scope verification:
  `privit-project`
- Web console UX, localized report presentation, Pages site, AI provider
  settings, GitHub readiness, AIGate workflow: `privit-aegis-workspace`

## Public Positioning

For stars and demos, lead with `privit-aegis-workspace`. It shows the full
experience: browser console, reports, documentation site, and CI gate. Link to
`privit-project` as the clean engine behind the experience.
