# GitHub Pages Setup

This repository includes a ready-to-run GitHub Pages site under `docs/pages`.
The deployment workflow is `.github/workflows/pages.yml`.

## Deployment Model

- Source directory: `docs/pages`
- Trigger: pushes to `main` that change README, repository docs, or the Pages
  site files
- Workflow permissions: `contents: read`, `pages: write`, `id-token: write`
- Pre-deploy validation: `npm run site:check`
- Expected URL after activation:
  `https://leehueeng.github.io/privit-aegis-workspace/`

## Enable Pages

If the repository plan supports Pages, enable workflow-based Pages publishing:

```sh
gh api --method POST repos/LeeHueeng/privit-aegis-workspace/pages -f build_type=workflow
```

Then rerun the Pages workflow from GitHub Actions or push a docs change.

## Private Repository Note

GitHub Pages is available for public repositories on GitHub Free. Private
repositories need a plan that supports Pages for private repositories, such as
GitHub Pro, Team, Enterprise Cloud, or Enterprise Server. If the repository is
private on an unsupported plan, the API returns:

```text
Your current plan does not support GitHub Pages for this repository.
```

For a star-focused open source launch, review the repository for secrets and
private scope data first, then make the repository public or move the Pages site
to a public docs repository.
