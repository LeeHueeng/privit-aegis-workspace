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

## Public Launch Note

For a star-focused open source launch, review the repository for secrets and
private scope data before enabling Pages. Keep the safe demo scope in the
repository and leave staging or customer-specific targets in ignored local files.

The Pages workflow validates the static site on every docs push. If Pages is not
enabled yet, deployment is skipped with a GitHub Actions summary instead of
failing the repository quality gate.
