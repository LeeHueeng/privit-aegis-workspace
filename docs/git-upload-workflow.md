# Git Upload Workflow

Use this flow for Privit Aegis changes.

1. Update scope, scripts, catalog, or docs.
2. Run `npm run ci:aegis`.
3. Run `npm run gate:ready`.
4. Commit only the focused workspace files.
5. Push to a work branch and open a pull request.

If a push fails because workflow files are included, refresh the GitHub token
with workflow permission before retrying:

```sh
gh auth refresh -h github.com -s workflow
git push -u origin main
```

For private repository creation and workflow upload together:

```sh
gh auth refresh -h github.com -s repo -s workflow
```
