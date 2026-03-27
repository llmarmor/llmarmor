# Releasing LLM Armor

This document describes how to cut a release and publish it to PyPI and GitHub Releases.

## Versioning

LLM Armor follows [Semantic Versioning](https://semver.org/) (`MAJOR.MINOR.PATCH`):

| Increment | When to use | Example |
|---|---|---|
| `PATCH` | Bug fixes, false-positive/negative corrections, dependency bumps | `0.1.0` → `0.1.1` |
| `MINOR` | New rules, new commands, or backwards-compatible features | `0.1.1` → `0.2.0` |
| `MAJOR` | Breaking changes to the CLI or public API | `0.x.x` → `1.0.0` |

> While the version is `0.x.x`, minor bumps may include breaking changes per semver convention.

### What triggers a release?

Not every merge to `main` is a release. Tag intentionally:

| Change type | Version bump | Tag + release? |
|---|---|---|
| README, docs, RELEASING.md only | None | No |
| CI workflow fix | None | No |
| Tests only | None | No |
| Fix a regex false positive/negative | PATCH | Yes |
| Fix a CLI crash | PATCH | Yes |
| Add a new detection rule | MINOR | Yes |
| Add new CLI command or flag | MINOR | Yes |
| Add language support (e.g. TypeScript) | MINOR | Yes |
| Breaking CLI change (rename/remove flag) | MAJOR | Yes |
| Rename or remove a rule ID | MAJOR | Yes |

## Release Process

### 1. Update the version number

The version is defined in two places — keep them in sync:

```bash
# src/llmarmor/__init__.py
__version__ = "0.2.0"

# pyproject.toml
version = "0.2.0"
```

### 2. Commit the version bump

```bash
git add src/llmarmor/__init__.py pyproject.toml
git commit -m "chore: bump version to v0.2.0"
git push origin main
```

### 3. Tag the release

```bash
git tag v0.2.0
git push origin v0.2.0
```

Pushing the tag automatically triggers the `publish.yml` GitHub Actions workflow, which:
1. Builds the package (`python -m build`)
2. Uploads it to PyPI using the `PYPI_TOKEN` secret
3. Creates a GitHub Release with the built files attached and auto-generated release notes

### 4. Verify the release

```bash
pip install --upgrade llmarmor
llmarmor --version   # should print 0.2.0
```

Check the package page at: **https://pypi.org/project/llmarmor/**

Check the GitHub Release at: **https://github.com/llmarmor/llmarmor/releases**

## First-Time PyPI Setup

If you have not published before, complete this one-time setup:

1. Create an account at [pypi.org](https://pypi.org/account/register/)
2. Generate an API token at [pypi.org/manage/account/token/](https://pypi.org/manage/account/token/)
3. Add the token to GitHub Secrets as `PYPI_TOKEN`:
   - **Settings → Secrets and variables → Actions → New repository secret**
   - Name: `PYPI_TOKEN`, Value: `pypi-XXXXX…`

The `GITHUB_TOKEN` secret used to create GitHub Releases is provided automatically by GitHub Actions — no setup needed.

After this setup, all future releases are fully automated — just tag and push.

## Retroactive Note: v0.1.0

`v0.1.0` was published to PyPI but has no corresponding GitHub Release or git tag. To retroactively create the tag:

```bash
# Find the commit that corresponded to the v0.1.0 PyPI publish
git log --oneline

# Tag that commit
git tag v0.1.0 <commit-sha>
git push origin v0.1.0
```

Then create a GitHub Release manually for it at:
**https://github.com/llmarmor/llmarmor/releases/new** — select the `v0.1.0` tag.

All future releases from `v0.2.0` onwards will have both a PyPI entry and a GitHub Release created automatically.

## Troubleshooting

| Problem | Fix |
|---|---|
| `403 Forbidden` on upload | Token is wrong or expired — regenerate at PyPI |
| `File already exists` | That version was already uploaded. Bump the version and rebuild. |
| Workflow did not trigger | Make sure the tag starts with `v` (e.g. `v0.2.0`, not `0.2.0`) |
| `pip install llmarmor` shows old version | PyPI indexing can take 1–2 minutes — try again shortly |
| GitHub Release not created | Check that `GITHUB_TOKEN` permissions include `contents: write` — already set in `publish.yml` |
