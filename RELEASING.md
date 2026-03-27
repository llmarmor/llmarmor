# Releasing LLM Armor

This document describes how to cut a release and publish it to PyPI.

## Versioning

LLM Armor follows [Semantic Versioning](https://semver.org/) (`MAJOR.MINOR.PATCH`):

| Increment | When to use | Example |
|---|---|---|
| `MAJOR` | Breaking changes to the CLI or public API | `0.x.x` → `1.0.0` |
| `MINOR` | New rules, new commands, or backwards-compatible features | `0.1.0` → `0.2.0` |
| `PATCH` | Bug fixes, documentation updates, dependency bumps | `0.1.0` → `0.1.1` |

> While the version is `0.x.x`, minor bumps may include breaking changes per semver convention.

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

Pushing the tag automatically triggers the `publish.yml` GitHub Actions workflow, which builds the package and uploads it to PyPI using the `PYPI_TOKEN` secret.

### 4. Create a GitHub Release (optional but recommended)

1. Go to [github.com/llmarmor/llmarmor/releases/new](https://github.com/llmarmor/llmarmor/releases/new)
2. Select the tag you just pushed (`v0.2.0`)
3. Write a short release title and changelog summary
4. Click **Publish release**

### 5. Verify the release

```bash
pip install --upgrade llmarmor
llmarmor --version   # should print 0.2.0
```

Check the package page at: **https://pypi.org/project/llmarmor/**

## First-Time PyPI Setup

If you have not published before, complete this one-time setup:

1. Create an account at [pypi.org](https://pypi.org/account/register/)
2. Generate an API token at [pypi.org/manage/account/token/](https://pypi.org/manage/account/token/)
3. Add the token to GitHub Secrets as `PYPI_TOKEN`:
   - **Settings → Secrets and variables → Actions → New repository secret**
   - Name: `PYPI_TOKEN`, Value: `pypi-XXXXX…`

After this setup, all future releases are fully automated — just tag and push.

## Troubleshooting

| Problem | Fix |
|---|---|
| `403 Forbidden` on upload | Token is wrong or expired — regenerate at PyPI |
| `File already exists` | That version was already uploaded. Bump the version and rebuild. |
| Workflow did not trigger | Make sure the tag starts with `v` (e.g. `v0.2.0`, not `0.2.0`) |
| `pip install llmarmor` shows old version | PyPI indexing can take 1–2 minutes — try again shortly |
