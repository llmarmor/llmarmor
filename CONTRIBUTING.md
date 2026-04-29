# Contributing to LLM Armor

Thank you for your interest in contributing to LLM Armor! This guide explains
how to set up a development environment, add new rules, and submit pull requests.

---

## Table of Contents

- [Development Setup](#development-setup)
- [Running Tests](#running-tests)
- [Code Style](#code-style)
- [Project Structure](#project-structure)
- [Adding a New Rule](#adding-a-new-rule)
- [Pull Request Process](#pull-request-process)
- [Code of Conduct](#code-of-conduct)

---

## Development Setup

**Requirements:** Python 3.10+

```bash
# Clone the repository
git clone https://github.com/llmarmor/llmarmor.git
cd llmarmor

# Install in editable mode with all dev dependencies
pip install -e ".[dev]"
```

The `[dev]` extras include `pytest`, `pytest-cov`, `ruff`, and other
development tools listed in `pyproject.toml`.

---

## Running Tests

```bash
# Run the full test suite
pytest

# Run with verbose output
pytest -v

# Run a specific test class or test
pytest tests/test_scanner.py::TestLLM01PromptInjection -v
pytest tests/test_llm08_excessive_agency.py -v

# Run with coverage report
pytest --cov=llmarmor --cov-report=term-missing
```

All 349+ tests must pass before a PR can be merged.  Tests are organised by
rule — one file per rule plus a central `test_scanner.py` for integration tests
and formatter tests.

---

## Code Style

LLM Armor uses:

- **Python 3.10+ type hints** throughout (no `Optional[X]` — use `X | None`)
- **`ruff`** for linting and formatting:

  ```bash
  ruff check src/ tests/
  ruff format --check src/ tests/
  ```

- **Docstrings** on all public functions, classes, and modules
- **No wildcard imports** — always import names explicitly
- **Single source of truth** — messages (what/why/fix/reference_url) must be
  defined in `src/llmarmor/messages.py`, never hardcoded in rule files

---

## Project Structure

```
src/llmarmor/
├── __init__.py          # Package version
├── cli.py               # Click CLI entry point (scan, rules commands)
├── scanner.py           # Main scan orchestration (run_scan)
├── ast_analysis.py      # AST-based taint analysis (LLM01/05/07/08)
├── registry.py          # Rule registry (RuleDefinition, RuleRegistry)
├── messages.py          # Centralized message catalog (what/why/fix/ref)
├── formatters.py        # Output formatters (grouped/flat/json/md/sarif)
├── config.py            # .llmarmor.yaml config file parsing
├── secret_patterns.py   # LLM API key regex patterns
├── rules/
│   ├── llm01_prompt_injection.py
│   ├── llm02_sensitive_info.py
│   ├── llm05_improper_output.py
│   ├── llm07_system_prompt_leak.py
│   ├── llm08_excessive_agency.py
│   └── llm10_unbounded_consumption.py
└── handlers/            # Non-Python file type handlers
    ├── env.py           # .env files
    ├── yaml_handler.py  # YAML config files
    ├── json_handler.py  # JSON files
    ├── js_handler.py    # JavaScript/TypeScript
    ├── docs_handler.py  # Markdown/text
    └── notebook.py      # Jupyter notebooks
```

---

## Adding a New Rule

Follow these steps to add a new detection rule:

### 1. Register the rule in `registry.py`

Add a `RuleDefinition` entry with `status=Status.ACTIVE`:

```python
registry.register(
    RuleDefinition(
        rule_id="LLM00",
        name="Your Rule Name",
        status=Status.ACTIVE,
        default_severity=Severity.HIGH,
        description="...",
        fix_suggestion="...",
    )
)
```

### 2. Add message catalog entries in `messages.py`

Add `MessageEntry` entries for each finding variant emitted by your rule:

```python
("LLM00", "variant_name"): MessageEntry(
    summary="Short one-line description",
    what="What was detected, in plain English.",
    why="Why this is dangerous, with a concrete attack scenario.",
    fix="Specific code-change recommendation.",
    reference_url=RULE_URLS["LLM00"],
),
```

Also add the OWASP URL to `RULE_URLS`:
```python
"LLM00": "https://genai.owasp.org/llmrisk/llm00-.../",
```

### 3. Create the rule file `src/llmarmor/rules/llm00_your_rule.py`

Follow the pattern of existing rules:

```python
"""LLM00: Your Rule Name detection rule."""

from llmarmor.messages import CATALOG, RULE_URLS

RULE_ID = "LLM00"
RULE_NAME = "Your Rule Name"
_REF = RULE_URLS[RULE_ID]

def check_your_rule(filepath: str, content: str) -> list[dict]:
    """LLM00: Detect ..."""
    findings = []
    # detection logic
    msg = CATALOG[("LLM00", "variant_name")]
    findings.append({
        "rule_id": RULE_ID,
        "rule_name": RULE_NAME,
        "severity": "HIGH",
        "filepath": str(filepath),
        "line": line_number,
        "description": msg.what,
        "fix_suggestion": msg.fix,
        "why": msg.why,
        "reference_url": _REF,
    })
    return findings
```

### 4. Wire up the rule in `scanner.py`

Import and call your new check function from the scanner's per-file dispatch.

### 5. Write tests

Create `tests/test_llm00_your_rule.py` with:
- At least one test for each severity level your rule emits
- At least one test that confirms false positives are NOT flagged
- Tests for `strict=True` if your rule has strict-mode promotion
- A test that the finding dict includes `reference_url`

Tests must be consistent in style with `tests/test_llm08_excessive_agency.py`.

### 6. Update README

- Add your rule to the **OWASP LLM Top 10 Coverage** table
- Add a "What Each Rule Detects" subsection
- Update the coverage level appropriately (🟢 Strong / 🟡 Partial)

---

## Pull Request Process

1. **Fork** the repository and create a feature branch from `main`
2. Ensure all tests pass: `pytest`
3. Ensure linting passes: `ruff check src/ tests/`
4. Update `CHANGELOG.md` under the `[Unreleased]` section
5. Submit a pull request with a clear description of what was added and why
6. PRs require all CI checks to pass before merging

Please keep PRs focused — one rule / one feature per PR makes review easier.

---

## Code of Conduct

This project follows the
[Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).
Please be respectful and constructive in all interactions.

If you experience or witness unacceptable behaviour, please report it by
opening a GitHub issue or contacting the maintainers directly.

---

## OWASP LLM Top 10 Contributions

Contributions that expand coverage of the
[OWASP LLM Top 10 (2025)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
are especially welcome. The categories not yet covered — **LLM03 (Supply Chain)**,
**LLM04 (Data and Model Poisoning)**, **LLM08 (Vector and Embedding Weaknesses)**,
and **LLM09 (Misinformation)** — are all open for contribution. If you're
working on a rule for one of these, please open an issue first to discuss
the approach before writing code.
