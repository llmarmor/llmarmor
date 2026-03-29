# 🛡️ LLM Armor

**OWASP LLM Top 10 security scanner for AI-powered applications.**

Scan your Python codebase for security vulnerabilities mapped to the
[OWASP Top 10 for Large Language Models](https://owasp.org/www-project-top-10-for-large-language-model-applications/).
LLM Armor combines fast regex pattern-matching with AST-based taint analysis
to catch prompt injection, leaked secrets, exposed system prompts, and unbounded
API consumption — with minimal false positives.

[![PyPI version](https://img.shields.io/pypi/v/llmarmor.svg)](https://pypi.org/project/llmarmor/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

> ⚠️ **Early release** — actively under development. Star the repo to follow progress.

---

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [CLI Reference](#cli-reference)
- [Output Formats](#output-formats)
- [Scan Modes](#scan-modes)
- [OWASP LLM Top 10 Coverage](#owasp-llm-top-10-coverage)
- [How It Works](#how-it-works--dual-layer-analysis)
- [Language Support](#language-support)
- [Contributing](#contributing)
- [Links](#links)
- [License](#license)

---

## Installation

```bash
pip install llmarmor
```

Or install from source for development:

```bash
git clone https://github.com/llmarmor/llmarmor.git
cd llmarmor
pip install -e ".[dev]"
```

### Requirements

- Python 3.10+
- No external runtime dependencies beyond `click` and `rich`

---

## Quick Start

```bash
# Scan the current directory
llmarmor scan .

# Scan a specific project
llmarmor scan ./my-llm-app/

# Strict mode — flag everything that could be a risk
llmarmor scan ./my-llm-app/ --strict

# Export results as JSON for CI/CD
llmarmor scan ./my-llm-app/ -f json > report.json

# Export a Markdown report
llmarmor scan ./my-llm-app/ -f md > SECURITY_REPORT.md

# List all available rules
llmarmor rules
```

---

## CLI Reference

### `llmarmor scan`

Scan a directory for LLM security vulnerabilities.

```
Usage: llmarmor scan [OPTIONS] [PATH]

  Scan PATH for LLM security vulnerabilities.

Arguments:
  PATH    Directory or file to scan. [default: .]

Options:
  --strict           Enable strict scanning mode. Flags borderline patterns
                     including unsanitized tainted variables passed directly
                     to role messages and promotes INFO findings to MEDIUM.
  -f, --format FMT   Output format. [default: grouped]
                     Choices: grouped, flat, json, md, markdown
  --help             Show this message and exit.
```

#### Examples

```bash
# Default grouped output
llmarmor scan ./src

# Strict mode with grouped output
llmarmor scan ./src --strict

# Flat output (one line per finding, legacy format)
llmarmor scan ./src -f flat

# JSON output to stdout
llmarmor scan ./src -f json

# JSON output piped to file
llmarmor scan ./src -f json > findings.json

# Markdown report
llmarmor scan ./src -f md > report.md

# Combine strict mode with any format
llmarmor scan ./src --strict -f json > strict-report.json
```

### `llmarmor rules`

List all OWASP LLM Top 10 rules grouped by support status.

```
Usage: llmarmor rules [OPTIONS]

Options:
  --help  Show this message and exit.
```

### `llmarmor --version`

Print the installed version.

```bash
llmarmor --version
```

---

## Output Formats

### Grouped (default)

Findings are grouped by rule, with one description per rule and all affected locations listed below. A summary line is printed at the end.

```
━━━ LLM01: Prompt Injection (CRITICAL) ━━━
User-controlled input interpolated into system role message via f-string.

  → app/chat.py:42
  → app/handlers.py:88

Fix: Pass user input as a separate 'role: user' message instead of
     interpolating it into system or assistant messages.

━━━ LLM10: Unbounded Consumption (MEDIUM) ━━━
LLM API call without max_tokens parameter.

  → services/ai.py:50
  → services/ai.py:75
  → utils/llm.py:30

Fix: Set max_tokens (or max_output_tokens for Gemini) on all LLM API calls
     to cap response length and control costs.

Summary: 5 findings (1 CRITICAL, 1 HIGH, 3 MEDIUM)
```

### Flat

One line per finding. Useful for grep-friendly output and editor integrations.

```
CRITICAL  LLM01  app/chat.py:42       User-controlled input interpolated...
CRITICAL  LLM01  app/handlers.py:88   User-controlled input interpolated...
MEDIUM    LLM10  services/ai.py:50    LLM API call without max_tokens...
```

### JSON

Valid JSON array written to stdout. Designed for CI/CD pipelines, SARIF conversion,
and integration with dashboards.

```json
[
  {
    "rule_id": "LLM01",
    "rule_name": "Prompt Injection",
    "severity": "CRITICAL",
    "filepath": "app/chat.py",
    "line": 42,
    "description": "User-controlled input interpolated into system role message via f-string.",
    "fix_suggestion": "Pass user input as a separate 'role: user' message."
  },
  {
    "rule_id": "LLM10",
    "rule_name": "Unbounded Consumption",
    "severity": "MEDIUM",
    "filepath": "services/ai.py",
    "line": 50,
    "description": "LLM API call without max_tokens parameter.",
    "fix_suggestion": "Set max_tokens on all LLM API calls."
  }
]
```

### Markdown (`md` / `markdown`)

Structured Markdown report suitable for pull request comments, Confluence pages,
or sharing with stakeholders.

```markdown
# LLM Armor Scan Report

**Scanned**: ./my-llm-app
**Date**: 2026-03-29
**Findings**: 5 (1 CRITICAL, 1 HIGH, 3 MEDIUM)

## LLM01: Prompt Injection (CRITICAL)

User-controlled input interpolated into system role message via f-string.

| File | Line |
|------|------|
| app/chat.py | 42 |
| app/handlers.py | 88 |

**Fix**: Pass user input as a separate 'role: user' message...

---

## LLM10: Unbounded Consumption (MEDIUM)

LLM API call without max_tokens parameter.

| File | Line |
|------|------|
| services/ai.py | 50 |
| services/ai.py | 75 |

**Fix**: Set max_tokens on all LLM API calls...
```

---

## Scan Modes

### Normal Mode (default)

```bash
llmarmor scan ./src
```

Focuses on **high-confidence findings only**. Minimizes false positives so that
every result is actionable. Recommended for day-to-day development and CI gates.

**What is flagged:**
- F-string, `.format()`, `%`-formatting, and string concatenation of tainted
  variables into system/assistant role messages
- Hardcoded API keys and secrets
- LLM API calls missing `max_tokens`

**What is NOT flagged:**
- Plain variable assignment to `content` (e.g., `"content": user_input`) —
  no string interpolation means no injection vector
- Eval/test/grading harness files — findings are downgraded to INFO
- Variables sourced from config, database, or environment — not user-controlled

### Strict Mode

```bash
llmarmor scan ./src --strict
```

Flags **everything that could be a risk**, including borderline patterns.
Recommended for pre-release security audits, compliance reviews, and new codebases.

**Additional findings in strict mode:**

| Pattern | Severity | Rationale |
|---|---|---|
| Tainted variable passed directly as system role `content` | MEDIUM | User controls the entire system instruction without sanitization |
| Tainted variable passed directly as user role `content` | LOW | Consider input validation, length limits, and content filtering |
| Hardcoded system prompt in source code | MEDIUM | May leak proprietary instructions if code is public or client-bundled |
| Eval/test file findings | Not downgraded | Treated the same as production code |

---

## OWASP LLM Top 10 Coverage

| OWASP Risk | Rule | Coverage |
|---|---|---|
| LLM01 | Prompt Injection — unsanitized user input in LLM prompts | 🟢 Strong |
| LLM02 | Sensitive Info Disclosure — hardcoded API keys | 🟢 Strong |
| LLM07 | System Prompt Leakage — prompts in client code | 🟢 Strong |
| LLM10 | Unbounded Consumption — missing rate limits/max\_tokens | 🟢 Strong |
| LLM05 | Improper Output Handling — LLM output in eval/exec/HTML | 🟡 Planned |
| LLM08 | Excessive Agency — over-permissioned LLM actions | 🟡 Planned |
| LLM03 | Supply Chain Vulnerabilities | 🔴 Out of scope |
| LLM04 | Data and Model Poisoning | 🔴 Out of scope |
| LLM06 | Insecure Plugin Design | 🔴 Out of scope |
| LLM09 | Misinformation | 🔴 Out of scope |

**Coverage levels:**
- 🟢 **Strong** — dual-layer detection: regex patterns + AST-based taint analysis
- 🟡 **Planned** — detection logic is in development
- 🔴 **Out of scope** — not detectable by static analysis alone; requires runtime or LLM-assisted review

### What Each Rule Detects

**LLM01 — Prompt Injection**
- Regex: direct interpolation via f-strings, `.format()`, `%`-formatting, and string concatenation
- AST: source-based taint tracking — a variable is tainted **only** when assigned from a user-controlled data source:
  - HTTP request objects: `request.json[...]`, `request.form.get(...)`, `request.args[...]`
  - Built-in stdin: `input(...)`
  - CLI arguments: `sys.argv[n]`
  - WebSocket messages: `websocket.receive()`, `ws.recv()`
  - Function parameters (any argument of a `def` or `async def`)
- Role-aware dict analysis: distinguishes the safe `role: user` pattern from dangerous `role: system` / `role: assistant` injection
- `str.join()` injection detection for tainted list elements
- Safe-source exclusions: variables assigned from `config.get()`, `os.environ`, `os.getenv()`, database calls, settings attributes, or string literals are **never** treated as user-controlled
- Taint propagates through direct alias assignments (`alias = tainted_var`) but **not** through function calls, so `clean = sanitize(raw)` leaves `clean` untainted

**LLM02 — Sensitive Info Disclosure**
- Regex: OpenAI (`sk-`), Anthropic (`sk-ant-`), Google (`AIza`), and HuggingFace (`hf_`) token patterns
- Minimum key length enforcement (20+ chars) to avoid matching SKUs and short placeholders
- Comment lines, test/mock variable names, and example values are skipped

**LLM07 — System Prompt Leakage**
- Regex: single-line hardcoded system prompt strings
- AST: multi-line implicit string concatenation and triple-quoted prompts;
  only flags strings longer than 100 characters to avoid noise from short generic prompts

**LLM10 — Unbounded Consumption**
- Regex: LLM API calls (`openai`, `anthropic`, `litellm`, Google Gemini) without `max_tokens` or `max_output_tokens`
- AST: resolves `**config` dict spreads — suppresses the finding when `max_tokens` or `max_output_tokens` is provably present in the spread dict

---

## How It Works — Dual-Layer Analysis

LLM Armor applies two complementary analysis layers to every Python file:

1. **Regex layer** — fast line-by-line pattern matching for the most common vulnerability
   patterns. Runs on all files regardless of whether they parse as valid Python.

2. **AST layer** — Python's `ast` module parses each file into a syntax tree and performs
   source-based taint-tracking analysis. This catches patterns that regex cannot detect:
   variable aliasing, role-aware dict construction, multi-line string concatenation, and
   `**kwargs` dict spreading. If a file has syntax errors, the AST layer gracefully falls
   back to empty output, leaving the regex results intact.

The two layers share finding deduplication: when both layers detect the same issue
on the same line, only one finding is reported.

### Source-Based Taint Tracking

The AST layer uses **source-based** taint tracking: a variable is considered
user-controlled only when it is assigned from a known dangerous source.

| Tainted (user-controlled) | Example |
|---|---|
| HTTP request | `data = request.json["prompt"]` |
| HTTP form | `data = request.form.get("field")` |
| Django request | `data = request.POST["query"]` |
| stdin | `data = input("Enter: ")` |
| CLI arguments | `data = sys.argv[1]` |
| WebSocket | `data = websocket.receive()` |
| Function parameter | `def handle(user_msg):` |

| Not tainted (safe sources) | Example |
|---|---|
| Config lookup | `prompt = config.get("default_prompt")` |
| Environment variable | `prompt = os.environ["PROMPT"]` |
| Database call | `prompt = db.fetch_prompt(id)` |
| Settings attribute | `prompt = settings.DEFAULT_PROMPT` |
| String literal | `prompt = "You are a helpful assistant."` |

Taint propagates through direct alias assignments (`alias = tainted`) but **not**
through function calls, so `clean = sanitize(raw)` does not taint `clean`.

---

## CI/CD Integration

### GitHub Actions

```yaml
name: LLM Security Scan
on: [push, pull_request]

jobs:
  llmarmor:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install llmarmor
      - run: llmarmor scan . -f json > llmarmor-report.json
      - name: Upload report
        uses: actions/upload-artifact@v4
        with:
          name: llmarmor-report
          path: llmarmor-report.json
```

### Exit Codes

| Code | Meaning |
|---|---|
| `0` | Scan completed, findings may or may not be present |
| `1` | Error (invalid path, unexpected exception) |

---

## Language Support

| Language | Status | Notes |
|---|---|---|
| Python | 🟢 Supported | Primary language; all rules active |
| TypeScript / JavaScript | 🟡 Planned | Rule patterns being adapted |
| Other | 🔴 Not supported | [Open an issue](https://github.com/llmarmor/llmarmor/issues) to request |

---

## Contributing

Contributions are welcome! See the [contributing guide](CONTRIBUTING.md) for details.

```bash
# Set up development environment
git clone https://github.com/llmarmor/llmarmor.git
cd llmarmor
pip install -e ".[dev]"

# Run tests
pytest -v

# Run the scanner locally
llmarmor scan ./tests/fixtures/
```

---

## Links

- 🌐 Website: [llmarmor.dev](https://llmarmor.dev)
- 📦 PyPI: [pypi.org/project/llmarmor](https://pypi.org/project/llmarmor/)
- 🐛 Issues: [github.com/llmarmor/llmarmor/issues](https://github.com/llmarmor/llmarmor/issues)
- 📖 Changelog: [CHANGELOG.md](CHANGELOG.md)

---

## License

MIT — see [LICENSE](LICENSE) for details.