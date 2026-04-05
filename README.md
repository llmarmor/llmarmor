# 🛡️ LLM Armor

**OWASP LLM Top 10 security scanner for AI-powered applications.**

Scan your codebase for security vulnerabilities mapped to the
[OWASP Top 10 for Large Language Models](https://owasp.org/www-project-top-10-for-large-language-model-applications/).
LLM Armor combines fast regex pattern-matching with AST-based taint analysis
to catch prompt injection, leaked secrets, exposed system prompts, improper
output handling, excessive agent permissions, and unbounded API consumption —
across Python files, config files, notebooks, and more.

[![PyPI version](https://img.shields.io/pypi/v/llmarmor.svg)](https://pypi.org/project/llmarmor/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

> ⚠️ **Early release** — actively under development. Star the repo to follow progress.

---

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [CLI Reference](#cli-reference)
- [Scan Modes](#scan-modes)
- [Output Formats](#output-formats)
- [File Type Support](#file-type-support)
- [OWASP LLM Top 10 Coverage](#owasp-llm-top-10-coverage)
- [How It Works](#how-it-works--dual-layer-analysis)
- [CI/CD Integration](#cicd-integration)
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
# Scan the current directory (CRITICAL, HIGH, MEDIUM findings shown)
llmarmor scan .

# Scan a specific project
llmarmor scan ./my-llm-app/

# Show all findings including INFO and LOW
llmarmor scan ./my-llm-app/ --verbose

# Strict mode — flag borderline patterns that normal mode skips
llmarmor scan ./my-llm-app/ --strict

# Strict + verbose — detect everything and show everything
llmarmor scan ./my-llm-app/ --strict --verbose

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
  -v, --verbose      Show all findings including INFO and LOW severity.
                     By default, only CRITICAL, HIGH, and MEDIUM findings
                     are displayed (they are still detected internally).
  -f, --format FMT   Output format. [default: grouped]
                     Choices: grouped, flat, json, md, markdown
  --help             Show this message and exit.
```

#### Examples

```bash
# Default grouped output — CRITICAL, HIGH, MEDIUM only
llmarmor scan ./src

# Show everything including INFO and LOW
llmarmor scan ./src --verbose

# Strict mode — flag borderline patterns too
llmarmor scan ./src --strict

# Strict mode with verbose output — maximum coverage
llmarmor scan ./src --strict --verbose

# Flat output (one line per finding)
llmarmor scan ./src -f flat

# JSON output to file
llmarmor scan ./src -f json > findings.json

# Markdown report
llmarmor scan ./src -f md > SECURITY_REPORT.md

# Combine strict + verbose + JSON for full CI report
llmarmor scan ./src --strict --verbose -f json > full-report.json
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

## Scan Modes

LLM Armor has three scan modes that control **what is flagged** and **what is shown**:

| Mode | Flags | What's Detected | What's Shown |
|---|---|---|---|
| Normal | *(default)* | High-confidence findings | CRITICAL, HIGH, MEDIUM |
| Strict | `--strict` | Normal + borderline patterns | CRITICAL, HIGH, MEDIUM |
| Verbose | `-v` / `--verbose` | Same as normal | All severities (including INFO, LOW) |
| Strict + Verbose | `--strict -v` | Everything | Everything |

### Normal Mode (default)

```bash
llmarmor scan ./src
```

Focuses on **high-confidence findings only**. Minimises false positives so
every result is actionable. Recommended for day-to-day development and CI gates.

INFO and LOW findings are still detected internally — they just aren't printed
unless you pass `--verbose`.

**What is flagged:**
- F-string, `.format()`, `%`-formatting, and string concatenation of tainted
  variables into system/assistant role messages
- Hardcoded API keys and secrets (all file types)
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
| `json.loads()` with LLM-named variable | MEDIUM | Promoted from INFO — deserialising unvalidated LLM output is risky |
| Broad agent tool descriptions (e.g., "use any tool") | MEDIUM | Promoted from INFO — may indicate missing explicit allowlist |
| Agent loop tool/function name retrieved from LLM response | MEDIUM | Promoted from INFO — validate against allowlist before dispatching |
| Eval/test file findings | Not downgraded | Treated the same as production code |

### Verbose Mode

```bash
llmarmor scan ./src --verbose        # short form: -v
```

Shows **all findings** that were detected, including INFO and LOW severity.
Useful for getting a complete picture of potential risks, security audits,
and generating comprehensive reports.

---

## Output Formats

### Grouped (default)

Findings are grouped by rule with one description per rule and all affected
locations listed below. A summary line is printed at the end.

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

Fix: Set max_tokens (or max_output_tokens for Gemini) on all LLM API calls.

Summary: 4 finding(s) (2 CRITICAL, 2 MEDIUM)
```

### Flat

One line per finding grouped by severity. Useful for grep-friendly output
and editor integrations.

### JSON

Structured JSON object with a `meta` block and grouped findings. Designed for
CI/CD pipelines, SARIF conversion, and integration with dashboards.

```bash
llmarmor scan ./src -f json > report.json
```

```json
{
  "meta": {
    "tool": "llmarmor",
    "version": "X.Y.Z",
    "scanned_path": "./src",
    "timestamp": "2026-04-01T12:00:00Z",
    "mode": "normal",
    "summary": {
      "total": 4,
      "critical": 1,
      "high": 0,
      "medium": 3,
      "low": 0,
      "info": 0
    }
  },
  "findings": [
    {
      "rule_id": "LLM01",
      "rule_name": "Prompt Injection",
      "severity": "CRITICAL",
      "description": "User-controlled input interpolated into system role message via f-string.",
      "fix_suggestion": "Pass user input as a separate 'role: user' message.",
      "locations": [
        {"filepath": "app/chat.py", "line": 42},
        {"filepath": "app/handlers.py", "line": 88}
      ]
    },
    {
      "rule_id": "LLM10",
      "rule_name": "Unbounded Consumption",
      "severity": "MEDIUM",
      "description": "LLM API call without max_tokens set.",
      "fix_suggestion": "Always set max_tokens on LLM API calls.",
      "locations": [
        {"filepath": "services/ai.py", "line": 50},
        {"filepath": "services/ai.py", "line": 75}
      ]
    }
  ]
}
```

The `meta.mode` field reflects the active scan mode: `"normal"`, `"strict"`,
`"verbose"`, or `"strict+verbose"`.

### Markdown (`md` / `markdown`)

Structured Markdown report suitable for pull request comments, Confluence pages,
or sharing with stakeholders.

```bash
llmarmor scan ./src -f md > SECURITY_REPORT.md
```

---

## File Type Support

LLM Armor scans more than just Python. Each file type has a dedicated handler
with appropriate detection logic:

| File Type | Extensions | Rules Detected | Notes |
|---|---|---|---|
| Python | `.py` | LLM01, LLM02, LLM05, LLM07, LLM08, LLM10 | Full dual-layer analysis (regex + AST) |
| Env files | `.env` | LLM02 | Parses `KEY=value` pairs, strips quotes |
| YAML/Config | `.yaml`, `.yml` | LLM02, LLM07 | Regex-based; no pyyaml dependency |
| JSON | `.json` | LLM02, LLM07 | Regex-based; stdlib json for validation |
| TOML | `.toml` | LLM02 | Regex-based |
| JavaScript | `.js`, `.ts` | LLM02, LLM07 | Detects secrets and system prompt literals |
| Docs/Notes | `.md`, `.txt` | LLM02, LLM07 | Catches accidentally committed secrets |
| Notebooks | `.ipynb` | LLM02, LLM07, LLM10 | Code cells run through Python scanner; **LLM01 (prompt injection) is intentionally skipped** — notebook functions are called locally with no external input boundary, so taint analysis produces false positives on tutorial/example code |

> **Note on placeholder secrets:** Example/placeholder secret values such as
> `sk-your_openai_key_here` or `sk-example-key` are automatically excluded from
> LLM02 findings across all file types, including Python. Only key-shaped strings
> that look like real credentials are reported.

**No new dependencies** are required — all handlers use stdlib or existing dependencies.

### Skipped Directories

The following directories are automatically skipped during scanning:

`.git`, `__pycache__`, `.venv`, `venv`, `node_modules`, `.tox`, `dist`, `build`, `.eggs`

---

## OWASP LLM Top 10 Coverage

| OWASP Risk | Rule | Coverage |
|---|---|---|
| LLM01 | Prompt Injection — unsanitized user input in LLM prompts | 🟢 Strong |
| LLM02 | Sensitive Info Disclosure — hardcoded API keys | 🟢 Strong |
| LLM05 | Improper Output Handling — LLM output in eval/exec/HTML/SQL | 🟢 Strong |
| LLM07 | System Prompt Leakage — prompts in source/config files | 🟢 Strong |
| LLM08 | Excessive Agency — over-permissioned LLM actions | 🟢 Strong |
| LLM10 | Unbounded Consumption — missing rate limits/max\_tokens | 🟢 Strong |
| LLM03 | Supply Chain Vulnerabilities | 🔴 Out of scope |
| LLM04 | Data and Model Poisoning | 🔴 Out of scope |
| LLM06 | Insecure Plugin Design | 🔴 Out of scope |
| LLM09 | Misinformation | 🔴 Out of scope |

**Coverage levels:**
- 🟢 **Strong** — dual-layer detection: regex patterns + AST-based taint analysis
- 🔴 **Out of scope** — not detectable by static analysis alone

### What Each Rule Detects

**LLM01 — Prompt Injection**
- Regex: direct interpolation via f-strings, `.format()`, `%`-formatting, and string concatenation
- AST: source-based taint tracking — a variable is tainted **only** when assigned from a
  user-controlled data source (HTTP requests, `input()`, `sys.argv`, WebSocket messages,
  or function parameters)
- Role-aware dict analysis: distinguishes the safe `role: user` pattern from dangerous
  `role: system` / `role: assistant` injection
- `str.join()` injection detection for tainted list elements
- Taint propagates through direct alias assignments but **not** through function calls

**LLM02 — Sensitive Info Disclosure**
- All file types: OpenAI (`sk-`), Anthropic (`sk-ant-`), Google (`AIza`), HuggingFace (`hf_`) patterns
- Minimum key length enforcement (20+ chars) to avoid matching SKUs and short placeholders
- Comment lines, test/mock variable names, and example values are skipped

**LLM05 — Improper Output Handling**
- Regex: detects LLM output variables (by name heuristic: requires both an LLM-context indicator
  such as `llm`, `gpt`, `ai`, `chat` AND a response indicator such as `response`, `output`,
  `text`, `content`) passed to dangerous sinks
- AST: taint-tracked detection — flags any tainted variable (from any user-controlled source)
  passed to dangerous sinks without the name-heuristic requirement
- `@tool`-decorated function parameters (LangChain, CrewAI, or any `@tool` framework) are
  treated as LLM output (source-tainted) — the LLM chooses their values at runtime, so sinks
  inside `@tool` bodies are flagged automatically: `subprocess.run(param)` → CRITICAL,
  `eval(param)` → CRITICAL, `Markup(param)` → HIGH, `json.loads(param)` → INFO
- Dangerous sinks: `eval()`, `exec()`, `compile()` → CRITICAL; `subprocess.run()`, `os.system()` → CRITICAL;
  `Markup()`, `render_template_string()`, `mark_safe()` → HIGH; SQL f-string interpolation → HIGH;
  `json.loads()` without schema validation → INFO (normal) / MEDIUM (strict)

**LLM07 — System Prompt Leakage**
- Python: single-line + multi-line hardcoded system prompt strings (> 100 chars)
- Config files: prompt values in `system_prompt:`, `system_message:`, `prompt:` keys
- Only flags strings longer than 100 characters to avoid noise from short generic prompts

**LLM08 — Excessive Agency**
- Regex and AST: detects overly broad agent permissions and unsafe dynamic dispatch patterns
- `globals()[fn_name]()` / `eval(fn_name)` — dynamic dispatch from LLM tool call → CRITICAL
- `tools=["*"]` — wildcard tool access violating least privilege → HIGH
- `ShellTool()`, `PythonREPLTool()`, `CodeInterpreterTool()` — shell/code execution capability → HIGH
- `subprocess.run(['powershell'/'bash'/'cmd'/'sh', ...])` — shell interpreter invocation → HIGH
- `@tool`-decorated functions (LangChain/CrewAI) whose bodies contain `subprocess.run()`, `os.system()`, or other shell sinks → HIGH
- `getattr(module, llm_name)()` — AST-taint-tracked dynamic dispatch → CRITICAL (AST) / HIGH (regex)
- `auto_approve=True`, `human_in_the_loop=False` — disabled approval gates → MEDIUM
- `FileManagementToolkit()`, `WriteFileTool()` — broad filesystem access → MEDIUM
- Broad tool descriptions, missing explicit allowlists → INFO (normal) / MEDIUM (strict)

**LLM10 — Unbounded Consumption**
- Regex: LLM API calls (openai, anthropic, litellm, Google Gemini) without `max_tokens`
- AST: resolves `**config` dict spreads — suppresses the finding when `max_tokens`
  or `max_output_tokens` is provably present in the spread dict

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

| Tainted (user-controlled) | Example |
|---|---|
| HTTP request | `data = request.json["prompt"]` |
| HTTP form | `data = request.form.get("field")` |
| Django request | `data = request.POST["query"]` |
| stdin | `data = input("Enter: ")` |
| CLI arguments | `data = sys.argv[1]` |
| WebSocket | `data = websocket.receive()` |
| Function parameter | `def handle(user_msg):` |
| `@tool` parameter | `@tool def my_tool(command: str):` |

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

      # Normal mode — annotate PRs with CRITICAL/HIGH/MEDIUM findings
      - run: llmarmor scan . -f json > llmarmor-report.json

      # Strict + verbose for a full security audit on release branches
      - run: llmarmor scan . --strict --verbose -f json > llmarmor-full-report.json
        if: github.ref == 'refs/heads/main'

      - name: Upload report
        uses: actions/upload-artifact@v4
        with:
          name: llmarmor-report
          path: llmarmor-report.json
```

### Parsing the JSON Report

The JSON output has a stable structure for easy integration:

```python
import json, subprocess

result = subprocess.run(
    ["llmarmor", "scan", ".", "-f", "json"],
    capture_output=True, text=True,
)
report = json.loads(result.stdout)

# Check for critical findings
critical = [
    f for f in report["findings"]
    if f["severity"] == "CRITICAL"
]
if critical:
    print(f"Build blocked: {len(critical)} CRITICAL finding(s)")
    for f in critical:
        for loc in f["locations"]:
            print(f"  {f['rule_id']} {loc['filepath']}:{loc['line']}")
    exit(1)

# Access metadata
print(f"Scanned: {report['meta']['scanned_path']}")
print(f"Total findings: {report['meta']['summary']['total']}")
```

### Exit Codes

| Code | Meaning |
|---|---|
| `0` | Scan completed (findings may be present) |
| `1` | Error (invalid path, unexpected exception) |

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