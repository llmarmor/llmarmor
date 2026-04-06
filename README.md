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
- [Severity Levels](#severity-levels)
- [Output Formats](#output-formats)
- [File Type Support](#file-type-support)
- [Suppressing False Positives](#suppressing-false-positives)
- [OWASP LLM Top 10 Coverage](#owasp-llm-top-10-coverage)
- [How It Works](#how-it-works--dual-layer-analysis)
- [CI/CD Integration](#cicd-integration)
- [Contributing](#contributing)
- [Changelog](#changelog)
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

# Show all findings including INFO and LOW
llmarmor scan ./my-llm-app/ --verbose

# Strict mode — flag borderline patterns that normal mode skips
llmarmor scan ./my-llm-app/ --strict

# Save a JSON report to file
llmarmor scan ./my-llm-app/ -f json -o report.json

# Save a Markdown report to file
llmarmor scan ./my-llm-app/ -f md -o SECURITY_REPORT.md

# SARIF output for GitHub Code Scanning
llmarmor scan ./my-llm-app/ -f sarif -o results.sarif

# Silent CI mode — exit code only, no output
llmarmor scan ./my-llm-app/ --quiet

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
  -q, --quiet        Suppress all output. Only the exit code communicates the
                     result. Useful in CI pipelines where output is not needed.
                     Mutually exclusive with --verbose.
  -f, --format FMT   Output format. [default: grouped]
                     Choices: grouped, flat, json, md, markdown, sarif
  -o, --output PATH  Write formatter output to PATH instead of stdout.
                     For grouped/flat formats, plain text is written.
                     For json/md/sarif, output is written directly.
                     A confirmation line is printed to stderr unless --quiet.
  --config PATH      Path to a .llmarmor.yaml configuration file.
                     Auto-detected in the scan root if not specified.
  --help             Show this message and exit.
```

#### Examples

```bash
# Default scan — shows CRITICAL, HIGH, MEDIUM findings
llmarmor scan ./src

# Save JSON report to file
llmarmor scan ./src -f json -o findings.json

# Silent CI gate — exit code only
llmarmor scan ./src --quiet && echo "Clean" || echo "Issues found"

# SARIF for GitHub Code Scanning
llmarmor scan ./src -f sarif -o results.sarif

# Markdown report for PR comments or stakeholders
llmarmor scan ./src -f md -o SECURITY_REPORT.md

# Show everything including INFO and LOW
llmarmor scan ./src --verbose

# Strict mode — flag borderline patterns too
llmarmor scan ./src --strict

# Strict + verbose — maximum coverage and visibility
llmarmor scan ./src --strict --verbose

# Flat output (detailed per-finding blocks with What/Why/Fix/Ref)
llmarmor scan ./src -f flat

# Combine strict + verbose + JSON for full CI audit report
llmarmor scan ./src --strict --verbose -f json -o full-report.json

# Use a configuration file
llmarmor scan ./src --config .llmarmor.yaml
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

## Severity Levels

LLM Armor classifies every finding into one of five severity levels. The level
determines whether the finding is shown in terminal output by default, what exit
code the process returns, and what action you should take before merging.

| Level | Icon | Meaning | Exit Code | Shown By Default |
|-------|------|---------|-----------|------------------|
| **CRITICAL** | 🔴 | Confirmed vulnerability — hardcoded secrets, tainted input in eval/exec/shell, attacker-controlled dispatch | `2` | ✅ Yes |
| **HIGH** | 🟠 | High-confidence issue — prompt injection via interpolation, dangerous tool classes, wildcard tool access | `1` | ✅ Yes |
| **MEDIUM** | 🟡 | Likely issue needing review — missing `max_tokens`, disabled approval gates, strict-mode promotions | `1` | ✅ Yes |
| **LOW** | 🔵 | Worth reviewing — unsanitized user input in user-role messages, filesystem tools without scoping | `0` | ❌ `--verbose` |
| **INFO** | ⚪ | Informational — hardcoded system prompts, eval/test context downgrades, plain variable assignments | `0` | ❌ `--verbose` |

**Exit code summary:**

- **`0`** — No findings at MEDIUM or above (clean scan, or only LOW/INFO findings).
- **`1`** — At least one HIGH or MEDIUM finding was detected.
- **`2`** — At least one CRITICAL finding — the scan found a confirmed vulnerability.

LOW and INFO findings are always detected internally but hidden from terminal
output unless `--verbose` is passed. In `--strict` mode, several LOW and INFO
findings are promoted to MEDIUM (see the [Scan Modes](#scan-modes) section for
the full promotion table).

**SARIF severity mapping** (for GitHub Code Scanning integration):

- CRITICAL and HIGH → SARIF `error`
- MEDIUM → SARIF `warning`
- LOW and INFO → SARIF `note`

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

One structured block per finding, ordered by severity. Each block includes
a What/Why/Fix/Ref breakdown. Useful for detailed per-finding review,
piping to other tools, and terminal output where you want full context
for every finding.

```bash
llmarmor scan ./src -f flat
```

```
[LLM01] [CRITICAL] — User input interpolated into prompt via f-string.
  Location: app/chat.py:42

What: User-controlled input is embedded into an LLM prompt string via f-string interpolation.
Why:  An attacker can craft input that overrides system instructions, exfiltrates data, or hijacks model behavior.
Fix:  Pass user input as a separate 'role: user' message. Never use f-strings to embed user data in system messages.
Ref:  https://genai.owasp.org/llmrisk/llm01-prompt-injection/

[LLM10] [MEDIUM] — LLM API call without max_tokens limit.
  Location: services/ai.py:50

What: An LLM API call is made without setting max_tokens, leaving token consumption unbounded.
Why:  Without a token limit, a single request can generate thousands of tokens, leading to high costs and slow responses.
Fix:  Always set max_tokens on every LLM API call. Example: client.chat.completions.create(..., max_tokens=500).
Ref:  https://genai.owasp.org/llmrisk/llm10-unbounded-consumption/

Summary: 2 finding(s) (1 CRITICAL, 1 MEDIUM)
```

### JSON

Structured JSON object with a `meta` block and grouped findings. Designed for
CI/CD pipelines, SARIF conversion, and integration with dashboards.

```bash
llmarmor scan ./src -f json -o report.json
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
      "why": "An attacker can override system instructions, exfiltrate data, or hijack model behavior.",
      "fix_suggestion": "Pass user input as a separate 'role: user' message.",
      "reference_url": "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
      "locations": [
        {"filepath": "app/chat.py", "line": 42},
        {"filepath": "app/handlers.py", "line": 88}
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

### SARIF (`sarif`)

[SARIF 2.1.0](https://sarifweb.azurewebsites.net/) output for GitHub Code
Scanning, VS Code SARIF Viewer, and security dashboards.

```bash
llmarmor scan ./src -f sarif > results.sarif
```

Upload to GitHub Code Scanning in your workflow:

```yaml
- name: LLM Armor SARIF scan
  run: llmarmor scan . -f sarif > llmarmor.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: llmarmor.sarif
```

Severity mapping in SARIF: CRITICAL/HIGH → `error`, MEDIUM → `warning`,
LOW/INFO → `note`.

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

| OWASP Risk | Rule | Coverage | What's Detected |
|---|---|---|---|
| LLM01 | Prompt Injection | 🟢 Strong | Regex + AST taint analysis across 6 injection vectors (f-string, .format(), %-format, concatenation, LangChain templates, aliased vars); role-aware detection distinguishes system from user role |
| LLM02 | Sensitive Info Disclosure | 🟡 Partial | 4 LLM API key patterns (OpenAI, Anthropic, Google, HuggingFace) across all file types; does not cover PII, DB connection strings, AWS/Azure credentials, or JWT tokens |
| LLM05 | Improper Output Handling | 🟡 Partial | eval/exec/shell/SQL/HTML sinks with variable-name heuristics; AST taint from LLM API calls; does not track taint through attribute chains like `response.choices[0].message.content` |
| LLM06 | Insecure Plugin Design | 🟡 Partial | @tool-decorated functions with dangerous sinks (eval/exec/shell); detects dangerous tool classes (ShellTool, PythonREPLTool, CodeInterpreterTool) |
| LLM07 | System Prompt Leakage | 🟡 Partial | Hardcoded prompts in source code (regex + AST multi-line detection); does not detect prompts in API responses, log output, or error messages |
| LLM08 | Excessive Agency | 🟢 Strong | 8 pattern categories: wildcard tool access, dangerous tool classes, disabled approval gates, dynamic dispatch (globals/getattr), shell interpreter sinks, broad tool descriptions, agent loop patterns, @tool sinks |
| LLM10 | Unbounded Consumption | 🟡 Partial | Missing max_tokens on LLM API calls; does not check timeouts, rate limits, retry bounds, or streaming limits |
| LLM03 | Supply Chain Vulnerabilities | 🔴 Out of scope | Requires dependency analysis and model provenance verification — not detectable by static analysis |
| LLM04 | Data and Model Poisoning | 🔴 Out of scope | Requires runtime monitoring and training pipeline analysis |
| LLM09 | Misinformation | 🔴 Out of scope | Requires factual verification at runtime — not detectable by static analysis |

**Coverage levels:**
- 🟢 **Strong** — dual-layer detection (regex + AST taint analysis), multiple pattern categories, high confidence
- 🟡 **Partial** — single-layer detection or limited pattern coverage; PRs welcome to expand
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
- `@tool`-decorated functions (LangChain, CrewAI, AutoGen, LlamaIndex, Smolagents, Google ADK, MCP, Marvin, ControlFlow),
  `@function_tool` (OpenAI Agents SDK), `@kernel_function` (Semantic Kernel), `@ai_tool` (Pydantic AI),
  and `@ai_fn` (Marvin AI) containing shell/subprocess sinks — AST-detected → HIGH
- `getattr(module, llm_name)()` — AST-taint-tracked dynamic dispatch → CRITICAL (AST) / HIGH (regex)
- `auto_approve=True`, `human_in_the_loop=False` — disabled approval gates → MEDIUM
- `FileManagementToolkit()`, `WriteFileTool()` — broad filesystem access → LOW (capability concern; scope to a directory)
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

## Suppressing False Positives

### Inline Suppression

Add a `# llmarmor: ignore` comment to suppress a finding on a specific line.
You can also scope suppression to a specific rule with `# llmarmor: ignore[RULE_ID]`:

```python
# Suppress all rules on the next line
# llmarmor: ignore
response = client.chat.completions.create(model="gpt-4", messages=messages)

# Suppress only LLM07 on this line
SYSTEM_PROMPT = "You are a helpful assistant."  # llmarmor: ignore[LLM07]

# Suppress multiple rules
result = eval(user_code)  # llmarmor: ignore[LLM05,LLM01]
```

Inline suppression works for both regex and AST findings. The comment can be
placed on the finding's own line or on the line immediately above it.

### `.llmarmorignore`

Create a `.llmarmorignore` file in your project root to skip files or
directories using gitignore-style glob patterns:

```
# .llmarmorignore

# Skip test fixtures that intentionally contain vulnerable patterns
tests/fixtures/**

# Skip generated files
build/**
dist/**

# Skip specific files
scripts/dev_seed.py
```

### Configuration File

Create a `.llmarmor.yaml` file in your project root (or pass it with
`--config`) to configure scan behaviour per project:

```yaml
# .llmarmor.yaml

# Minimum severity to report (CRITICAL, HIGH, MEDIUM, LOW, INFO)
severity_threshold: MEDIUM

# Enable strict mode by default
strict: false

# Per-rule configuration
rules:
  LLM01:
    enabled: true
    severity: HIGH         # Override default severity for this rule
  LLM07:
    enabled: false         # Disable this rule entirely for this project

# Additional paths to exclude (gitignore-style globs)
exclude_paths:
  - "tests/**"
  - "scripts/dev_*"
  - "docs/**"
```

CLI flags always take precedence over config file values. The config file is
auto-detected in the scan root directory if `--config` is not specified.

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
| `0` | No findings at MEDIUM or above (clean, or only INFO/LOW findings) |
| `1` | At least one HIGH or MEDIUM finding detected |
| `2` | At least one CRITICAL finding detected — must fix immediately |

This makes it easy to fail CI/CD pipelines on security findings:

```bash
llmarmor scan ./src; echo "Exit code: $?"
# Exit code: 0 — clean
# Exit code: 1 — medium/high findings
# Exit code: 2 — critical findings
```

---

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for the full
development guide, including how to add a new rule.

```bash
# Set up development environment
git clone https://github.com/llmarmor/llmarmor.git
cd llmarmor
pip install -e ".[dev]"

# Run tests
pytest
```

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a complete list of changes.

---

## Links

- 🌐 Website: [llmarmor.dev](https://llmarmor.dev)
- 📦 PyPI: [pypi.org/project/llmarmor](https://pypi.org/project/llmarmor/)
- 🐛 Issues: [github.com/llmarmor/llmarmor/issues](https://github.com/llmarmor/llmarmor/issues)
- 📖 Changelog: [CHANGELOG.md](CHANGELOG.md)

---

## License

MIT — see [LICENSE](LICENSE) for details.
