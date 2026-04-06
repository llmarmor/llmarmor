# Changelog

All notable changes to LLM Armor are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- **Centralized message catalog** (`src/llmarmor/messages.py`) — single source of truth
  for all finding messages. Every finding variant now has structured `summary`, `what`,
  `why`, `fix`, and `reference_url` fields defined in one place.
- **`reference_url` field** in every finding dict — OWASP rule-specific link
  (e.g., `https://genai.owasp.org/llmrisk/llm01-prompt-injection/`) included in all
  output formats and programmatic results.
- **`why` field** in every finding dict — concrete attack scenario explaining why each
  finding is dangerous.
- **Structured message template** for `flat`, `json`, `md`/`markdown` output formats:

  ```
  [LLM01] [CRITICAL] — User input interpolated into system role message

  What: User-controlled input is embedded into a system-role LLM message.
  Why:  An attacker can override system instructions, extract data, or hijack model behavior.
  Fix:  Pass user input as a separate "role: user" message.
  Ref:  https://genai.owasp.org/llmrisk/llm01-prompt-injection/
  ```

- **`--quiet` / `-q` flag** for `llmarmor scan` — suppresses all stdout/stderr output;
  only the exit code communicates the result. Mutually exclusive with `--verbose`.
  Useful in CI pipelines.
- **`--output PATH` / `-o PATH` flag** for `llmarmor scan` — writes formatter output to
  a file instead of stdout. For grouped/flat formats, plain text is written; for
  json/md/sarif, output is written directly. A confirmation line is printed to stderr.
- **SARIF improvements** — rule `helpUri` now points to the OWASP rule-specific page for
  each rule (was the top-level OWASP project page). Results include `reference_url` and
  `why` in `properties`.
- **Grouped format Ref URL** — the grouped output format now shows a `Ref:` URL line after
  each rule's Fix line.
- **`CONTRIBUTING.md`** — development setup, test instructions, how to add a new rule,
  PR process, and code of conduct reference.
- **`CHANGELOG.md`** (this file) — initial changelog.
- **README improvements**:
  - Added `--quiet` and `--output` to the CLI Reference options table and examples
  - Updated LLM08 severity note: `FileManagementToolkit`/`WriteFileTool` → LOW
  - Updated filesystem tools severity in "What Each Rule Detects" section
  - Replaced inline Contributing section with link to `CONTRIBUTING.md`

### Changed
- **Severity: strict mode user-role finding** — changed from `MEDIUM` to `LOW` to match
  the documented behavior. Passing user input in the `role: user` position is the correct
  pattern; the finding is an informational reminder to add validation, not a confirmed
  injection vector.
- **Severity: `FileManagementToolkit` / `WriteFileTool`** — downgraded from `MEDIUM` to
  `LOW`. The presence of filesystem tools alone is a "review this" signal, not a confirmed
  vulnerability. Disabled approval gates (`auto_approve=True`) remain `MEDIUM`.
- **`format_flat`** — redesigned from a Rich table view to a structured per-finding block
  with What/Why/Fix/Ref sections (more readable for terminal output and piping).
- **`formatters.py`** — removed duplicate `_RULE_NAMES` dict; rule names are now read from
  the central registry (`registry.py`).
- All rule files (`llm01` through `llm10`) now import descriptions, fix suggestions, and
  reference URLs from the message catalog instead of having them hardcoded inline.

### Fixed
- `ast_analysis.py` — strict mode user-role plain variable finding emitted `MEDIUM` instead
  of `LOW` as documented in the README and module docstring. Fixed to `LOW`.

---

## [0.1.0] — 2025-01

> Initial public release baseline.

### Added
- **LLM01 — Prompt Injection**: regex (f-string, .format(), %-format, concatenation,
  LangChain PromptTemplate) + AST taint analysis with role-aware detection
- **LLM02 — Sensitive Information Disclosure**: OpenAI, Anthropic, Google, HuggingFace
  API key patterns across Python, YAML, JSON, .env, JS/TS, Markdown, and Notebook files
- **LLM05 — Improper Output Handling**: eval/exec/shell/SQL/HTML sinks with variable-name
  heuristics and AST taint tracking from LLM API calls
- **LLM06 — Insecure Plugin Design**: `@tool`-decorated functions with dangerous sinks;
  registered as ACTIVE in the rule registry
- **LLM07 — System Prompt Leakage**: hardcoded system prompts in source code (regex + AST
  multi-line detection across Python, YAML, JSON, and config files)
- **LLM08 — Excessive Agency**: 8 pattern categories (wildcard tools, dangerous tool classes,
  disabled approval gates, dynamic dispatch via globals/getattr, shell interpreter sinks,
  broad tool descriptions, agent loop patterns, @tool shell sinks)
- **LLM10 — Unbounded Consumption**: missing `max_tokens` on LLM API calls with **kwargs
  spread resolution
- **Dual-layer analysis**: regex patterns for quick scanning + AST taint analysis for
  confirmed findings with source-based taint seeding
- **5 output formats**: `grouped` (default), `flat`, `json`, `md`/`markdown`, `sarif` (SARIF 2.1.0)
- **Scan modes**: normal, `--strict`, `--verbose`, `--strict --verbose`
- **Exit codes**: `0` (clean), `1` (MEDIUM/HIGH), `2` (CRITICAL)
- **Inline suppression**: `# llmarmor: ignore[RULE_ID]` comments
- **Config file**: `.llmarmor.yaml` with per-rule severity overrides and suppression lists
- **Multi-file-type support**: Python, YAML, JSON, .env, JavaScript/TypeScript, Markdown,
  text files, and Jupyter notebooks
- **Rule registry** (`registry.py`) — single source of truth for rule metadata, severities,
  and descriptions

[Unreleased]: https://github.com/llmarmor/llmarmor/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/llmarmor/llmarmor/releases/tag/v0.1.0
