# 🛡️ LLM Armor

**OWASP LLM Top 10 security scanner for AI-powered applications.**

Scan your Python codebase for security vulnerabilities mapped to the
[OWASP Top 10 for Large Language Models](https://owasp.org/www-project-top-10-for-large-language-model-applications/).

> ⚠️ **Early release** — actively under development. Star the repo to follow progress.

## Install

```bash
pip install llmarmor
```

## Usage

```bash
# Scan current directory
llmarmor scan .

# Scan a specific path
llmarmor scan ./my-llm-app/

# List available rules
llmarmor rules
```

## OWASP LLM Top 10 Coverage

| OWASP Risk | Rule | Coverage |
|---|---|---|
| LLM01 | Prompt Injection — unsanitized user input in LLM prompts | 🟢 Strong |
| LLM02 | Sensitive Info Disclosure — hardcoded API keys | 🟢 Strong |
| LLM07 | System Prompt Leakage — prompts in client code | 🟢 Strong |
| LLM10 | Unbounded Consumption — missing rate limits/max_tokens | 🟢 Strong |
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

### What each rule detects

**LLM01 — Prompt Injection:**
- Regex: direct interpolation via f-strings, `.format()`, `%`-formatting, and string concatenation
- AST: source-based taint tracking — a variable is tainted **only** when assigned from a
  user-controlled data source:
  - HTTP request objects: `request.json[...]`, `request.form.get(...)`, `req.args[...]`
  - Built-in stdin prompt: `input(...)`
  - Command-line arguments: `sys.argv[n]`
  - WebSocket messages: `websocket.receive()`, `ws.recv()`
  - Function parameters (any argument of a `def` or `async def` statement)
  Taint propagates through direct alias assignments (`alias = tainted_var`) but does **not**
  propagate through function calls, so `clean = sanitize(raw)` leaves `clean` untainted.
- Role-aware dict analysis: distinguishes the safe `role: user` pattern from dangerous
  `role: system` / `role: assistant` injection
- `str.join()` injection detection for tainted list elements
- Safe-source exclusions: variables assigned from `config.get()`, `os.environ`,
  `os.getenv()`, database calls, settings attributes, or string literals are **never**
  treated as user-controlled, preventing false positives

**LLM02 — Sensitive Info Disclosure:**
- Regex: OpenAI, Anthropic, Google, and HuggingFace (`hf_`) token patterns with minimum key length
- Comment lines, test/mock variable names, and short placeholder values are skipped

**LLM07 — System Prompt Leakage:**
- Regex: single-line hardcoded system prompt strings
- AST: multi-line implicit string concatenation and explicit `+`-concatenated prompts;
  only flags strings longer than 100 characters to avoid noise from short generic prompts

**LLM10 — Unbounded Consumption:**
- Regex: LLM API calls (`openai`, `anthropic`, `litellm`, etc.) without `max_tokens`
- AST: resolves `**config` dict spreads (suppresses the finding when `max_tokens` or
  `max_output_tokens` is provably set inside the spread dict); supports Gemini's
  `max_output_tokens` parameter

## How It Works — Dual-Layer Analysis

LLM Armor applies two complementary analysis layers to every Python file:

1. **Regex layer** — fast line-by-line pattern matching for the most common vulnerability
   patterns. Runs on all files regardless of whether they are valid Python.

2. **AST layer** — Python's `ast` module parses each file into a syntax tree and performs
   a single-pass source-based taint-tracking analysis. This catches patterns that regex
   cannot detect: variable aliasing, role-aware dict construction, multi-line string
   concatenation, and `**kwargs` dict spreading. If a file has syntax errors the AST layer
   gracefully falls back to empty output, leaving the regex results intact.

### Source-Based Taint Tracking

The AST layer uses **source-based** taint tracking: a variable is considered
user-controlled only when it is assigned from a known user-data source.

| Source | Example |
|---|---|
| HTTP request | `data = request.json["prompt"]` |
| HTTP form | `data = request.form.get("field")` |
| stdin prompt | `data = input("Enter: ")` |
| CLI arguments | `data = sys.argv[1]` |
| WebSocket | `data = websocket.receive()` |
| Function parameter | `def handle(user_msg):` |

Taint propagates through direct alias assignments (`alias = tainted`) but **not** through
function calls, so `clean = sanitize(raw)` does not taint `clean`.

The following are explicitly **not** taint sources:

| Not a taint source | Example |
|---|---|
| Config lookup | `config.get("prompt")` |
| Environment variable | `os.environ["PROMPT"]` / `os.getenv("PROMPT")` |
| Database call | `db.fetch_prompt(id)` |
| Settings attribute | `settings.DEFAULT_PROMPT` |
| String literal | `"You are a helpful assistant."` |

The two layers share findings deduplication: when both layers detect the same issue on the
same line, only one finding is reported.

## Language Support

| Language | Status | Notes |
|---|---|---|
| Python | 🟢 Supported | Primary language; all rules active |
| TypeScript / JavaScript | 🟡 Planned | Rule patterns being adapted |
| Other | 🔴 Not supported | Open an issue to request support |

## Links

- 🌐 Website: [llmarmor.dev](https://llmarmor.dev)
- 📦 PyPI: [pypi.org/project/llmarmor](https://pypi.org/project/llmarmor/)
- 🐛 Issues: [github.com/llmarmor/llmarmor/issues](https://github.com/llmarmor/llmarmor/issues)

## License

MIT
