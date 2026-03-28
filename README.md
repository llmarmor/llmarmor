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
- AST: variable aliasing / taint propagation, role-aware dict analysis (distinguishes the safe
  `role: user` pattern from dangerous `role: system` injection), and `str.join()` injection
- False-positive reduction: variables named `user_prompt` that are assigned from config, database,
  environment variables, or hardcoded strings are NOT treated as user-controlled

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
   a single-pass taint-tracking analysis. This catches patterns that regex cannot detect:
   variable aliasing, role-aware dict construction, multi-line string concatenation, and
   `**kwargs` dict spreading. If a file has syntax errors the AST layer gracefully falls
   back to empty output, leaving the regex results intact.

The two layers share findings deduplication: when the AST layer detects the same issue on
the same line as the regex layer, only one finding is reported.

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
