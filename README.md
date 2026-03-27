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
| LLM01 | Prompt Injection — unsanitized user input in LLM prompts | 🟢 Basic |
| LLM02 | Sensitive Info Disclosure — hardcoded API keys | 🟢 Basic |
| LLM07 | System Prompt Leakage — prompts in client code | 🟢 Basic |
| LLM10 | Unbounded Consumption — missing rate limits/max_tokens | 🟢 Basic |
| LLM05 | Improper Output Handling — LLM output in eval/exec/HTML | 🟡 Planned |
| LLM08 | Excessive Agency — over-permissioned LLM actions | 🟡 Planned |
| LLM03 | Supply Chain Vulnerabilities | 🔴 Out of scope |
| LLM04 | Data and Model Poisoning | 🔴 Out of scope |
| LLM06 | Insecure Plugin Design | 🔴 Out of scope |
| LLM09 | Misinformation | 🔴 Out of scope |

**Coverage levels:**
- 🟢 **Basic** — regex-based pattern detection (fast, offline, no false negatives on common patterns)
- 🟡 **Planned** — detection logic is in development
- 🔴 **Out of scope** — not detectable by static analysis alone; requires runtime or LLM-assisted review

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
