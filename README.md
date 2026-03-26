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

## What It Detects

| OWASP Risk | Rule | Status |
|---|---|---|
| LLM01 | Prompt Injection — unsanitized user input in LLM prompts | 🟢 Active |
| LLM02 | Sensitive Info Disclosure — hardcoded API keys | 🟢 Active |
| LLM05 | Improper Output Handling — LLM output in eval/exec/HTML | 🟡 Coming soon |
| LLM07 | System Prompt Leakage — prompts in client code | 🟢 Active |
| LLM10 | Unbounded Consumption — missing rate limits/max_tokens | 🟢 Active |

## Links

- 🌐 Website: [llmarmor.dev](https://llmarmor.dev)
- 📦 PyPI: [pypi.org/project/llmarmor](https://pypi.org/project/llmarmor/)
- 🐛 Issues: [github.com/llmarmor/llmarmor/issues](https://github.com/llmarmor/llmarmor/issues)

## License

MIT
