"""LLM02: Sensitive Information Disclosure — hardcoded API key detection."""

import re

RULE_ID = "LLM02"
RULE_NAME = "Sensitive Information Disclosure"
SEVERITY = "CRITICAL"

# OpenAI keys: sk- followed by 20+ alphanumeric chars, but NOT sk-ant- (Anthropic)
OPENAI_KEY_PATTERN = re.compile(r'sk-(?!ant-)(?:[A-Za-z0-9_-]{20,})')

# Anthropic keys: sk-ant- followed by 20+ chars
ANTHROPIC_KEY_PATTERN = re.compile(r'sk-ant-[A-Za-z0-9_-]{20,}')

# Google AI keys: AIza followed by exactly 35 chars
GOOGLE_KEY_PATTERN = re.compile(r'AIza[A-Za-z0-9_-]{35}')

_PATTERNS = [
    (OPENAI_KEY_PATTERN, "OpenAI API key"),
    (ANTHROPIC_KEY_PATTERN, "Anthropic API key"),
    (GOOGLE_KEY_PATTERN, "Google AI API key"),
]

FIX_SUGGESTION = (
    "Never hardcode API keys in source code. Store secrets in environment variables "
    "and access them via os.environ.get('KEY_NAME'). Use a secrets manager for "
    "production deployments."
)


def check_sensitive_info(filepath: str, content: str) -> list[dict]:
    """LLM02: Detect hardcoded LLM API keys in source files."""
    findings = []
    lines = content.splitlines()

    for i, line in enumerate(lines):
        stripped = line.strip()
        # Skip comment-only lines
        if stripped.startswith("#"):
            continue

        for pattern, key_type in _PATTERNS:
            if pattern.search(line):
                findings.append(
                    {
                        "rule_id": RULE_ID,
                        "rule_name": RULE_NAME,
                        "severity": SEVERITY,
                        "filepath": str(filepath),
                        "line": i + 1,
                        "description": (
                            f"Hardcoded {key_type} detected. Committing API keys to "
                            "version control exposes them to anyone with repository access."
                        ),
                        "fix_suggestion": FIX_SUGGESTION,
                    }
                )
                break  # one finding per line is enough

    return findings
