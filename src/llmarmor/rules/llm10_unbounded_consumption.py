"""LLM10: Unbounded Consumption detection rule."""

import re

RULE_ID = "LLM10"
RULE_NAME = "Unbounded Consumption"
SEVERITY = "MEDIUM"

# LLM API call patterns
API_CALL_PATTERN = re.compile(
    r"\.(chat\.completions\.create|completions\.create|messages\.create|chat\.complete)\s*\(",
    re.IGNORECASE,
)

# max_tokens presence
MAX_TOKENS_PATTERN = re.compile(r"\bmax_tokens\s*=", re.IGNORECASE)

_CONTEXT_WINDOW = 10  # lines after the API call to search for max_tokens

FIX_SUGGESTION = (
    "Always set max_tokens (or equivalent) on LLM API calls to prevent runaway "
    "token consumption and unexpected costs. Also consider adding timeout and "
    "per-user rate limits."
)


def check_unbounded_consumption(filepath: str, content: str) -> list[dict]:
    """LLM10: Detect LLM API calls without a max_tokens limit."""
    findings = []
    lines = content.splitlines()

    for i, line in enumerate(lines):
        if not API_CALL_PATTERN.search(line):
            continue

        # Look ahead for max_tokens within the call block (up to _CONTEXT_WINDOW lines)
        end = min(len(lines), i + _CONTEXT_WINDOW + 1)
        block = "\n".join(lines[i:end])

        if not MAX_TOKENS_PATTERN.search(block):
            findings.append(
                {
                    "rule_id": RULE_ID,
                    "rule_name": RULE_NAME,
                    "severity": SEVERITY,
                    "filepath": str(filepath),
                    "line": i + 1,
                    "description": (
                        "LLM API call without max_tokens set. This can lead to "
                        "unexpectedly large responses and higher-than-expected costs."
                    ),
                    "fix_suggestion": FIX_SUGGESTION,
                }
            )

    return findings
