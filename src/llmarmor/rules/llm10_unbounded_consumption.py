"""LLM10: Unbounded Consumption detection rule."""

import re

from llmarmor.messages import CATALOG, RULE_URLS

RULE_ID = "LLM10"
RULE_NAME = "Unbounded Consumption"
SEVERITY = "MEDIUM"
_REF = RULE_URLS[RULE_ID]
_MSG = CATALOG[("LLM10", "missing_max_tokens")]

# LLM API call patterns — text/chat completion endpoints only
API_CALL_PATTERN = re.compile(
    r"\.(chat\.completions\.create|completions\.create|messages\.create|chat\.complete"
    r"|completion)\s*\(",
    re.IGNORECASE,
)

# max_tokens or max_output_tokens (Google Gemini API) presence
MAX_TOKENS_PATTERN = re.compile(r"\bmax_(?:output_)?tokens\s*=", re.IGNORECASE)

_CONTEXT_WINDOW = 10  # lines after the API call to search for max_tokens

FIX_SUGGESTION = _MSG.fix


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
            kwargs_note = (
                " Note: **kwargs is present — ensure max_tokens is always supplied "
                "by callers at runtime."
                if "**kwargs" in block
                else ""
            )
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
                        + kwargs_note
                    ),
                    "fix_suggestion": FIX_SUGGESTION,
                    "why": _MSG.why,
                    "reference_url": _REF,
                }
            )

    return findings
