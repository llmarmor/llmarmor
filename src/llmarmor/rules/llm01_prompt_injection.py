"""LLM01: Prompt Injection detection rule."""

import re

RULE_ID = "LLM01"
RULE_NAME = "Prompt Injection"
SEVERITY = "CRITICAL"

_USER_INPUT_ALT = (
    r"user_input|user_message|user_query|user_text|user_prompt|"
    r"request|input|query|message|user_data|user_content|"
    r"user_request|human_input|human_message"
)

# Patterns for LLM prompt contexts
PROMPT_CONTEXT = re.compile(
    r"(messages\s*=|content\s*=|prompt\s*=|system\s*=)",
    re.IGNORECASE,
)

# f-string containing a user-input variable interpolation: f"...{user_input}..."
FSTRING_PATTERN = re.compile(
    r"f['\"].*?\{(" + _USER_INPUT_ALT + r")[^}]*\}"
)

# String concatenation with user input in prompt context
CONCAT_PATTERN = re.compile(
    r"(?:content|prompt|message)\s*[=+]\s*['\"][^'\"]*['\"\s]*\+\s*("
    + _USER_INPUT_ALT
    + r")\b",
    re.IGNORECASE,
)

FIX_SUGGESTION = (
    "Validate and sanitize user input before including it in LLM prompts. "
    "Consider using an allowlist, input length limits, or a prompt-injection "
    "detection library. Passing user input in the 'user' role is expected for "
    "chat applications; ensure it is not injected into system prompts or other "
    "trusted contexts where it could override instructions."
)

_CONTEXT_WINDOW = 5  # lines to look before/after for prompt context


def check_prompt_injection(filepath: str, content: str) -> list[dict]:
    """LLM01: Detect f-strings or concatenation with user input in LLM prompt contexts."""
    findings = []
    lines = content.splitlines()

    for i, line in enumerate(lines):
        # Check for f-string with a user-input variable
        if FSTRING_PATTERN.search(line):
            # Look in nearby lines for a prompt-construction context
            start = max(0, i - _CONTEXT_WINDOW)
            end = min(len(lines), i + _CONTEXT_WINDOW + 1)
            context = "\n".join(lines[start:end])
            if PROMPT_CONTEXT.search(context):
                findings.append(
                    {
                        "rule_id": RULE_ID,
                        "rule_name": RULE_NAME,
                        "severity": SEVERITY,
                        "filepath": str(filepath),
                        "line": i + 1,
                        "description": (
                            "User-controlled input is interpolated directly into an LLM "
                            "prompt via an f-string. This is expected in the 'user' role "
                            "for chat apps, but can enable prompt injection attacks if "
                            "user input is embedded in system prompts or trusted contexts."
                        ),
                        "fix_suggestion": FIX_SUGGESTION,
                    }
                )
                continue

        # Check for string concatenation with user input in a prompt context
        if CONCAT_PATTERN.search(line):
            findings.append(
                {
                    "rule_id": RULE_ID,
                    "rule_name": RULE_NAME,
                    "severity": SEVERITY,
                    "filepath": str(filepath),
                    "line": i + 1,
                    "description": (
                        "User-controlled input is concatenated directly into an LLM "
                        "prompt. This is expected in the 'user' role for chat apps, "
                        "but can enable prompt injection attacks if user input reaches "
                        "system prompts or other trusted contexts."
                    ),
                    "fix_suggestion": FIX_SUGGESTION,
                }
            )

    return findings
