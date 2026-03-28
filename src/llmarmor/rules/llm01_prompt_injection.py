"""LLM01: Prompt Injection detection rule."""

import re

RULE_ID = "LLM01"
RULE_NAME = "Prompt Injection"
SEVERITY = "CRITICAL"

_USER_INPUT_ALT = (
    r"user_input|user_message|user_query|user_text|user_prompt|"
    r"user_data|user_content|user_request|human_input|human_message"
)

# Patterns for LLM prompt contexts
PROMPT_CONTEXT = re.compile(
    r"(messages\s*=|content\s*=|prompt\s*=|system\s*=)",
    re.IGNORECASE,
)

# f-string containing a user-input variable interpolation (single or triple quoted)
FSTRING_PATTERN = re.compile(
    r'f(?:"""|\'\'\'|["\']).*?\{(' + _USER_INPUT_ALT + r")[^}]*\}"
)

# String concatenation with user input in prompt context
CONCAT_PATTERN = re.compile(
    r"(?:content|prompt|message)\s*[=+]\s*['\"][^'\"]*['\"\s]*\+\s*("
    + _USER_INPUT_ALT
    + r")\b",
    re.IGNORECASE,
)

# .format() call with user input variable as argument
FORMAT_PATTERN = re.compile(
    r"\.format\s*\([^)]*\b(" + _USER_INPUT_ALT + r")\b",
    re.IGNORECASE,
)

# Percent-formatting with user input: "..." % user_input or "..." % (user_input, ...)
PERCENT_FORMAT_PATTERN = re.compile(
    r'["\'][^"\']*%[sd][^"\']*["\']\s*%\s*\(?\s*(' + _USER_INPUT_ALT + r")\b",
    re.IGNORECASE,
)

# LangChain PromptTemplate with a user-input variable placeholder in the template
LANGCHAIN_PATTERN = re.compile(
    r"PromptTemplate(?:\.from_template)?\s*\(.*?\{(?:" + _USER_INPUT_ALT + r")[^}]*\}",
    re.IGNORECASE,
)

FIX_SUGGESTION = (
    "Avoid interpolating user input directly into prompt strings. Instead, pass "
    "user input as a separate 'role: user' message without interpolation. If you "
    "must include user input in a prompt template, validate and sanitize it first "
    "— consider input length limits, allowlists, or a prompt-injection detection library."
)

_CONTEXT_WINDOW = 5  # lines to look before/after for prompt context


def check_prompt_injection(filepath: str, content: str) -> list[dict]:
    """LLM01: Detect f-strings or concatenation with user input in LLM prompt contexts."""
    findings = []
    lines = content.splitlines()

    for i, line in enumerate(lines):
        stripped = line.strip()
        # Skip comment-only lines
        if stripped.startswith("#"):
            continue

        start = max(0, i - _CONTEXT_WINDOW)
        end = min(len(lines), i + _CONTEXT_WINDOW + 1)
        context = "\n".join(lines[start:end])

        # Check for f-string with a user-input variable
        if FSTRING_PATTERN.search(line):
            if PROMPT_CONTEXT.search(context):
                findings.append(
                    {
                        "rule_id": RULE_ID,
                        "rule_name": RULE_NAME,
                        "severity": SEVERITY,
                        "filepath": str(filepath),
                        "line": i + 1,
                        "description": (
                            "User input is interpolated into a prompt string via an f-string. "
                            "If this constructs a system or assistant message, it may enable "
                            "prompt injection. Passing user input as a separate 'role: user' "
                            "message without interpolation is the recommended safe pattern."
                        ),
                        "fix_suggestion": FIX_SUGGESTION,
                    }
                )
                continue

        # Check for .format() call with user input variable as argument
        if FORMAT_PATTERN.search(line):
            if PROMPT_CONTEXT.search(context):
                findings.append(
                    {
                        "rule_id": RULE_ID,
                        "rule_name": RULE_NAME,
                        "severity": SEVERITY,
                        "filepath": str(filepath),
                        "line": i + 1,
                        "description": (
                            "User input is interpolated into a prompt string via .format(). "
                            "If this constructs a system or assistant message, it may enable "
                            "prompt injection. Passing user input as a separate 'role: user' "
                            "message without interpolation is the recommended safe pattern."
                        ),
                        "fix_suggestion": FIX_SUGGESTION,
                    }
                )
                continue

        # Check for percent-formatting with user input
        if PERCENT_FORMAT_PATTERN.search(line):
            if PROMPT_CONTEXT.search(context):
                findings.append(
                    {
                        "rule_id": RULE_ID,
                        "rule_name": RULE_NAME,
                        "severity": SEVERITY,
                        "filepath": str(filepath),
                        "line": i + 1,
                        "description": (
                            "User input is interpolated into a prompt string via "
                            "%-formatting. If this constructs a system or assistant "
                            "message, it may enable prompt injection. Passing user "
                            "input as a separate 'role: user' message without "
                            "interpolation is the recommended safe pattern."
                        ),
                        "fix_suggestion": FIX_SUGGESTION,
                    }
                )
                continue

        # Check for LangChain PromptTemplate with user input variable
        if LANGCHAIN_PATTERN.search(line):
            findings.append(
                {
                    "rule_id": RULE_ID,
                    "rule_name": RULE_NAME,
                    "severity": SEVERITY,
                    "filepath": str(filepath),
                    "line": i + 1,
                    "description": (
                        "LangChain PromptTemplate with a user-input variable placeholder "
                        "detected. If user input is passed to this template without "
                        "validation, it may enable prompt injection attacks."
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
                        "User input is interpolated into a prompt string via string "
                        "concatenation. If this constructs a system or assistant message, "
                        "it may enable prompt injection. Passing user input as a separate "
                        "'role: user' message without interpolation is the recommended safe pattern."
                    ),
                    "fix_suggestion": FIX_SUGGESTION,
                }
            )

    return findings
