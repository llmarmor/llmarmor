"""LLM01: Prompt Injection detection rule."""

import re

from llmarmor.messages import CATALOG, RULE_URLS

RULE_ID = "LLM01"
RULE_NAME = "Prompt Injection"
_REF = RULE_URLS[RULE_ID]
# Regex-only detection (without AST-confirmed taint): HIGH confidence but not
# confirmed. AST-confirmed findings (system-role f-string injection) remain CRITICAL.
SEVERITY = "HIGH"

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

_FSTRING_MSG = CATALOG[("LLM01", "fstring")]
_FORMAT_MSG = CATALOG[("LLM01", "format_method")]
_PERCENT_MSG = CATALOG[("LLM01", "percent_format")]
_LANGCHAIN_MSG = CATALOG[("LLM01", "langchain_template")]
_CONCAT_MSG = CATALOG[("LLM01", "concat")]

FIX_SUGGESTION = _FSTRING_MSG.fix

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
                        "description": _FSTRING_MSG.what,
                        "fix_suggestion": _FSTRING_MSG.fix,
                        "why": _FSTRING_MSG.why,
                        "reference_url": _REF,
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
                        "description": _FORMAT_MSG.what,
                        "fix_suggestion": _FORMAT_MSG.fix,
                        "why": _FORMAT_MSG.why,
                        "reference_url": _REF,
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
                        "description": _PERCENT_MSG.what,
                        "fix_suggestion": _PERCENT_MSG.fix,
                        "why": _PERCENT_MSG.why,
                        "reference_url": _REF,
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
                    "description": _LANGCHAIN_MSG.what,
                    "fix_suggestion": _LANGCHAIN_MSG.fix,
                    "why": _LANGCHAIN_MSG.why,
                    "reference_url": _REF,
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
                    "description": _CONCAT_MSG.what,
                    "fix_suggestion": _CONCAT_MSG.fix,
                    "why": _CONCAT_MSG.why,
                    "reference_url": _REF,
                }
            )

    return findings
