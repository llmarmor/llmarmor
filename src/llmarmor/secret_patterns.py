"""Shared secret-detection patterns for LLM Armor.

These patterns are used by the Python rule (LLM02) and by the non-Python file
handlers so that detection logic is defined once and reused everywhere.
"""

import re

# OpenAI keys: sk- followed by 20+ alphanumeric/dash/underscore chars,
# but NOT sk-ant- (Anthropic).
OPENAI_KEY_PATTERN = re.compile(r"sk-(?!ant-)(?:[A-Za-z0-9_-]{20,})")

# Anthropic keys: sk-ant- followed by 20+ chars.
ANTHROPIC_KEY_PATTERN = re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}")

# Google AI keys: AIza followed by exactly 35 chars.
GOOGLE_KEY_PATTERN = re.compile(r"AIza[A-Za-z0-9_-]{35}")

# Hugging Face tokens: hf_ followed by 20+ alphanumeric chars.
HF_TOKEN_PATTERN = re.compile(r"hf_[A-Za-z0-9]{20,}")

# All secret patterns with human-readable labels.
SECRET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (OPENAI_KEY_PATTERN, "OpenAI API key"),
    (ANTHROPIC_KEY_PATTERN, "Anthropic API key"),
    (GOOGLE_KEY_PATTERN, "Google AI API key"),
    (HF_TOKEN_PATTERN, "Hugging Face API token"),
]

# Variables whose names indicate they are placeholders and not real secrets.
TEST_VAR_PATTERN = re.compile(
    r"(?<![A-Za-z0-9])(?:test|fake|mock|example|dummy|placeholder)(?![A-Za-z0-9])",
    re.IGNORECASE,
)

# Values that look like placeholder/documentation secrets rather than real keys.
# Applied to the *matched value* (the token matched by a SECRET_PATTERN), not the
# variable name.  If a match is found, the finding is suppressed.
PLACEHOLDER_VALUE_PATTERN = re.compile(
    r"(?:your|example|test|fake|mock|dummy|placeholder|replace|insert|put|change|fill|xxx|sample|demo|here)",
    re.IGNORECASE,
)
