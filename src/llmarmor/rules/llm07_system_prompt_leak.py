"""LLM07: System Prompt Leakage detection rule."""

import re

RULE_ID = "LLM07"
RULE_NAME = "System Prompt Leakage"
SEVERITY = "INFO"

MIN_PROMPT_LENGTH = 100

# Variable assignment: system_prompt / SYSTEM_PROMPT / system_message / etc.
SYSTEM_VAR_PATTERN = re.compile(
    r'(?:system_prompt|SYSTEM_PROMPT|system_message|SYSTEM_MESSAGE|'
    r'sys_prompt|SYS_PROMPT)\s*=\s*["\'](.+)["\']',
    re.IGNORECASE,
)

# Dict literal with role=system and a long hardcoded content string
ROLE_SYSTEM_PATTERN = re.compile(
    r'\{[^}]*["\']role["\']\s*:\s*["\']system["\']\s*,[^}]*'
    r'["\']content["\']\s*:\s*["\']([^"\']{50,})["\'][^}]*\}',
    re.DOTALL,
)

_FIX_SUGGESTION = (
    "Hardcoded system prompts in source code are visible to anyone with repository "
    "access. If the prompt contains sensitive business logic or secrets, load it from "
    "environment variables or a server-side configuration store instead."
)

_DESCRIPTION_NORMAL = (
    "System prompt is hardcoded in source code. Consider moving to environment "
    "variables or a config file for easier management and to prevent exposure "
    "in version control."
)

_DESCRIPTION_STRICT = (
    "System prompt is hardcoded in source code. If this code is published "
    "(open source, client-side bundle, shared package), the prompt contents "
    "will be visible to users. This may leak proprietary instructions, internal "
    "tool descriptions, or behavioral constraints that could be exploited. "
    "Move to environment variables or a secure config service."
)


def check_system_prompt_leak(filepath: str, content: str, strict: bool = False) -> list[dict]:
    """LLM07: Detect hardcoded system prompts in source files."""
    findings = []
    lines = content.splitlines()

    severity = "MEDIUM" if strict else SEVERITY
    description_var = _DESCRIPTION_STRICT if strict else _DESCRIPTION_NORMAL

    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue

        # Check variable assignment pattern
        m = SYSTEM_VAR_PATTERN.search(line)
        if m and len(m.group(1)) > MIN_PROMPT_LENGTH:
            findings.append(
                {
                    "rule_id": RULE_ID,
                    "rule_name": RULE_NAME,
                    "severity": severity,
                    "filepath": str(filepath),
                    "line": i + 1,
                    "description": description_var,
                    "fix_suggestion": _FIX_SUGGESTION,
                }
            )
            continue

        # Check role=system dict pattern
        m = ROLE_SYSTEM_PATTERN.search(line)
        if m:
            findings.append(
                {
                    "rule_id": RULE_ID,
                    "rule_name": RULE_NAME,
                    "severity": severity,
                    "filepath": str(filepath),
                    "line": i + 1,
                    "description": description_var,
                    "fix_suggestion": _FIX_SUGGESTION,
                }
            )

    return findings

