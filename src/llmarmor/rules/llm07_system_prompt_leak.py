"""LLM07: System Prompt Leakage detection rule."""

import re

RULE_ID = "LLM07"
RULE_NAME = "System Prompt Leakage"
SEVERITY = "HIGH"

MIN_PROMPT_LENGTH = 50

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

FIX_SUGGESTION = (
    "Do not hardcode system prompts in client-side or version-controlled code. "
    "Load system prompts from environment variables, a secrets manager, or a "
    "server-side configuration store that is not exposed to end users."
)


def check_system_prompt_leak(filepath: str, content: str) -> list[dict]:
    """LLM07: Detect hardcoded system prompts in source files."""
    findings = []
    lines = content.splitlines()

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
                    "severity": SEVERITY,
                    "filepath": str(filepath),
                    "line": i + 1,
                    "description": (
                        "Hardcoded system prompt detected in a variable assignment. "
                        "System prompts in source code are visible to anyone with "
                        "repository access and may expose business logic or secrets."
                    ),
                    "fix_suggestion": FIX_SUGGESTION,
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
                    "severity": SEVERITY,
                    "filepath": str(filepath),
                    "line": i + 1,
                    "description": (
                        'Hardcoded system prompt in {"role": "system", "content": ...} '
                        "literal. System prompts in source code expose business logic "
                        "to anyone with repository access."
                    ),
                    "fix_suggestion": FIX_SUGGESTION,
                }
            )

    return findings
