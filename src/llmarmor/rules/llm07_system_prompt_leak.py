"""LLM07: System Prompt Leakage detection rule."""

import re

from llmarmor.messages import CATALOG, RULE_URLS

RULE_ID = "LLM07"
RULE_NAME = "System Prompt Leakage"
SEVERITY = "INFO"
_REF = RULE_URLS[RULE_ID]
_MSG_NORMAL = CATALOG[("LLM07", "hardcoded_normal")]
_MSG_STRICT = CATALOG[("LLM07", "hardcoded_strict")]

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

_FIX_SUGGESTION = _MSG_NORMAL.fix

_DESCRIPTION_NORMAL = _MSG_NORMAL.what
_DESCRIPTION_STRICT = _MSG_STRICT.what


def check_system_prompt_leak(filepath: str, content: str, strict: bool = False) -> list[dict]:
    """LLM07: Detect hardcoded system prompts in source files."""
    findings = []
    lines = content.splitlines()

    severity = "MEDIUM" if strict else SEVERITY
    description = _DESCRIPTION_STRICT if strict else _DESCRIPTION_NORMAL
    why = _MSG_STRICT.why if strict else _MSG_NORMAL.why

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
                    "description": description,
                    "fix_suggestion": _FIX_SUGGESTION,
                    "why": why,
                    "reference_url": _REF,
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
                    "description": description,
                    "fix_suggestion": _FIX_SUGGESTION,
                    "why": why,
                    "reference_url": _REF,
                }
            )

    return findings

