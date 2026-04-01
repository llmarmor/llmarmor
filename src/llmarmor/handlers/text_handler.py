"""Handler for ``.md`` / ``.txt`` files — detect accidentally committed secrets (LLM02)
and system prompts (LLM07).
"""

import re

from llmarmor.secret_patterns import SECRET_PATTERNS, TEST_VAR_PATTERN

# Long prose that looks like a system prompt: matches lines/blocks starting with
# common system-prompt indicators and exceeding the minimum length.
_PROMPT_LINE_PATTERN = re.compile(
    r"(?:system prompt|system message|you are a|you are an|act as a|act as an"
    r"|your role is|your task is|your job is|instructions:)\s*[:\-]?\s*(.{80,})",
    re.IGNORECASE,
)

_LLM07_FIX = (
    "Do not commit system prompt content to version control in documentation or "
    "text files. Store prompts in environment variables or a secure configuration "
    "store and reference them by name."
)

_LLM02_FIX = (
    "Never commit API keys to version control, even in documentation or notes. "
    "Rotate any exposed key immediately and use environment variables or a secrets "
    "manager going forward."
)


def scan_text_file(filepath: str, content: str) -> list[dict]:
    """Scan a Markdown/text file for accidentally committed secrets and system prompts."""
    findings: list[dict] = []
    lines = content.splitlines()

    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped:
            continue

        # --- LLM02: Secrets ---
        if not TEST_VAR_PATTERN.search(line):
            for pattern, key_type in SECRET_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        {
                            "rule_id": "LLM02",
                            "rule_name": "Sensitive Information Disclosure",
                            "severity": "HIGH",
                            "filepath": filepath,
                            "line": i + 1,
                            "description": (
                                f"Hardcoded {key_type} found in a documentation/text file. "
                                "If committed to version control this exposes the secret to "
                                "anyone with repository access."
                            ),
                            "fix_suggestion": _LLM02_FIX,
                        }
                    )
                    break

        # --- LLM07: System prompts in documentation ---
        m = _PROMPT_LINE_PATTERN.search(line)
        if m:
            findings.append(
                {
                    "rule_id": "LLM07",
                    "rule_name": "System Prompt Leakage",
                    "severity": "INFO",
                    "filepath": filepath,
                    "line": i + 1,
                    "description": (
                        "System prompt content detected in a documentation/text file. "
                        "If committed to version control, proprietary prompt instructions "
                        "will be visible to anyone with repository access."
                    ),
                    "fix_suggestion": _LLM07_FIX,
                }
            )

    return findings
