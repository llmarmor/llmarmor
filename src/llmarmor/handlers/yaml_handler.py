"""Handler for ``.yaml`` / ``.yml`` files — detect secrets (LLM02) and system prompts (LLM07).

Scanning is regex-based on raw text — no pyyaml dependency required.
"""

import re

from llmarmor.secret_patterns import SECRET_PATTERNS, TEST_VAR_PATTERN

# YAML keys that may contain system prompts
_PROMPT_KEY_PATTERN = re.compile(
    r"^\s*(?:system_prompt|system_message|system|prompt)\s*:\s*['\"]?(.+?)['\"]?\s*$",
    re.IGNORECASE,
)

_MIN_PROMPT_LENGTH = 100

_LLM07_FIX = (
    "Hardcoded system prompts in configuration files may be exposed through "
    "version control. Consider loading them from environment variables or a "
    "secure configuration store."
)

_LLM02_FIX = (
    "Never hardcode API keys in YAML configuration files. Use environment variable "
    "references (e.g. ${OPENAI_API_KEY}) or a secrets manager instead."
)


def scan_yaml_file(filepath: str, content: str) -> list[dict]:
    """Scan a YAML/YML file for secrets (LLM02) and exposed system prompts (LLM07)."""
    findings: list[dict] = []
    lines = content.splitlines()

    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        # --- LLM02: Secrets in values ---
        if not TEST_VAR_PATTERN.search(line):
            for pattern, key_type in SECRET_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        {
                            "rule_id": "LLM02",
                            "rule_name": "Sensitive Information Disclosure",
                            "severity": "CRITICAL",
                            "filepath": filepath,
                            "line": i + 1,
                            "description": (
                                f"Hardcoded {key_type} detected in YAML file. "
                                "Committing secrets to version control exposes them to "
                                "anyone with repository access."
                            ),
                            "fix_suggestion": _LLM02_FIX,
                        }
                    )
                    break

        # --- LLM07: Exposed system prompts in known keys ---
        m = _PROMPT_KEY_PATTERN.match(line)
        if m and len(m.group(1)) >= _MIN_PROMPT_LENGTH:
            findings.append(
                {
                    "rule_id": "LLM07",
                    "rule_name": "System Prompt Leakage",
                    "severity": "INFO",
                    "filepath": filepath,
                    "line": i + 1,
                    "description": (
                        "System prompt is hardcoded in a YAML configuration file. "
                        "If this file is committed to version control, the prompt "
                        "contents will be visible to anyone with repository access."
                    ),
                    "fix_suggestion": _LLM07_FIX,
                }
            )

    return findings
