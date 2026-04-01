"""Handler for ``.toml`` files — detect secrets (LLM02).

Scanning is regex-based on raw text — no tomllib dependency required.
"""

from llmarmor.secret_patterns import SECRET_PATTERNS, TEST_VAR_PATTERN

_LLM02_FIX = (
    "Never hardcode API keys in TOML configuration files. Use environment variable "
    "references or a secrets manager instead."
)


def scan_toml_file(filepath: str, content: str) -> list[dict]:
    """LLM02: Detect hardcoded secrets in TOML files."""
    findings: list[dict] = []
    lines = content.splitlines()

    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if TEST_VAR_PATTERN.search(line):
            continue

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
                            f"Hardcoded {key_type} detected in TOML file. "
                            "Committing secrets to version control exposes them to "
                            "anyone with repository access."
                        ),
                        "fix_suggestion": _LLM02_FIX,
                    }
                )
                break

    return findings
