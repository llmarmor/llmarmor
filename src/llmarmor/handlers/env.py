"""Handler for ``.env`` files — detect hardcoded secrets (LLM02)."""

from llmarmor.secret_patterns import PLACEHOLDER_VALUE_PATTERN, SECRET_PATTERNS, TEST_VAR_PATTERN

RULE_ID = "LLM02"
RULE_NAME = "Sensitive Information Disclosure"

FIX_SUGGESTION = (
    "Never hardcode API keys in .env files committed to version control. "
    "Add .env to .gitignore and use a secrets manager or CI/CD secrets store for "
    "production deployments."
)


def scan_env_file(filepath: str, content: str) -> list[dict]:
    """LLM02: Detect hardcoded secrets in ``.env`` files.

    Parses ``KEY=value`` pairs, strips surrounding quotes, and checks the
    value against all known API-key patterns.  Comment lines and empty lines
    are skipped.
    """
    findings: list[dict] = []
    lines = content.splitlines()

    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        # Skip lines where the variable name suggests a test/placeholder value.
        if TEST_VAR_PATTERN.search(stripped):
            continue

        # Parse KEY=value (may have export prefix).
        if "=" not in stripped:
            continue
        _, _, value = stripped.partition("=")
        # Strip surrounding quotes.
        value = value.strip().strip("\"'")

        for pattern, key_type in SECRET_PATTERNS:
            if pattern.search(value):
                if PLACEHOLDER_VALUE_PATTERN.search(value):
                    continue
                findings.append(
                    {
                        "rule_id": RULE_ID,
                        "rule_name": RULE_NAME,
                        "severity": "CRITICAL",
                        "filepath": filepath,
                        "line": i + 1,
                        "description": (
                            f"Hardcoded {key_type} detected in .env file. "
                            "Committing secrets to version control exposes them to "
                            "anyone with repository access."
                        ),
                        "fix_suggestion": FIX_SUGGESTION,
                    }
                )
                break  # one finding per line is enough

    return findings
