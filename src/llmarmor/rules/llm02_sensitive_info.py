"""LLM02: Sensitive Information Disclosure — hardcoded API key detection."""

from llmarmor.secret_patterns import SECRET_PATTERNS, TEST_VAR_PATTERN

RULE_ID = "LLM02"
RULE_NAME = "Sensitive Information Disclosure"
SEVERITY = "CRITICAL"

_PATTERNS = SECRET_PATTERNS
_TEST_VAR_PATTERN = TEST_VAR_PATTERN

FIX_SUGGESTION = (
    "Never hardcode API keys in source code. Store secrets in environment variables "
    "and access them via os.environ.get('KEY_NAME'). Use a secrets manager for "
    "production deployments."
)


def check_sensitive_info(filepath: str, content: str) -> list[dict]:
    """LLM02: Detect hardcoded LLM API keys in source files."""
    findings = []
    lines = content.splitlines()

    for i, line in enumerate(lines):
        stripped = line.strip()
        # Skip comment-only lines
        if stripped.startswith("#"):
            continue

        # Skip lines where the variable name suggests a test/placeholder value
        if _TEST_VAR_PATTERN.search(line):
            continue

        for pattern, key_type in _PATTERNS:
            if pattern.search(line):
                findings.append(
                    {
                        "rule_id": RULE_ID,
                        "rule_name": RULE_NAME,
                        "severity": SEVERITY,
                        "filepath": str(filepath),
                        "line": i + 1,
                        "description": (
                            f"Hardcoded {key_type} detected. Committing API keys to "
                            "version control exposes them to anyone with repository access."
                        ),
                        "fix_suggestion": FIX_SUGGESTION,
                    }
                )
                break  # one finding per line is enough

    return findings
