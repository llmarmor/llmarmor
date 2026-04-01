"""Handler for ``.js`` / ``.ts`` files — detect secrets (LLM02) and system prompts (LLM07)."""

import re

from llmarmor.secret_patterns import SECRET_PATTERNS, TEST_VAR_PATTERN

# String literals (single, double, or template) following a prompt-related variable name.
_PROMPT_VAR_PATTERN = re.compile(
    r"(?:systemPrompt|system_prompt|systemMessage|system_message|SYSTEM_PROMPT"
    r"|SYSTEM_MESSAGE)\s*[=:]\s*[`\"']([^`\"']{100,})[`\"']",
    re.IGNORECASE,
)

_LLM07_FIX = (
    "Hardcoded system prompts in JavaScript/TypeScript source files may be exposed "
    "through version control or bundled client-side code. Load them from environment "
    "variables or a server-side configuration service instead."
)

_LLM02_FIX = (
    "Never hardcode API keys in JavaScript/TypeScript files. Use environment variables "
    "(process.env.KEY) or a secrets manager. Never bundle API keys in client-side code."
)


def scan_js_file(filepath: str, content: str) -> list[dict]:
    """Scan a JS/TS file for secrets (LLM02) and system prompts (LLM07)."""
    findings: list[dict] = []
    lines = content.splitlines()

    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue

        # --- LLM02: Secrets ---
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
                                f"Hardcoded {key_type} detected in JS/TS file. "
                                "Committing secrets to version control exposes them to "
                                "anyone with repository access, and bundling them in "
                                "client-side code exposes them to end users."
                            ),
                            "fix_suggestion": _LLM02_FIX,
                        }
                    )
                    break

        # --- LLM07: System prompts ---
        m = _PROMPT_VAR_PATTERN.search(line)
        if m:
            findings.append(
                {
                    "rule_id": "LLM07",
                    "rule_name": "System Prompt Leakage",
                    "severity": "INFO",
                    "filepath": filepath,
                    "line": i + 1,
                    "description": (
                        "System prompt is hardcoded in a JS/TS source file. "
                        "If this code is bundled for client-side delivery or "
                        "committed to version control, the prompt will be visible "
                        "to anyone who inspects the bundle or repository."
                    ),
                    "fix_suggestion": _LLM07_FIX,
                }
            )

    return findings
