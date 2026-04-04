"""LLM05: Improper Output Handling detection rule.

Detects when LLM API responses are passed to dangerous execution sinks without
validation or sanitisation.  Both a variable-name heuristic (regex layer) and
an AST taint-propagation layer are used; the regex layer is implemented here.

Severity mapping
----------------
CRITICAL  eval / exec / compile with LLM output; subprocess / os.system
HIGH      SQL interpolation with LLM output; Markup / render_template_string / mark_safe
INFO      json.loads (normal mode) — promoted to MEDIUM in --strict mode
INFO      generic tainted variable passed to unknown function (--strict → MEDIUM)
"""

import re

RULE_ID = "LLM05"
RULE_NAME = "Improper Output Handling"

# ---------------------------------------------------------------------------
# LLM-output variable-name heuristics
# ---------------------------------------------------------------------------

# Fragment patterns that indicate a variable holds an LLM *context* (i.e. is
# produced by or associated with an LLM call).  At least one of these must
# appear in the variable name.
_LLM_CONTEXT = re.compile(
    r"(?:llm|gpt|ai|chat|openai|anthropic|gemini|completion|model)",
    re.IGNORECASE,
)

# Fragment patterns that indicate a variable holds a *response* / output value.
_LLM_RESPONSE = re.compile(
    r"(?:response|output|reply|answer|result|text|content|message)",
    re.IGNORECASE,
)


def _is_llm_var(name: str) -> bool:
    """Return True if *name* looks like an LLM response variable.

    Requires BOTH an LLM-context indicator AND a response indicator to avoid
    false positives on generic variables like ``result = db.query(…)``.
    """
    return bool(_LLM_CONTEXT.search(name)) and bool(_LLM_RESPONSE.search(name))


# ---------------------------------------------------------------------------
# Pattern groups
# ---------------------------------------------------------------------------

# Code-execution sinks: eval / exec / compile
_EXEC_SINKS = re.compile(
    r"\b(eval|exec|compile)\s*\(\s*(\w+)",
    re.IGNORECASE,
)

# Shell-execution sinks: subprocess.run/call/Popen, os.system/popen
_SHELL_SINKS = re.compile(
    r"\b(?:subprocess\.(?:run|call|check_call|check_output|Popen)|"
    r"os\.(?:system|popen))\s*\(\s*(\w+)",
    re.IGNORECASE,
)

# SQL interpolation sinks: cursor.execute / connection.execute with f-string or % formatting
_SQL_SINK = re.compile(
    r"\b(?:cursor|conn|connection|db)\s*\.\s*execute\s*\(\s*"
    r"(?:f['\"]|['\"].*%|\"|'[^']*\{)",
    re.IGNORECASE,
)

# SQL variable-based: cursor.execute(variable) or cursor.execute(some_string.format(...)
_SQL_SINK_VAR = re.compile(
    r"\b(?:cursor|conn|connection|db)\s*\.\s*execute\s*\(\s*(\w+)",
    re.IGNORECASE,
)

# HTML / XSS sinks
_HTML_SINKS = re.compile(
    r"\b(Markup|render_template_string|mark_safe)\s*\(\s*(\w+)",
    re.IGNORECASE,
)

# JSON deserialisation
_JSON_LOADS = re.compile(
    r"\bjson\.loads\s*\(\s*(\w+)",
    re.IGNORECASE,
)

_FIX_EXEC = (
    "Never pass LLM-generated output directly to eval(), exec(), or compile(). "
    "Validate and sanitise LLM output before any code execution. "
    "Consider using a safe evaluation sandbox if dynamic code execution is required."
)
_FIX_SHELL = (
    "Never pass LLM-generated output directly to shell or subprocess calls. "
    "Use a fixed command allowlist and pass arguments as a list (not a shell string). "
    "Apply strict input validation before any system command execution."
)
_FIX_SQL = (
    "Never interpolate LLM output into SQL queries. "
    "Use parameterised queries (cursor.execute(sql, params)) and validate all LLM output "
    "against an expected schema before using it in database operations."
)
_FIX_HTML = (
    "Never pass LLM output directly to HTML rendering functions. "
    "Escape or sanitise LLM output with bleach or html.escape() before rendering, "
    "and validate output against an expected schema."
)
_FIX_JSON = (
    "Validate JSON deserialized from LLM output against a strict schema (e.g. pydantic). "
    "LLM output can be manipulated to produce unexpected JSON structures. "
    "Never pass deserialized data to further unsafe operations without validation."
)


def check_improper_output(
    filepath: str, content: str, strict: bool = False
) -> list[dict]:
    """LLM05: Detect LLM output passed to dangerous execution sinks."""
    findings: list[dict] = []
    lines = content.splitlines()

    for i, line in enumerate(lines):
        stripped = line.strip()
        # Skip comment-only lines
        if stripped.startswith("#"):
            continue

        # --- CRITICAL: code-execution sinks ---
        m = _EXEC_SINKS.search(line)
        if m:
            var_name = m.group(2)
            if _is_llm_var(var_name):
                findings.append(
                    {
                        "rule_id": RULE_ID,
                        "rule_name": RULE_NAME,
                        "severity": "CRITICAL",
                        "filepath": str(filepath),
                        "line": i + 1,
                        "description": (
                            f"LLM output variable '{var_name}' is passed to "
                            f"{m.group(1)}() without validation. This enables "
                            "arbitrary code execution from LLM-generated content."
                        ),
                        "fix_suggestion": _FIX_EXEC,
                    }
                )
                continue

        # --- CRITICAL: shell-execution sinks ---
        m = _SHELL_SINKS.search(line)
        if m:
            var_name = m.group(1)
            if _is_llm_var(var_name):
                findings.append(
                    {
                        "rule_id": RULE_ID,
                        "rule_name": RULE_NAME,
                        "severity": "CRITICAL",
                        "filepath": str(filepath),
                        "line": i + 1,
                        "description": (
                            f"LLM output variable '{var_name}' is passed to a shell "
                            "execution sink without validation. This enables OS command "
                            "injection from LLM-generated content."
                        ),
                        "fix_suggestion": _FIX_SHELL,
                    }
                )
                continue

        # --- HIGH: SQL interpolation ---
        # Check f-string / format-string interpolation into SQL
        m = _SQL_SINK.search(line)
        if m:
            # Extract any LLM variable name embedded in the interpolation
            var_m = re.search(r"\{(\w+)\}", line)
            if var_m and _is_llm_var(var_m.group(1)):
                findings.append(
                    {
                        "rule_id": RULE_ID,
                        "rule_name": RULE_NAME,
                        "severity": "HIGH",
                        "filepath": str(filepath),
                        "line": i + 1,
                        "description": (
                            f"LLM output is interpolated into a SQL query. "
                            "This may enable SQL injection via LLM-generated content."
                        ),
                        "fix_suggestion": _FIX_SQL,
                    }
                )
                continue

        # --- HIGH: HTML / XSS sinks ---
        m = _HTML_SINKS.search(line)
        if m:
            var_name = m.group(2)
            if _is_llm_var(var_name):
                findings.append(
                    {
                        "rule_id": RULE_ID,
                        "rule_name": RULE_NAME,
                        "severity": "HIGH",
                        "filepath": str(filepath),
                        "line": i + 1,
                        "description": (
                            f"LLM output variable '{var_name}' is passed to "
                            f"{m.group(1)}() without sanitisation. This may enable "
                            "cross-site scripting (XSS) or HTML injection."
                        ),
                        "fix_suggestion": _FIX_HTML,
                    }
                )
                continue

        # --- INFO / MEDIUM: json.loads ---
        m = _JSON_LOADS.search(line)
        if m:
            var_name = m.group(1)
            if _is_llm_var(var_name):
                severity = "MEDIUM" if strict else "INFO"
                findings.append(
                    {
                        "rule_id": RULE_ID,
                        "rule_name": RULE_NAME,
                        "severity": severity,
                        "filepath": str(filepath),
                        "line": i + 1,
                        "description": (
                            f"LLM output variable '{var_name}' is deserialised with "
                            "json.loads() without schema validation. If the parsed data "
                            "feeds further unsafe operations this may be exploitable."
                        ),
                        "fix_suggestion": _FIX_JSON,
                    }
                )
                continue

    return findings
