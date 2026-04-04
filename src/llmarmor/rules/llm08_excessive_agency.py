"""LLM08: Excessive Agency detection rule.

Detects when LLM-powered applications grant overly broad permissions to agents:
wildcard tool access, dangerous built-in tool classes, disabled approval gates,
unrestricted dynamic dispatch, and missing explicit allowlists.

Framework-aware: recognises LangChain, OpenAI function calling, AutoGen,
CrewAI, and generic agent-loop patterns.

Severity mapping
----------------
CRITICAL  globals()[fn_name]() / eval(fn_name) — dynamic dispatch from LLM tool call
HIGH      tools=["*"] — wildcard tool access
HIGH      ShellTool / PythonREPLTool / CodeInterpreterTool
HIGH      getattr(module, llm_name)() — dynamic dispatch via getattr
MEDIUM    auto_approve=True / human_in_the_loop=False
MEDIUM    FileManagementToolkit / WriteFileTool
INFO      Broad tool description / no explicit allowlist (--strict → MEDIUM)
"""

import re

RULE_ID = "LLM08"
RULE_NAME = "Excessive Agency"

# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------

# Dynamic dispatch via globals() — CRITICAL
_GLOBALS_DISPATCH = re.compile(
    r"\bglobals\s*\(\s*\)\s*\[",
    re.IGNORECASE,
)

# Wildcard tool list — HIGH
_WILDCARD_TOOLS = re.compile(
    r'\btools\s*=\s*\[\s*["\']?\s*\*\s*["\']?\s*\]',
    re.IGNORECASE,
)

# Dangerous tool classes — HIGH
_DANGEROUS_TOOLS = re.compile(
    r"\b(ShellTool|PythonREPLTool|CodeInterpreterTool|BashTool|TerminalTool)\s*\(",
)

# Dynamic dispatch via getattr with variable function name — HIGH
# Matches: getattr(something, variable_name) where the second arg is a bare name (not a string literal)
_GETATTR_DISPATCH = re.compile(
    r"\bgetattr\s*\(\s*\w[\w.]*\s*,\s*(?![\"\'])(\w+)\s*\)",
)

# Disabled approval gates — MEDIUM
_DISABLED_APPROVAL = re.compile(
    r"\b(?:auto_approve|autoApprove)\s*=\s*True"
    r"|\bhuman_in_the_loop\s*=\s*False"
    r"|\ballow_dangerous_requests\s*=\s*True"
    r"|\bconfirm_before_action\s*=\s*False",
    re.IGNORECASE,
)

# Broad filesystem tools — MEDIUM
_FILESYSTEM_TOOLS = re.compile(
    r"\b(FileManagementToolkit|WriteFileTool|FileTool|DeleteFileTool)\s*\(",
)

# Broad / permissive agent descriptions that suggest no allowlist — INFO
# e.g. description="You can use any tool", "execute any", "run any command"
_BROAD_DESCRIPTION = re.compile(
    r'(?:description|desc)\s*=\s*["\'].*?'
    r'(?:any\s+tool|any\s+command|any\s+function|execute\s+any|run\s+any|all\s+tools)',
    re.IGNORECASE,
)

# Generic agent loop with no explicit allowlist check — INFO
# Detects tool invocation patterns from LLM JSON that lack an allowlist guard.
# e.g. tool_name = response["tool_call"]["name"] followed by direct execution
_AGENT_LOOP_EXEC = re.compile(
    r'(?:tool|function|action)\s*=\s*(?:\w+\[.+?\]|\w+\.get\s*\()',
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Fix suggestions
# ---------------------------------------------------------------------------

_FIX_DYNAMIC_DISPATCH = (
    "Never call globals()[name]() or eval(name) with LLM-provided function names. "
    "Use an explicit allowlist: `ALLOWED = {'func_a': func_a}; ALLOWED[name]()`. "
    "Validate and restrict the callable set strictly."
)
_FIX_WILDCARD = (
    "Replace wildcard tool access (tools=['*']) with an explicit allowlist of safe tools. "
    "Apply the principle of least privilege — only expose the minimum tools an agent needs."
)
_FIX_DANGEROUS_TOOL = (
    "Avoid granting LLM agents access to shell execution or REPL tools unless strictly "
    "necessary. Prefer purpose-built, restricted tools and apply sandboxing."
)
_FIX_GETATTR = (
    "Never dispatch function calls with LLM-provided names via getattr(). "
    "Validate the name against an explicit allowlist before calling: "
    "`if name in ALLOWED_FUNCTIONS: getattr(obj, name)()`."
)
_FIX_APPROVAL = (
    "Do not disable human-in-the-loop approval gates for LLM agents. "
    "Require explicit human confirmation for high-impact or irreversible actions."
)
_FIX_FILESYSTEM = (
    "Restrict filesystem tools to a specific directory scope. "
    "Avoid granting LLM agents broad write/delete access; "
    "scope FileManagementToolkit to a sandboxed directory."
)
_FIX_BROAD_DESC = (
    "Provide an explicit tool allowlist to the agent instead of permissive descriptions. "
    "Restrict agent capabilities to the minimum required for the task."
)
_FIX_AGENT_LOOP = (
    "Validate the tool or function name returned by the LLM against an explicit allowlist "
    "before dispatching. Never execute LLM-chosen function names without validation."
)


def check_excessive_agency(
    filepath: str, content: str, strict: bool = False
) -> list[dict]:
    """LLM08: Detect overly broad permissions granted to LLM agents."""
    findings: list[dict] = []
    lines = content.splitlines()

    for i, line in enumerate(lines):
        stripped = line.strip()
        # Skip comment-only lines
        if stripped.startswith("#"):
            continue

        # --- CRITICAL: globals() dynamic dispatch ---
        if _GLOBALS_DISPATCH.search(line):
            findings.append(
                {
                    "rule_id": RULE_ID,
                    "rule_name": RULE_NAME,
                    "severity": "CRITICAL",
                    "filepath": str(filepath),
                    "line": i + 1,
                    "description": (
                        "globals() is used to dynamically dispatch function calls. "
                        "If the function name originates from an LLM tool call, an "
                        "attacker can invoke any function in the module."
                    ),
                    "fix_suggestion": _FIX_DYNAMIC_DISPATCH,
                }
            )
            continue

        # --- HIGH: wildcard tool access ---
        if _WILDCARD_TOOLS.search(line):
            findings.append(
                {
                    "rule_id": RULE_ID,
                    "rule_name": RULE_NAME,
                    "severity": "HIGH",
                    "filepath": str(filepath),
                    "line": i + 1,
                    "description": (
                        "Wildcard tool access (tools=['*']) grants the LLM agent "
                        "unrestricted access to all available tools, violating the "
                        "principle of least privilege."
                    ),
                    "fix_suggestion": _FIX_WILDCARD,
                }
            )
            continue

        # --- HIGH: dangerous tool classes ---
        m = _DANGEROUS_TOOLS.search(line)
        if m:
            findings.append(
                {
                    "rule_id": RULE_ID,
                    "rule_name": RULE_NAME,
                    "severity": "HIGH",
                    "filepath": str(filepath),
                    "line": i + 1,
                    "description": (
                        f"{m.group(1)}() grants the LLM agent shell or code "
                        "execution capability, which enables arbitrary OS-level "
                        "command execution."
                    ),
                    "fix_suggestion": _FIX_DANGEROUS_TOOL,
                }
            )
            continue

        # --- HIGH: getattr dynamic dispatch ---
        m = _GETATTR_DISPATCH.search(line)
        if m:
            findings.append(
                {
                    "rule_id": RULE_ID,
                    "rule_name": RULE_NAME,
                    "severity": "HIGH",
                    "filepath": str(filepath),
                    "line": i + 1,
                    "description": (
                        f"getattr() is called with a dynamic name '{m.group(1)}'. "
                        "If this name originates from an LLM response, the agent "
                        "can be directed to call arbitrary functions."
                    ),
                    "fix_suggestion": _FIX_GETATTR,
                }
            )
            continue

        # --- MEDIUM: disabled approval gates ---
        if _DISABLED_APPROVAL.search(line):
            findings.append(
                {
                    "rule_id": RULE_ID,
                    "rule_name": RULE_NAME,
                    "severity": "MEDIUM",
                    "filepath": str(filepath),
                    "line": i + 1,
                    "description": (
                        "Human-in-the-loop approval is disabled. LLM agents can "
                        "take high-impact actions without human oversight, increasing "
                        "the risk of unintended consequences."
                    ),
                    "fix_suggestion": _FIX_APPROVAL,
                }
            )
            continue

        # --- MEDIUM: broad filesystem tools ---
        m = _FILESYSTEM_TOOLS.search(line)
        if m:
            findings.append(
                {
                    "rule_id": RULE_ID,
                    "rule_name": RULE_NAME,
                    "severity": "MEDIUM",
                    "filepath": str(filepath),
                    "line": i + 1,
                    "description": (
                        f"{m.group(1)}() provides LLM agents with broad filesystem "
                        "access. Without explicit directory scoping, the agent can "
                        "read, write, or delete arbitrary files."
                    ),
                    "fix_suggestion": _FIX_FILESYSTEM,
                }
            )
            continue

        # --- INFO / MEDIUM (strict): broad tool description ---
        if _BROAD_DESCRIPTION.search(line):
            severity = "MEDIUM" if strict else "INFO"
            findings.append(
                {
                    "rule_id": RULE_ID,
                    "rule_name": RULE_NAME,
                    "severity": severity,
                    "filepath": str(filepath),
                    "line": i + 1,
                    "description": (
                        "Agent tool description suggests unrestricted access "
                        "('any tool', 'any command'). This may indicate that no "
                        "explicit tool allowlist is enforced."
                    ),
                    "fix_suggestion": _FIX_BROAD_DESC,
                }
            )
            continue

        # --- INFO / MEDIUM (strict): agent loop without explicit allowlist ---
        if strict and _AGENT_LOOP_EXEC.search(line):
            findings.append(
                {
                    "rule_id": RULE_ID,
                    "rule_name": RULE_NAME,
                    "severity": "MEDIUM",
                    "filepath": str(filepath),
                    "line": i + 1,
                    "description": (
                        "Agent loop retrieves tool/function name from LLM response. "
                        "Ensure this name is validated against an explicit allowlist "
                        "before dispatching."
                    ),
                    "fix_suggestion": _FIX_AGENT_LOOP,
                }
            )
            continue

    return findings
