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
HIGH      subprocess.run(['powershell'/'bash'/'cmd'/'sh', ...]) — shell interpreter invocation
HIGH      getattr(module, llm_name)() — dynamic dispatch via getattr
MEDIUM    auto_approve=True / human_in_the_loop=False
LOW       FileManagementToolkit / WriteFileTool (capability concern, not confirmed exploit)
INFO      Broad tool description / no explicit allowlist (--strict → MEDIUM)
"""

import re

from llmarmor.messages import CATALOG, RULE_URLS

RULE_ID = "LLM08"
RULE_NAME = "Excessive Agency"
_REF = RULE_URLS[RULE_ID]

_GLOBALS_MSG = CATALOG[("LLM08", "globals_dispatch")]
_WILDCARD_MSG = CATALOG[("LLM08", "wildcard_tools")]
_DANG_TOOL_MSG = CATALOG[("LLM08", "dangerous_tool")]
_SUBPROC_MSG = CATALOG[("LLM08", "subprocess_shell")]
_GETATTR_MSG = CATALOG[("LLM08", "getattr_dispatch")]
_APPROVAL_MSG = CATALOG[("LLM08", "disabled_approval")]
_FS_MSG = CATALOG[("LLM08", "filesystem_tools")]
_BROAD_MSG = CATALOG[("LLM08", "broad_description")]
_LOOP_MSG = CATALOG[("LLM08", "agent_loop")]

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

# subprocess/os called with a shell interpreter executable — HIGH
# Matches: subprocess.run(['powershell', ...]), subprocess.Popen(['bash', ...]),
#          subprocess.call('sh', ...), os.system('cmd ...'), etc.
_SUBPROCESS_SHELL_EXEC = re.compile(
    r"\bsubprocess\.\w+\s*\(\s*\[?\s*['\"](?:powershell|bash|sh|cmd|zsh|fish|pwsh)['\"]",
    re.IGNORECASE,
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

_FIX_DYNAMIC_DISPATCH = _GLOBALS_MSG.fix
_FIX_WILDCARD = _WILDCARD_MSG.fix
_FIX_DANGEROUS_TOOL = _DANG_TOOL_MSG.fix
_FIX_SUBPROCESS_SHELL_EXEC = _SUBPROC_MSG.fix
_FIX_GETATTR = _GETATTR_MSG.fix
_FIX_APPROVAL = _APPROVAL_MSG.fix
_FIX_FILESYSTEM = _FS_MSG.fix
_FIX_BROAD_DESC = _BROAD_MSG.fix
_FIX_AGENT_LOOP = _LOOP_MSG.fix


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
                    "why": _GLOBALS_MSG.why,
                    "reference_url": _REF,
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
                    "why": _WILDCARD_MSG.why,
                    "reference_url": _REF,
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
                    "why": _DANG_TOOL_MSG.why,
                    "reference_url": _REF,
                }
            )
            continue

        # --- HIGH: subprocess with shell interpreter executable ---
        if _SUBPROCESS_SHELL_EXEC.search(line):
            findings.append(
                {
                    "rule_id": RULE_ID,
                    "rule_name": RULE_NAME,
                    "severity": "HIGH",
                    "filepath": str(filepath),
                    "line": i + 1,
                    "description": (
                        "subprocess is called with a shell interpreter "
                        "(powershell, bash, cmd, sh, etc.) as the first argument. "
                        "If this code is reachable from an LLM agent tool, it grants "
                        "OS-level command execution capability."
                    ),
                    "fix_suggestion": _FIX_SUBPROCESS_SHELL_EXEC,
                    "why": _SUBPROC_MSG.why,
                    "reference_url": _REF,
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
                    "why": _GETATTR_MSG.why,
                    "reference_url": _REF,
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
                    "why": _APPROVAL_MSG.why,
                    "reference_url": _REF,
                }
            )
            continue

        # --- LOW: broad filesystem tools ---
        # Presence of these tools alone is a "review this" signal, not a confirmed
        # vulnerability like auto_approve=True. Downgraded from MEDIUM to LOW.
        m = _FILESYSTEM_TOOLS.search(line)
        if m:
            findings.append(
                {
                    "rule_id": RULE_ID,
                    "rule_name": RULE_NAME,
                    "severity": "LOW",
                    "filepath": str(filepath),
                    "line": i + 1,
                    "description": (
                        f"{m.group(1)}() provides LLM agents with broad filesystem "
                        "access. Without explicit directory scoping, the agent can "
                        "read, write, or delete arbitrary files."
                    ),
                    "fix_suggestion": _FIX_FILESYSTEM,
                    "why": _FS_MSG.why,
                    "reference_url": _REF,
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
                    "why": _BROAD_MSG.why,
                    "reference_url": _REF,
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
                    "why": _LOOP_MSG.why,
                    "reference_url": _REF,
                }
            )
            continue

    return findings
