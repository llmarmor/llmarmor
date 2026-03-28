"""AST-based static analysis to complement LLM Armor's regex rules.

This module provides supplementary findings for patterns that regex cannot
detect reliably (variable aliasing / taint propagation, role-aware dict
detection, ``str.join`` injection) and resolves ``**config`` spreads so that
an LLM API call supplying ``max_tokens`` via a spread dict is not flagged.

Public API::

    result = analyze(filepath, content)
    result["findings"]   # list[dict] — additional findings (same schema as regex rules)
    result["cleared"]    # set[tuple[int,str]] — (1-based line, rule_id) pairs where
                         # the corresponding regex finding should be suppressed

On ``SyntaxError`` (or any other parse failure), both values are empty.
"""

import ast

_LLM01 = "LLM01"
_LLM07 = "LLM07"

# Variables explicitly named as user-controlled input (must match _USER_INPUT_ALT
# in llm01_prompt_injection.py so taint seeds are consistent).
_USER_INPUT_NAMES: frozenset[str] = frozenset(
    [
        "user_input",
        "user_message",
        "user_query",
        "user_text",
        "user_prompt",
        "user_data",
        "user_content",
        "user_request",
        "human_input",
        "human_message",
    ]
)

# Fragments that identify system-prompt variable names (case-insensitive).
_SYSTEM_PROMPT_FRAGMENTS: frozenset[str] = frozenset(
    ["system_prompt", "system_message", "sys_prompt"]
)

# LLM API method suffixes recognised by the LLM10 regex rule.
_LLM10_METHODS: frozenset[str] = frozenset(
    [
        "chat.completions.create",
        "completions.create",
        "messages.create",
        "chat.complete",
        "completion",
    ]
)

_MIN_SYSTEM_PROMPT_LEN = 100


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def analyze(filepath: str, content: str) -> dict:
    """Run AST-based checks on *content*.

    Returns a dict with two keys:

    ``findings``
        A list of finding dicts (same schema as the regex-rule functions).
        These represent patterns not caught by the regex rules (e.g. aliased
        user-input variables, role-aware dict detection, ``str.join`` injection,
        and multi-line system prompts built from string concatenation).

    ``cleared``
        A ``set`` of ``(line, rule_id)`` tuples.  The scanner should suppress
        any regex finding whose ``(line, rule_id)`` is in this set to avoid
        double-reporting the same issue, or to suppress false positives where
        the AST has confirmed the pattern is safe (e.g. ``**config`` spread
        that includes ``max_tokens``).

    If *content* cannot be parsed as valid Python the function returns
    ``{"findings": [], "cleared": set()}`` so callers never need to handle
    exceptions.
    """
    try:
        tree = ast.parse(content, filename=str(filepath))
    except SyntaxError:
        return {"findings": [], "cleared": set()}

    visitor = _Analyzer(str(filepath))
    visitor.visit(tree)
    return {"findings": visitor.findings, "cleared": visitor.cleared}


# ---------------------------------------------------------------------------
# AST visitor
# ---------------------------------------------------------------------------


class _Analyzer(ast.NodeVisitor):
    """Single-pass AST visitor that accumulates findings and cleared-line pairs."""

    def __init__(self, filepath: str) -> None:
        self.filepath = filepath
        self.findings: list[dict] = []
        # (1-based line, rule_id) pairs — matching regex findings are suppressed.
        self.cleared: set[tuple[int, str]] = set()

        # Forward taint tracking: set of variable names known to carry user input.
        self._tainted: set[str] = set()
        # Config-dict tracking: var name → set of string keys in its dict literal.
        self._config_dicts: dict[str, set[str]] = {}

    # ------------------------------------------------------------------
    # Assignments — taint propagation, config-dict tracking, LLM07
    # ------------------------------------------------------------------

    def visit_Assign(self, node: ast.Assign) -> None:  # noqa: N802
        for target in node.targets:
            if not isinstance(target, ast.Name):
                continue
            name = target.id
            rhs = node.value

            # Taint propagation: msg = user_input  →  msg is tainted
            if isinstance(rhs, ast.Name):
                if rhs.id in _USER_INPUT_NAMES or rhs.id in self._tainted:
                    self._tainted.add(name)

            # Config-dict tracking for LLM10 **config suppression.
            if isinstance(rhs, ast.Dict):
                str_keys: set[str] = {
                    k.value
                    for k in rhs.keys
                    if isinstance(k, ast.Constant) and isinstance(k.value, str)
                }
                self._config_dicts[name] = str_keys

            # LLM07: system-prompt variable assigned a long hardcoded string.
            # This catches multi-line implicit concatenation that the single-line
            # regex cannot see (e.g. SYSTEM_PROMPT = ("part1 " "part2 " ...)).
            if _is_system_prompt_var(name):
                extracted = _concat_string(rhs)
                if extracted is not None and len(extracted) > _MIN_SYSTEM_PROMPT_LEN:
                    self.findings.append(
                        _finding(
                            _LLM07,
                            "System Prompt Leakage",
                            "INFO",
                            self.filepath,
                            node.lineno,
                            (
                                "Hardcoded system prompt detected in source code. "
                                "In server-side code this is often acceptable; flag "
                                "if the prompt contains sensitive business logic or "
                                "is bundled in client-facing or public code."
                            ),
                            (
                                "Move system prompts to environment variables or a "
                                "secure config file."
                            ),
                        )
                    )
                    # Suppress the regex LLM07 finding on the same line to avoid
                    # emitting a duplicate finding for the same pattern.
                    self.cleared.add((node.lineno, _LLM07))

        self.generic_visit(node)

    # ------------------------------------------------------------------
    # Dict literals — role-aware LLM01 detection
    # ------------------------------------------------------------------

    def visit_Dict(self, node: ast.Dict) -> None:  # noqa: N802
        if _is_message_dict(node):
            role_node = _dict_value(node, "role")
            content_node = _dict_value(node, "content")

            if isinstance(role_node, ast.Constant) and isinstance(role_node.value, str):
                role = role_node.value

                if role in ("system", "assistant") and content_node is not None:
                    if self._is_tainted_node(content_node):
                        # Dangerous: user input reaches a system/assistant message.
                        self.findings.append(
                            _finding(
                                _LLM01,
                                "Prompt Injection",
                                "CRITICAL",
                                self.filepath,
                                node.lineno,
                                (
                                    "User input is interpolated into a system or assistant "
                                    "role message. This may enable prompt injection attacks. "
                                    "Pass user input only as a separate 'role: user' message "
                                    "without string interpolation."
                                ),
                                (
                                    "Avoid interpolating user input into system prompts. "
                                    "Pass user input as a separate 'role: user' message."
                                ),
                            )
                        )
                        # Suppress the regex LLM01 finding at this line (same issue).
                        self.cleared.add((node.lineno, _LLM01))

                elif role == "user" and content_node is not None:
                    # Safe pattern: user input as standalone value in a user-role message.
                    # Only suppress the regex false positive when content is a bare name
                    # (no f-string wrapping).  An f-string in a user-role message may
                    # still be flagged by the regex rule intentionally.
                    if isinstance(content_node, ast.Name) and self._is_tainted_node(
                        content_node
                    ):
                        self.cleared.add((node.lineno, _LLM01))

        self.generic_visit(node)

    # ------------------------------------------------------------------
    # Call expressions — str.join injection and LLM10 **config resolution
    # ------------------------------------------------------------------

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        # LLM01: str.join() with a tainted element in the sequence argument.
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "join"
            and node.args
            and isinstance(node.args[0], (ast.List, ast.Tuple))
        ):
            for elt in node.args[0].elts:
                if self._is_tainted_node(elt):
                    self.findings.append(
                        _finding(
                            _LLM01,
                            "Prompt Injection",
                            "CRITICAL",
                            self.filepath,
                            node.lineno,
                            (
                                "User input is joined into a string via str.join(). "
                                "If this string is used as an LLM prompt, it may enable "
                                "prompt injection attacks. Pass user input as a separate "
                                "'role: user' message instead."
                            ),
                            (
                                "Avoid joining user input into prompt strings. "
                                "Pass user input as a separate 'role: user' message."
                            ),
                        )
                    )
                    break  # one finding per join call is enough

        # LLM10: resolve **config spread to suppress false positives where
        # max_tokens is supplied through a known config dict.
        method = _attr_chain(node.func)
        if _is_llm10_call(method):
            self._handle_llm10(node)

        self.generic_visit(node)

    def _handle_llm10(self, node: ast.Call) -> None:
        """Clear LLM10 on *node*'s line when max_tokens is provably set."""
        # Explicit keyword argument: max_tokens=... or max_output_tokens=...
        for kw in node.keywords:
            if kw.arg in ("max_tokens", "max_output_tokens"):
                self.cleared.add((node.lineno, "LLM10"))
                return

        # **config spread where the config dict contains max_tokens.
        for kw in node.keywords:
            if kw.arg is None and isinstance(kw.value, ast.Name):
                keys = self._config_dicts.get(kw.value.id, set())
                if "max_tokens" in keys or "max_output_tokens" in keys:
                    self.cleared.add((node.lineno, "LLM10"))
                    return

    # ------------------------------------------------------------------
    # Taint helper
    # ------------------------------------------------------------------

    def _is_tainted_node(self, node: ast.expr) -> bool:
        """Return True if *node* references a known user-input or tainted variable."""
        if isinstance(node, ast.Name):
            return node.id in _USER_INPUT_NAMES or node.id in self._tainted
        if isinstance(node, ast.JoinedStr):
            # Walk the f-string for any tainted Name reference.
            for child in ast.walk(node):
                if isinstance(child, ast.Name):
                    if child.id in _USER_INPUT_NAMES or child.id in self._tainted:
                        return True
        return False


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _is_system_prompt_var(name: str) -> bool:
    name_lower = name.lower()
    return any(frag in name_lower for frag in _SYSTEM_PROMPT_FRAGMENTS)


def _is_message_dict(node: ast.Dict) -> bool:
    """Return True if the dict has both ``"role"`` and ``"content"`` string keys."""
    str_keys = {
        k.value
        for k in node.keys
        if isinstance(k, ast.Constant) and isinstance(k.value, str)
    }
    return "role" in str_keys and "content" in str_keys


def _dict_value(node: ast.Dict, key: str) -> ast.expr | None:
    for k, v in zip(node.keys, node.values):
        if isinstance(k, ast.Constant) and k.value == key:
            return v
    return None


def _concat_string(node: ast.expr) -> str | None:
    """Recursively extract a plain string from constants and ``BinOp(Add)`` chains.

    Python's parser concatenates adjacent string literals at parse time
    (``"a" "b"`` → a single ``ast.Constant``), so implicit multi-line
    concatenation inside parentheses arrives here as a single constant.
    Explicit ``+`` chains are handled recursively.

    Returns ``None`` if the expression is not purely string constants.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _concat_string(node.left)
        right = _concat_string(node.right)
        if left is not None and right is not None:
            return left + right
    return None


def _attr_chain(node: ast.expr) -> str:
    """Return the dot-joined attribute chain for a call's ``func`` node."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _attr_chain(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _is_llm10_call(method: str) -> bool:
    return any(method.endswith(m) for m in _LLM10_METHODS) and "images" not in method


def _finding(
    rule_id: str,
    rule_name: str,
    severity: str,
    filepath: str,
    line: int,
    description: str,
    fix_suggestion: str,
) -> dict:
    return {
        "rule_id": rule_id,
        "rule_name": rule_name,
        "severity": severity,
        "filepath": filepath,
        "line": line,
        "description": description,
        "fix_suggestion": fix_suggestion,
    }
