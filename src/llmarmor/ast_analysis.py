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

    tainted = collect_tainted(tree)
    # set[str] — variable names whose values are user-controlled

Taint seeding (source-based, not name-based):
    A variable is tainted only if it is assigned from one of these sources:
    - ``request.json``, ``request.form``, ``request.args``, ``request.get_json()`` (HTTP)
    - ``input()`` (built-in prompt)
    - ``sys.argv[...]`` (command-line arguments)
    - ``websocket.receive()`` / ``websocket.recv()`` (WebSocket messages)
    - A function parameter (any argument of a ``def`` statement)
    - An alias of another already-tainted variable

    The following are explicitly NOT taint sources:
    ``config.get()``, ``os.environ``, ``os.getenv()``, database calls,
    settings attributes, and string literals.

On ``SyntaxError`` (or any other parse failure), both values are empty.
"""

import ast

_LLM01 = "LLM01"
_LLM07 = "LLM07"

# Root receiver names for objects that are considered safe config/DB sources.
# Assignments like ``prompt = config.get("x")`` or ``prompt = settings.DEFAULT``
# are NOT treated as user-controlled.
_SAFE_RECEIVER_PREFIXES: frozenset[str] = frozenset(
    [
        "config",
        "cfg",
        "conf",
        "settings",
        "db",
        "database",
        "dao",
        "repo",
        "repository",
        "cache",
    ]
)

# Root receiver names for HTTP request objects.
# Assignments like ``data = request.json["prompt"]`` ARE user-controlled.
_REQUEST_RECEIVER_PREFIXES: frozenset[str] = frozenset(["request", "req"])

# Built-in / stdlib call names whose return value is user-controlled.
# ``input()`` reads from stdin; ``sys.argv`` is handled via subscript detection.
_USER_DATA_CALL_NAMES: frozenset[str] = frozenset(["input"])

# Method attribute names whose return value is user-controlled regardless of receiver.
# Covers ``websocket.receive()`` and ``websocket.recv()``.
_USER_DATA_CALL_ATTRS: frozenset[str] = frozenset(["receive", "recv"])

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
# Public entry points
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


def collect_tainted(tree: ast.AST) -> set[str]:
    """Return the set of variable names that carry user-controlled data in *tree*.

    Taint is seeded from explicit user-data *sources* (not variable names):

    * ``request.json``, ``request.form``, ``request.args``, ``request.get_json()``
      — HTTP request objects
    * ``input()`` — built-in stdin prompt
    * ``sys.argv[...]`` — command-line argument vector
    * ``websocket.receive()`` / ``websocket.recv()`` — WebSocket messages
    * Any argument of a ``def`` statement — function parameters are treated as
      external inputs at the boundary of the function

    Taint propagates via direct alias assignments (``alias = tainted_var``).
    It does NOT propagate through arbitrary function calls, so
    ``validated = sanitize(user_input)`` does *not* taint ``validated``.

    Variables assigned from ``config.get()``, ``os.environ``, ``os.getenv()``,
    database calls, settings attributes, and string literals are NOT tainted.
    """
    collector = _TaintCollector()
    collector.visit(tree)
    return collector.tainted


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
        # Taint is seeded from actual user-data *sources* (request, input(), sys.argv,
        # websocket.receive(), function parameters), not from variable names.
        self._tainted: set[str] = set()
        # Config-dict tracking: var name → set of string keys in its dict literal.
        self._config_dicts: dict[str, set[str]] = {}

    # ------------------------------------------------------------------
    # Function definitions — seed parameters as tainted sources
    # ------------------------------------------------------------------

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        """Treat every function parameter as a tainted (user-controlled) source.

        Function boundaries are where external data enters the program.
        All parameters — positional, keyword-only, *args, and **kwargs — are
        treated as potentially user-controlled.
        """
        all_args = (
            node.args.posonlyargs
            + node.args.args
            + node.args.kwonlyargs
        )
        for arg in all_args:
            self._tainted.add(arg.arg)
        if node.args.vararg:
            self._tainted.add(node.args.vararg.arg)
        if node.args.kwarg:
            self._tainted.add(node.args.kwarg.arg)
        self.generic_visit(node)

    # Async functions share the same taint-seeding logic.
    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    # ------------------------------------------------------------------
    # Assignments — taint propagation, config-dict tracking, LLM07
    # ------------------------------------------------------------------

    def visit_Assign(self, node: ast.Assign) -> None:  # noqa: N802
        for target in node.targets:
            if not isinstance(target, ast.Name):
                continue
            name = target.id
            rhs = node.value

            # Source-based taint seeding: taint the variable when it is
            # assigned directly from a user-controlled data source.
            if _is_user_data_source_rhs(rhs):
                self._tainted.add(name)
            # Taint propagation: alias = tainted_var  →  alias is tainted.
            # Does NOT propagate through function calls to avoid false positives
            # from sanitizer patterns like ``clean = sanitize(user_input)``.
            elif isinstance(rhs, ast.Name) and rhs.id in self._tainted:
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
                    # Only flag when there is actual string *interpolation* of tainted
                    # data (f-string or concatenation).  A plain variable reference like
                    # ``{"role": "system", "content": system_var}`` is the standard, safe
                    # way to pass a pre-built prompt and must NOT be flagged regardless of
                    # whether the variable happens to be in the tainted set.
                    if self._is_tainted_interpolation(content_node):
                        # Dangerous: tainted data is interpolated into a system/assistant
                        # message via an f-string or concatenation expression.
                        self.findings.append(
                            _finding(
                                _LLM01,
                                "Prompt Injection",
                                "CRITICAL",
                                self.filepath,
                                node.lineno,
                                (
                                    "User input is interpolated into a system or assistant "
                                    "role message via string interpolation (f-string or "
                                    "concatenation). This may enable prompt injection attacks. "
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
                    # User-role messages with a plain variable reference are safe:
                    # ``{"role": "user", "content": user_var}`` is the standard pattern
                    # and should not produce any regex false positive.
                    # Only suppress the regex finding when content is a bare name reference
                    # (not an f-string).  An f-string in a user-role message may still be
                    # flagged by the regex rule as a suspicious pattern.
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
        """Return True if *node* references a tainted (user-controlled) variable."""
        if isinstance(node, ast.Name):
            return node.id in self._tainted
        if isinstance(node, ast.JoinedStr):
            # Walk the f-string for any tainted Name reference.
            for child in ast.walk(node):
                if isinstance(child, ast.Name):
                    if child.id in self._tainted:
                        return True
        return False

    def _is_tainted_interpolation(self, node: ast.expr) -> bool:
        """Return True only when *node* is a string *interpolation* that uses tainted data.

        A plain ``ast.Name`` reference (bare variable) is intentionally excluded —
        ``{"role": "system", "content": system_var}`` is the standard, safe way to
        pass a pre-built prompt and should never be flagged on its own.

        Recognised interpolation forms:
        * ``ast.JoinedStr`` — f-strings (e.g. ``f"Help: {user_input}"``).
        * ``ast.BinOp`` with ``ast.Add`` — string concatenation
          (e.g. ``"Help: " + user_input``).  The entire BinOp subtree is walked so
          that multi-operand chains like ``"a" + b + c + d`` are handled correctly
          regardless of nesting depth.
        """
        if isinstance(node, ast.JoinedStr):
            for child in ast.walk(node):
                if isinstance(child, ast.Name) and child.id in self._tainted:
                    return True
            return False
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            for child in ast.walk(node):
                if isinstance(child, ast.Name) and child.id in self._tainted:
                    return True
            return False
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


def _receiver_root(node: ast.expr) -> str:
    """Return the root Name identifier of an attribute/subscript chain.

    Examples::

        os.environ["KEY"]   → "os"
        request.form.get()  → "request"
        config.get()        → "config"
    """
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return _receiver_root(node.value)
    if isinstance(node, ast.Subscript):
        return _receiver_root(node.value)
    return ""


def _is_user_data_source_rhs(node: ast.expr) -> bool:
    """Return True if *node* is a direct user-controlled data source.

    Recognised sources:

    * ``input()`` — built-in stdin prompt
    * ``websocket.receive()`` / ``websocket.recv()`` (or any receiver)
    * ``request.json[...]``, ``request.form.get(...)``, ``req.args[...]``
      — HTTP request objects (``request``/``req`` receiver prefixes)
    * ``sys.argv[...]`` — command-line argument subscript

    Notably excluded (not user-controlled):
    ``config.get()``, ``os.environ``, ``os.getenv()``, DB calls,
    settings attributes, and string literals.
    """
    if isinstance(node, ast.Call):
        func = node.func
        # Bare function call: input()
        if isinstance(func, ast.Name) and func.id in _USER_DATA_CALL_NAMES:
            return True
        # Method call: websocket.receive(), ws.recv(), …
        if isinstance(func, ast.Attribute) and func.attr in _USER_DATA_CALL_ATTRS:
            return True
        # HTTP request call: request.form.get(), request.get_json(), …
        if _receiver_root(func) in _REQUEST_RECEIVER_PREFIXES:
            return True

    if isinstance(node, ast.Subscript):
        # HTTP request subscript: request.json["key"], request.form["key"]
        if _receiver_root(node.value) in _REQUEST_RECEIVER_PREFIXES:
            return True
        # sys.argv[n]
        value = node.value
        if isinstance(value, ast.Attribute):
            root = _receiver_root(value.value)
            if root == "sys" and value.attr == "argv":
                return True

    # Bare attribute: request.json, request.form (assigned as a whole object)
    if isinstance(node, ast.Attribute):
        if _receiver_root(node.value) in _REQUEST_RECEIVER_PREFIXES:
            return True

    return False


def _is_request_rhs(node: ast.expr) -> bool:
    """Return True if *node* originates from an HTTP request (user-controlled).

    Matches patterns such as ``request.json["prompt"]``,
    ``request.form.get("prompt")``, or ``req.args["q"]``.

    .. deprecated:: 0.2.0
        Use :func:`_is_user_data_source_rhs` for all new code; this helper is
        kept for internal backward compatibility and may be removed in a future
        version.
    """
    if isinstance(node, ast.Subscript):
        if _receiver_root(node.value) in _REQUEST_RECEIVER_PREFIXES:
            return True
    if isinstance(node, ast.Call):
        if _receiver_root(node.func) in _REQUEST_RECEIVER_PREFIXES:
            return True
    if isinstance(node, ast.Attribute):
        if _receiver_root(node.value) in _REQUEST_RECEIVER_PREFIXES:
            return True
    return False


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


# ---------------------------------------------------------------------------
# _TaintCollector — backing implementation for collect_tainted()
# ---------------------------------------------------------------------------


class _TaintCollector(ast.NodeVisitor):
    """Lightweight AST visitor that collects tainted variable names.

    Used by :func:`collect_tainted` to perform a pre-pass over the module
    and return the set of variable names that originate from user-controlled
    sources.  The ``_Analyzer`` class performs the same collection inline
    during its single-pass analysis visit.
    """

    def __init__(self) -> None:
        self.tainted: set[str] = set()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        all_args = (
            node.args.posonlyargs
            + node.args.args
            + node.args.kwonlyargs
        )
        for arg in all_args:
            self.tainted.add(arg.arg)
        if node.args.vararg:
            self.tainted.add(node.args.vararg.arg)
        if node.args.kwarg:
            self.tainted.add(node.args.kwarg.arg)
        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def visit_Assign(self, node: ast.Assign) -> None:  # noqa: N802
        for target in node.targets:
            if not isinstance(target, ast.Name):
                continue
            rhs = node.value
            if _is_user_data_source_rhs(rhs):
                self.tainted.add(target.id)
            elif isinstance(rhs, ast.Name) and rhs.id in self.tainted:
                self.tainted.add(target.id)
        self.generic_visit(node)
