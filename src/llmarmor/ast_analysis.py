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
from pathlib import Path as _Path

_LLM01 = "LLM01"
_LLM05 = "LLM05"
_LLM07 = "LLM07"
_LLM08 = "LLM08"

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
# LLM05 — Improper Output Handling: dangerous sink sets
# ---------------------------------------------------------------------------

# Built-in code-execution sinks: eval / exec / compile
_DANGEROUS_EXEC_SINKS: frozenset[str] = frozenset(["eval", "exec", "compile"])

# Shell-execution sinks (method chains resolved to bare attribute name)
_DANGEROUS_SHELL_SINKS: frozenset[str] = frozenset(
    [
        "subprocess.run",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.Popen",
        "os.system",
        "os.popen",
    ]
)

# HTML / XSS rendering sinks
_DANGEROUS_HTML_SINKS: frozenset[str] = frozenset(
    ["Markup", "render_template_string", "mark_safe"]
)

# Path segments (directory or file stem, case-insensitive) that indicate an
# eval / test / grading harness.  When detected, LLM01 findings are downgraded
# to INFO severity to reduce noise in legitimate evaluation code.
_EVAL_PATH_SEGMENTS: frozenset[str] = frozenset(
    [
        "eval",
        "evals",
        "test",
        "tests",
        "grader",
        "graders",
        "benchmark",
        "benchmarks",
        "fixture",
        "fixtures",
    ]
)

# Top-level import names whose presence suggests an eval / test harness.
_EVAL_IMPORT_NAMES: frozenset[str] = frozenset(
    ["pytest", "unittest", "deepeval", "ragas", "promptfoo"]
)

# Fragments matched (case-insensitive) against function / class names to
# identify eval / test / grading contexts.
_EVAL_NAME_FRAGMENTS: frozenset[str] = frozenset(
    ["eval", "grade", "grader", "judge", "benchmark", "test"]
)


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------


def analyze(filepath: str, content: str, strict: bool = False) -> dict:
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

    When *strict* is ``True``, additional borderline patterns are flagged:

    * A plain tainted variable used as the ``content`` of a system/assistant
      role message (MEDIUM severity).
    * A plain tainted variable used as the ``content`` of a user role message
      (LOW severity).
    * Hardcoded system prompts are promoted from INFO to MEDIUM severity with
      more detailed messaging about exposure risk.
    """
    try:
        tree = ast.parse(content, filename=str(filepath))
    except SyntaxError:
        return {"findings": [], "cleared": set()}

    visitor = _Analyzer(str(filepath), strict=strict)
    visitor.visit(tree)

    findings = visitor.findings
    if _is_eval_context(filepath, tree):
        findings = [
            {
                **f,
                "severity": "INFO",
                "description": f"[eval context] {f['description']}",
            }
            if f["rule_id"] == _LLM01
            else f
            for f in findings
        ]

    return {"findings": findings, "cleared": visitor.cleared}


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

    def __init__(self, filepath: str, strict: bool = False) -> None:
        self.filepath = filepath
        self.strict = strict
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
                    # Use a single consistent description regardless of mode so
                    # that grouped output does not split the same rule into two
                    # separate sections (one per description variant).  Only the
                    # severity differs between normal (INFO) and strict (MEDIUM).
                    severity = "MEDIUM" if self.strict else "INFO"
                    description = (
                        "System prompt is hardcoded in source code. "
                        "If this code is published (open source, client-side bundle, "
                        "shared package), the prompt contents will be visible to users. "
                        "This may leak proprietary instructions, internal tool descriptions, "
                        "or behavioral constraints that could be exploited. "
                        "Move to environment variables or a secure config service."
                    )
                    self.findings.append(
                        _finding(
                            _LLM07,
                            "System Prompt Leakage",
                            severity,
                            self.filepath,
                            node.lineno,
                            description,
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
                    # A plain variable reference (ast.Name) is not string
                    # interpolation — the content arrives pre-formed and there is
                    # no injection of instructions mixed with data.  Only flag
                    # when the content involves string construction: f-strings
                    # (JoinedStr), concatenation (BinOp + Add), or .format()
                    # calls that embed tainted data.
                    if not isinstance(content_node, ast.Name) and self._is_tainted_node(
                        content_node
                    ):
                        # Dangerous: tainted input is interpolated into a
                        # system or assistant role message.
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

                    elif isinstance(content_node, ast.Name) and self._is_tainted_node(
                        content_node
                    ):
                        if self.strict:
                            # Strict mode: plain tainted variable as system/assistant content.
                            # The user controls the entire message content — flag as MEDIUM.
                            self.findings.append(
                                _finding(
                                    _LLM01,
                                    "Prompt Injection",
                                    "MEDIUM",
                                    self.filepath,
                                    node.lineno,
                                    (
                                        f"Tainted variable passed directly as {role} message content. "
                                        "If the variable contains unsanitized user input, the user "
                                        "controls the entire system instruction."
                                    ),
                                    (
                                        "Validate and sanitize the variable before using it as "
                                        "system message content, or use a fixed system prompt."
                                    ),
                                )
                            )
                        else:
                            # Normal mode: plain variable assignment is not string interpolation,
                            # so no injection vector exists.  Emit INFO so --verbose can show it
                            # and --strict can promote it.
                            self.findings.append(
                                _finding(
                                    _LLM01,
                                    "Prompt Injection",
                                    "INFO",
                                    self.filepath,
                                    node.lineno,
                                    (
                                        f"Tainted variable passed directly as {role} message content "
                                        "(plain assignment, not interpolated). Consider validating "
                                        "or sanitizing the value before use."
                                    ),
                                    (
                                        "Validate and sanitize the variable before using it as "
                                        "system message content, or use a fixed system prompt."
                                    ),
                                )
                            )

                elif role == "user" and content_node is not None:
                    if isinstance(content_node, ast.Name) and self._is_tainted_node(
                        content_node
                    ):
                        if self.strict:
                            # Strict mode: flag plain tainted variable in user role too.
                            self.findings.append(
                                _finding(
                                    _LLM01,
                                    "Prompt Injection",
                                    "MEDIUM",
                                    self.filepath,
                                    node.lineno,
                                    (
                                        "User input is passed directly without sanitization. "
                                        "Consider input validation and length limits."
                                    ),
                                    (
                                        "Validate user input before passing it to the LLM. "
                                        "Apply length limits and content filtering."
                                    ),
                                )
                            )
                        else:
                            # Normal mode: plain user-role assignment is safe (no injection
                            # vector), but emit INFO so --verbose can surface it.
                            # Suppress any regex false-positive for this line.
                            self.cleared.add((node.lineno, _LLM01))
                            self.findings.append(
                                _finding(
                                    _LLM01,
                                    "Prompt Injection",
                                    "INFO",
                                    self.filepath,
                                    node.lineno,
                                    (
                                        "User input is passed directly as user role content "
                                        "(plain assignment, not interpolated). Consider applying "
                                        "input validation and length limits."
                                    ),
                                    (
                                        "Validate user input before passing it to the LLM. "
                                        "Apply length limits and content filtering."
                                    ),
                                )
                            )


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

        # LLM05: dangerous execution sinks receiving tainted input.
        if self._check_llm05_exec_sinks(node):
            self.generic_visit(node)
            return
        if self._check_llm05_shell_sinks(node, method):
            self.generic_visit(node)
            return
        if self._check_llm05_html_sinks(node, method):
            self.generic_visit(node)
            return
        self._check_llm05_json_loads(node, method)

        # LLM08: taint-tracked dynamic dispatch.
        self._check_llm08_dynamic_dispatch(node, method)

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
    # LLM05 — Improper Output Handling (AST taint-tracked checks)
    # ------------------------------------------------------------------

    def _check_llm05_exec_sinks(self, node: ast.Call) -> bool:
        """Return True (and emit a finding) when a tainted var is passed to eval/exec/compile."""
        func = node.func
        # Bare function call: eval(x), exec(x), compile(x)
        if isinstance(func, ast.Name) and func.id in _DANGEROUS_EXEC_SINKS:
            if node.args and self._is_tainted_node(node.args[0]):
                self.findings.append(
                    _finding(
                        _LLM05,
                        "Improper Output Handling",
                        "CRITICAL",
                        self.filepath,
                        node.lineno,
                        (
                            f"Tainted value passed to {func.id}() — this enables "
                            "arbitrary code execution from user-controlled input."
                        ),
                        (
                            "Never pass user-controlled or LLM-generated data to "
                            "eval(), exec(), or compile(). Validate strictly or "
                            "use a safe sandbox."
                        ),
                    )
                )
                self.cleared.add((node.lineno, _LLM05))
                return True
        return False

    def _check_llm05_shell_sinks(self, node: ast.Call, method: str) -> bool:
        """Return True (and emit a finding) when a tainted var is passed to a shell sink."""
        if method in _DANGEROUS_SHELL_SINKS:
            if node.args and self._is_tainted_node(node.args[0]):
                self.findings.append(
                    _finding(
                        _LLM05,
                        "Improper Output Handling",
                        "CRITICAL",
                        self.filepath,
                        node.lineno,
                        (
                            f"Tainted value passed to {method}() — this enables "
                            "OS command injection from user-controlled input."
                        ),
                        (
                            "Never pass user-controlled or LLM-generated data to "
                            "shell or subprocess calls. Use a fixed command allowlist "
                            "and pass arguments as a list."
                        ),
                    )
                )
                self.cleared.add((node.lineno, _LLM05))
                return True
        return False

    def _check_llm05_html_sinks(self, node: ast.Call, method: str) -> bool:
        """Return True (and emit a finding) when a tainted var is passed to an HTML sink."""
        # method may be a full attr chain; check the last component
        sink_name = method.split(".")[-1] if "." in method else method
        if sink_name in _DANGEROUS_HTML_SINKS:
            if node.args and self._is_tainted_node(node.args[0]):
                self.findings.append(
                    _finding(
                        _LLM05,
                        "Improper Output Handling",
                        "HIGH",
                        self.filepath,
                        node.lineno,
                        (
                            f"Tainted value passed to {sink_name}() — this may enable "
                            "cross-site scripting (XSS) or HTML injection."
                        ),
                        (
                            "Sanitise or escape user-controlled / LLM-generated data "
                            "before passing it to HTML rendering functions."
                        ),
                    )
                )
                self.cleared.add((node.lineno, _LLM05))
                return True
        return False

    def _check_llm05_json_loads(self, node: ast.Call, method: str) -> bool:
        """Return True (and emit a finding) when a tainted var is passed to json.loads()."""
        if method == "json.loads":
            if node.args and self._is_tainted_node(node.args[0]):
                severity = "MEDIUM" if self.strict else "INFO"
                self.findings.append(
                    _finding(
                        _LLM05,
                        "Improper Output Handling",
                        severity,
                        self.filepath,
                        node.lineno,
                        (
                            "Tainted value passed to json.loads() without schema "
                            "validation. If the parsed result feeds further unsafe "
                            "operations this may be exploitable."
                        ),
                        (
                            "Validate JSON deserialised from user-controlled or "
                            "LLM-generated data against a strict schema (e.g. pydantic) "
                            "before using the result in further operations."
                        ),
                    )
                )
                self.cleared.add((node.lineno, _LLM05))
                return True
        return False

    # ------------------------------------------------------------------
    # LLM08 — Excessive Agency (AST taint-tracked checks)
    # ------------------------------------------------------------------

    def _check_llm08_dynamic_dispatch(self, node: ast.Call, method: str) -> bool:
        """Return True (and emit a finding) for taint-tracked dynamic dispatch patterns.

        Detects:
        * ``getattr(module, tainted_name)()`` — function name controlled by tainted var
        * ``globals()[tainted_name]()`` — globals dict lookup with tainted key
        """
        func = node.func

        # getattr(obj, tainted_name) — the call node IS the getattr call itself;
        # we detect when it is used as a callable (i.e. getattr(...)(...))
        # by checking whether the *parent* call's func is this node.
        # At visit_Call time, node is the *outer* call: node.func is the getattr call.
        if isinstance(func, ast.Call):
            inner = func
            inner_func = inner.func
            # getattr(module, tainted_name)
            if (
                isinstance(inner_func, ast.Name)
                and inner_func.id == "getattr"
                and len(inner.args) >= 2
                and self._is_tainted_node(inner.args[1])
            ):
                self.findings.append(
                    _finding(
                        _LLM08,
                        "Excessive Agency",
                        "CRITICAL",
                        self.filepath,
                        node.lineno,
                        (
                            "getattr() is called with a tainted (user-controlled) "
                            "function name. An attacker can redirect execution to any "
                            "method on the target object."
                        ),
                        (
                            "Validate the function name against an explicit allowlist "
                            "before calling: `if name in ALLOWED: getattr(obj, name)()`."
                        ),
                    )
                )
                self.cleared.add((node.lineno, _LLM08))
                return True

            # globals()[tainted_name]()
            # node.func is a Subscript: globals()[tainted_name]
            if isinstance(func, ast.Subscript):
                subscript_val = func.value
                if (
                    isinstance(subscript_val, ast.Call)
                    and isinstance(subscript_val.func, ast.Name)
                    and subscript_val.func.id == "globals"
                    and self._is_tainted_node(func.slice)
                ):
                    self.findings.append(
                        _finding(
                            _LLM08,
                            "Excessive Agency",
                            "CRITICAL",
                            self.filepath,
                            node.lineno,
                            (
                                "globals() is subscripted with a tainted key and the "
                                "result is called. An attacker can invoke any function "
                                "in the module namespace."
                            ),
                            (
                                "Use an explicit allowlist instead of globals() dispatch: "
                                "`ALLOWED = {'fn': fn}; ALLOWED[name]()`."
                            ),
                        )
                    )
                    self.cleared.add((node.lineno, _LLM08))
                    return True

        # globals()[tainted_name]() — node.func is the Subscript directly
        if isinstance(func, ast.Subscript):
            subscript_val = func.value
            if (
                isinstance(subscript_val, ast.Call)
                and isinstance(subscript_val.func, ast.Name)
                and subscript_val.func.id == "globals"
                and self._is_tainted_node(func.slice)
            ):
                self.findings.append(
                    _finding(
                        _LLM08,
                        "Excessive Agency",
                        "CRITICAL",
                        self.filepath,
                        node.lineno,
                        (
                            "globals() is subscripted with a tainted key and the "
                            "result is called. An attacker can invoke any function "
                            "in the module namespace."
                        ),
                        (
                            "Use an explicit allowlist instead of globals() dispatch: "
                            "`ALLOWED = {'fn': fn}; ALLOWED[name]()`."
                        ),
                    )
                )
                self.cleared.add((node.lineno, _LLM08))
                return True

        return False

    # ------------------------------------------------------------------
    # Taint helper
    # ------------------------------------------------------------------

    def _is_tainted_node(self, node: ast.expr) -> bool:
        """Return True if *node* references a tainted (user-controlled) variable.

        Recognises:
        * ``ast.Name`` — plain variable reference
        * ``ast.JoinedStr`` — f-string containing a tainted name anywhere inside
        * ``ast.BinOp(Add)`` — string concatenation where any operand is tainted
        """
        if isinstance(node, ast.Name):
            return node.id in self._tainted
        if isinstance(node, ast.JoinedStr):
            # Walk the f-string for any tainted Name reference.
            for child in ast.walk(node):
                if isinstance(child, ast.Name):
                    if child.id in self._tainted:
                        return True
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            # Walk the concatenation tree iteratively to avoid deep recursion.
            for child in ast.walk(node):
                if isinstance(child, ast.Name) and child.id in self._tainted:
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


def _is_eval_context(filepath: str, tree: ast.AST) -> bool:
    """Return True if *filepath* / *tree* indicates an eval / test / grading harness.

    Three independent heuristics are applied; any one is sufficient:

    1. **Path segments** — a directory component or the file stem contains a
       known eval/test keyword (case-insensitive): ``eval``, ``evals``,
       ``test``, ``tests``, ``grader``, ``benchmark``, ``fixture``, etc.

    2. **Imports** — the file imports a recognised eval or test library such as
       ``pytest``, ``unittest``, ``deepeval``, ``ragas``, or ``promptfoo``.

    3. **Names** — a function or class definition has a name (case-insensitive)
       containing ``eval``, ``grade``, ``judge``, ``benchmark``, or ``test``.
    """
    # Heuristic 1: path segments
    path = _Path(filepath)
    path_parts = {p.lower() for p in path.parts}
    # Also check the file stem (e.g. "graders" in "graders.py")
    path_parts.add(path.stem.lower())
    if path_parts & _EVAL_PATH_SEGMENTS:
        return True

    # Heuristic 2: imports
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in _EVAL_IMPORT_NAMES:
                    return True
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] in _EVAL_IMPORT_NAMES:
                return True

    # Heuristic 3: function / class names
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            name_lower = node.name.lower()
            if any(frag in name_lower for frag in _EVAL_NAME_FRAGMENTS):
                return True

    return False


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
