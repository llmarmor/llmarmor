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
import collections
from pathlib import Path as _Path

_LLM01 = "LLM01"
_LLM05 = "LLM05"
_LLM07 = "LLM07"
_LLM08 = "LLM08"

# Decorator names that register a function as an LLM-agent-invocable tool.
# Covers LangChain/CrewAI/AutoGen/LlamaIndex/Smolagents/ADK/MCP (@tool),
# OpenAI Agents SDK (@function_tool), Microsoft Semantic Kernel (@kernel_function),
# Pydantic AI (@ai_tool), and Marvin AI (@ai_fn).
_TOOL_DECORATOR_NAMES: frozenset[str] = frozenset([
    "tool",              # LangChain, CrewAI, AutoGen, LlamaIndex, Smolagents, Google ADK, MCP, ControlFlow, Marvin (primary)
    "function_tool",     # OpenAI Agents SDK
    "kernel_function",   # Microsoft Semantic Kernel
    "ai_tool",           # Pydantic AI
    "ai_fn",             # Marvin AI (alternate)
])

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

    Returns a dict with exactly three keys:

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

    ``is_eval_context``
        ``True`` when the file is identified as an eval / test / grading
        harness.  The scanner uses this to downgrade LLM05 and LLM08 regex
        findings from test files to INFO severity.

    If *content* cannot be parsed as valid Python the function returns
    ``{"findings": [], "cleared": set(), "is_eval_context": False}`` so
    callers never need to handle exceptions.

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
        return {"findings": [], "cleared": set(), "is_eval_context": False}

    visitor = _Analyzer(str(filepath), strict=strict)
    visitor.visit(tree)

    findings = visitor.findings
    eval_ctx = _is_eval_context(filepath, tree)
    if eval_ctx:
        findings = [
            {
                **f,
                "severity": "INFO",
                "description": f"[eval context] {f['description']}",
            }
            if f["rule_id"] in (_LLM01, _LLM05, _LLM08)
            else f
            for f in findings
        ]

    return {"findings": findings, "cleared": visitor.cleared, "is_eval_context": eval_ctx}


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
        # LLM-response taint: subset of _tainted whose values originate specifically
        # from LLM API responses.  Used to propagate LLM taint through attribute
        # and subscript access (e.g. response.choices[0].message.content).
        self._llm_tainted: set[str] = set()
        # Source taint: variables assigned from explicit user/LLM-controlled sources
        # (request.json, input(), sys.argv, websocket, LLM API calls).
        # Plain function parameters are NOT included to avoid false positives in
        # utility functions.  Exception: parameters of ``@tool``-decorated functions
        # ARE included because the LLM chooses their values at runtime.
        self._source_tainted: set[str] = set()
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

        Parameters of ``@tool``-decorated functions are additionally promoted to
        ``_source_tainted`` because their values are chosen by the LLM at
        runtime — they are effectively LLM output and must be treated with the
        same scrutiny as ``request.json`` or ``sys.argv``.  This allows the
        existing LLM05 checks (shell sinks, exec sinks, HTML sinks, json.loads)
        to fire automatically for ``@tool`` function bodies.

        Also detects ``@tool``-decorated functions whose bodies directly contain
        shell execution sinks (``subprocess.run``, ``os.system``, etc.) and emits
        an LLM08 HIGH finding for each sink found.
        """
        all_args = (
            node.args.posonlyargs
            + node.args.args
            + node.args.kwonlyargs
        )
        is_tool_func = self._has_tool_decorator(node)
        for arg in all_args:
            self._tainted.add(arg.arg)
            if is_tool_func:
                self._source_tainted.add(arg.arg)
        if node.args.vararg:
            self._tainted.add(node.args.vararg.arg)
            if is_tool_func:
                self._source_tainted.add(node.args.vararg.arg)
        if node.args.kwarg:
            self._tainted.add(node.args.kwarg.arg)
            if is_tool_func:
                self._source_tainted.add(node.args.kwarg.arg)

        # LLM08: @tool decorator + shell sink detection
        if is_tool_func:
            self._check_llm08_tool_shell_sinks(node)

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
                self._source_tainted.add(name)
            # Taint propagation: alias = tainted_var  →  alias is tainted.
            # Does NOT propagate through function calls to avoid false positives
            # from sanitizer patterns like ``clean = sanitize(user_input)``.
            elif isinstance(rhs, ast.Name) and rhs.id in self._tainted:
                self._tainted.add(name)
                if rhs.id in self._source_tainted:
                    self._source_tainted.add(name)

            # LLM-response taint seeding: the variable receives the return value
            # of a recognised LLM API call (e.g. client.chat.completions.create).
            if _is_llm_api_call_rhs(rhs):
                self._llm_tainted.add(name)
                self._source_tainted.add(name)
                self._tainted.add(name)
            # LLM-taint propagation through direct aliases and attribute/subscript
            # access on an already-LLM-tainted receiver.  This covers patterns like:
            #   content = response.choices[0].message.content
            # where ``response`` is LLM-tainted and ``content`` should be too.
            elif isinstance(rhs, ast.Name) and rhs.id in self._llm_tainted:
                self._llm_tainted.add(name)
                self._source_tainted.add(name)
            elif isinstance(rhs, (ast.Attribute, ast.Subscript)):
                if _receiver_root(rhs) in self._llm_tainted:
                    self._llm_tainted.add(name)
                    self._source_tainted.add(name)

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
        """Return True (and emit a finding) when a source-tainted var is passed to a shell sink.

        Only variables whose taint originates from an explicit user-controlled or
        LLM-controlled source (``_source_tainted``) are flagged.  Plain function
        parameters are not included in this set, which avoids false positives in
        utility functions like ``def run_job(cmd): subprocess.Popen(cmd)`` where
        ``cmd`` is a parameter that may not carry attacker-controlled data.

        Parameters of ``@tool``-decorated functions are an exception: they are
        promoted to ``_source_tainted`` in ``visit_FunctionDef`` because their
        values are chosen by the LLM at runtime and must be treated as
        attacker-controlled input.
        """
        if method in _DANGEROUS_SHELL_SINKS:
            if node.args and self._is_source_tainted_node(node.args[0]):
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

    @staticmethod
    def _has_tool_decorator(node: ast.FunctionDef) -> bool:
        """Return True if *node* is decorated with a known tool decorator.

        Recognises bare ``@tool``, called ``@tool('Shell Tool', args_schema=…)``,
        and module-qualified ``@module.tool(...)`` forms across multiple frameworks:
        LangChain, CrewAI, OpenAI Agents SDK, Semantic Kernel, Pydantic AI, etc.
        """
        for decorator in node.decorator_list:
            # Bare decorator: @tool, @function_tool, @kernel_function, etc.
            if isinstance(decorator, ast.Name) and decorator.id in _TOOL_DECORATOR_NAMES:
                return True
            # Called decorator: @tool('Name', ...), @function_tool(...), etc.
            if isinstance(decorator, ast.Call):
                func = decorator.func
                # @tool(...) form — func is ast.Name
                if isinstance(func, ast.Name) and func.id in _TOOL_DECORATOR_NAMES:
                    return True
                # @module.tool(...) form — func is ast.Attribute
                if isinstance(func, ast.Attribute) and func.attr in _TOOL_DECORATOR_NAMES:
                    return True
        return False

    def _check_llm08_tool_shell_sinks(self, node: ast.FunctionDef) -> None:
        """Emit HIGH LLM08 finding for each shell sink inside a ``@tool``-decorated function.

        Walks the body of *node* looking for ``subprocess.*`` or ``os.system`` /
        ``os.popen`` calls.  The traversal stops at nested function/class
        boundaries to avoid false positives from helper functions defined inside
        the tool that are not themselves LLM-invocable.
        """
        queue: collections.deque[ast.AST] = collections.deque(ast.iter_child_nodes(node))
        while queue:
            child = queue.popleft()
            # Do not recurse into nested function/class definitions — shell
            # sinks in those scopes are not directly invoked by the @tool body.
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            if isinstance(child, ast.Call):
                method = _attr_chain(child.func)
                if method in _DANGEROUS_SHELL_SINKS:
                    self.findings.append(
                        _finding(
                            _LLM08,
                            "Excessive Agency",
                            "HIGH",
                            self.filepath,
                            child.lineno,
                            (
                                f"@tool-decorated function '{node.name}' contains "
                                f"{method}() call — this grants the LLM agent "
                                "OS-level command execution capability."
                            ),
                            (
                                "Avoid placing shell or subprocess calls inside "
                                "@tool-decorated functions. If shell access is required, "
                                "apply strict input validation and sandbox the execution "
                                "environment."
                            ),
                        )
                    )
            queue.extend(ast.iter_child_nodes(child))

    def _check_llm08_dynamic_dispatch(self, node: ast.Call, method: str) -> bool:
        """Return True (and emit a finding) for taint-tracked dynamic dispatch patterns.

        Detects:
        * ``getattr(module, tainted_name)()`` — function name controlled by tainted var
        * ``globals()[tainted_name]()`` — globals dict lookup with tainted key

        Also suppresses the LLM08 regex finding on lines where a ``getattr``
        call uses a string *literal* as the second argument (i.e. the name is
        hardcoded and cannot be attacker-controlled), even though the regex
        layer's negative-lookahead should already exclude such cases.
        """
        func = node.func

        # getattr(obj, tainted_name)(args) — node.func is the inner getattr() call.
        if isinstance(func, ast.Call):
            inner_func = func.func
            if isinstance(inner_func, ast.Name) and inner_func.id == "getattr" and len(func.args) >= 2:
                second_arg = func.args[1]
                if isinstance(second_arg, ast.Constant) and isinstance(second_arg.value, str):
                    # String literal — name is fixed, no dispatch risk.
                    # Suppress any regex false-positive on this line.
                    self.cleared.add((node.lineno, _LLM08))
                    return True
                if self._is_tainted_node(second_arg):
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

        # Bare getattr(obj, "literal") call (result not immediately invoked).
        # Suppress regex finding when the second argument is a string constant.
        if isinstance(func, ast.Name) and func.id == "getattr" and len(node.args) >= 2:
            second_arg = node.args[1]
            if isinstance(second_arg, ast.Constant) and isinstance(second_arg.value, str):
                self.cleared.add((node.lineno, _LLM08))
                return True

        # globals()[tainted_name]() — node.func is a Subscript: globals()[tainted_name].
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

    def _is_llm_tainted_node(self, node: ast.expr) -> bool:
        """Return True if *node* references a variable that carries LLM API response data.

        Same shape as :meth:`_is_tainted_node` but consults ``_llm_tainted``
        instead of ``_tainted``.
        """
        if isinstance(node, ast.Name):
            return node.id in self._llm_tainted
        if isinstance(node, ast.JoinedStr):
            for child in ast.walk(node):
                if isinstance(child, ast.Name) and child.id in self._llm_tainted:
                    return True
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            for child in ast.walk(node):
                if isinstance(child, ast.Name) and child.id in self._llm_tainted:
                    return True
        return False

    def _is_source_tainted_node(self, node: ast.expr) -> bool:
        """Return True if *node* references a variable tainted from an explicit source.

        Unlike :meth:`_is_tainted_node`, this excludes variables that are only
        tainted because they are function parameters.  It covers:

        * ``request.json``, ``request.form``, ``input()``, ``sys.argv`` — user data
        * LLM API call results and their attribute/subscript derivatives

        Used by :meth:`_check_llm05_shell_sinks` to avoid false positives from
        utility functions whose parameters coincidentally reach a subprocess call.
        """
        if isinstance(node, ast.Name):
            return node.id in self._source_tainted
        if isinstance(node, ast.JoinedStr):
            for child in ast.walk(node):
                if isinstance(child, ast.Name) and child.id in self._source_tainted:
                    return True
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            for child in ast.walk(node):
                if isinstance(child, ast.Name) and child.id in self._source_tainted:
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


def _is_llm_api_call_rhs(node: ast.expr) -> bool:
    """Return True if *node* is a call to a recognised LLM API method.

    Used to seed the ``_llm_tainted`` set: when a variable is assigned the
    direct result of an LLM API call (e.g. ``response = client.chat.completions
    .create(...)``), it is tagged as LLM-response-tainted.  This is a stricter
    taint category than ordinary user-controlled taint and is used to restrict
    LLM05 shell-sink findings to genuine LLM output flows.
    """
    if not isinstance(node, ast.Call):
        return False
    chain = _attr_chain(node.func)
    return _is_llm10_call(chain)


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
        self.source_tainted: set[str] = set()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        all_args = (
            node.args.posonlyargs
            + node.args.args
            + node.args.kwonlyargs
        )
        is_tool_func = _Analyzer._has_tool_decorator(node)
        for arg in all_args:
            self.tainted.add(arg.arg)
            if is_tool_func:
                self.source_tainted.add(arg.arg)
        if node.args.vararg:
            self.tainted.add(node.args.vararg.arg)
            if is_tool_func:
                self.source_tainted.add(node.args.vararg.arg)
        if node.args.kwarg:
            self.tainted.add(node.args.kwarg.arg)
            if is_tool_func:
                self.source_tainted.add(node.args.kwarg.arg)
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
