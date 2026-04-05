"""Central rule registry for LLM Armor.

All OWASP LLM Top 10 rules are registered here as a single source of truth.
Rules are categorised as ACTIVE (scannable), PLANNED (future), or OUT_OF_SCOPE.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class Status(Enum):
    ACTIVE = "active"
    PLANNED = "planned"
    OUT_OF_SCOPE = "out_of_scope"


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass(frozen=True)
class RuleDefinition:
    rule_id: str
    name: str
    status: Status
    default_severity: Severity
    description: str
    fix_suggestion: str
    strict_severity: Optional[Severity] = None


class RuleRegistry:
    def __init__(self) -> None:
        self._rules: dict[str, RuleDefinition] = {}

    def register(self, rule: RuleDefinition) -> RuleDefinition:
        """Register a rule and return it (chainable)."""
        self._rules[rule.rule_id] = rule
        return rule

    def get(self, rule_id: str) -> RuleDefinition:
        """Return the RuleDefinition for *rule_id*, raising KeyError if not found."""
        return self._rules[rule_id]

    def active_rules(self) -> list[RuleDefinition]:
        """Return all rules with ACTIVE status, in rule-ID order."""
        return sorted(
            [r for r in self._rules.values() if r.status == Status.ACTIVE],
            key=lambda r: r.rule_id,
        )

    def all_rules(self) -> list[RuleDefinition]:
        """Return all registered rules in rule-ID order."""
        return sorted(self._rules.values(), key=lambda r: r.rule_id)

    def by_status(self, status: Status) -> list[RuleDefinition]:
        """Return all rules with the given *status*, in rule-ID order."""
        return sorted(
            [r for r in self._rules.values() if r.status == status],
            key=lambda r: r.rule_id,
        )


# ---------------------------------------------------------------------------
# Global registry instance
# ---------------------------------------------------------------------------

registry = RuleRegistry()

# ---------------------------------------------------------------------------
# OWASP LLM Top 10 — Active rules
# ---------------------------------------------------------------------------

registry.register(
    RuleDefinition(
        rule_id="LLM01",
        name="Prompt Injection",
        status=Status.ACTIVE,
        default_severity=Severity.HIGH,
        description=(
            "User-controlled input is mixed into LLM prompt strings, allowing attackers "
            "to override system instructions, extract sensitive data, or hijack the "
            "model's behavior. Detection based on variable naming convention — verify "
            "that the flagged variable actually carries user-supplied data."
        ),
        fix_suggestion=(
            "Pass user input as a separate 'role: user' message without interpolation. "
            "Never use f-strings, .format(), or concatenation to embed user data in "
            "system or assistant messages. If a prompt template is required, use a "
            "dedicated library with injection-safe variable substitution."
        ),
        strict_severity=Severity.MEDIUM,
    )
)

registry.register(
    RuleDefinition(
        rule_id="LLM02",
        name="Sensitive Information Disclosure",
        status=Status.ACTIVE,
        default_severity=Severity.CRITICAL,
        description=(
            "Hardcoded API keys or tokens found in source code. These secrets are exposed "
            "to anyone with repository access and will be captured by version control "
            "history even after removal. An attacker with the key can make authenticated "
            "API calls, incur costs, or exfiltrate data."
        ),
        fix_suggestion=(
            "Remove the hardcoded secret immediately and rotate it. Store secrets in "
            "environment variables and read them with os.environ.get('KEY_NAME'). "
            "For production, use a secrets manager (AWS Secrets Manager, HashiCorp Vault, "
            "or similar). Add secret patterns to .gitignore and pre-commit hooks."
        ),
    )
)

registry.register(
    RuleDefinition(
        rule_id="LLM07",
        name="System Prompt Leakage",
        status=Status.ACTIVE,
        default_severity=Severity.INFO,
        description=(
            "A hardcoded system prompt was found in source code. Anyone with repository "
            "access can read the prompt, potentially revealing proprietary instructions, "
            "personas, tool descriptions, or information about internal systems that "
            "should remain confidential."
        ),
        fix_suggestion=(
            "Load the system prompt from an environment variable or a secure configuration "
            "store at runtime rather than embedding it in source code. Example: "
            "system_prompt = os.environ.get('SYSTEM_PROMPT', ''). This keeps proprietary "
            "instructions out of version control."
        ),
        strict_severity=Severity.MEDIUM,
    )
)

registry.register(
    RuleDefinition(
        rule_id="LLM10",
        name="Unbounded Consumption",
        status=Status.ACTIVE,
        default_severity=Severity.MEDIUM,
        description=(
            "LLM API call without a max_tokens limit. Without this guard, a single request "
            "can generate thousands of tokens, leading to unexpectedly large costs, "
            "slow response times, and potential denial-of-service when processing many "
            "requests concurrently."
        ),
        fix_suggestion=(
            "Always set max_tokens (or max_output_tokens for Gemini) on every LLM API call. "
            "Example: client.chat.completions.create(..., max_tokens=500). Also consider "
            "adding per-user rate limits and request timeouts for production deployments."
        ),
    )
)

# ---------------------------------------------------------------------------
# OWASP LLM Top 10 — Active rules (LLM05, LLM08)
# ---------------------------------------------------------------------------

registry.register(
    RuleDefinition(
        rule_id="LLM05",
        name="Improper Output Handling",
        status=Status.ACTIVE,
        default_severity=Severity.HIGH,
        description=(
            "LLM output is passed directly to a dangerous sink (eval, exec, shell command, "
            "SQL query, or HTML renderer) without validation. An attacker who can influence "
            "the model's output can execute arbitrary code, run shell commands, or inject "
            "malicious SQL/HTML. Detection based on variable naming convention — verify "
            "that the flagged variable actually carries LLM-generated content."
        ),
        fix_suggestion=(
            "Never pass LLM output directly to eval(), exec(), subprocess, SQL queries, or "
            "HTML rendering functions. Validate and sanitize all model responses before use. "
            "For code execution use cases, run in a sandboxed environment (e.g., Docker, "
            "subprocess with a restricted user). For SQL, use parameterized queries."
        ),
        strict_severity=Severity.MEDIUM,
    )
)

registry.register(
    RuleDefinition(
        rule_id="LLM08",
        name="Excessive Agency",
        status=Status.ACTIVE,
        default_severity=Severity.HIGH,
        description=(
            "LLM agent is granted capabilities beyond what is necessary for its task. "
            "Overly broad tool access, dynamic function dispatch, or disabled human "
            "oversight gates allow an attacker who controls the model's input or output "
            "to trigger dangerous actions (file deletion, shell commands, arbitrary "
            "code execution) without human review."
        ),
        fix_suggestion=(
            "Restrict tools to only what the agent needs. Use an explicit allowlist of "
            "callable functions instead of globals() or getattr() dispatch. Require "
            "human confirmation before high-impact actions. Example: "
            "ALLOWED_TOOLS = {'search': search_fn, 'summarize': summarize_fn}; "
            "fn = ALLOWED_TOOLS.get(tool_name) and call fn() only if fn is not None."
        ),
        strict_severity=Severity.MEDIUM,
    )
)

# ---------------------------------------------------------------------------
# OWASP LLM Top 10 — Out of scope (static analysis not applicable)
# ---------------------------------------------------------------------------

registry.register(
    RuleDefinition(
        rule_id="LLM03",
        name="Supply Chain Vulnerabilities",
        status=Status.OUT_OF_SCOPE,
        default_severity=Severity.HIGH,
        description=(
            "Supply chain risks in LLM components, model weights, and dependencies "
            "can introduce backdoors or malicious behaviour."
        ),
        fix_suggestion=(
            "Audit and pin LLM dependencies. Use verified model sources and checksums."
        ),
    )
)

registry.register(
    RuleDefinition(
        rule_id="LLM04",
        name="Data and Model Poisoning",
        status=Status.OUT_OF_SCOPE,
        default_severity=Severity.HIGH,
        description=(
            "Training data manipulation can introduce backdoors or biases into the model."
        ),
        fix_suggestion=(
            "Validate training data sources and implement data integrity checks."
        ),
    )
)

registry.register(
    RuleDefinition(
        rule_id="LLM06",
        name="Insecure Plugin Design",
        status=Status.ACTIVE,
        default_severity=Severity.HIGH,
        description=(
            "LLM tool/plugin decorated with @tool or equivalent contains a dangerous "
            "sink (eval, exec, shell command). Since the LLM controls tool invocation, "
            "a prompt injection attack can redirect execution to these dangerous sinks. "
            "Detection is based on @tool decorator presence combined with sink patterns."
        ),
        fix_suggestion=(
            "Apply secure-by-default design to all LLM plugin interfaces. Validate all "
            "inputs to @tool-decorated functions as if they come from untrusted sources. "
            "Avoid eval/exec/shell sinks inside tool functions. Use parameterized "
            "interfaces and explicit allowlists for any dynamic dispatch."
        ),
    )
)

registry.register(
    RuleDefinition(
        rule_id="LLM09",
        name="Misinformation",
        status=Status.OUT_OF_SCOPE,
        default_severity=Severity.MEDIUM,
        description=(
            "LLM generates false or misleading information that is presented as fact, "
            "which can mislead users or downstream systems."
        ),
        fix_suggestion=(
            "Implement fact-checking, output verification, and user-facing disclaimers."
        ),
    )
)
