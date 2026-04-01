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
        default_severity=Severity.CRITICAL,
        description=(
            "Prompt injection occurs when user-controlled input is mixed into LLM prompts, "
            "potentially allowing attackers to override system instructions or extract "
            "sensitive information."
        ),
        fix_suggestion=(
            "Pass user input as a separate 'role: user' message without interpolation. "
            "Validate and sanitize all user inputs before including them in prompts."
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
            "Hardcoded API keys, tokens, or other secrets in source code can be exposed "
            "through version control, logs, or code sharing."
        ),
        fix_suggestion=(
            "Never hardcode API keys in source code. Use environment variables or a "
            "secrets manager for production deployments."
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
            "Hardcoded system prompts in source code are visible to anyone with repository "
            "access and may expose proprietary instructions or internal tool descriptions."
        ),
        fix_suggestion=(
            "Load system prompts from environment variables or a secure configuration store "
            "rather than hardcoding them in source files."
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
            "LLM API calls without token limits can lead to unexpectedly large responses, "
            "higher-than-expected costs, and potential denial of service."
        ),
        fix_suggestion=(
            "Always set max_tokens (or equivalent) on LLM API calls. Consider adding "
            "per-user rate limits and request timeouts."
        ),
    )
)

# ---------------------------------------------------------------------------
# OWASP LLM Top 10 — Planned rules
# ---------------------------------------------------------------------------

registry.register(
    RuleDefinition(
        rule_id="LLM05",
        name="Improper Output Handling",
        status=Status.PLANNED,
        default_severity=Severity.HIGH,
        description=(
            "LLM outputs are not validated before being used in downstream processing, "
            "which can lead to code injection, XSS, or other attacks."
        ),
        fix_suggestion=(
            "Validate and sanitize all LLM outputs before using them in downstream processing."
        ),
    )
)

registry.register(
    RuleDefinition(
        rule_id="LLM08",
        name="Excessive Agency",
        status=Status.PLANNED,
        default_severity=Severity.HIGH,
        description=(
            "LLM agents granted excessive permissions or capabilities can cause unintended "
            "harm by taking actions beyond what is necessary."
        ),
        fix_suggestion=(
            "Apply the principle of least privilege to all LLM agents and their tools. "
            "Require human approval for high-impact actions."
        ),
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
        status=Status.OUT_OF_SCOPE,
        default_severity=Severity.HIGH,
        description=(
            "LLM plugins with insufficient input validation or access controls can be "
            "exploited to bypass security boundaries."
        ),
        fix_suggestion=(
            "Apply secure-by-default design principles to all LLM plugin interfaces."
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
