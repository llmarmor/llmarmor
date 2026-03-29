"""Detection rules for OWASP LLM Top 10 vulnerabilities."""

import functools

from llmarmor.rules.llm01_prompt_injection import check_prompt_injection
from llmarmor.rules.llm02_sensitive_info import check_sensitive_info
from llmarmor.rules.llm07_system_prompt_leak import check_system_prompt_leak
from llmarmor.rules.llm10_unbounded_consumption import check_unbounded_consumption

ALL_RULES = [
    check_prompt_injection,
    check_sensitive_info,
    check_system_prompt_leak,
    check_unbounded_consumption,
]


def get_rules(strict: bool = False) -> list:
    """Return a list of rule-checker callables configured for *strict* mode.

    Each callable accepts ``(filepath, content)`` and returns a list of finding dicts.
    When *strict* is ``True``, rules that support strict mode produce additional or
    higher-severity findings.
    """
    if not strict:
        return list(ALL_RULES)
    return [
        check_prompt_injection,
        check_sensitive_info,
        functools.partial(check_system_prompt_leak, strict=True),
        check_unbounded_consumption,
    ]
