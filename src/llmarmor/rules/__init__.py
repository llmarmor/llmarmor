"""Detection rules for OWASP LLM Top 10 vulnerabilities."""

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
