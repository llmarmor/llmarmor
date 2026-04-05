"""Configuration loading for LLM Armor.

Supports reading a YAML configuration file (``.llmarmor.yaml``) from an
explicit path or auto-detected from the scan root directory.

Example configuration file::

    # .llmarmor.yaml
    severity_threshold: MEDIUM    # Only report findings at this level or above
    strict: false                 # Enable strict mode
    rules:
      LLM01:
        enabled: true
        severity: HIGH            # Override default severity for this rule
      LLM07:
        enabled: false            # Disable this rule entirely
    exclude_paths:
      - "tests/**"
      - "scripts/dev_*"
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import yaml

_CONFIG_FILENAME = ".llmarmor.yaml"

# Valid severity levels in descending order of severity.
_VALID_SEVERITIES = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"})


class LLMArmorConfig:
    """Parsed and validated LLM Armor configuration.

    Attributes:
        severity_threshold: Minimum severity level to report. Findings below
            this threshold are suppressed (after the verbose filter). Defaults
            to ``"INFO"`` (report everything).
        strict: Whether to enable strict scanning mode. Defaults to ``False``.
        rules: Per-rule overrides. Each key is a rule ID (e.g. ``"LLM01"``)
            and the value is a dict with optional ``enabled`` and ``severity``
            keys.
        exclude_paths: List of glob patterns (relative to the scan root) for
            files and directories to skip.
    """

    def __init__(self, data: dict) -> None:
        raw_threshold = str(data.get("severity_threshold", "INFO")).upper()
        self.severity_threshold: str = (
            raw_threshold if raw_threshold in _VALID_SEVERITIES else "INFO"
        )
        self.strict: bool = bool(data.get("strict", False))
        self.rules: dict[str, dict] = {
            k: v for k, v in (data.get("rules", {}) or {}).items() if isinstance(v, dict)
        }
        self.exclude_paths: list[str] = list(data.get("exclude_paths", []) or [])

    def is_rule_enabled(self, rule_id: str) -> bool:
        """Return ``True`` if *rule_id* is enabled (default: enabled)."""
        rule_cfg = self.rules.get(rule_id, {})
        return bool(rule_cfg.get("enabled", True))

    def rule_severity_override(self, rule_id: str) -> Optional[str]:
        """Return a severity override for *rule_id*, or ``None`` if not set."""
        rule_cfg = self.rules.get(rule_id, {})
        raw = rule_cfg.get("severity")
        if raw and str(raw).upper() in _VALID_SEVERITIES:
            return str(raw).upper()
        return None


def load_config(
    config_path: Optional[str] = None,
    scan_root: Optional[str] = None,
) -> Optional[LLMArmorConfig]:
    """Load a configuration file and return a :class:`LLMArmorConfig`.

    Resolution order:

    1. *config_path* — explicit path supplied by the caller / CLI flag.
    2. *scan_root* / ``.llmarmor.yaml`` — auto-detected in the scan root.
    3. Current working directory / ``.llmarmor.yaml`` — fallback auto-detection.

    Returns ``None`` if no configuration file is found, allowing the caller to
    use defaults without modification.

    :raises yaml.YAMLError: if the configuration file is not valid YAML.
    :raises OSError: if the file exists but cannot be read.
    """
    path: Optional[Path] = None

    if config_path:
        path = Path(config_path)
    else:
        # Auto-detect from scan root first, then CWD.
        candidates: list[Path] = []
        if scan_root:
            candidates.append(Path(scan_root) / _CONFIG_FILENAME)
        candidates.append(Path.cwd() / _CONFIG_FILENAME)

        for candidate in candidates:
            if candidate.exists():
                path = candidate
                break

    if path is None or not path.exists():
        return None

    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}

    return LLMArmorConfig(data)
