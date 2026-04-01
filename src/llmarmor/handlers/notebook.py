"""Handler for ``.ipynb`` Jupyter notebooks.

Strategy:
- Parse the notebook JSON with stdlib ``json``.
- Extract source lines from code cells and run the Python scanner on them.
- Scan markdown cells for accidentally committed API keys.
"""

import json
import warnings
from pathlib import Path

from llmarmor.secret_patterns import PLACEHOLDER_VALUE_PATTERN, SECRET_PATTERNS, TEST_VAR_PATTERN

_LLM02_FIX = (
    "Never hardcode API keys in notebook cells. Use environment variables "
    "(os.environ.get('KEY')) or a secrets manager. Consider using nbstripout "
    "to remove outputs before committing notebooks."
)


def scan_notebook_file(filepath: str, content: str) -> list[dict]:
    """Scan a Jupyter notebook for secrets and LLM vulnerabilities.

    Code cells are joined and run through the Python AST + regex scanner.
    Markdown cells are scanned for accidentally committed API keys.
    """
    findings: list[dict] = []

    try:
        nb = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return findings

    cells = nb.get("cells", [])

    # We import lazily to avoid circular imports at module load time.
    from llmarmor.scanner import _scan_file as _python_scan_file

    # Running total of source lines seen across all preceding cells.
    # Used to convert per-cell line numbers into notebook-level line numbers
    # so that reported line numbers point to the correct location even when
    # a finding is in a later cell.
    notebook_line = 0

    for cell in cells:
        cell_type = cell.get("cell_type", "")
        source = cell.get("source", [])

        # source may be a list of strings or a single string.
        if isinstance(source, list):
            cell_text = "".join(source)
        else:
            cell_text = str(source)

        cell_source_lines = cell_text.splitlines()
        # Record where this cell starts in the notebook's logical line space,
        # then advance the counter *before* any early-continue so that empty
        # cells are still accounted for in the running total.
        cell_start = notebook_line
        notebook_line += len(cell_source_lines)

        if not cell_text.strip():
            continue

        if cell_type == "code":
            # Run the full Python scanner on the cell source.
            cell_findings: list[dict] = []
            # Use a synthetic path so the cell is treated as a Python file.
            pseudo_path = Path(filepath)
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", SyntaxWarning)
                    _python_scan_file(pseudo_path, cell_text, cell_findings)
            except (SyntaxError, ValueError, RecursionError):  # noqa: BLE001
                pass
            for f in cell_findings:
                # Notebooks are tutorial/example code — skip prompt injection
                # checks entirely to avoid noisy false positives from taint
                # analysis on locally-called functions with no external input
                # boundary.
                if f["rule_id"] == "LLM01":
                    continue
                f["filepath"] = filepath
                # Offset cell-relative line numbers to notebook-level numbers.
                f["line"] = cell_start + f["line"]
                findings.append(f)

        elif cell_type in ("markdown", "raw"):
            # Scan for accidentally committed API keys in markdown text.
            for line_idx, line in enumerate(cell_source_lines):
                if not line.strip() or TEST_VAR_PATTERN.search(line):
                    continue
                for pattern, key_type in SECRET_PATTERNS:
                    m = pattern.search(line)
                    if m and not PLACEHOLDER_VALUE_PATTERN.search(m.group(0)):
                        findings.append(
                            {
                                "rule_id": "LLM02",
                                "rule_name": "Sensitive Information Disclosure",
                                "severity": "HIGH",
                                "filepath": filepath,
                                # Offset to notebook-level line number.
                                "line": cell_start + line_idx + 1,
                                "description": (
                                    f"Hardcoded {key_type} found in a notebook "
                                    "markdown/text cell. Committing secrets to version "
                                    "control exposes them to anyone with repository access."
                                ),
                                "fix_suggestion": _LLM02_FIX,
                            }
                        )
                        break

    return findings
