"""File-type handler infrastructure for LLM Armor.

Each handler scans a specific file type (e.g. ``.env``, ``.yaml``) and returns
finding dicts in the same format as the Python scanner.

Usage::

    from llmarmor.handlers import HANDLERS

    for ext, handler in HANDLERS.items():
        if filepath.suffix == ext:
            findings = handler(str(filepath), content)
"""

from dataclasses import dataclass
from typing import Callable

from llmarmor.handlers.env import scan_env_file
from llmarmor.handlers.yaml_handler import scan_yaml_file
from llmarmor.handlers.json_handler import scan_json_file
from llmarmor.handlers.toml_handler import scan_toml_file
from llmarmor.handlers.js_handler import scan_js_file
from llmarmor.handlers.text_handler import scan_text_file
from llmarmor.handlers.notebook import scan_notebook_file


@dataclass(frozen=True)
class FileHandler:
    """Associates a set of file extensions with a scanning function."""

    extensions: tuple[str, ...]
    scanner: Callable[[str, str], list[dict]]


# ---------------------------------------------------------------------------
# Extension → scanner mapping
# ---------------------------------------------------------------------------

HANDLERS: dict[str, Callable[[str, str], list[dict]]] = {
    ".env": scan_env_file,
    ".yaml": scan_yaml_file,
    ".yml": scan_yaml_file,
    ".json": scan_json_file,
    ".toml": scan_toml_file,
    ".js": scan_js_file,
    ".ts": scan_js_file,
    ".md": scan_text_file,
    ".txt": scan_text_file,
    ".ipynb": scan_notebook_file,
}

__all__ = ["FileHandler", "HANDLERS"]
