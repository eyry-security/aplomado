"""aplomado: AI security scanner and reviewer built on Pinnace."""

from .findings import SEVERITIES, normalize_findings
from .prompts import SYSTEM_PROMPT, build_prompt
from .scanner import load_target_file, run_scan
from .store import FindingStore, NullStore, RuttStore, resolve_store

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "FindingStore",
    "NullStore",
    "RuttStore",
    "SEVERITIES",
    "SYSTEM_PROMPT",
    "build_prompt",
    "load_target_file",
    "normalize_findings",
    "resolve_store",
    "run_scan",
]
