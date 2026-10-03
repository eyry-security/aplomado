"""aplomado: AI security scanner and reviewer built on Pinnace."""

from .findings import SEVERITIES, normalize_findings
from .scanner import build_prompt, load_target_file, run_scan

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "SEVERITIES",
    "build_prompt",
    "load_target_file",
    "normalize_findings",
    "run_scan",
]
