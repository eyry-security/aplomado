"""aplomado: AI security scanner and reviewer built on Pinnace."""

from .events import EventSink, FileSink, NullSink as NullEventSink, StdoutSink, build_event, resolve_sink
from .findings import SEVERITIES, finding_id, normalize_findings
from .prompts import SYSTEM_PROMPT, build_prompt
from .scratchpad import SCRATCHPAD_PATH, python_scratchpad_tool
from .scanner import load_target_file, parse_stdin_record, run_scan
from .store import FindingStore, NullStore, RuttStore, resolve_store

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "EventSink",
    "FileSink",
    "FindingStore",
    "NullEventSink",
    "NullStore",
    "RuttStore",
    "SCRATCHPAD_PATH",
    "SEVERITIES",
    "SYSTEM_PROMPT",
    "StdoutSink",
    "build_event",
    "build_prompt",
    "finding_id",
    "load_target_file",
    "normalize_findings",
    "parse_stdin_record",
    "python_scratchpad_tool",
    "resolve_sink",
    "resolve_store",
    "run_scan",
]
