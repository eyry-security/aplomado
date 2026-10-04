"""aplomado: AI security scanner and reviewer built on Pinnace."""

from .events import EventSink, FileSink, NullSink as NullEventSink, StdoutSink, build_event, resolve_sink
from .findings import SEVERITIES, finding_id, normalize_findings
from .prompts import SYSTEM_PROMPT, build_prompt
from .scanner import load_target_file, parse_stdin_record, run_scan
from .store import FindingStore, NullStore, RuttStore, resolve_store
from .write_policy import (
    WRITE_MAX_BYTES,
    WRITE_ROOT,
    WritePolicySandbox,
    harden_sandbox,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "EventSink",
    "FileSink",
    "FindingStore",
    "NullEventSink",
    "NullStore",
    "RuttStore",
    "SEVERITIES",
    "SYSTEM_PROMPT",
    "StdoutSink",
    "WRITE_MAX_BYTES",
    "WRITE_ROOT",
    "WritePolicySandbox",
    "build_event",
    "build_prompt",
    "finding_id",
    "harden_sandbox",
    "load_target_file",
    "normalize_findings",
    "parse_stdin_record",
    "resolve_sink",
    "resolve_store",
    "run_scan",
]
