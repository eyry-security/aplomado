"""aplomado: AI security scanner and reviewer built on Pinnace."""

from .events import EventSink, FileSink, NullSink as NullEventSink, StdoutSink, build_event, resolve_sink
from .findings import SEVERITIES, finding_id, normalize_findings
from .prompts import SYSTEM_PROMPT, build_prompt
from .scanner import load_target_file, parse_stdin_record, run_scan
from .store import FindingStore, NullStore, RuttStore, resolve_store
from .wordlists import Wordlist, get_wordlist, list_wordlists, read_wordlist

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
    "Wordlist",
    "build_event",
    "build_prompt",
    "finding_id",
    "get_wordlist",
    "list_wordlists",
    "load_target_file",
    "normalize_findings",
    "parse_stdin_record",
    "read_wordlist",
    "resolve_sink",
    "resolve_store",
    "run_scan",
]
