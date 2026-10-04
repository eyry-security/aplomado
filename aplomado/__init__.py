"""aplomado: AI security scanner and reviewer built on Pinnace."""

from .events import EventSink, FileSink, NullSink as NullEventSink, StdoutSink, build_event, resolve_sink
from .findings import SEVERITIES, finding_id, normalize_findings
from .prompts import (
    DEFAULT_PROMPT_PACK_ID,
    SYSTEM_PROMPT,
    PromptError,
    PromptPack,
    available_prompt_packs,
    build_prompt,
    get_prompt_pack,
    load_prompt_pack,
)
from .scanner import load_target_file, parse_stdin_record, run_scan
from .store import FindingStore, NullStore, RuttStore, resolve_store

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "DEFAULT_PROMPT_PACK_ID",
    "EventSink",
    "FileSink",
    "FindingStore",
    "NullEventSink",
    "NullStore",
    "PromptError",
    "PromptPack",
    "RuttStore",
    "SEVERITIES",
    "SYSTEM_PROMPT",
    "StdoutSink",
    "available_prompt_packs",
    "build_event",
    "build_prompt",
    "finding_id",
    "get_prompt_pack",
    "load_prompt_pack",
    "load_target_file",
    "normalize_findings",
    "parse_stdin_record",
    "resolve_sink",
    "resolve_store",
    "run_scan",
]
