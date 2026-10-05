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
from .auth import CookieJar, auth_tools
from .crawl import crawl_tools, hakrawler_tool, katana_tool
from .nuclei import nuclei_tool
from .xss import dalfox_tool
from .sqli import sqli_tool
from .params import param_discovery_tool
from .jsrecon import js_recon_tool
from .store import FindingStore, NullStore, RuttStore, resolve_store
from .wordlists import Wordlist, get_wordlist, list_wordlists, read_wordlist
from .write_policy import (
    WRITE_MAX_BYTES,
    WRITE_ROOT,
    WritePolicySandbox,
    harden_sandbox,
)

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
    "Wordlist",
    "build_event",
    "build_prompt",
    "finding_id",
    "get_wordlist",
    "list_wordlists",
    "available_prompt_packs",
    "get_prompt_pack",
    "load_prompt_pack",
    "WRITE_MAX_BYTES",
    "WRITE_ROOT",
    "WritePolicySandbox",
    "harden_sandbox",
    "load_target_file",
    "normalize_findings",
    "parse_stdin_record",
    "read_wordlist",
    "resolve_sink",
    "resolve_store",
    "run_scan",
    "CookieJar",
    "auth_tools",
    "crawl_tools",
    "hakrawler_tool",
    "katana_tool",
    "nuclei_tool",
    "dalfox_tool",
    "sqli_tool",
    "param_discovery_tool",
    "js_recon_tool",
]
