"""Coverage ledger and prompt for the partial-finish salvage path.

When a provider keeps rejecting a scan's tool-message pairing, the run cannot
continue safely. The salvage path builds a fresh, minimal request from the
coverage the agent genuinely observed: the scan target, the tool calls that
actually ran, the persisted todo ledger, and the usage records.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from urllib.parse import urlsplit

_URL_RE = re.compile(r"https?://[^\s\"'<>\\]+")
_TARGET_RE = re.compile(r"^\s*TARGET:\s*(.+?)\s*$", re.MULTILINE)
_HOST_KEYS = {"url", "target", "host", "hostname", "endpoint"}
_MAX_HOSTS = 12
_MAX_TODOS = 8

_CLASS_TOOL_MAP = {
    "sqli": "SQL injection",
    "dalfox": "XSS",
}
_CLASS_KEYWORDS = (
    ("sql injection", "SQL injection"),
    ("sqli", "SQL injection"),
    ("sqlmap", "SQL injection"),
    ("cross-site scripting", "XSS"),
    ("xss", "XSS"),
    ("local file inclusion", "LFI"),
    ("path traversal", "LFI"),
    ("lfi", "LFI"),
    ("remote code execution", "RCE"),
    ("command injection", "RCE"),
    ("rce", "RCE"),
    ("auth bypass", "auth bypass"),
    ("auth-bypass", "auth bypass"),
    ("idor", "auth bypass"),
    ("bola", "auth bypass"),
    ("access control", "auth bypass"),
)


def target_from_prompt(prompt: str) -> str:
    """Read the TARGET line from the rendered run prompt."""
    match = _TARGET_RE.search(prompt or "")
    return match.group(1).strip() if match else ""


def _host_from_url(value: str) -> str:
    match = _URL_RE.search(value)
    if not match:
        return ""
    return urlsplit(match.group(0)).netloc


def _host_from_value(value: str) -> str:
    text = value.strip()
    if not text:
        return ""
    host = _host_from_url(text)
    if host:
        return host
    candidate = text.split()[0]
    if "/" not in candidate and "@" not in candidate and " " not in candidate:
        if "." in candidate or candidate.startswith("["):
            return candidate
    return ""


def _collect_hosts(value: object, hosts: set[str]) -> None:
    if isinstance(value, str):
        for match in _URL_RE.findall(value):
            host = _host_from_url(match)
            if host:
                hosts.add(host)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).lower() in _HOST_KEYS and isinstance(item, str):
                host = _host_from_value(item)
                if host:
                    hosts.add(host)
            _collect_hosts(item, hosts)
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            _collect_hosts(item, hosts)


def _tool_calls(messages: list) -> list[dict]:
    calls: list[dict] = []
    for message in messages or []:
        for call in getattr(message, "tool_calls", None) or []:
            if isinstance(call, dict):
                calls.append(call)
    return calls


def _attempted_classes(calls: list[dict]) -> list[str]:
    classes: set[str] = set()
    for call in calls:
        name = str(call.get("name") or "").lower()
        mapped = _CLASS_TOOL_MAP.get(name)
        if mapped:
            classes.add(mapped)
        text = f"{name} {json.dumps(call.get('args') or {}, default=str)}".lower()
        for needle, label in _CLASS_KEYWORDS:
            if needle in text:
                classes.add(label)
    return sorted(classes)


def _todo_ledger(todos: list[dict]) -> str:
    if not todos:
        return "todo ledger: empty"
    done = sum(1 for item in todos if item.get("status") == "done")
    skipped = sum(1 for item in todos if item.get("status") == "skipped")
    open_count = len(todos) - done - skipped
    summary = (
        f"todo ledger: done={done} open={open_count} total={len(todos)}"
    )
    if skipped:
        summary += f" skipped={skipped}"
    highlights = []
    for item in todos:
        status = item.get("status")
        note = item.get("note") or ""
        if status in {"done", "skipped", "in_progress"} or note:
            line = f"[{status or 'pending'}] {item.get('text', '')}"
            if note:
                line += f" ({note})"
            highlights.append(line)
        if len(highlights) >= _MAX_TODOS:
            break
    if highlights:
        summary += " — " + "; ".join(highlights)
    return summary


def _usage_summary(records: list[dict]) -> str:
    if not records:
        return ""
    kinds = Counter(
        str(record.get("call_kind") or "model_call")
        for record in records
        if isinstance(record, dict)
    )
    detail = ", ".join(f"{kind}={count}" for kind, count in sorted(kinds.items()))
    return f"model calls recorded={len(records)} ({detail})"


def build_coverage_statement(
    *,
    target: str,
    messages: list,
    todos: list[dict],
    usage_records: list[dict],
) -> str:
    """Describe only the coverage the agent actually observed."""
    calls = _tool_calls(messages)
    hosts: set[str] = set()
    checks: Counter[str] = Counter()
    for call in calls:
        name = str(call.get("name") or "").strip()
        if not name or name == "finish":
            continue
        checks[name] += 1
        _collect_hosts(call.get("args") or {}, hosts)

    parts = [f"target {target or 'unknown'}"]
    if hosts:
        selected = sorted(hosts)[:_MAX_HOSTS]
        parts.append("hosts in completed tool calls: " + ", ".join(selected))
    else:
        parts.append("hosts in completed tool calls: none")
    if checks:
        detail = ", ".join(
            f"{name} x{count}" for name, count in sorted(checks.items())
        )
        parts.append("tools invoked: " + detail)
    else:
        parts.append("tools invoked: none")
    parts.append(_todo_ledger(todos))
    classes = _attempted_classes(calls)
    parts.append(
        "vulnerability classes attempted: "
        + (", ".join(classes) if classes else "none")
    )
    usage = _usage_summary(usage_records)
    if usage:
        parts.append(usage)
    return "Partial-scan coverage: " + "; ".join(parts) + "."


def build_salvage_prompt(coverage: str) -> str:
    """Build the single user message for the fresh salvage request."""
    return (
        "PARTIAL-SCAN SALVAGE REQUEST\n\n"
        "The provider rejected this run's tool-message pairing after every "
        "retry, so the scan cannot continue. Do not run any more tests or "
        "call any tool except finish(), and call finish() exactly once now.\n\n"
        "Coverage ledger (the only run state available in this fresh "
        "context):\n"
        f"{coverage}\n\n"
        "Return one JSON object as the finish() argument. Include only "
        "findings you actually confirmed before the failure; never invent "
        "evidence or coverage. The summary must state plainly that the run "
        "is PARTIAL, must carry the coverage statement above verbatim, and "
        "must give a disposition for every vulnerability class attempted "
        "(for example: SQL injection — attempted, no confirmed finding)."
    )
