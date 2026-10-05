"""Run an Aplomado scan: a PinnaceAgent with the security-reviewer prompt."""

from __future__ import annotations

import json

from pinnace import PinnaceAgent
from pinnace.sandbox import DockerSandbox, SandboxError

from .findings import normalize_findings
from .fuzz import ffuf_tool
from .prompts import PromptPack, build_prompt, get_prompt_pack
from .thinking import ThinkingModel, prepare_thinking_model
from .store import FindingStore, NullStore, resolve_store
from .events import EventSink, NullSink, build_event
from .write_policy import harden_sandbox
from .command_policy import harden_commands
from .scratchpad import scratchpad_tools
from .auth import CookieJar, auth_tools
from .crawl import crawl_tools
from .nuclei import nuclei_tool
from .xss import dalfox_tool
from .sqli import sqli_tool
from .params import param_discovery_tool
from .jsrecon import js_recon_tool


class AplomadoError(RuntimeError):
    """Aplomado-side failures: bad input, missing files, scan setup."""


def parse_stdin_record(line: str) -> tuple[str, str | None]:
    """Parse one line from stdin into (target, context_or_None).

    Accepts Vedette JSONL (extracts url/host/input + builds context block)
    or a bare hostname/URL string.

    Raises AplomadoError on unparseable input.
    """
    line = line.strip()
    if not line:
        raise AplomadoError("empty line")
    if line.startswith(("{", "[")):
        try:
            record = json.loads(line)
        except json.JSONDecodeError as e:
            raise AplomadoError(f"invalid JSON: {e}") from e
        if not isinstance(record, dict):
            raise AplomadoError("expected a JSON object")
    else:
        # Bare hostname or URL
        return line, None
    label = (
        record.get("url") or record.get("host") or record.get("input")
    )
    if not label:
        raise AplomadoError("no url, host, or input field")
    context = "Target context (one Vedette prober record):\n" + json.dumps(
        record, indent=2
    )
    return str(label), context


def load_target_file(path: str) -> tuple[str, str]:
    """Read one Vedette JSONL record; return (target label, context block).

    Takes the first non-empty line. The label prefers url > host > input.
    Raises AplomadoError on missing file, empty file, or bad JSON.
    """
    try:
        with open(path, encoding="utf-8") as fh:
            line = next((ln.strip() for ln in fh if ln.strip()), "")
    except OSError as e:
        raise AplomadoError(f"can't read target file {path!r}: {e}") from e
    if not line:
        raise AplomadoError(f"target file {path!r} is empty")
    try:
        record = json.loads(line)
    except json.JSONDecodeError as e:
        raise AplomadoError(f"target file {path!r}: first line isn't JSON: {e}") from e
    if not isinstance(record, dict):
        raise AplomadoError(f"target file {path!r}: first line isn't a JSON object")
    label = (
        record.get("url") or record.get("host") or record.get("input") or line[:120]
    )
    context = "Target context (one Vedette prober record):\n" + json.dumps(
        record, indent=2
    )
    return str(label), context


def _unwrap_finish_payload(structured: object) -> object:
    """Undo pinnace's finish() wrapping.

    finish() takes a JSON object as a string; when the model hands it something
    that isn't valid JSON, parse_finish returns {"result": <raw string>}.
    Unwrap that single-key form so normalization sees the raw payload.
    """
    if isinstance(structured, dict) and set(structured) == {"result"}:
        return structured["result"]
    return structured


def _default_sandbox():
    """Create the default DockerSandbox.

    Mirrors the helpful error PinnaceAgent used to raise itself: DockerSandbox
    construction fails fast when the daemon isn't reachable, so say so plainly
    and point at the explicit-sandbox escape hatch.
    """
    try:
        return DockerSandbox()
    except SandboxError as e:
        raise AplomadoError(
            f"{e} Pass sandbox= explicitly (e.g. LocalSandbox for dev)."
        ) from e


def _bughunter_tools(sandbox) -> list:
    """Build the bug-hunter toolset sharing one auth cookie jar.

    The jar is shared so a single set_auth_session call propagates to
    every tool that accepts credentials (katana, nuclei, dalfox).
    """
    jar = CookieJar()
    return (
        auth_tools(jar)
        + crawl_tools(sandbox, jar)
        + [
            nuclei_tool(sandbox, jar),
            dalfox_tool(sandbox, jar),
            sqli_tool(sandbox, jar),
            param_discovery_tool(sandbox, jar),
            js_recon_tool(sandbox, jar),
        ]
    )


def run_scan(
    target: str,
    *,
    model=None,
    sandbox=None,
    target_context: str | None = None,
    max_turns: int = 30,
    session_id: str | None = None,
    session_store=None,
    store: FindingStore | None = None,
    event_sink: EventSink | None = None,
    prompt_pack: PromptPack | None = None,
    thinking: str | None = None,
    log=None,
) -> dict:
    """Run one scan and return the normalized findings envelope.

    model: a langchain chat model, a "provider:model" ref, or None (then
        PinnaceAgent falls back to $PINNACE_MODEL / its default).
    sandbox: a pinnace Sandbox, or None for the default Docker sandbox.
    store: a FindingStore to persist results to (NullStore if None).
    event_sink: an EventSink to emit an aplomado.scan.completed event to.
    prompt_pack: versioned system/run prompts (the default pack if None).
    thinking: opt-in reasoning narration: ``"compact"`` or ``"verbose"``.
        Reasoning is sent only to ``log`` and is bounded in both modes.
    """
    prompts = prompt_pack or get_prompt_pack()
    effective_log = log or (lambda *args: None)
    model = prepare_thinking_model(model, thinking)
    # The ffuf tool needs the same sandbox instance the agent runs in, so the
    # default DockerSandbox is built here (not inside PinnaceAgent) and torn
    # down after the run.
    own_sandbox = False
    if sandbox is None:
        sandbox = _default_sandbox()
        own_sandbox = True
    # Harden the sandbox: writes jailed to scratch/, sensitive paths blocked,
    # commands restricted to allowlist.
    sandbox = harden_commands(harden_sandbox(sandbox))
    try:
        agent = PinnaceAgent(
            model=model,
            sandbox=sandbox,
            tools=(
                [ffuf_tool(sandbox)]
                + _bughunter_tools(sandbox)
                + scratchpad_tools(lambda: sandbox)
            ),
            system_prompt=prompts.system_prompt,
            max_turns=max_turns,
            session_id=session_id,
            session_store=session_store,
            log=effective_log,
        )
        if thinking is not None:
            # Keep agent.model concrete for Pinnace capability checks; only observe
            # the final tool-bound invocation layer.
            agent.bound = ThinkingModel(agent.bound, thinking, effective_log)
        result = agent.run(build_prompt(target, target_context, prompts))
    finally:
        if own_sandbox:
            try:
                sandbox.close()
            except Exception:  # noqa: BLE001 - best-effort teardown
                pass

    ok = True
    error = None
    if result.finished:
        envelope = normalize_findings(_unwrap_finish_payload(result.structured), target)
    else:
        envelope = normalize_findings(
            {
                "summary": result.final or "scan ended without calling finish()",
                "findings": [],
            },
            target,
        )
        if not result.final:
            ok = False
            error = "scan ended without calling finish()"

    if store is not None:
        store.save(envelope)

    if event_sink is not None:
        event_sink.emit(build_event(envelope, ok=ok, error=error))

    return envelope
