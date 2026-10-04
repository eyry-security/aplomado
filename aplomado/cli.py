"""Command-line interface.

Subcommands:
  scan    run an AI security review against one target (or stream from stdin)
  config  show resolved configuration

Stdin ingestion (the pipeline use case):

    foretop | vedette | aplomado scan --event-sink -

When ``--target`` and ``--target-file`` are both absent and stdin is not a TTY,
Aplomado scans every valid Vedette JSONL record as it arrives — one isolated
agent run per input line. Malformed records are reported on stderr and do not
stop later records.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from pinnace import DockerSandbox, LocalSandbox

from . import __version__
from .scanner import AplomadoError, load_target_file, parse_stdin_record, run_scan
from .store import resolve_store
from .events import build_event, resolve_sink
from .findings import normalize_findings
from .wordlists import get_wordlist, list_wordlists


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="aplomado",
        description="AI security scanner and reviewer, built on Pinnace.",
    )
    p.add_argument("--version", action="version", version=f"aplomado {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("scan", help="recon a target in a sandbox and report findings")
    sp.add_argument("--target", default=None, help="host or URL to scan")
    sp.add_argument(
        "--target-file",
        help="Vedette JSONL file; the first record becomes the target context",
    )
    sp.add_argument(
        "--all",
        action="store_true",
        dest="scan_all",
        help=argparse.SUPPRESS,  # compatibility no-op: stdin always scans all records
    )
    sp.add_argument(
        "--model",
        default=None,
        help="model ref 'provider:model' (default: $PINNACE_MODEL)",
    )
    sp.add_argument("--sandbox", choices=["docker", "local"], default="docker")
    sp.add_argument(
        "--unsafe-ok",
        action="store_true",
        help="allow the local sandbox (dev/tests only)",
    )
    sp.add_argument(
        "--image", default="python:3.12-slim", help="docker image for the sandbox"
    )
    sp.add_argument(
        "--no-net", action="store_true", help="cut sandbox network egress"
    )
    sp.add_argument(
        "--workdir", default="./aplomado-work", help="workdir for the local sandbox"
    )
    sp.add_argument("--max-turns", type=int, default=30, help="agent turn limit")
    sp.add_argument("--session", help="persist/resume the transcript under this name")
    sp.add_argument("--json", action="store_true", help="print the findings as JSON")
    sp.add_argument(
        "--rutt-dsn",
        default=None,
        help="persist findings to Rutt (env $RUTT_DSN / $DATABASE_URL)",
    )
    sp.add_argument(
        "--event-sink",
        default=None,
        help="write aplomado.scan.completed events: file path, or '-' for stdout",
    )

    wp = sub.add_parser(
        "wordlists", help="list or print the curated discovery wordlists"
    )
    wp.add_argument(
        "name",
        nargs="?",
        help="logical list name; omit to show the installed catalog",
    )
    wp.add_argument(
        "--json", action="store_true", help="print catalog metadata as JSON"
    )

    sub.add_parser("config", help="show resolved configuration")

    return p


def _log(msg: str) -> None:
    print(f"[aplomado] {msg}", file=sys.stderr, flush=True)


def _make_sandbox(args):
    if args.sandbox == "local":
        if not args.unsafe_ok:
            _log("local sandbox runs model-generated commands on YOUR machine.")
            _log("re-run with --unsafe-ok if that's really what you want (dev/tests only).")
            raise AplomadoError("refusing local sandbox without --unsafe-ok")
        return LocalSandbox(args.workdir, unsafe_ok=True)
    return DockerSandbox(image=args.image, network="none" if args.no_net else None)


def _print_findings(env: dict) -> None:
    print(f"target:     {env['target']}")
    print(f"scanned_at: {env['scanned_at']}")
    print(f"summary:    {env['summary']}")
    findings = env["findings"]
    print(f"findings:   {len(findings)}")
    for f in findings:
        fid = f.get("id", "")[:12]
        prefix = f"[{f['severity'].upper()}]"
        print(f"\n{prefix} {f['title']}" + (f"  ({fid})" if fid else ""))
        if f.get("detail"):
            print("  " + f["detail"].replace("\n", "\n  "))
        if f.get("evidence"):
            print("  evidence:")
            for line in f["evidence"].splitlines():
                print(f"  | {line}")


def _iter_targets(args):
    """Yield ``(target, context, line_number, error)`` without buffering stdin."""
    if args.target:
        context = None
        if args.target_file:
            try:
                _, context = load_target_file(args.target_file)
            except AplomadoError:
                pass  # explicit target wins; file context is best-effort
        yield args.target, context, None, None
        return

    if args.target_file:
        target, context = load_target_file(args.target_file)
        yield target, context, None, None
        return

    if sys.stdin.isatty():
        raise AplomadoError(
            "no target given. Use --target, --target-file, or pipe Vedette JSONL to stdin"
        )

    saw_input = False
    for lineno, line in enumerate(sys.stdin, 1):
        line = line.strip()
        if not line:
            continue
        saw_input = True
        try:
            target, context = parse_stdin_record(line)
        except AplomadoError as exc:
            yield None, None, lineno, str(exc)
            continue
        yield target, context, lineno, None

    if not saw_input:
        raise AplomadoError("no targets found on stdin")


def _resolve_targets(args) -> list[tuple[str, str | None]]:
    """Compatibility helper that materializes valid targets for callers/tests."""
    targets = []
    for target, context, lineno, error in _iter_targets(args):
        if error:
            _log(f"stdin line {lineno}: {error} (skipped)")
            continue
        targets.append((target, context))
    if not targets:
        raise AplomadoError("no valid targets found on stdin")
    return targets


def _run_one(target: str, context: str | None, args, sandbox, store, sink,
             session_id: str | None = None) -> dict:
    """Run a single scan and return the envelope."""
    return run_scan(
        target,
        model=args.model,
        sandbox=sandbox,
        target_context=context,
        max_turns=args.max_turns,
        session_id=session_id if session_id is not None else args.session,
        store=store,
        event_sink=sink,
        log=_log,
    )


def cmd_scan(args) -> int:
    try:
        targets = _iter_targets(args)
        store = resolve_store(args.rutt_dsn)
        sink = resolve_sink(args.event_sink)
    except (AplomadoError, OSError, RuntimeError) as exc:
        _log(str(exc))
        return 2

    failed = False
    scanned = 0
    try:
        try:
            for target, context, lineno, input_error in targets:
                if input_error:
                    _log(f"stdin line {lineno}: {input_error} (skipped)")
                    failed = True
                    continue

                scanned += 1
                location = f"stdin line {lineno}" if lineno is not None else "explicit input"
                _log(
                    f"scanning {target} ({location}; model: "
                    f"{args.model or '$PINNACE_MODEL'})"
                )
                sandbox = None
                try:
                    sandbox = _make_sandbox(args)
                    session_id = (
                        f"{args.session}-{lineno}" if args.session and lineno is not None
                        else args.session
                    )
                    envelope = _run_one(
                        target, context, args, sandbox, store, sink,
                        session_id=session_id,
                    )
                except Exception as exc:  # isolate one record from the rest of the stream
                    _log(f"error scanning {target}: {type(exc).__name__}: {exc}")
                    failed = True
                    envelope = normalize_findings(
                        {"summary": "", "findings": []}, target
                    )
                    try:
                        sink.emit(build_event(envelope, ok=False, error=str(exc)))
                    except Exception as sink_exc:
                        _log(f"event sink failed for {target}: {sink_exc}")
                    continue
                finally:
                    if sandbox is not None:
                        try:
                            sandbox.close()
                        except Exception:  # noqa: BLE001
                            pass

                # Stdout event sinks own stdout so the pipeline remains JSONL.
                if args.event_sink == "-":
                    continue
                if args.json:
                    print(json.dumps(envelope, separators=(",", ":")), flush=True)
                else:
                    if scanned > 1:
                        print()
                    _print_findings(envelope)
        except AplomadoError as exc:
            _log(str(exc))
            return 2
    finally:
        try:
            store.close()
        except Exception:  # noqa: BLE001
            pass
        try:
            sink.close()
        except Exception:  # noqa: BLE001
            pass

    if scanned == 0:
        _log("no valid targets found on stdin")
        return 2
    return 1 if failed else 0


def cmd_config(args) -> int:
    """Show resolved configuration (model, sandbox, store)."""
    model = os.environ.get("PINNACE_MODEL", "anthropic:claude-opus-4-6")
    rutt_dsn = os.environ.get("RUTT_DSN") or os.environ.get("DATABASE_URL") or "(not set)"
    print(f"  model              {model}")
    print(f"  default sandbox    docker (python:3.12-slim)")
    print(f"  rutt_dsn           {rutt_dsn}")
    return 0


def cmd_wordlists(args) -> int:
    """List bundled wordlists or print one as raw, pipe-friendly text."""
    if args.name:
        try:
            wordlist = get_wordlist(args.name)
        except ValueError as exc:
            _log(str(exc))
            return 2
        if args.json:
            payload = wordlist.as_dict()
            payload["words"] = list(wordlist.entries())
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            sys.stdout.write(wordlist.read_text())
        return 0

    catalog = [wordlist.as_dict() for wordlist in list_wordlists()]
    if args.json:
        print(json.dumps(catalog, indent=2, sort_keys=True))
        return 0

    for item in catalog:
        print(
            f"{item['name']:<16} {item['kind']:<9} "
            f"{item['entries']:>3}  {item['description']}"
        )
    return 0


_DISPATCH = {"scan": cmd_scan, "config": cmd_config, "wordlists": cmd_wordlists}


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return _DISPATCH[args.cmd](args)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
