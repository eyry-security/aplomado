"""Command-line interface.

Subcommands:
  scan    run an AI security review against one target (or stream from stdin)
  config  show resolved configuration

Stdin ingestion (the pipeline use case):

    foretop | vedette | aplomado scan --event-sink -

When ``--target`` and ``--target-file`` are both absent and stdin is not a TTY,
Aplomado reads Vedette JSONL from stdin.  By default only the **first record**
is scanned (safe for exploratory use).  Pass ``--all`` to scan every record —
one agent run per input line.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from pinnace import DockerSandbox, LocalSandbox, PinnaceError, SandboxError

from . import __version__
from .scanner import AplomadoError, load_target_file, parse_stdin_record, run_scan
from .store import resolve_store
from .events import resolve_sink


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
        help="scan every record from stdin (default: first record only)",
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


def _resolve_targets(args) -> list[tuple[str, str | None]]:
    """Resolve the scan target(s) from CLI args or stdin.

    Returns a list of (target, context_or_None) tuples.
    """
    # Explicit --target
    if args.target:
        context = None
        if args.target_file:
            try:
                _, context = load_target_file(args.target_file)
            except AplomadoError:
                pass  # target wins; file context is best-effort
        return [(args.target, context)]

    # Explicit --target-file (first record)
    if args.target_file:
        target, context = load_target_file(args.target_file)
        return [(target, context)]

    # stdin ingestion
    if sys.stdin.isatty():
        raise AplomadoError(
            "no target given. Use --target, --target-file, or pipe Vedette JSONL to stdin"
        )

    targets: list[tuple[str, str | None]] = []
    for lineno, line in enumerate(sys.stdin, 1):
        line = line.strip()
        if not line:
            continue
        try:
            target, context = parse_stdin_record(line)
        except AplomadoError as e:
            _log(f"stdin line {lineno}: {e} (skipped)")
            continue
        targets.append((target, context))
        if not args.scan_all:
            break  # first record only

    if not targets:
        raise AplomadoError("no valid targets found on stdin")
    return targets


def _run_one(target: str, context: str | None, args, sandbox, store, sink) -> dict:
    """Run a single scan and return the envelope."""
    return run_scan(
        target,
        model=args.model,
        sandbox=sandbox,
        target_context=context,
        max_turns=args.max_turns,
        session_id=args.session,
        store=store,
        event_sink=sink,
        log=_log,
    )


def cmd_scan(args) -> int:
    try:
        targets = _resolve_targets(args)
    except AplomadoError as e:
        _log(str(e))
        return 2

    try:
        sandbox = _make_sandbox(args)
    except (AplomadoError, SandboxError) as e:
        _log(str(e))
        return 2

    store = resolve_store(args.rutt_dsn)
    sink = resolve_sink(args.event_sink)

    failed = False
    try:
        for i, (target, context) in enumerate(targets):
            if len(targets) > 1:
                _log(f"[{i + 1}/{len(targets)}] scanning {target}")
            else:
                _log(f"scanning {target} (model: {args.model or '$PINNACE_MODEL'})")
            try:
                envelope = _run_one(target, context, args, sandbox, store, sink)
            except PinnaceError as e:
                _log(f"error scanning {target}: {e}")
                failed = True
                continue

            if args.json:
                print(json.dumps(envelope, indent=2), flush=True)
            else:
                _print_findings(envelope)
                if i < len(targets) - 1:
                    print()  # blank line between results
    finally:
        try:
            sandbox.close()
        except Exception:  # noqa: BLE001
            pass
        try:
            store.close()
        except Exception:  # noqa: BLE001
            pass
        try:
            sink.close()
        except Exception:  # noqa: BLE001
            pass

    return 1 if failed else 0


def cmd_config(args) -> int:
    """Show resolved configuration (model, sandbox, store)."""
    model = os.environ.get("PINNACE_MODEL", "anthropic:claude-opus-4-6")
    rutt_dsn = os.environ.get("RUTT_DSN") or os.environ.get("DATABASE_URL") or "(not set)"
    print(f"  model              {model}")
    print(f"  default sandbox    docker (python:3.12-slim)")
    print(f"  rutt_dsn           {rutt_dsn}")
    return 0


_DISPATCH = {"scan": cmd_scan, "config": cmd_config}


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return _DISPATCH[args.cmd](args)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
