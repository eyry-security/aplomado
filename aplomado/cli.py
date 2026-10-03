"""Command-line interface.

Subcommands:
  scan    run an AI security review against one target
"""

from __future__ import annotations

import argparse
import json
import sys

from pinnace import DockerSandbox, LocalSandbox, PinnaceError, SandboxError

from . import __version__
from .scanner import AplomadoError, load_target_file, run_scan


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="aplomado",
        description="AI security scanner and reviewer, built on Pinnace.",
    )
    p.add_argument("--version", action="version", version=f"aplomado {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("scan", help="recon a target in a sandbox and report findings")
    sp.add_argument("--target", required=True, help="host or URL to scan")
    sp.add_argument(
        "--target-file",
        help="Vedette JSONL file; the first record becomes the target context",
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
        print(f"\n[{f['severity'].upper()}] {f['title']}")
        if f["detail"]:
            print("  " + f["detail"].replace("\n", "\n  "))
        if f["evidence"]:
            print("  evidence:")
            for line in f["evidence"].splitlines():
                print(f"  | {line}")


def cmd_scan(args) -> int:
    target = args.target
    context = None
    if args.target_file:
        try:
            target, context = load_target_file(args.target_file)
        except AplomadoError as e:
            _log(str(e))
            return 2

    try:
        sandbox = _make_sandbox(args)
    except (AplomadoError, SandboxError) as e:
        _log(str(e))
        return 2

    _log(f"scanning {target} (model: {args.model or '$PINNACE_MODEL'})")
    try:
        envelope = run_scan(
            target,
            model=args.model,
            sandbox=sandbox,
            target_context=context,
            max_turns=args.max_turns,
            session_id=args.session,
            log=_log,
        )
    except PinnaceError as e:
        _log(f"error: {e}")
        return 1
    finally:
        try:
            sandbox.close()
        except Exception:  # noqa: BLE001 - best-effort teardown
            pass

    if args.json:
        print(json.dumps(envelope, indent=2), flush=True)
    else:
        _print_findings(envelope)
    return 0


_DISPATCH = {"scan": cmd_scan}


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return _DISPATCH[args.cmd](args)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
