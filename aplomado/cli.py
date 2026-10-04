"""Aplomado command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Iterable

from . import __version__
from .config import ScanConfig
from .findings import ScanResult


def _common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--model", help="model name (env PINNACE_MODEL)")
    parser.add_argument("--api-key", help="API key (env OPENAI_API_KEY)")
    parser.add_argument("--base-url", help="OpenAI-compatible API base URL")
    parser.add_argument("--sandbox-image", help="scanner Docker image")
    parser.add_argument("--max-turns", type=int, help="maximum agent turns")
    parser.add_argument("--max-findings", type=int, help="maximum accepted findings")
    parser.add_argument("--rutt-dsn", help="persist results to this Rutt database")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aplomado", description="Sandboxed AI security reviewer")
    parser.add_argument("--version", action="version", version=f"aplomado {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan a target or a JSONL input stream")
    _common(scan)
    scan.add_argument("target", nargs="?", help="authorized hostname or HTTP(S) URL")
    scan.add_argument("--input", type=Path, help="Vedette JSONL or plain targets (default stdin)")
    scan.add_argument("--json", action="store_true", help="emit one JSON result per target")
    scan.add_argument("--quiet", action="store_true", help="suppress agent narration")

    config = sub.add_parser("config", help="show resolved configuration")
    _common(config)
    config.add_argument("--json", action="store_true")
    return parser


def _config(args: argparse.Namespace) -> ScanConfig:
    return ScanConfig.resolve(
        model=args.model, api_key=args.api_key, base_url=args.base_url,
        sandbox_image=args.sandbox_image, max_turns=args.max_turns,
        max_findings=args.max_findings, rutt_dsn=args.rutt_dsn,
    )


def _records(lines: Iterable[str]) -> Iterable[tuple[str, dict]]:
    for number, line in enumerate(lines, 1):
        line = line.strip()
        if not line:
            continue
        if not line.startswith("{"):
            yield line, {}
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"input line {number}: invalid JSON ({exc.msg})") from exc
        if not isinstance(record, dict):
            raise ValueError(f"input line {number}: expected a JSON object")
        target = record.get("url") or record.get("host") or record.get("input")
        if not isinstance(target, str) or not target.strip():
            raise ValueError(f"input line {number}: no url, host, or input field")
        yield target, record


def _narration(quiet: bool):
    if quiet:
        return None
    def emit(role: str, content: str) -> None:
        print(f"[{role}] {content}", file=sys.stderr, flush=True)
    return emit


def _print_result(result: ScanResult, machine: bool) -> None:
    if machine:
        print(json.dumps(result.to_dict(), separators=(",", ":")))
        return
    state = "ok" if result.ok else "failed"
    print(f"{result.target}: {state} — {result.summary or result.error or 'no summary'}")
    for finding in result.findings:
        print(f"  [{finding.severity.upper()}] {finding.title}")


def cmd_scan(args: argparse.Namespace) -> int:
    from .scanner import Scanner

    if args.target and args.input:
        raise ValueError("target and --input are mutually exclusive")
    opened = None
    if args.target:
        inputs = [(args.target, {})]
    else:
        if args.input:
            opened = args.input.open(encoding="utf-8")
            stream = opened
        else:
            if sys.stdin.isatty():
                raise ValueError("provide a target, --input, or piped stdin")
            stream = sys.stdin
        inputs = _records(stream)

    failed = False
    try:
        with Scanner(_config(args)) as scanner:
            for target, context in inputs:
                result = scanner.scan(target, context=context,
                                      on_message=_narration(args.quiet))
                _print_result(result, args.json)
                failed = failed or not result.ok
    finally:
        if opened:
            opened.close()
    return 1 if failed else 0


def cmd_config(args: argparse.Namespace) -> int:
    values = asdict(_config(args))
    if values["api_key"]:
        values["api_key"] = "***"
    if args.json:
        print(json.dumps(values, indent=2))
    else:
        for key, value in values.items():
            print(f"{key:24} {value}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return {"scan": cmd_scan, "config": cmd_config}[args.command](args)
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        print(f"[aplomado] {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
