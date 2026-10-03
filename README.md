# aplomado

> AI security scanner and reviewer, built on Pinnace (Python).

Part of **[Eyry](https://eyry.io)**: open-source, agentic recon and offensive security tooling for
bug bounty hunters, red teamers, and pentesters. Aplomado is the strike: point it at a target, it
investigates inside a sandbox and reports findings.

## Status

**v0.** One command, one target, one findings report. Queue/worker mode and Postgres storage land
later, with Quarterdeck orchestration.

## What it does

- Takes a host/URL (or one Vedette prober record) as a target
- Runs a security-reviewer agent on it inside an isolated Docker sandbox via Pinnace
- Does light recon with what's actually in the image — DNS, headers, TLS, common files — and is
  honest about tool limits (no pretending nmap exists in a slim image)
- Emits findings in a shared JSON schema (see below)

Only scan targets you're authorized to test. Aplomado does recon, not exploitation, but pointing
any scanner at someone else's infrastructure without permission is on you.

## Install

```bash
pip install -e .            # the aplomado CLI
pip install -e ../pinnace   # not on PyPI yet; needed for local dev
pip install "pinnace[anthropic]"  # or pinnace[openai], for a real model
```

Set your model the Pinnace way: `export PINNACE_MODEL=anthropic:claude-sonnet-4-5`
(see [pinnace](https://github.com/eyry-security/pinnace)).

## Quickstart

```bash
# scan one target, findings as JSON
aplomado scan --target https://example.com --json

# scan with the context Vedette already gathered (first JSONL record)
vedette -l hosts.txt -o results.jsonl
aplomado scan --target https://example.com --target-file results.jsonl --json

# human-readable report instead of JSON
aplomado scan --target https://example.com

# no Docker? run the sandbox on your machine (dev only — reads the warning)
aplomado scan --target https://example.com --sandbox local --unsafe-ok
```

## Findings schema

Every scan returns this envelope — it seeds the suite's shared findings schema, so Vedette's
prober output flows into Aplomado and Aplomado's findings flow on to Quarterdeck:

```json
{
  "target": "https://example.com",
  "summary": "One paragraph: the overall verdict.",
  "scanned_at": "2026-10-03T23:40:00+00:00",
  "findings": [
    {
      "severity": "critical|high|medium|low|info",
      "title": "Server header leaks version",
      "detail": "nginx/1.25.3 exposed; check for known CVEs in this build.",
      "evidence": "Server: nginx/1.25.3"
    }
  ]
}
```

The model is told to call `finish()` with exactly this shape, but models drift — so
`aplomado.findings.normalize_findings()` coerces whatever arrives into a valid envelope: unknown
severities fall back to `info`, missing fields get defaults, and garbage output becomes an empty
findings list with a summary instead of a crash. Use it any time you consume model output.

## CLI reference

```
aplomado scan --target <host-or-URL> [--target-file vedette.jsonl]
    [--model provider:model] [--sandbox docker|local] [--unsafe-ok]
    [--image IMG] [--no-net] [--max-turns N] [--session NAME] [--json]
```

| Flag | Default | Notes |
|---|---|---|
| `--target` | (required) | Host or URL. Overridden by `--target-file`'s record if given |
| `--target-file` | – | Vedette JSONL; the first record supplies the target label + context |
| `--model` | `$PINNACE_MODEL` | `provider:model`, e.g. `anthropic:claude-sonnet-4-5` |
| `--sandbox` | `docker` | `local` needs `--unsafe-ok` (dev/tests only) |
| `--image` | `python:3.12-slim` | Docker image for the sandbox |
| `--no-net` | off | Cut sandbox network egress |
| `--max-turns` | 30 | Agent turn limit |
| `--session` | – | Persist/resume the transcript under this name |
| `--json` | off | Print the findings envelope as JSON to stdout |

Exit codes: `0` scan completed (even with critical findings — parse `--json` output for those),
`2` bad input/sandbox setup, `1` agent runtime error, `130` interrupted.

## Python API

```python
from aplomado import run_scan, normalize_findings

envelope = run_scan(
    "https://example.com",
    model="anthropic:claude-sonnet-4-5",
    max_turns=20,
)
print(envelope["findings"])
```

## Tests

```bash
pytest
```

Scripted fake models, `LocalSandbox` — no Docker, no API keys, no network.

## The Eyry suite

- **Vedette**: fast, multi-threaded HTTP prober (Rust) — feeds Aplomado targets
- **Foretop**: configurable producer of new hosts from pluggable feeds (certstream first)
- **Purser**: Redis-backed priority queue and work distributor (hot/warm/cold/DLQ)
- **Pinnace**: general multi-turn agent runtime with compaction, tools, and a Docker sandbox
- **Aplomado**: AI security scanner and reviewer built on Pinnace (this repo)
- **Quarterdeck**: agent control plane, scheduler, events, IRC-style chat, and pipeline orchestration

## License

MIT, Eyry.
