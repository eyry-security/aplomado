# aplomado

> AI security scanner and reviewer, built on Pinnace (Python).

Part of **[Eyry](https://eyry.io)**: open-source, agentic recon and offensive security tooling for authorized bug bounty, red-team, and penetration-testing work.

## Status

🚧 **Early development.** Aplomado can run a sandboxed review of one target, consume Vedette JSONL, emit structured findings, and optionally persist through Rutt. APIs will change.

## Install

Requires Python 3.10+, Docker, an OpenAI-compatible API key, and the sibling Pinnace package.

```bash
pip install -e ../pinnace -e .
docker build -t aplomado-sandbox:latest .
export OPENAI_API_KEY=...
```

## Usage

Only scan systems you own or are explicitly authorized to test.

```bash
# One target
aplomado scan https://app.example.com

# Machine-readable result
aplomado scan app.example.com --json --quiet

# Vedette pipeline or saved JSONL
vedette < hosts.txt | aplomado scan --json --quiet
aplomado scan --input vedette.jsonl --json

# Inspect effective settings (API keys are masked)
aplomado config
```

A JSON scan result contains `target`, `ok`, `summary`, validated and deduplicated `findings`, `error`, and `metadata`. Findings include severity, confidence, description, evidence, remediation, references, and a stable fingerprint. Narration is written to stderr; `--json` reserves stdout for JSONL.

Set `RUTT_DSN` or pass `--rutt-dsn` to store findings through Rutt's public API. The Rutt package and initialized schema must be available. Without a DSN, Aplomado runs without persistence.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `PINNACE_MODEL` | `gpt-4o` | OpenAI-compatible model |
| `OPENAI_API_KEY` | empty | Provider API key |
| `OPENAI_BASE_URL` | empty | Alternate compatible endpoint |
| `APLOMADO_SANDBOX_IMAGE` | `aplomado-sandbox:latest` | Ephemeral scanner image |
| `APLOMADO_SANDBOX_TIMEOUT` | `180` | Per-command timeout in seconds |
| `APLOMADO_SANDBOX_MEMORY` | `1g` | Container memory cap |
| `APLOMADO_MAX_TURNS` | `40` | Agent turn limit |
| `APLOMADO_MAX_FINDINGS` | `50` | Accepted findings per target |
| `RUTT_DSN` / `DATABASE_URL` | empty | Optional persistence DSN |

Scanner containers have network access because probes must reach the authorized target. They are ephemeral and resource-capped, but operators remain responsible for scope and authorization.

## The Eyry suite

- **Vedette**: fast, multi-threaded HTTP prober (Rust)
- **Foretop**: configurable producer of new hosts from pluggable feeds
- **Purser**: Redis-backed priority queue and work distributor
- **Pinnace**: multi-turn agent runtime with compaction, tools, and Docker sandbox
- **Aplomado**: AI security scanner and reviewer built on Pinnace
- **Quarterdeck**: agent control plane and pipeline orchestrator

## License

MIT, Eyry.
