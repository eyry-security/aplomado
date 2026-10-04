# aplomado

> The aplomado falcon: small, fast, strikes precisely. An AI security reviewer built on Pinnace.

Part of **[Eyry](https://eyry.io)** — open-source, agentic recon and offensive security tooling for authorized bug bounty, red-team, and penetration-testing work.

**Early development — APIs will change.** Aplomado is mid-convergence: the scanner currently runs against the pre-convergence Pinnace scaffold API and moves to the converged Pinnace API (`PinnaceAgent`, `AgentConfig`, `finish()`) as the branches land. Every command below is verified against the current scaffold code.

**Use only against systems you are authorized to test.**

## What it does

- **Target in, findings out.** Hand it one hostname or URL; a sandboxed Pinnace agent investigates and returns structured findings
- **Consumes Vedette output.** Reads targets from a positional arg, `--input` (Vedette JSONL or plain targets, one per line), or piped stdin. JSONL records pull the target from `url`, `host`, or `input`; lines that aren't JSON are treated as targets directly
- **Evidence-driven review policy.** The agent's system prompt is fixed: stay within the exact target, non-destructive checks only, no DoS, no credential attacks, no persistence, no exfiltration. It distinguishes confirmed findings from hypotheses and refuses to report generic best-practice advice as a vulnerability
- **Validated, deduplicated findings.** Each finding carries severity (`info`/`low`/`medium`/`high`/`critical`), confidence (`low`/`medium`/`high`/`confirmed`), title, description, evidence, remediation, references, and a stable `fingerprint` (sha256 of title + evidence). Malformed findings are rejected and reported in `metadata.rejected_findings`, not silently dropped
- **Machine-readable results.** `--json` emits one compact JSON result per target on stdout; narration goes to stderr
- **Rutt persistence (optional).** With `RUTT_DSN` set, findings land in Rutt via its public lifecycle API (source `aplomado`); targets with no findings are recorded as reviewed
- **Real scanner sandbox.** The Docker image ships nuclei and nmap, runs as a non-root `scanner` user, and is memory-capped (1g default). Network is on because probes must reach the authorized target — operators remain responsible for scope and authorization

## Install

Requires Python 3.10+, Docker, the sibling Pinnace package, and a provider API key.

```bash
pip install -e ../pinnace -e .
docker build -t aplomado-sandbox:latest .

# suite default model (explicit — the scaffold's hardcoded fallback is still
# gpt-4o and gets replaced during convergence; see Configuration)
export PINNACE_MODEL=anthropic:claude-opus-4-6
export ANTHROPIC_API_KEY=...
```

## Quickstart

```bash
# one target
aplomado scan https://app.example.com

# machine-readable result, quiet narration
aplomado scan app.example.com --json --quiet

# a Vedette run piped straight in
vedette < hosts.txt | aplomado scan --json --quiet

# saved JSONL
aplomado scan --input vedette.jsonl --json

# inspect effective settings (API keys are masked)
aplomado config
aplomado config --json
```

Targets are normalized and validated: hostname or `http(s)` URL, no credentials, no fragments. A bare `app.example.com` becomes `https://app.example.com`.

## CLI

```
aplomado scan [target] [--input FILE] [--json] [--quiet]
    [--model provider:model] [--api-key KEY] [--base-url URL]
    [--sandbox-image IMG] [--max-turns N] [--max-findings N]
    [--rutt-dsn DSN]
aplomado config [--json] [same --model/--api-key/... overrides]
```

`target` and `--input` are mutually exclusive; with neither, targets are read from piped stdin. Exit code is 1 if any target's scan failed, 2 on usage errors.

## Findings schema

One result per target:

```json
{
  "target": "https://app.example.com",
  "ok": true,
  "summary": "Exposed .git directory allows source disclosure.",
  "findings": [
    {
      "title": "Exposed .git directory",
      "severity": "high",
      "confidence": "confirmed",
      "description": "The .git directory is served over HTTP, exposing the full repository.",
      "evidence": "GET /.git/HEAD returned 200 with 'ref: refs/heads/main'",
      "remediation": "Block access to /.git at the web server or remove it from the document root.",
      "references": ["https://owasp.org/www-community/attacks/..."],
      "fingerprint": "9f2c...e1"
    }
  ],
  "error": null,
  "metadata": {}
}
```

Without `--json` you get the human form: `{target}: ok — {summary}` followed by one `  [SEVERITY] title` line per finding. Invalid agent output surfaces as `ok: false` with `error` set — a scan that can't parse never looks clean.

## Configuration

| Variable | Scaffold default | Purpose |
|---|---|---|
| `PINNACE_MODEL` | `gpt-4o` (stale — see below) | Model ref the agent runs on |
| `OPENAI_API_KEY` | empty | Provider API key |
| `OPENAI_BASE_URL` | empty | Alternate OpenAI-compatible endpoint |
| `APLOMADO_SANDBOX_IMAGE` | `aplomado-sandbox:latest` | Ephemeral scanner image |
| `APLOMADO_SANDBOX_TIMEOUT` | `180` | Per-command timeout, seconds |
| `APLOMADO_SANDBOX_MEMORY` | `1g` | Container memory cap |
| `APLOMADO_MAX_TURNS` | `40` | Agent turn limit |
| `APLOMADO_MAX_FINDINGS` | `50` | Accepted findings per target |
| `RUTT_DSN` / `DATABASE_URL` | empty | Optional persistence DSN |

**Model note:** the suite-wide decision is `claude-opus-4-6` via the Anthropic API (`DIRECTION.md` decision 1). The scaffold still falls back to `gpt-4o` when `PINNACE_MODEL` is unset — stale, and replaced during convergence. Set `PINNACE_MODEL=anthropic:claude-opus-4-6` (and `ANTHROPIC_API_KEY`) until then.

## Where it fits

Aplomado takes Vedette output and emits findings into Rutt: Foretop notices a new host, Purser queues it, Vedette probes it, Rutt records it, Aplomado reviews it. Quarterdeck will schedule Aplomado reviews as a pipeline stage and route its findings to chat.

## The Eyry suite

- **eyry**: one CLI that wires the data plane together — discover → queue → probe → store
- **vedette**: fast, multi-threaded HTTP prober (Rust) — confirms what's live and fingerprints it
- **foretop**: pluggable live feed of new hosts, starting with Certificate Transparency logs
- **purser**: Redis-backed priority work queue — hot/warm/cold lanes, retries, dead-letter queue
- **rutt**: Postgres store for the host lifecycle (discovered → probed → reviewed) with an append-only scan log
- **pinnace**: general multi-turn agent runtime — compaction, tools, Docker sandbox, resumable sessions
- **aplomado**: AI security reviewer built on Pinnace — target in, structured findings out
- **quarterdeck**: agent control plane — scheduler, wake/sleep, identity and memory, IRC-style chat, ChatOps, pipeline orchestration

## Roadmap

- Converge on one Aplomado base (compare `claude/aplomado-scaffold` against `vector/dev-aplomado-v0`; the latter is already built on the converged Pinnace API)
- Port the scaffold's `store.py` and `prompts.py` into the converged base
- Build the full review agent on the converged Pinnace API (`PinnaceAgent.run`, `finish()` findings payload), drop the stale `gpt-4o` fallback
- Wire Aplomado into the recon pipeline as the `probed → reviewed` stage
- First public release after dogfooding on authorized bounty scopes

## License

MIT © Eyry.