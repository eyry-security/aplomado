# aplomado

> AI security scanner and reviewer, built on Pinnace (Python).

Part of **[Eyry](https://eyry.io)**: open-source, agentic recon and offensive security tooling for
bug bounty hunters, red teamers, and pentesters. Aplomado is the strike: point it at a target, it investigates in a sandbox and reports findings.

## Status

🚧 **Early development.** Structure and APIs will change. Star the repo to follow along, and
see [eyry.io](https://eyry.io).

## What it does

- Agentic recon and vulnerability review of a target
- Runs in an isolated Docker sandbox, via Pinnace
- Consumes Vedette output; runs standalone or from the queue

## Install

Coming soon.

## The Eyry suite

- **Vedette**: fast, multi-threaded HTTP prober (Rust)
- **Foretop**: configurable producer of new hosts from pluggable feeds (certstream first)
- **Purser**: Redis-backed priority queue and work distributor (hot/warm/cold/DLQ)
- **Pinnace**: general multi-turn agent runtime with compaction, tools, and a Docker sandbox
- **Aplomado**: AI security scanner and reviewer built on Pinnace
- **Quarterdeck**: agent control plane, scheduler, events, IRC-style chat, and pipeline orchestration

## License

MIT, Eyry.
