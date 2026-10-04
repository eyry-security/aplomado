# Aplomado Roadmap

Planned capabilities for the AI scanner. Owner: Claude (Kiro) — Ben' sets priority.

## Agent tooling

- [ ] **ffuf fuzzing tool** — let the agent call ffuf for content and parameter
  discovery during scans (directories, vhosts, params).
- [ ] **Pre-bundled wordlists** — ship a curated wordlist pack (SecLists-style)
  so scans work out of the box with no setup. Open questions: curate a tight
  default set vs. bundle full SecLists (size, licensing). Asking the community
  in public — see @eyrysec on X.
- [ ] **Python 3 scratchpad tool** — let the agent submit Python code and get
  stdout/stderr back, for custom analysis and data munging mid-scan.

## Hardening

- [ ] **Harden file-writing toolset** — constrain where and what the agent can
  write: scoped paths, size limits, no clobbering sensitive files.
- [ ] **Harden command-exec toolset** — constrain what the agent can run:
  command allowlist, no destructive ops, sandboxing where possible.

## Shipped

- Pinnace convergence (agent harness on Vector's v0 base)
- Scan event emission for Quarterdeck
- Stdin ingestion + deterministic (canonical-JSON) finding IDs
- `eyry up` AI-review pipeline stage
