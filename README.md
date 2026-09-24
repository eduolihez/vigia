# Vigía

> External Attack Surface Management (EASM) OSINT agent, powered by a local LLM.

*[Versión en español](README.es.md)*

**Status: Phase 1 of 9 (Base) — early scaffolding, not yet functional.** See
[CLAUDE.md](CLAUDE.md) for current phase status and commands.

## What is Vigía?

Given a domain you own or are explicitly authorized to test, Vigía uses a local LLM
(via [Ollama](https://ollama.com)) as an agent to enumerate its external attack
surface — subdomains, exposed services, DNS/email misconfigurations, dangling DNS
records, leaked secrets, and more — verifies every finding against stored raw
evidence, prioritizes it with CISA KEV and FIRST EPSS data, and presents it all in a
web dashboard with an asset graph and an exportable report.

It's a portfolio project for SOC/Blue Team work: the code quality, tests, guardrails,
and documentation matter as much as the feature set.

Design principle: the LLM **decides and drafts** (what to investigate next, how to
write the report); deterministic code **executes, normalizes, scores, and validates**.
The LLM never runs arbitrary commands or builds tool arguments outside a fixed schema.

## Status

This repository is under active, phased development. Nothing here should be
considered production-ready. See [CLAUDE.md](CLAUDE.md) for exactly what works today.

## Ethical use

Vigía must only be run against domains you own or have explicit written authorization
to test. See [docs/ethics.md](docs/ethics.md).

## Documentation

- [CLAUDE.md](CLAUDE.md) — commands, conventions, current status
- [docs/architecture.md](docs/architecture.md)
- [docs/decisions.md](docs/decisions.md) — ADR log
- [docs/ethics.md](docs/ethics.md)

## License

[MIT](LICENSE)
