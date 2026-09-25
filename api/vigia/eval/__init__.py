"""Benchmark lab (Phase 8, brief section 9): synthetic scan scenarios with known
ground truth, used to measure the agent's actual OSINT quality end to end — real
planner (Ollama), real orchestrator/risk/report-writer code, but every tool call is
scripted rather than a real network request, so nothing here ever touches a real
domain (brief rule 6). See `eval/README.md` at the repo root for how to run it and
read results; `eval/ground_truth/*.json` mirrors `scenarios.py`'s expectations as
plain data.
"""
