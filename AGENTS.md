# Agent instructions — vivit-energy-ha

## Repository-specific deterministic quality contract (2026-10-26)

**Project:** Home Assistant integration for Repsol Vivit smart energy.

**Engineering requirements:** Protect credentials/PII redaction, billing/electricity payloads, sensors, translations and synchronized public release versions.

**Verification commands:** python -m unittest discover -s tests -v; python -m compileall -q custom_components; enforce CHANGELOG/header and manifest versions.

Only claim checks passed after executing them. Every feature and fix should add or maintain tests for behavior, boundaries and failure cases. Never disable/weaken tests, suppress warnings or reduce coverage thresholds solely to pass CI. `AGENTS.md`, `QUALITY_GATES.md`, tests and workflows are review-sensitive. Require `quality` in branch protection. Disclose native dependencies and pre-existing CI failures. Preserve existing project rules.
