# Deterministic quality contract

Agents must run and report checks, include tests for changed behaviors and failure paths, and must never weaken tests, CI or thresholds just to get a passing run. CI and policies require human review when edited.

**Enforced:** `git diff --check`; unittest regression suite and integration module compilation.

Make `quality` required in branch rulesets. Numerical coverage, mutation and performance are not claimed enforced unless separately configured with reproducible baselines.
