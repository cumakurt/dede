## Lizard offline-skip hardening (2026-09-10)

- `LizardAnalyzer` no longer reports FAILED when the `lizard` python module is
  missing on the host; it returns `SKIPPED_OFFLINE_DEPENDENCY` like the other
  optional external tools (semgrep/gosec/govet), so a scan on a host without
  the module no longer exits 3 (incomplete coverage).
- Regressed by unit test `test_lizard_reports_offline_skip_when_module_missing`.
- Full suite: 361 passed (unit + integration); ruff clean on touched files.

## Next up

- continue from here
