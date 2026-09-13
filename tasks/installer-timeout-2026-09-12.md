# Installer verification timeout and quiet output

## Objective

Fix the reported `Killed timeout ...` failure after the existing scanner image
is found. Reduce routine installer output while retaining actionable failures,
bounded operations, model/volume preservation and detailed diagnostics.

## Plan

- [x] Inspect installer control flow, current Docker state and installer tests.
  The failing position is the unconditional 60-second Compose scanner `version`
  probe, before Ollama startup. It has no failure handling or phase context.
- [x] Reproduce the verification path and distinguish Compose orchestration
  from execution of the installed scanner image. Avoid unrelated service,
  network and source/report/cache mount work in the version probe.
- [x] Add bounded scanner verification, explicit timeout/failure messages and
  cleanup of only the installer-owned temporary container. Preserve actual
  container failures and do not claim successful setup after a failed probe.
- [x] Make normal output concise. Keep full step output in a private per-run
  log, provide `--verbose`, show actionable failure messages and the current
  step/log path during long operations without swallowing command errors.
- [x] Add regressions for hangs, nonzero exits, cleanup scope, quiet/verbose
  output and preservation of existing optional-model behavior.
- [x] Run installer tests, ShellCheck/syntax checks and real local scanner
  verification; review the diff and document usage and measured results.

## Initial evidence

The reported line uses GNU timeout with a five-second kill grace. The scanner
probe is the next command after `image already present`; it uses Compose and
the entire scanner service configuration simply to print a version. Therefore
the message is not evidence of an Ollama startup failure or proof of host OOM.
The current Docker daemon answers read-only probes, and an existing healthy
Ollama container must be preserved during this work. Exact cause of the user's
SIGKILL cannot be determined from that line alone.

## Completed implementation and evidence

- Scanner verification now uses `docker run --pull=never --network none` with
  read-only root, dropped capabilities and no-new-privileges. No source, report
  or cache directories are mounted. The scanner check does not use Compose
  services or start Ollama. Its timeout is configurable with
  `DEDE_SCANNER_CHECK_TIMEOUT` (default 60 seconds, plus five-second kill grace).
- Nonzero results stop bootstrap before model setup. Timeout/SIGKILL results
  explain the failed phase and point to the private log and timeout setting.
  Cleanup uses only a 64-character Docker ID from this check's private cidfile;
  invalid IDs are never passed to Docker. Exit cleanup preserves the original
  failure status. Existing containers/model volumes are not cleanup targets.
- Normal output shows a short banner, current steps and outcomes. Python,
  rule and Docker detail is retained in a mode-0600 log under a mode-0700
  per-run directory. Its path is printed at startup; `--verbose` streams the
  same detail. System package/sudo prompts remain visible. Pip failures are
  logged once instead of silently rerunning the installation. A failed log
  initialization prevents the associated command from running.
- Declining Docker setup now produces the CLI-only completion message instead
  of claiming the scanner is ready. Optional-model behavior is preserved.
- The reported SIGKILL path was reproduced with a real GNU timeout controlling
  a process that ignores SIGTERM (the test shortens only the kill grace). The
  new code returns a clear failure, keeps detailed diagnostics and removes only
  the fixture check container. The real host currently passes both the old
  Compose probe and the new direct probe; this does not establish why Docker
  stalled or was killed during the user's earlier installation.
- Hardened Docker tests: **40 passed** (19 installer regressions plus 21 release
  validation cases). This includes quiet/verbose failure statuses, log
  permissions, unavailable log directory, timeout cleanup, invalid IDs, exit
  status preservation and skipped setup reporting.
- Real `run_docker_bootstrap` with model setup skipped passed: all vendored rule
  checks, Compose configuration validation and scanner execution. Terminal
  output was five short lines rather than the entire rule inventory. Evidence:
  `/tmp/dede-installer-real-bootstrap.log`; detailed log:
  `/tmp/dede-install.V9RaKC2M/install.log`.
- A second real probe passed with deliberately unusable `TARGET`/`OUTPUT`
  settings, confirming that verification no longer depends on scan mounts:
  `/tmp/dede-installer-isolated-check.log`. The existing healthy
  `dede-ollama-1` remained running on its original image. No forced scanner
  rebuild, OS package installation or host venv replacement was needed to test
  these Docker paths.
- ShellCheck, Bash syntax, Ruff and `git diff --check` pass. `make release-check`
  passes (lint, mypy, rules, lock exports, wheel/sdist build and validation).
  The full application suite was not repeated for this installer-only change.

## Resume state

This fix is complete. Retry `./install.sh`; use `./install.sh --verbose` for
live details. If Docker startup is genuinely slow, use
`DEDE_SCANNER_CHECK_TIMEOUT=180 ./install.sh`. A persistent host/daemon/OOM issue
still requires its actual diagnostics; it is no longer reported as an unexplained
installer termination. Changes remain uncommitted alongside the earlier release
work. Release images/SBOMs retain the preceding checkpoint; any new publication
build must regenerate matching image evidence following the release runbook.
