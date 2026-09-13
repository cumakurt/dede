# Scan runtime regressions

## Plan

- [x] Reproduce the CLI parameter error in the shipped scanner image.
- [x] Identify report ownership and Typer/Click compatibility failures.
- [ ] Add regressions for help/errors and cross-user report/cache directories.
- [ ] Fix dependency compatibility and runtime directory validation.
- [ ] Rebuild scanner and test images; run the test suite and real host CLI scans.
- [ ] Validate release artifacts and document results and limitations.

## Evidence and decisions

- Existing image: `scan /does-not-exist` raises `TyperArgument.make_metavar` TypeError.
- Lockfile contains Typer 0.15.3 and Click 8.4.2.
- `/tmp/dede` belongs to UID 1000 with mode 0700. A root scanner with all
  capabilities dropped cannot access this directory. Root must not bypass the
  host ownership check: that does not grant the container filesystem access.
- Preserve foreign directories. Use a per-user default when the traditional
  default belongs to another user; reject explicitly selected foreign output
  and cache directories before changing permissions or removing old reports.
- Upstream compatibility reference: https://typer.tiangolo.com/release-notes/
