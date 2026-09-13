# Contributing

## Development setup

Use Python 3.12 or newer and Docker. Install the locked development environment
with `uv sync --locked --all-extras` (or install from
`requirements-dev.lock` with pip). Use `uv run dede --help` for the CLI entry
point; use `uv run make lint` and `uv run make typecheck` for host checks. Runtime scans must remain offline after the bootstrap step.

## Required checks

Before opening a pull request, run:

```text
make lint
make typecheck
make test
python scripts/validate_release.py
```

Rule changes also require unsafe and safe regression examples. Update the
native manifest with `python scripts/validate_release.py --write` only after
reviewing the resulting digest and count changes. Do not commit credentials,
customer source, generated caches, or unreviewed vendored rule content.

## Pull requests

Explain the behavior change, compatibility impact, security reasoning, and
validation evidence. Keep unrelated formatting and dependency upgrades out of
the change. Changes to release inputs must include provenance or checksum
updates and a changelog entry.
