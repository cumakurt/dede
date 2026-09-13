#!/usr/bin/env bash
# Bootstrap helper (online). Delegates to make setup.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
exec make setup
