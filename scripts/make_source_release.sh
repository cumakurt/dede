#!/usr/bin/env bash
set -euo pipefail
VERSION="$(python - <<'PY'
import tomllib
print(tomllib.load(open('pyproject.toml','rb'))['project']['version'])
PY
)"
OUT="${1:-dist/dede-${VERSION}-source.zip}"
mkdir -p "$(dirname "$OUT")"
rm -f "$OUT"
python - "$OUT" <<'PY'
from pathlib import Path
import sys, zipfile
out = Path(sys.argv[1]).resolve()
root = Path('.').resolve()
exclude_dirs = {'.git','.venv','venv','__pycache__','.pytest_cache','.ruff_cache','.mypy_cache','dist','build','audit-reports','audit-reports-offline-test','sbom','.claude','.freebuff'}
exclude_files = {'.env'}
with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as z:
    for p in sorted(root.rglob('*')):
        rel = p.relative_to(root)
        if any(part in exclude_dirs or part.startswith('.venv-backup.') for part in rel.parts):
            continue
        if p.name in exclude_files or p.suffix in {'.tmp', '.pyc'} or not p.is_file():
            continue
        z.write(p, Path('dede') / rel)
print(out)
PY
