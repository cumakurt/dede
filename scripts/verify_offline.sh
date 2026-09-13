#!/usr/bin/env bash
# Verify offline scan: network none, reports under /tmp/<project-name>.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SAMPLE="${ROOT}/tests/vulnerable_samples"
PROJECT_NAME="$(basename "${SAMPLE}")"
OUT="/tmp/${PROJECT_NAME}"
IMAGE="${DEDE_SCANNER_IMAGE:-dede-scanner:1.10.0}"
HOST_UID="$(id -u)"
HOST_GID="$(id -g)"
CACHE="/tmp/dede-offline-cache-${HOST_UID}"
cd "${ROOT}"

mkdir -p "${OUT}" "${CACHE}"
chmod 700 "${OUT}" "${CACHE}"

echo "==> Ensuring scanner image exists"
docker compose -f "${ROOT}/docker-compose.yml" build scanner

# Migrate outputs left by old fixed-UID releases without making the report
# directory world-writable. This helper has no network and mounts only OUT.
docker run --rm --network none --read-only \
  --security-opt no-new-privileges:true \
  --cap-drop ALL --cap-add DAC_OVERRIDE --user 0:0 \
  --entrypoint /bin/rm \
  -v "${OUT}:/reports" \
  "${IMAGE}" -rf -- \
  /reports/report.json /reports/report.html /reports/report.pdf \
  /reports/report.sarif /reports/metadata.json /reports/raw

echo "==> Running offline scan (docker --network none, --no-ai)"
docker run --rm \
  --network none \
  --read-only \
  --security-opt no-new-privileges:true \
  --cap-drop ALL \
  --tmpfs /tmp:size=512m,mode=1777 \
  -e SEMGREP_SEND_METRICS=off \
  -e SEMGREP_ENABLE_VERSION_CHECK=0 \
  -e DO_NOT_TRACK=1 \
  -e DEDE_IN_CONTAINER=1 \
  -e DEDE_CACHE_DIR=/var/lib/dede/cache \
  -e GOCACHE=/var/lib/dede/cache/go-build \
  -e GOMODCACHE=/var/lib/dede/cache/go-mod \
  -e DEDE_OLLAMA_HOST=http://127.0.0.1:9 \
  -v "${SAMPLE}:/workspace:ro" \
  -v "${OUT}:/reports" \
  -v "${CACHE}:/var/lib/dede/cache" \
  -w /workspace \
  --user "${HOST_UID}:${HOST_GID}" \
  "${IMAGE}" \
  scan /workspace --output /reports --no-ai --format json --format html --format pdf

echo "==> Validating reports in ${OUT}"
test -f "${OUT}/report.json"
test -f "${OUT}/report.html"
test -f "${OUT}/report.pdf"

OUT="/tmp/${PROJECT_NAME}" python - <<'PY'
import json
import os
from pathlib import Path
out = Path(os.environ["OUT"])
data = json.loads((out / "report.json").read_text())
findings = data.get("findings") or []
assert findings, "Expected at least one security finding"
expected = {"dede-engine", "semgrep", "duplicate", "code_smell", "gitleaks",
            "bandit", "ruff", "lizard", "go_vet", "gosec"}
statuses = {result["tool"]: result["status"] for result in data["tool_statuses"]}
assert set(statuses) == expected, f"Missing or unexpected analyzers: {statuses}"
assert all(status == "SUCCESS" for status in statuses.values()), f"Incomplete scan: {statuses}"
raw = (out / "report.json").read_text() + (out / "report.html").read_text()
assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in raw, "Secret leaked into report"
print(f"OK: {len(findings)} findings; reports in {out}; secrets redacted")
PY

echo "==> Offline verification passed"
