#!/usr/bin/env bash
# Generate both release inventories from the same immutable local image.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${DEDE_SBOM_DIR:-${ROOT}/sbom}"
IMAGE="${DEDE_SCANNER_IMAGE:-dede-scanner:1.10.0}"
for tool in syft docker python3; do
  command -v "${tool}" >/dev/null || { echo "${tool} is required for release SBOMs" >&2; exit 2; }
done
image_id="$(docker image inspect --format '{{.Id}}' "${IMAGE}")"
mkdir -p "${OUT}"
staging="$(mktemp -d "${OUT}/.staging-XXXXXXXX")"
trap 'rm -f "${staging}/sbom.cdx.json" "${staging}/sbom.spdx.json" "${staging}/provenance.json"; rmdir "${staging}"' EXIT
SYFT_CHECK_FOR_APP_UPDATE=false syft scan "docker:${image_id}" \
  -o "cyclonedx-json=${staging}/sbom.cdx.json" -o "spdx-json=${staging}/sbom.spdx.json"
python3 - "${staging}" "${image_id}" "${IMAGE}" <<'PY'
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

out = Path(sys.argv[1])
files = {}
for name, inventory_key in [('sbom.cdx.json', 'components'), ('sbom.spdx.json', 'packages')]:
    contents = (out / name).read_bytes()
    if not json.loads(contents).get(inventory_key):
        raise SystemExit(f'Empty release inventory: {name}')
    files[name] = hashlib.sha256(contents).hexdigest()
provenance = {
    'image_id': sys.argv[2], 'requested_image': sys.argv[3], 'sha256': files,
    'syft_version': subprocess.check_output(['syft', 'version'], text=True),
    'syft_binary_sha256': hashlib.sha256(Path(shutil.which('syft')).read_bytes()).hexdigest(),
}
(out / 'provenance.json').write_text(json.dumps(provenance, indent=2) + '\n')
PY
mv "${staging}/sbom.cdx.json" "${staging}/sbom.spdx.json" "${staging}/provenance.json" "${OUT}/"
echo "SBOMs and provenance written to ${OUT} for ${image_id}"
