#!/usr/bin/env bash
# Preserve full findings and fail on HIGH/CRITICAL issues, including unfixed CVEs.
set -euo pipefail
umask 077
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${DEDE_SCANNER_IMAGE:-dede-scanner:1.10.0}"
OUT="${DEDE_AUDIT_DIR:-${ROOT}/dist/security}"
OFFLINE="${TRIVY_OFFLINE:-false}"
if [[ "${TRIVY_IGNORE_UNFIXED:-false}" != false ]]; then
  echo 'Release audits cannot ignore unfixed vulnerabilities.' >&2
  exit 2
fi
case "${OFFLINE}" in true|false) ;; *) echo 'TRIVY_OFFLINE must be true or false' >&2; exit 2 ;; esac
for tool in trivy docker python3; do
  command -v "${tool}" >/dev/null || { echo "${tool} is required for security audits" >&2; exit 2; }
done
image_id="$(docker image inspect --format '{{.Id}}' "${IMAGE}")"
mkdir -p "${OUT}"
report_dir="$(mktemp -d "${OUT}/run-XXXXXXXX")"
trap 'rm -f "${report_dir}/image.raw.json" "${report_dir}/source.raw.json"' EXIT
args=(--config /dev/null --ignorefile /dev/null --ignore-unfixed=false
  --scanners 'vuln,secret,misconfig' --severity 'UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL'
  --format json --exit-code 0 --skip-version-check --timeout 15m)
if [[ "${OFFLINE}" == true ]]; then
  args+=(--offline-scan --skip-db-update --skip-java-db-update --skip-check-update --skip-vex-repo-update)
fi
# Online mode may update databases. Offline mode requires a pre-provisioned cache.
# The excluded Go Dockerfiles are toolchain build fixtures, not deployed services.
scan_failed=0
trivy image "${args[@]}" --image-src docker \
  --skip-files '/usr/local/go/src/**/Dockerfile' \
  --output "${report_dir}/image.raw.json" "${image_id}" || scan_failed=1
trivy fs "${args[@]}" \
  --skip-dirs "${ROOT}/tests" --skip-dirs "${ROOT}/.git" --skip-dirs "${ROOT}/sbom" \
  --skip-dirs "${ROOT}/.venv*" --skip-dirs "${ROOT}/dist" --skip-dirs "${ROOT}/build" \
  --skip-dirs "${ROOT}/.pytest_cache" --skip-dirs "${ROOT}/audit-reports" --skip-dirs "${OUT}" \
  --output "${report_dir}/source.raw.json" "${ROOT}" || scan_failed=1
trivy --version --format json > "${report_dir}/scanner.json"
python3 "${ROOT}/scripts/validate_security_audit.py" "${report_dir}" "${image_id}" "${scan_failed}" "${OFFLINE}"
