#!/usr/bin/env bash
# Safely remove Dede-owned runtime resources. Unrelated Docker resources are
# never pruned. Models/config can be retained explicitly.
set -Eeuo pipefail

DEDE_HOME="${DEDE_HOME:-/opt/dede}"
SCRIPT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ASSUME_YES=0
KEEP_MODELS=0
KEEP_CONFIG=0

usage() {
  cat <<'EOF'
Usage: ./uninstall.sh [--yes] [--keep-models] [--keep-config]

  -y, --yes       Do not ask for confirmation
  --keep-models   Keep the persistent Ollama model volume
  --keep-config   Keep /opt/dede/config (when present)
  -h, --help      Show help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -y|--yes) ASSUME_YES=1; shift ;;
    --keep-models) KEEP_MODELS=1; shift ;;
    --keep-config) KEEP_CONFIG=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'Unknown option: %s\n' "$1" >&2; exit 2 ;;
  esac
done

die() { printf 'uninstall: %s\n' "$*" >&2; exit 1; }
run_root() {
  if [[ "$(id -u)" -eq 0 ]]; then "$@"; return; fi
  command -v sudo >/dev/null 2>&1 || die "root or sudo is required"
  sudo "$@"
}

# Refuse to operate on an accidentally overridden or unresolved path.
[[ -n "${DEDE_HOME}" && "${DEDE_HOME}" == /opt/dede ]] || die "DEDE_HOME must be exactly /opt/dede"

if [[ "${ASSUME_YES}" -ne 1 ]]; then
  printf 'Remove Dede-owned containers, images, networks and %s? [y/N] ' \
    "$( ((KEEP_MODELS)) && printf 'keep models' || printf 'remove models' )"
  read -r answer || answer=""
  [[ "${answer}" =~ ^[Yy]([Ee][Ss])?$ ]] || { printf 'Cancelled.\n'; exit 0; }
fi

if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  # Compose down is scoped to this checkout/project and does not remove
  # volumes by default. The label filters below handle resources created by
  # older installs that are no longer represented in the compose file.
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1 \
    && [[ -f "${SCRIPT_ROOT}/docker-compose.yml" ]]; then
    docker compose -f "${SCRIPT_ROOT}/docker-compose.yml" down --remove-orphans >/dev/null 2>&1 || true
  fi

  mapfile -t managed_containers < <(docker ps -aq --filter label=com.dede.managed=true)
  if [[ "${#managed_containers[@]}" -gt 0 ]]; then
    docker rm -f "${managed_containers[@]}" >/dev/null 2>&1 || true
  fi

  mapfile -t managed_networks < <(docker network ls -q --filter label=com.dede.managed=true)
  if [[ "${#managed_networks[@]}" -gt 0 ]]; then
    docker network rm "${managed_networks[@]}" >/dev/null 2>&1 || true
  fi

  if [[ "${KEEP_MODELS}" -ne 1 ]]; then
    mapfile -t managed_volumes < <(docker volume ls -q --filter label=com.dede.managed=true)
    if [[ "${#managed_volumes[@]}" -gt 0 ]]; then
      docker volume rm "${managed_volumes[@]}" >/dev/null 2>&1 || true
    fi
  fi

  # Remove only Dede-built images. Never remove shared upstream images such as
  # ollama/ollama merely because Dede used them.
  mapfile -t dede_images < <(docker images --format '{{.Repository}}:{{.Tag}}' 'dede-scanner*' 2>/dev/null || true)
  if [[ "${#dede_images[@]}" -gt 0 ]]; then
    docker image rm "${dede_images[@]}" >/dev/null 2>&1 || true
  fi
else
  printf 'Docker unavailable; skipped Docker resource cleanup.\n' >&2
fi

link="/usr/local/sbin/dede"
if [[ -L "${link}" ]]; then
  target="$(readlink -f "${link}" 2>/dev/null || true)"
  if [[ "${target}" == "${DEDE_HOME}"/* ]]; then
    run_root unlink "${link}"
  else
    printf 'Preserved %s (it points outside %s).\n' "${link}" "${DEDE_HOME}"
  fi
elif [[ -e "${link}" ]]; then
  printf 'Preserved %s (not a Dede symlink).\n' "${link}" >&2
fi

if [[ "${KEEP_CONFIG}" -eq 1 && -d "${DEDE_HOME}/config" ]]; then
  run_root find "${DEDE_HOME}" -mindepth 1 -maxdepth 1 ! -name config -exec rm -rf -- {} +
  printf 'Removed Dede runtime; kept %s/config.\n' "${DEDE_HOME}"
elif [[ -d "${DEDE_HOME}" ]]; then
  run_root rm -rf -- "${DEDE_HOME}"
fi

printf 'Dede uninstall complete.\n'
