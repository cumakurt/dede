#!/usr/bin/env bash
# Dede installer — smart, quiet, colorful Linux bootstrap.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

ASSUME_YES=0
SKIP_DOCKER_SETUP=0
WITH_DOCKER=0
WITH_REPORTING=0
SKIP_MODEL=0
PULL_MODEL=0
FORCE_REBUILD=0
VERBOSE=0
INSTALL_LOG=""
SCANNER_CHECK_CID=""
INSTALL_STARTED=$SECONDS
PHASE_NO=0
PHASE_TOTAL=7

DEFAULT_MODEL="${DEDE_MODEL:-qwen3-coder:30b}"
SCANNER_IMAGE="${DEDE_SCANNER_IMAGE:-dede-scanner:1.10.0}"
ENV_FILE="${ROOT}/.env"
OLLAMA_START_TIMEOUT="${DEDE_OLLAMA_START_TIMEOUT:-300}"
OLLAMA_READY_TIMEOUT="${DEDE_OLLAMA_READY_TIMEOUT:-90}"
SCANNER_CHECK_TIMEOUT="${DEDE_SCANNER_CHECK_TIMEOUT:-60}"

dede_compose() {
  local -a command=(docker compose -f "${ROOT}/docker-compose.yml")
  if [[ "${DEDE_DEVICE:-auto}" == "cuda" ]]; then
    command+=(-f "${ROOT}/docker-compose.gpu.yml")
  fi
  if [[ -n "${COMPOSE_TIMEOUT:-}" ]]; then
    timeout --kill-after=5 "${COMPOSE_TIMEOUT}" "${command[@]}" "$@"
  else
    "${command[@]}" "$@"
  fi
}

# ---------------------------------------------------------------------------
# Colors / UI (disabled when not a TTY or NO_COLOR is set)
# ---------------------------------------------------------------------------
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  C_RESET=$'\033[0m'
  C_DIM=$'\033[2m'
  C_BOLD=$'\033[1m'
  C_RED=$'\033[31m'
  C_GREEN=$'\033[32m'
  C_YELLOW=$'\033[33m'
  C_BLUE=$'\033[34m'
  C_CYAN=$'\033[36m'
  C_MAGENTA=$'\033[35m'
else
  C_RESET=""; C_DIM=""; C_BOLD=""; C_RED=""; C_GREEN=""
  C_YELLOW=""; C_BLUE=""; C_CYAN=""; C_MAGENTA=""
fi

ok()   { printf '%s✓%s %s\n' "$C_GREEN" "$C_RESET" "$*"; }
skip() { if [[ "$VERBOSE" -eq 1 ]]; then printf '%s·%s %s\n' "$C_DIM" "$C_RESET" "$*"; fi; }
info() { printf '%s▸%s %s\n' "$C_CYAN" "$C_RESET" "$*"; }
warn() { printf '%s!%s %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2; }
fail() { printf '%s✗%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; }
die()  { fail "$*"; exit 1; }

header() {
  printf '\n%s%s━━ %s ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n' "$C_BOLD" "$C_BLUE" "$*" "$C_RESET"
}

phase() {
  PHASE_NO=$((PHASE_NO + 1))
  local title="$1" description="${2:-}"
  printf '\n%s%s[%d/%d] %s%s\n' "$C_BOLD" "$C_MAGENTA" "$PHASE_NO" "$PHASE_TOTAL" "$title" "$C_RESET"
  [[ -n "$description" ]] && printf '      %s%s%s\n' "$C_DIM" "$description" "$C_RESET"
}

kv() {
  printf '  %s%-15s%s %s\n' "$C_DIM" "$1" "$C_RESET" "$2"
}

option_note() {
  printf '  %s○%s %s%s%s\n' "$C_BLUE" "$C_RESET" "$C_BOLD" "$1" "$C_RESET"
  printf '    %s%s%s\n' "$C_DIM" "$2" "$C_RESET"
}

banner() {
  printf '%s%s\n' "$C_BOLD$C_MAGENTA" '╭────────────────────────────────────────────────────────────╮'
  printf '│  %-58s│\n' 'DEDE · Privacy-first static analysis setup'
  printf '%s%s\n' '╰────────────────────────────────────────────────────────────╯' "$C_RESET"
  printf '%sDeterministic core · Optional Docker · Optional local AI%s\n' "$C_DIM" "$C_RESET"
}

init_install_log() {
  if [[ -z "$INSTALL_LOG" ]]; then
    local directory
    directory="$(mktemp -d "${TMPDIR:-/tmp}/dede-install.XXXXXXXX")" || return 1
    INSTALL_LOG="${directory}/install.log"
    if ! (umask 077; : > "$INSTALL_LOG"); then
      INSTALL_LOG=""
      return 1
    fi
    info "Details: ${INSTALL_LOG} (--verbose streams output)"
  fi
}

# Log command output once; quiet mode retains errors without dumping package,
# rule or Docker progress. Group redirection also captures Bash's SIGKILL notice.
run_logged() {
  local label="$1" status=0
  shift
  init_install_log || return 1
  printf '\n'
  info "$label"
  printf '\n== %s ==\n' "$label" >> "$INSTALL_LOG" || return 1
  if [[ "$VERBOSE" -eq 1 ]]; then
    local -a statuses=()
    if { "$@"; } 2>&1 | tee -a "$INSTALL_LOG"; then
      ok "$label completed"
      return 0
    else
      statuses=("${PIPESTATUS[@]}")
      status="${statuses[0]}"
      [[ "$status" -ne 0 ]] || status="${statuses[1]}"
    fi
  else
    local started=$SECONDS pid frame=0 elapsed=0
    local -a spinner=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
    { "$@"; } >> "$INSTALL_LOG" 2>&1 &
    pid=$!
    while kill -0 "$pid" >/dev/null 2>&1; do
      elapsed=$((SECONDS - started))
      if [[ -t 1 ]]; then
        printf '\r    %s%s%s %-38s %4ss  %sCtrl+C to cancel%s' \
          "$C_CYAN" "${spinner[$frame]}" "$C_RESET" "$label" "$elapsed" "$C_DIM" "$C_RESET"
        frame=$(((frame + 1) % ${#spinner[@]}))
      elif (( elapsed > 0 && elapsed % 15 == 0 )); then
        printf '    … %s still running (%ss)\n' "$label" "$elapsed"
      fi
      command sleep 1
    done
    wait "$pid" || status=$?
    if [[ -t 1 ]]; then
      printf '\r%*s\r' 90 ''
    fi
  fi
  if [[ "$status" -ne 0 ]]; then
    warn "${label} failed (exit ${status}). Details: ${INSTALL_LOG}"
  else
    ok "${label} completed"
  fi
  return "$status"
}

cleanup_scanner_check() {
  [[ -n "$SCANNER_CHECK_CID" && -f "$SCANNER_CHECK_CID" ]] || return 0
  local container_id=""
  read -r container_id < "$SCANNER_CHECK_CID" || true
  if [[ "$container_id" =~ ^[a-f0-9]{64}$ ]]; then
    # Only the ID written by our own Docker run may be removed. Never operate
    # on the project, other containers or persistent model volumes.
    if ! timeout --kill-after=2 10 docker rm -f "$container_id" >> "$INSTALL_LOG" 2>&1; then
      warn "Scanner check cleanup could not be confirmed; container ID: ${container_id}"
      return 0
    fi
  fi
  rm -f -- "$SCANNER_CHECK_CID"
  SCANNER_CHECK_CID=""
}

installer_exit() {
  local status=$?
  cleanup_scanner_check
  return "$status"
}

usage() {
  cat <<'EOF'
Usage: ./install.sh [options]

  -y, --yes              Non-interactive (accept all default choices, including optional components)
  --with-docker          Build/verify the optional Docker scanner image
  --with-reporting       Install native PDF/PDF-A reporting support
  --skip-docker-setup    Never build/verify the optional Docker scanner image
  --skip-model           Never pull an LLM model
  --pull-model           Allow pulling the default model when none are installed
  --force-rebuild        Rebuild scanner image even if present
  -v, --verbose         Show detailed package, rule and Docker output
  -h, --help             Show help

Docker is optional: the host CLI can scan in native mode without a scanner image.
Already-installed OS packages, Docker images and Ollama models are never re-downloaded.
Downloaded models live in the persistent Docker volume 'ollama-data' and survive
reinstalls and updates. With -y, all default choices are accepted, including optional reporting, Docker image setup when Docker is available, and the default local model unless an explicit --skip-* flag is used.
Ollama startup is bounded by DEDE_OLLAMA_START_TIMEOUT (default: 300 seconds),
followed by DEDE_OLLAMA_READY_TIMEOUT (default: 90 seconds) for API readiness.
Scanner verification uses an isolated, network-disabled container with a
DEDE_SCANNER_CHECK_TIMEOUT limit (default: 60 seconds). Python/rule/Docker output is
saved in a private /tmp/dede-install.*/install.log directory (or under TMPDIR).
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -y|--yes) ASSUME_YES=1; shift ;;
    --with-docker) WITH_DOCKER=1; shift ;;
    --with-reporting) WITH_REPORTING=1; shift ;;
    --skip-docker-setup) SKIP_DOCKER_SETUP=1; shift ;;
    --skip-model) SKIP_MODEL=1; shift ;;
    --pull-model) PULL_MODEL=1; shift ;;
    --force-rebuild) FORCE_REBUILD=1; shift ;;
    -v|--verbose) VERBOSE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown option: $1" ;;
  esac
done

if [[ "$FORCE_REBUILD" -eq 1 ]]; then
  WITH_DOCKER=1
fi
if [[ "$WITH_DOCKER" -eq 1 && "$SKIP_DOCKER_SETUP" -eq 1 ]]; then
  die "--with-docker and --skip-docker-setup cannot be used together"
fi

confirm() {
  local prompt="$1"
  if [[ "$ASSUME_YES" -eq 1 ]]; then
    return 0
  fi
  local answer=""
  printf '%s?%s %s Type "yes" or "no" [default=yes]: ' "$C_YELLOW" "$C_RESET" "$prompt"
  read -r answer || true
  case "${answer}" in
    ""|y|Y|yes|YES)
      printf '→ yes\n'
      return 0 ;;
    *)
      printf '→ no\n'
      return 1 ;;
  esac
}

# ---------------------------------------------------------------------------
# Distro
# ---------------------------------------------------------------------------
DISTRO_ID="unknown"
DISTRO_LIKE=""
DISTRO_VERSION=""
PKG_FAMILY="unknown"

detect_distro() {
  if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    DISTRO_ID="${ID:-unknown}"
    DISTRO_LIKE="${ID_LIKE:-}"
    DISTRO_VERSION="${VERSION_ID:-}"
  fi
  local key
  key="$(echo "${DISTRO_ID} ${DISTRO_LIKE}" | tr '[:upper:]' '[:lower:]')"
  case " ${key} " in
    *" debian "*|*" ubuntu "*|*" kali "*|*" raspbian "*|*" linuxmint "*|*" pop "*)
      PKG_FAMILY="debian" ;;
    *" rhel "*|*" fedora "*|*" centos "*|*" rocky "*|*" almalinux "*|*" ol "*)
      PKG_FAMILY="rhel" ;;
    *" arch "*|*" manjaro "*|*" endeavouros "*)
      PKG_FAMILY="arch" ;;
    *" suse "*|*" opensuse "*)
      PKG_FAMILY="suse" ;;
    *) PKG_FAMILY="unknown" ;;
  esac
}

run_root() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo "$@"
  else
    die "Root/sudo required."
  fi
}

# ---------------------------------------------------------------------------
# Package helpers — only install what is truly missing
# ---------------------------------------------------------------------------
pkg_installed() {
  local pkg="$1"
  case "${PKG_FAMILY}" in
    debian)
      dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed"
      ;;
    rhel)
      rpm -q "$pkg" >/dev/null 2>&1
      ;;
    arch)
      pacman -Qi "$pkg" >/dev/null 2>&1
      ;;
    suse)
      rpm -q "$pkg" >/dev/null 2>&1
      ;;
    *)
      return 1
      ;;
  esac
}

filter_uninstalled_pkgs() {
  local -a out=()
  local p skipped=0
  for p in "$@"; do
    [[ -z "$p" ]] && continue
    if pkg_installed "$p"; then
      skipped=$((skipped + 1))
    else
      out+=("$p")
    fi
  done
  if [[ "$skipped" -gt 0 && "${#out[@]}" -gt 0 ]]; then
    skip "${skipped} packages already installed (skipped)" >&2
  fi
  if [[ "${#out[@]}" -gt 0 ]]; then
    printf '%s\n' "${out[@]}"
  fi
}

pkg_for() {
  local logical="$1"
  case "${PKG_FAMILY}:${logical}" in
    debian:docker) echo "docker.io docker-compose-v2" ;;
    debian:python3) echo "python3" ;;
    debian:venv) echo "python3-venv" ;;
    debian:pip) echo "python3-pip" ;;
    debian:make) echo "make" ;;
    debian:curl) echo "curl" ;;
    debian:git) echo "git" ;;
    debian:ca) echo "ca-certificates" ;;
    debian:pdf) echo "libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0 libffi-dev shared-mime-info fonts-dejavu-core" ;;
    rhel:docker) echo "docker docker-compose-plugin" ;;
    rhel:python3) echo "python3" ;;
    rhel:venv) echo "python3" ;;
    rhel:pip) echo "python3-pip" ;;
    rhel:make) echo "make" ;;
    rhel:curl) echo "curl" ;;
    rhel:git) echo "git" ;;
    rhel:ca) echo "ca-certificates" ;;
    rhel:pdf) echo "pango gdk-pixbuf2 libffi-devel shared-mime-info dejavu-sans-fonts" ;;
    arch:docker) echo "docker docker-compose" ;;
    arch:python3) echo "python" ;;
    arch:venv) echo "python" ;;
    arch:pip) echo "python-pip" ;;
    arch:make) echo "make" ;;
    arch:curl) echo "curl" ;;
    arch:git) echo "git" ;;
    arch:ca) echo "ca-certificates" ;;
    arch:pdf) echo "pango gdk-pixbuf2 libffi shared-mime-info ttf-dejavu" ;;
    suse:docker) echo "docker docker-compose" ;;
    suse:python3) echo "python3" ;;
    suse:venv) echo "python3-venv" ;;
    suse:pip) echo "python3-pip" ;;
    suse:make) echo "make" ;;
    suse:curl) echo "curl" ;;
    suse:git) echo "git" ;;
    suse:ca) echo "ca-certificates" ;;
    suse:pdf) echo "pango gdk-pixbuf libffi-devel shared-mime-info dejavu-fonts" ;;
    *) echo "" ;;
  esac
}

append_missing_packages() {
  local -a packages=()
  read -r -a packages <<< "$(pkg_for "$1")"
  MISSING_PKGS+=("${packages[@]}")
}

declare -a MISSING_LABELS=()
declare -a MISSING_PKGS=()
declare -a OPTIONAL_LABELS=()
declare -a OPTIONAL_PKGS=()
declare -a NOTES=()
declare -a PRESENT=()

mark_present() { PRESENT+=("$1"); }

need_cmd() {
  local cmd="$1" logical="$2" label="$3"
  if command -v "$cmd" >/dev/null 2>&1; then
    mark_present "$label"
    return 0
  fi
  MISSING_LABELS+=("$label")
  local pkgs
  pkgs="$(pkg_for "$logical")"
  if [[ -n "$pkgs" ]]; then
    # shellcheck disable=SC2206
    MISSING_PKGS+=(${pkgs})
  else
    NOTES+=("Manual install: $label")
  fi
}

need_docker_compose() {
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    mark_present "Docker + Compose"
    return 0
  fi
  if ! command -v docker >/dev/null 2>&1; then
    MISSING_LABELS+=("Docker Engine")
  else
    MISSING_LABELS+=("Docker Compose v2")
  fi
  local pkgs
  pkgs="$(pkg_for docker)"
  # shellcheck disable=SC2206
  [[ -n "$pkgs" ]] && MISSING_PKGS+=(${pkgs})
  return 0
}

need_python() {
  if ! command -v python3 >/dev/null 2>&1; then
    need_cmd python3 python3 "Python 3.12+"
    return
  fi
  local major minor
  major="$(python3 -c 'import sys; print(sys.version_info.major)')"
  minor="$(python3 -c 'import sys; print(sys.version_info.minor)')"
  if [[ "$major" -lt 3 ]] || [[ "$major" -eq 3 && "$minor" -lt 12 ]]; then
    warn "Python ${major}.${minor} found; 3.12+ recommended"
    MISSING_LABELS+=("Python 3.12+")
    append_missing_packages python3
  else
    mark_present "Python ${major}.${minor}"
  fi
  if ! python3 -m venv --help >/dev/null 2>&1; then
    MISSING_LABELS+=("python3-venv")
    append_missing_packages venv
  fi
  if ! python3 -m pip --version >/dev/null 2>&1; then
    MISSING_LABELS+=("python3-pip")
    append_missing_packages pip
  fi
}

need_optional_pdf() {
  local pkgs=""
  case "${PKG_FAMILY}" in
    debian)
      if ! ldconfig -p 2>/dev/null | grep -q 'libpango-1.0.so'; then
        pkgs="$(pkg_for pdf)"
      else
        mark_present "PDF libs (pango)"
        return 0
      fi
      ;;
    rhel|arch|suse)
      if ! ldconfig -p 2>/dev/null | grep -Eq 'libpango|pango'; then
        pkgs="$(pkg_for pdf)"
      else
        mark_present "PDF libs"
        return 0
      fi
      ;;
  esac
  if [[ -n "$pkgs" ]]; then
    OPTIONAL_LABELS+=("WeasyPrint PDF libs")
    # shellcheck disable=SC2206
    OPTIONAL_PKGS+=(${pkgs})
  fi
}

unique_list() {
  local -A seen=()
  local p
  for p in "$@"; do
    [[ -z "$p" ]] && continue
    [[ -n "${seen[$p]+x}" ]] && continue
    seen[$p]=1
    printf '%s\n' "$p"
  done
}

install_packages() {
  local -a pkgs=("$@")
  [[ "${#pkgs[@]}" -eq 0 ]] && return 0
  case "${PKG_FAMILY}" in
    debian)
      # Keep sudo authentication on the terminal; redirecting its prompt into
      # the diagnostic log would make an unprivileged install appear stuck.
      run_root apt-get update -qq || return $?
      run_root env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${pkgs[@]}"
      ;;
    rhel)
      if command -v dnf >/dev/null 2>&1; then
        run_root dnf install -y -q "${pkgs[@]}"
      else
        run_root yum install -y -q "${pkgs[@]}"
      fi
      ;;
    arch)
      run_root pacman -Sy --noconfirm --quiet "${pkgs[@]}"
      ;;
    suse)
      run_root zypper --non-interactive install -y "${pkgs[@]}"
      ;;
    *)
      die "Unsupported distro: ${DISTRO_ID}"
      ;;
  esac
}

ensure_docker_ready() {
  command -v docker >/dev/null 2>&1 || return 1
  if ! timeout --kill-after=5 15 docker info >/dev/null 2>&1; then
    if command -v systemctl >/dev/null 2>&1; then
      info "Starting Docker service"
      run_root timeout --kill-after=5 30 systemctl enable --now docker || true
    fi
  fi
  timeout --kill-after=5 15 docker info >/dev/null 2>&1 || return 1
  docker compose version >/dev/null 2>&1 || return 1
  return 0
}

image_exists() {
  timeout --kill-after=5 15 docker image inspect "$SCANNER_IMAGE" >/dev/null 2>&1
}

ollama_reachable() {
  curl -fsS --max-time 2 "http://127.0.0.1:11434/api/tags" >/dev/null 2>&1
}

model_installed() {
  local model="$1"
  python3 - "$model" <<'PY' 2>/dev/null || return 1
import json, sys, urllib.request
name = sys.argv[1]
try:
    with urllib.request.urlopen("http://127.0.0.1:11434/api/tags", timeout=5) as r:
        data = json.load(r)
except Exception:
    sys.exit(1)
names = {m.get("name", "") for m in data.get("models", [])}
sys.exit(0 if name in names else 1)
PY
}

list_installed_models() {
  python3 - <<'PY' 2>/dev/null || true
import json, urllib.request
try:
    with urllib.request.urlopen("http://127.0.0.1:11434/api/tags", timeout=5) as r:
        data = json.load(r)
except Exception:
    raise SystemExit(0)
for m in data.get("models", []):
    name = m.get("name") or ""
    if name:
        print(name)
PY
}

count_installed_models() {
  local -a models=()
  mapfile -t models < <(list_installed_models)
  echo "${#models[@]}"
}

ensure_ollama_up() {
  if ollama_reachable; then
    return 0
  fi
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    local status=0
    # An unexpected volume-recreation prompt must never approve data loss.
    COMPOSE_TIMEOUT="$OLLAMA_START_TIMEOUT" run_logged "Starting Ollama (${OLLAMA_START_TIMEOUT}s limit)" dede_compose --progress plain up -d ollama </dev/null || status=$?
    if [[ "$status" -ne 0 ]]; then
      warn "Ollama startup failed (exit ${status}; 124/137 means timeout)."
      warn "Inspect with: docker compose ps -a; docker compose logs --tail 50 ollama"
      return 1
    fi
    local deadline=$((SECONDS + OLLAMA_READY_TIMEOUT))
    info "Waiting for Ollama API (timeout: ${OLLAMA_READY_TIMEOUT}s)"
    until ollama_reachable; do
      if [[ "$SECONDS" -ge "$deadline" ]]; then
        warn "Ollama API did not become ready within ${OLLAMA_READY_TIMEOUT}s."
        COMPOSE_TIMEOUT=10 run_logged "Reading Ollama diagnostics" dede_compose logs --tail 50 ollama || true
        return 1
      fi
      sleep 2
    done
    return 0
  fi
  return 1
}

stop_managed_ollama() {
  # Ollama is an on-demand dependency.  Keeping it up after installation pins
  # RAM/VRAM and makes a later --no-ai scan look as if AI were still active.
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    COMPOSE_TIMEOUT=10 dede_compose stop --timeout 2 ollama >/dev/null 2>&1 || true
  fi
}

install_host_cli() {
  local py="python3"
  command -v python3.12 >/dev/null 2>&1 && py="python3.12"

  local venv_py="${ROOT}/.venv/bin/python"
  local venv_ok=0
  if [[ -x "${venv_py}" ]] && "${venv_py}" -c "import sys" >/dev/null 2>&1; then
    venv_ok=1
    # A moved venv keeps a working python symlink but leaves console scripts
    # (bin/pip) with shebangs pointing at the old interpreter path.
    if [[ -e "${ROOT}/.venv/bin/pip" ]] && ! "${ROOT}/.venv/bin/pip" --version >/dev/null 2>&1; then
      venv_ok=0
    fi
  fi
  if [[ -d "${ROOT}/.venv" ]] && [[ -n "$(find "${ROOT}/.venv" -type f ! -writable -print -quit)" ]]; then
    warn "venv contains files not writable by the current user"
    venv_ok=0
  fi
  if [[ -d "${ROOT}/.venv/bin" && ! -w "${ROOT}/.venv/bin" ]]; then
    venv_ok=0
  fi

  # A venv whose interpreter is gone (e.g. OS Python upgraded, dangling symlink)
  # silently falls back to the system pip and dies on PEP 668 — recreate it.
  if [[ ! -d "${ROOT}/.venv" ]]; then
    info "Creating venv (${py})"
    if ! "${py}" -m venv "${ROOT}/.venv"; then
      die "Failed to create venv — install python3-venv (e.g. sudo apt install python3-venv)"
    fi
  elif [[ "${venv_ok}" -ne 1 ]]; then
    warn "venv broken or not writable — preserving it and creating a new environment"
    local backup_dir
    backup_dir="$(mktemp -d "${ROOT}/.venv-backup.XXXXXX")"
    mv -T "${ROOT}/.venv" "${backup_dir}"
    info "Previous environment preserved at ${backup_dir}"
    if ! "${py}" -m venv "${ROOT}/.venv"; then
      die "Failed to create venv — install python3-venv (e.g. sudo apt install python3-venv)"
    fi
  else
    skip "venv exists"
  fi

  local vpython="${ROOT}/.venv/bin/python"
  # Some distro venvs lack pip (ensurepip missing) — bootstrap it before use.
  if ! "${vpython}" -m pip --version >/dev/null 2>&1; then
    "${vpython}" -m ensurepip --upgrade >/dev/null 2>&1 || true
  fi
  if ! "${vpython}" -m pip --version >/dev/null 2>&1; then
    die "pip missing in venv — install python3-venv and retry"
  fi

  # Interrupted installs leave '~<name>.dist-info' directories behind; pip
  # cannot clean them itself and warns "Ignoring invalid distribution" forever.
  local stale_dir stale_count=0
  while IFS= read -r stale_dir; do
    if rm -rf "${stale_dir}" 2>/dev/null; then
      stale_count=$((stale_count + 1))
    else
      warn "Could not remove stale ${stale_dir} (permissions)"
    fi
  done < <(find "${ROOT}/.venv/lib" -maxdepth 3 -type d -name '~*' 2>/dev/null)
  [[ "${stale_count}" -gt 0 ]] && ok "cleaned ${stale_count} stale dist-info leftover(s)"

  # Activation scripts retain absolute paths when a checkout is moved.
  # Use the current interpreter and script directory explicitly instead.
  export PATH="${ROOT}/.venv/bin:${PATH}"
  hash -r

  run_logged "Preparing Python tools" "${vpython}" -m pip install --upgrade pip setuptools wheel || \
    die "Could not prepare the Python environment"
  # Host-native mode always includes the deterministic Dede analyzers; external analyzers remain optional.
  run_logged "Installing host CLI" "${vpython}" -m pip install -e "${ROOT}" || \
    die "Could not install the host CLI"

  skip "native core scanner installed; external analyzers are optional; Docker is not required"

  local bindir="${ROOT}/.venv/bin"
  local target_bin="${HOME}/.local/bin"
  mkdir -p "${target_bin}"
  ln -sfn "${bindir}/dede" "${target_bin}/dede"
  case ":${PATH}:" in
    *":${target_bin}:"*) ;;
    *)
      NOTES+=("PATH: export PATH=\"${target_bin}:\$PATH\"")
      export PATH="${target_bin}:${PATH}"
      ;;
  esac
  ok "CLI: $(command -v dede 2>/dev/null || echo "${target_bin}/dede")"
}

write_env_file() {
  if [[ -f "${ENV_FILE}" ]]; then
    skip "environment file already exists: ${ENV_FILE}"
    return 0
  fi
  cat >"${ENV_FILE}" <<EOF
# Generated by install.sh. Edit values as needed, then run docker compose.
DEDE_MODEL=${DEFAULT_MODEL}
DEDE_DEVICE=${DEDE_DEVICE:-auto}
DEDE_MAX_FILE_SIZE_MB=${DEDE_MAX_FILE_SIZE_MB:-5}
DEDE_LLM_MAX_CONTEXT=${DEDE_LLM_MAX_CONTEXT:-32768}
DEDE_OLLAMA_HOST=${DEDE_OLLAMA_HOST:-http://ollama:11434}
DEDE_OFFLINE=${DEDE_OFFLINE:-false}
ANALYZER_TIMEOUT_SECONDS=${ANALYZER_TIMEOUT_SECONDS:-300}
MAX_FILES=${MAX_FILES:-50000}
MAX_LLM_FINDINGS=${MAX_LLM_FINDINGS:-200}
LLM_CONCURRENCY=${LLM_CONCURRENCY:-2}
SEMGREP_SEND_METRICS=${SEMGREP_SEND_METRICS:-off}
SEMGREP_ENABLE_VERSION_CHECK=${SEMGREP_ENABLE_VERSION_CHECK:-0}
DO_NOT_TRACK=${DO_NOT_TRACK:-1}
TARGET=${TARGET:-.}
EOF
  chmod 600 "${ENV_FILE}" 2>/dev/null || true
  ok "environment: ${ENV_FILE} created"
}

verify_scanner_image() {
  init_install_log || return 1
  local status=0
  SCANNER_CHECK_CID="${INSTALL_LOG}.scanner.cid"
  # A version probe needs no Compose networks, target/report/cache mounts or
  # Ollama. Disable implicit pulls and stdin so verification stays local.
  run_logged "Checking scanner image (${SCANNER_CHECK_TIMEOUT}s limit)" \
    timeout --kill-after=5 "$SCANNER_CHECK_TIMEOUT" docker run --rm --pull=never \
    --cidfile "$SCANNER_CHECK_CID" --network none --read-only \
    --cap-drop ALL --security-opt no-new-privileges:true \
    --tmpfs /tmp:size=64m,mode=1777 -e DEDE_IN_CONTAINER=1 \
    "$SCANNER_IMAGE" version </dev/null || status=$?
  if [[ "$status" -ne 0 ]]; then
    cleanup_scanner_check
    case "$status" in
      124|137)
        warn "Scanner verification exceeded its ${SCANNER_CHECK_TIMEOUT}s limit or was killed."
        warn "Check Docker resources/daemon logs; if startup is slow, retry with DEDE_SCANNER_CHECK_TIMEOUT=180."
        ;;
      *) warn "Scanner image could not run. Inspect the log; rebuild with --force-rebuild if the image is incompatible." ;;
    esac
    return 1
  fi
  # Docker --rm already removed a successful probe.
  rm -f -- "$SCANNER_CHECK_CID"
  SCANNER_CHECK_CID=""
  ok "Scanner ready: ${SCANNER_IMAGE}"
}

run_scanner_bootstrap() {
  cp -n "${ROOT}/.env.example" "${ROOT}/.env" 2>/dev/null || true

  # Validate/vendor first so the image itself contains the complete ruleset
  # and works without relying on the development checkout bind mount.
  run_logged "Checking offline rules" make --no-print-directory -s -C "${ROOT}" rules || return $?

  if [[ "$FORCE_REBUILD" -eq 1 ]] || ! image_exists; then
    DEDE_SCANNER_IMAGE="$SCANNER_IMAGE" run_logged "Building optional scanner image (${SCANNER_IMAGE})" make --no-print-directory -s -C "${ROOT}" build || return $?
  else
    skip "image already present: ${SCANNER_IMAGE}"
  fi

  COMPOSE_TIMEOUT=15 run_logged "Checking Compose configuration" dede_compose config --quiet || return $?
  verify_scanner_image || return $?

  if [[ -f "${ROOT}/rules/dede-engine/core.json" ]]; then
    skip "Native engine rules present"
  else
    warn "rules/dede-engine/core.json missing — native engine will be disabled"
  fi
}

run_model_bootstrap() {
  if [[ "$SKIP_MODEL" -eq 1 ]]; then
    skip "model step skipped (--skip-model)"
    return 0
  fi

  if ! ensure_ollama_up; then
    warn "Ollama unreachable — model skipped (later: dede model pull ${DEFAULT_MODEL})"
    return 0
  fi

  if model_installed "$DEFAULT_MODEL"; then
    ok "model already installed: ${DEFAULT_MODEL} — no re-download (stored in persistent volume)"
    if command -v dede >/dev/null 2>&1; then
      dede model use "$DEFAULT_MODEL" >/dev/null 2>&1 || true
    fi
    stop_managed_ollama
    return 0
  fi

  local -a existing=()
  mapfile -t existing < <(list_installed_models)
  if [[ "${#existing[@]}" -gt 0 ]]; then
    ok "${#existing[@]} model(s) present in Ollama — no re-download"
    local m
    for m in "${existing[@]}"; do skip "$m"; done
    skip "default (${DEFAULT_MODEL}) missing; keeping existing models"
    info "Optional: dede model use <name>  |  dede model pull ${DEFAULT_MODEL}"
    stop_managed_ollama
    return 0
  fi

  info "Ollama empty; default model: ${DEFAULT_MODEL}"
  local allow_pull=0
  if [[ "$PULL_MODEL" -eq 1 ]]; then
    allow_pull=1
  elif [[ "$ASSUME_YES" -eq 1 ]]; then
    allow_pull=1
  elif confirm "Download the optional AI model (${DEFAULT_MODEL})?"; then
    allow_pull=1
  fi

  if [[ "$allow_pull" -ne 1 ]]; then
    skip "model download skipped"
    stop_managed_ollama
    return 0
  fi

  if command -v dede >/dev/null 2>&1; then
    if dede model check "$DEFAULT_MODEL" >/dev/null; then
      dede model pull "$DEFAULT_MODEL" -y
    else
      warn "Model appears incompatible with this host — pull skipped"
      info "Suggestion: dede model recommend"
    fi
  else
    DEDE_MODEL="$DEFAULT_MODEL" make -C "${ROOT}" model
  fi
  stop_managed_ollama
}

# Backward-compatible helper used by older automation/tests. Docker scanner and
# AI model setup are deliberately separate in the interactive installer.
run_docker_bootstrap() {
  run_scanner_bootstrap || return $?
  run_model_bootstrap
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
  banner
  [[ "$(uname -s)" == "Linux" ]] || die "Only Linux is supported"
  [[ "$OLLAMA_START_TIMEOUT" =~ ^[1-9][0-9]{0,4}$ ]] || die "DEDE_OLLAMA_START_TIMEOUT must be a positive integer (seconds)"
  [[ "$OLLAMA_READY_TIMEOUT" =~ ^[1-9][0-9]{0,4}$ ]] || die "DEDE_OLLAMA_READY_TIMEOUT must be a positive integer (seconds)"
  [[ "$SCANNER_CHECK_TIMEOUT" =~ ^[1-9][0-9]{0,4}$ ]] || die "DEDE_SCANNER_CHECK_TIMEOUT must be a positive integer (seconds)"
  init_install_log
  trap installer_exit EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM

  phase "Inspecting this system" "Detecting the Linux distribution, Python toolchain and optional runtimes."
  detect_distro
  kv "Distribution" "${DISTRO_ID} ${DISTRO_VERSION:-unknown} (${PKG_FAMILY})"
  kv "Architecture" "$(uname -m)"
  kv "Install root" "$ROOT"
  kv "Log file" "$INSTALL_LOG"

  MISSING_LABELS=(); MISSING_PKGS=()
  OPTIONAL_LABELS=(); OPTIONAL_PKGS=()
  NOTES=(); PRESENT=()

  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    mark_present "Docker + Compose (optional)"
  elif [[ "$WITH_DOCKER" -eq 1 ]]; then
    need_docker_compose
  else
    NOTES+=("Docker is optional; native scanning remains fully available")
  fi
  need_python
  need_cmd make make "Make"
  need_cmd curl curl "curl"
  need_cmd git git "git"
  if [[ "${PKG_FAMILY}" == "debian" && ! -f /etc/ssl/certs/ca-certificates.crt ]]; then
    MISSING_LABELS+=("ca-certificates")
    append_missing_packages ca
  else
    mark_present "ca-certificates"
  fi
  need_optional_pdf

  if [[ "${#PRESENT[@]}" -gt 0 ]]; then
    ok "Detected: ${PRESENT[*]}"
  fi
  option_note "Native scanner" "Always installed. Includes Dede Engine, semantic analysis, DedeQL, lifecycle and HTML/JSON/SARIF reporting."
  option_note "Docker scanner" "Optional. Provides an isolated, reproducible runtime with the packaged external analyzer toolchain."
  option_note "Local AI/Ollama" "Optional and independent. Static analysis remains fully functional with --no-ai."

  phase "Resolving required dependencies" "Only missing host prerequisites are installed; existing packages are left untouched."
  mapfile -t CANDIDATE_PKGS < <(unique_list "${MISSING_PKGS[@]:-}")
  mapfile -t TO_INSTALL < <(filter_uninstalled_pkgs "${CANDIDATE_PKGS[@]:-}")

  if [[ "${#MISSING_LABELS[@]}" -gt 0 && "${#TO_INSTALL[@]}" -gt 0 ]]; then
    warn "Missing required prerequisites: ${MISSING_LABELS[*]}"
    printf '  Packages to install: %s\n' "${TO_INSTALL[*]}"
    [[ "${PKG_FAMILY}" != "unknown" ]] || die "Unrecognized Linux distribution; install the listed prerequisites manually"
    if confirm "Install the missing required packages?"; then
      install_packages "${TO_INSTALL[@]}"
      ok "Required prerequisites installed"
    else
      die "Installation cancelled because required prerequisites are missing"
    fi
  elif [[ "${#MISSING_LABELS[@]}" -gt 0 && "${#TO_INSTALL[@]}" -eq 0 ]]; then
    warn "Some commands are still unavailable even though related packages appear installed: ${MISSING_LABELS[*]}"
  else
    ok "Required host prerequisites are ready"
  fi

  # An explicit Docker request is a contract: validate it before changing the
  # Python environment so a broken daemon fails fast with a clear explanation.
  if [[ "$WITH_DOCKER" -eq 1 ]] && ! ensure_docker_ready; then
    die "--with-docker requested, but Docker + Compose is unavailable"
  fi

  phase "Creating the Dede host environment" "Building an isolated Python environment and installing the native CLI/runtime."
  install_host_cli
  write_env_file
  kv "CLI" "$(command -v dede 2>/dev/null || echo "${ROOT}/.venv/bin/dede")"
  kv "Native runtime" "ready"
  kv "Configuration" "$ENV_FILE"

  phase "Configuring reporting support" "JSON, HTML and SARIF are built in. Native PDF/PDF-A support is optional."
  local reporting_ready=0 install_reporting=0
  if "${ROOT}/.venv/bin/python" -c 'import weasyprint' >/dev/null 2>&1; then
    reporting_ready=1
    ok "Native PDF/PDF-A reporting is already available"
  else
    if [[ "$WITH_REPORTING" -eq 1 || "$ASSUME_YES" -eq 1 ]]; then
      install_reporting=1
    elif [[ "$ASSUME_YES" -eq 0 ]]; then
      option_note "Native PDF/PDF-A reporting" "Installs WeasyPrint plus any missing system libraries. Skip this if HTML/JSON/SARIF are sufficient."
      if confirm "Install optional native PDF/PDF-A reporting support?"; then
        install_reporting=1
      fi
    fi

    if [[ "$install_reporting" -eq 1 ]]; then
      mapfile -t OPT_CAND < <(unique_list "${OPTIONAL_PKGS[@]:-}")
      mapfile -t OPT_INSTALL < <(filter_uninstalled_pkgs "${OPT_CAND[@]:-}")
      if [[ "${#OPT_INSTALL[@]}" -gt 0 ]]; then
        info "Installing the system libraries required by WeasyPrint"
        install_packages "${OPT_INSTALL[@]}" || die "Could not install the native PDF system dependencies"
      fi
      run_logged "Installing native PDF/PDF-A support"         "${ROOT}/.venv/bin/python" -m pip install -e "${ROOT}[reporting]" ||         die "Could not install the native PDF reporting extra"
      if "${ROOT}/.venv/bin/python" -c 'import weasyprint' >/dev/null 2>&1; then
        reporting_ready=1
        ok "Native PDF/PDF-A reporting ready"
      else
        die "WeasyPrint installation completed but could not be imported"
      fi
    else
      info "Native PDF support skipped; HTML/JSON/SARIF reporting remains available"
    fi
  fi

  phase "Selecting the scanner runtime" "Native mode requires no Docker image. Docker is an optional reproducible runtime."
  local docker_ready=0 scanner_ready=0
  if ensure_docker_ready; then
    docker_ready=1
    ok "Docker + Compose available"
  else
    if [[ "$WITH_DOCKER" -eq 1 ]]; then
      die "--with-docker was requested, but Docker + Compose is unavailable after dependency setup"
    fi
    info "Docker is unavailable; Dede will use the native runtime"
  fi

  if [[ "$docker_ready" -eq 1 ]] && image_exists && [[ "$FORCE_REBUILD" -eq 0 ]]; then
    scanner_ready=1
    ok "Optional Docker scanner image already exists: ${SCANNER_IMAGE}"
  fi

  if [[ "$SKIP_DOCKER_SETUP" -eq 1 ]]; then
    info "Docker scanner setup disabled by --skip-docker-setup"
  elif [[ "$docker_ready" -ne 1 ]]; then
    info "Skipping Docker image setup; native runtime is ready"
  else
    local build_docker=0
    if [[ "$WITH_DOCKER" -eq 1 || "$ASSUME_YES" -eq 1 ]]; then
      build_docker=1
    elif [[ "$scanner_ready" -eq 1 ]]; then
      build_docker=1
    elif [[ "$ASSUME_YES" -eq 0 ]]; then
      option_note "Optional Docker scanner image" "Choose this for an isolated toolchain. Choose no if you prefer host-native scanning."
      if confirm "Build and verify the optional Docker scanner image?"; then
        build_docker=1
      fi
    fi
    if [[ "$build_docker" -eq 1 ]]; then
      run_scanner_bootstrap
      scanner_ready=1
    else
      info "Docker image skipped; nothing else is required for native scanning"
    fi
  fi

  phase "Configuring optional local AI" "AI never creates the deterministic core findings and can be disabled permanently with --no-ai."
  if [[ "$SKIP_MODEL" -eq 1 ]]; then
    info "AI model setup disabled by --skip-model"
  elif [[ "$docker_ready" -ne 1 ]]; then
    info "Docker-managed Ollama is unavailable; configure a local Ollama endpoint later if desired"
  else
    local setup_model=0
    if [[ "$PULL_MODEL" -eq 1 || "$ASSUME_YES" -eq 1 ]]; then
      setup_model=1
    elif [[ "$ASSUME_YES" -eq 0 ]]; then
      option_note "Local AI model" "Optional explanation/hunt layer. It is not required for scanning, policies, semantic dataflow or reports."
      if confirm "Configure optional local AI/Ollama now?"; then
        setup_model=1
      fi
    fi
    if [[ "$setup_model" -eq 1 ]]; then
      run_model_bootstrap
    else
      info "AI/model setup skipped"
    fi
  fi

  phase "Verifying the installation" "Checking the CLI, native engine rules and runtime configuration before finishing."
  run_logged "Verifying Dede CLI" dede version || die "Dede CLI verification failed"
  if dede doctor --runtime native >/dev/null 2>>"$INSTALL_LOG"; then
    ok "Native runtime health checks passed"
  else
    die "Native runtime verification failed; inspect ${INSTALL_LOG}"
  fi
  if [[ "$scanner_ready" -eq 1 ]]; then
    ok "Docker scanner runtime verified: ${SCANNER_IMAGE}"
  else
    info "Docker scanner image not installed (optional)"
  fi

  if [[ "${#NOTES[@]}" -gt 0 ]]; then
    printf '\n%sNotes%s\n' "$C_BOLD" "$C_RESET"
    local n
    for n in "${NOTES[@]}"; do
      printf '  %s·%s %s\n' "$C_DIM" "$C_RESET" "$n"
    done
  fi

  local duration=$((SECONDS - INSTALL_STARTED))
  printf '\n%s%s╭──────────────── Installation complete ────────────────╮%s\n' "$C_BOLD" "$C_GREEN" "$C_RESET"
  printf '  Native scanner : %sready%s\n' "$C_GREEN" "$C_RESET"
  if [[ "$scanner_ready" -eq 1 ]]; then
    printf '  Docker scanner : %sready%s (%s)\n' "$C_GREEN" "$C_RESET" "$SCANNER_IMAGE"
  else
    printf '  Docker scanner : %snot installed%s (optional)\n' "$C_DIM" "$C_RESET"
  fi
  if [[ "$reporting_ready" -eq 1 ]]; then
    printf '  Native PDF     : %sready%s\n' "$C_GREEN" "$C_RESET"
  else
    printf '  Native PDF     : %snot installed%s (optional)\n' "$C_DIM" "$C_RESET"
  fi
  printf '  AI model       : %soptional%s\n' "$C_DIM" "$C_RESET"
  printf '  Duration       : %ss\n' "$duration"
  printf '%s%s╰──────────────────────────────────────────────────────╯%s\n' "$C_BOLD" "$C_GREEN" "$C_RESET"
  info "Start a deterministic scan: dede scan . --runtime native --no-ai"
  info "Automatic runtime selection: dede scan . --no-ai"
  info "Add Docker later: ./install.sh --with-docker --skip-model"
  info "Health check: dede doctor --runtime native"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
