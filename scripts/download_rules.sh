#!/usr/bin/env bash
# Vendor Semgrep Registry packs for offline use (as complete as CE allows).
# Network is used only during bootstrap / `dede rules update`.
# Runtime scans never download rules.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RULES_DIR="${ROOT}/rules/semgrep"
CUSTOM_DIR="${RULES_DIR}/custom"
PACKS_DIR="${RULES_DIR}/packs"
VERSION_FILE="${RULES_DIR}/VERSION"
MANIFEST_FILE="${RULES_DIR}/MANIFEST.yml"
CHECKSUMS_FILE="${RULES_DIR}/SHA256SUMS"
FORCE_REFRESH="${FORCE_REFRESH:-0}"
REQUIRE_RULE_CHECKSUMS="${REQUIRE_RULE_CHECKSUMS:-1}"
UPDATE_RULE_CHECKSUMS="${UPDATE_RULE_CHECKSUMS:-0}"
CURL_BASE="${SEMGREP_REGISTRY_CURL_BASE:-https://semgrep.dev/c}"

# ---------------------------------------------------------------------------
# Full offline corpus
# - r/all: complete Community Edition rule dump (preferred for profile=full)
# - p/* : language / security / framework packs (smart profile + redundancy)
# ---------------------------------------------------------------------------
REQUIRED_PACKS=(
  r/all
  p/default
  p/security-audit
  p/owasp-top-ten
  p/cwe-top-25
  p/python
  p/javascript
  p/typescript
  p/golang
  p/java
  p/csharp
  p/php
  p/ruby
  p/kotlin
  p/scala
  p/rust
  p/c
  p/swift
  p/terraform
  p/dockerfile
  p/kubernetes
  p/nginx
  p/react
  p/django
  p/flask
  p/fastapi
)

OPTIONAL_PACKS=(
  p/ci
  p/r2c
  p/comment
  p/insecure-transport
  p/xss
  p/sql-injection
  p/command-injection
  p/jwt
  p/secrets
  p/trailofbits
  p/gitlab
  p/findsecbugs
  p/bandit
  p/eslint
  p/nodejs
  p/docker
  p/apex
  p/ocaml
  p/supply-chain
)

CUSTOM_FILES=(
  python-security.yml
  python-taint.yml
  python-web-security.yml
  javascript-security.yml
  javascript-taint.yml
  javascript-web-security.yml
  go-security.yml
  go-web-security.yml
  java-security.yml
  java-web-security.yml
  csharp-security.yml
  csharp-advanced-security.yml
  multilang-advanced-security.yml
  multilang-advanced-security-v2.yml
  php-security.yml
  php-web-security.yml
  ruby-security.yml
  rust-security.yml
  cpp-security.yml
  dockerfile-security.yml
  shell-security.yml
)

mkdir -p "${CUSTOM_DIR}" "${PACKS_DIR}"

# Migrate legacy flat rule files into custom/
for f in python-security.yml javascript-security.yml go-security.yml; do
  if [[ -f "${RULES_DIR}/${f}" && ! -f "${CUSTOM_DIR}/${f}" ]]; then
    mv "${RULES_DIR}/${f}" "${CUSTOM_DIR}/${f}"
    echo "Migrated ${f} → custom/"
  fi
done

missing_custom=0
for f in "${CUSTOM_FILES[@]}"; do
  if [[ ! -f "${CUSTOM_DIR}/${f}" ]]; then
    echo "Missing custom rule file: custom/${f}" >&2
    missing_custom=1
  fi
done
if [[ "$missing_custom" -ne 0 ]]; then
  exit 1
fi

sha256_file() {
  local path="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$path" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$path" | awk '{print $1}'
  else
    python3 - "$path" <<'PY'
import hashlib, sys
p = sys.argv[1]
h = hashlib.sha256()
with open(p, "rb") as f:
    for chunk in iter(lambda: f.read(1 << 20), b""):
        h.update(chunk)
print(h.hexdigest())
PY
  fi
}

count_rules() {
  local path="$1"
  python3 - "$path" <<'PY' 2>/dev/null || echo 0
import sys, yaml
path = sys.argv[1]
with open(path, "r", encoding="utf-8") as f:
    data = yaml.safe_load(f) or {}
rules = data.get("rules") if isinstance(data, dict) else None
print(len(rules) if isinstance(rules, list) else 0)
PY
}

verify_checksum() {
  local path="$1"
  local required="${2:-${REQUIRE_RULE_CHECKSUMS}}"
  local relative="${3:-${path#"${ROOT}"/}}" expected actual
  if [[ ! -f "${CHECKSUMS_FILE}" ]]; then
    if [[ "${required}" == "1" ]]; then
      echo "Trusted rule checksum manifest is missing: ${CHECKSUMS_FILE}" >&2
      return 1
    fi
    return 0
  fi
  expected="$(awk -v target="${relative}" '$2 == target {print $1; exit}' "${CHECKSUMS_FILE}")"
  if [[ -z "${expected}" ]]; then
    if [[ "${required}" == "1" ]]; then
      echo "No trusted checksum recorded for ${relative}" >&2
      return 1
    fi
    return 0
  fi
  actual="$(sha256_file "${path}")"
  if [[ "${actual}" != "${expected}" ]]; then
    echo "Checksum mismatch for ${relative}: expected ${expected}, got ${actual}" >&2
    return 1
  fi
}

validate_yaml() {
  local path="$1"
  python3 - "$path" <<'PY'
import sys, yaml
path = sys.argv[1]
with open(path, "r", encoding="utf-8") as f:
    data = yaml.safe_load(f)
if not isinstance(data, dict) or "rules" not in data:
    raise SystemExit(f"Invalid Semgrep YAML (missing rules:): {path}")
if not isinstance(data["rules"], list) or not data["rules"]:
    raise SystemExit(f"Empty rules list: {path}")
PY
}

download_pack() {
  local registry_path="$1"
  local required="${2:-1}"
  local name="${registry_path#*/}"
  local kind="${registry_path%%/*}"
  local out="${PACKS_DIR}/${name}.yml"
  local url="${CURL_BASE}/${kind}/${name}"
  local tmp
  local max_time=180

  # r/all is multi-MB
  if [[ "$name" == "all" ]]; then
    max_time=600
  fi

  if [[ -f "$out" && "$FORCE_REFRESH" != "1" ]]; then
    if validate_yaml "$out" 2>/dev/null; then
      if [[ "${UPDATE_RULE_CHECKSUMS}" != 1 ]] && ! verify_checksum "$out"; then
        return 1
      fi
      # Registry rules are public; the non-root scanner must read bind-mounted packs.
      chmod a+r "$out"
      echo "· pack already vendored: ${registry_path} ($(count_rules "$out") rules)"
      return 0
    fi
    echo "! invalid existing pack, re-downloading: ${registry_path}"
  fi

  if ! command -v curl >/dev/null 2>&1; then
    if [[ -f "$out" ]]; then
      echo "· curl unavailable; keeping existing pack: ${name}"
      return 0
    fi
    echo "curl required to download pack: ${registry_path}" >&2
    return 1
  fi

  tmp="$(mktemp)"
  echo "▸ downloading ${registry_path}"
  if ! curl -fsSL --retry 3 --retry-delay 2 --connect-timeout 20 --max-time "${max_time}" \
      -o "$tmp" "$url"; then
    rm -f "$tmp"
    if [[ -f "$out" ]]; then
      echo "! download failed; keeping existing: ${name}"
      return 0
    fi
    if [[ "$required" -eq 0 ]]; then
      echo "! optional pack unavailable: ${registry_path}"
      return 0
    fi
    echo "Failed to download ${url}" >&2
    return 1
  fi

  if ! validate_yaml "$tmp"; then
    rm -f "$tmp"
    if [[ "$required" -eq 0 ]]; then
      echo "! optional pack empty/invalid, skipped: ${registry_path}"
      return 0
    fi
    echo "Downloaded pack failed validation: ${registry_path}" >&2
    return 1
  fi

  if ! verify_checksum "$tmp" "${REQUIRE_RULE_CHECKSUMS}" "${out#"${ROOT}"/}"; then
    # A refreshed pack must be explicitly approved and recorded rather than
    # silently replacing a trusted release input.
    if [[ "${UPDATE_RULE_CHECKSUMS}" != "1" ]]; then
      rm -f "$tmp"
      return 1
    fi
  fi

  chmod a+r "$tmp"
  mv "$tmp" "$out"
  echo "✓ vendored ${name} ($(count_rules "$out") rules)"
}

# Validate local custom rules before any network work. This makes a malformed
# checkout fail fast and prevents a bad custom ruleset from triggering dozens
# of unnecessary registry downloads.
# Normalize existing pack permissions first. A failed custom validation must
# not leave an otherwise valid offline corpus unreadable by uid 10001.
find "${PACKS_DIR}" -maxdepth 1 -type f -name '*.yml' -exec chmod a+r {} +
if command -v semgrep >/dev/null 2>&1; then
  echo "▸ semgrep --validate (custom)"
  semgrep_tmp="$(mktemp -d)"
  # Resolve once so test harnesses and hermetic bootstrap environments can
  # provide a dedicated Semgrep binary via PATH without Bash command hashing
  # selecting a previously discovered system executable.
  semgrep_bin=""
  path_entry=""
  IFS=: read -r -a _path_entries <<< "${PATH:-}"
  for path_entry in "${_path_entries[@]}"; do
    if [[ -f "${path_entry}/semgrep" ]]; then
      semgrep_bin="${path_entry}/semgrep"
      break
    fi
  done
  [[ -n "${semgrep_bin}" ]] || semgrep_bin="$(command -v semgrep)"
  run_semgrep() {
    if [[ -x "${semgrep_bin}" ]]; then
      "${semgrep_bin}" "$@"
      return
    fi
    # Some hardened /tmp mounts are noexec.  A mounted shell/Python wrapper
    # can still be invoked through the interpreter named by its shebang.
    local shebang interpreter
    IFS= read -r shebang < "${semgrep_bin}" || return 126
    [[ "${shebang}" == '#!'* ]] || return 126
    interpreter="${shebang#\#!}"
    # Semgrep's console script has a single interpreter path; preserve the
    # simple form and avoid evaluating arbitrary source content.
    "${interpreter}" "${semgrep_bin}" "$@"
  }
  if ! SEMGREP_SEND_METRICS=off \
      SEMGREP_ENABLE_VERSION_CHECK=0 \
      SEMGREP_SETTINGS_FILE="${semgrep_tmp}/settings.yml" \
      SEMGREP_LOG_FILE=/dev/null \
      EIO_URING=posix \
      run_semgrep --validate --config "${CUSTOM_DIR}" --metrics off --disable-version-check; then
    rm -rf "${semgrep_tmp}"
    echo "Custom rule validation failed; ruleset manifest was not updated." >&2
    exit 1
  fi
  rm -rf "${semgrep_tmp}"
fi

# Existing optional packs and custom rules are release inputs too. Verify them
# before downloads or manifest regeneration, including when refresh falls back
# to a cached file. Explicit checksum updates are reviewed through git diff.
while IFS= read -r path; do
  validate_yaml "${path}"
  if [[ "${UPDATE_RULE_CHECKSUMS}" != 1 ]]; then
    verify_checksum "${path}" || exit 1
  fi
done < <(find "${PACKS_DIR}" "${CUSTOM_DIR}" -maxdepth 1 -type f \
  \( -name '*.yml' -o -name '*.yaml' \) -print)

failed=0
echo "━━ Required packs (full offline corpus) ━━"
for pack in "${REQUIRED_PACKS[@]}"; do
  if ! download_pack "$pack" 1; then
    failed=1
  fi
done

echo "━━ Optional packs ━━"
for pack in "${OPTIONAL_PACKS[@]}"; do
  if ! download_pack "$pack" 0; then
    failed=1
  fi
done

if [[ "$failed" -ne 0 ]]; then
  echo "One or more packs failed validation or could not be vendored." >&2
  exit 1
fi

if [[ ! -f "${PACKS_DIR}/all.yml" ]]; then
  echo "Critical: packs/all.yml (r/all) missing — offline full profile incomplete." >&2
  exit 1
fi

if [[ "${UPDATE_RULE_CHECKSUMS}" == "1" ]]; then
  {
    find "${PACKS_DIR}" "${CUSTOM_DIR}" -maxdepth 1 -type f \
      \( -name '*.yml' -o -name '*.yaml' \) -print | sort | while IFS= read -r path; do
      echo "$(sha256_file "${path}")  ${path#"${ROOT}"/}"
    done
  } > "${CHECKSUMS_FILE}"
  chmod a+r "${CHECKSUMS_FILE}"
fi

VERSION_TAG="2026.09.09-advanced-security-v2"
echo "${VERSION_TAG}" > "${VERSION_FILE}"

ALL_PACKS=("${REQUIRED_PACKS[@]}" "${OPTIONAL_PACKS[@]}")

{
  echo "# Auto-generated by scripts/download_rules.sh — do not edit by hand."
  echo "version: \"${VERSION_TAG}\""
  echo "registry_base: \"${CURL_BASE}\""
  echo "offline_full: true"
  echo "packs:"
  for registry_path in "${ALL_PACKS[@]}"; do
    name="${registry_path#*/}"
    kind="${registry_path%%/*}"
    path="${PACKS_DIR}/${name}.yml"
    [[ -f "$path" ]] || continue
    echo "  - id: ${name}"
    echo "    registry: ${registry_path}"
    echo "    file: packs/${name}.yml"
    echo "    url: ${CURL_BASE}/${kind}/${name}"
    echo "    sha256: $(sha256_file "$path")"
    echo "    rule_count: $(count_rules "$path")"
  done
  echo "custom:"
  for f in "${CUSTOM_FILES[@]}"; do
    path="${CUSTOM_DIR}/${f}"
    echo "  - file: custom/${f}"
    echo "    sha256: $(sha256_file "$path")"
    echo "    rule_count: $(count_rules "$path")"
  done
} > "${MANIFEST_FILE}"

pack_files="$(find "${PACKS_DIR}" -maxdepth 1 -name '*.yml' | wc -l | tr -d ' ')"
echo "Rules ready at ${RULES_DIR} (${pack_files} pack files + custom) — $(cat "${VERSION_FILE}")"
echo "Full offline dump: packs/all.yml ($(count_rules "${PACKS_DIR}/all.yml") rules)"
