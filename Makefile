SHELL := /bin/bash
ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
TARGET ?= $(ROOT)
# Reports always land under /tmp/<project-dir-name> unless OUTPUT is overridden
OUTPUT ?= /tmp/$(notdir $(abspath $(TARGET)))
HOST_UID := $(shell id -u)
HOST_GID := $(shell id -g)
HOST_CACHE ?= /tmp/dede-cache-$(HOST_UID)
COMPOSE_FILES := -f $(ROOT)/docker-compose.yml
ifeq ($(DEDE_DEVICE),cuda)
COMPOSE_FILES += -f $(ROOT)/docker-compose.gpu.yml
endif
COMPOSE := docker compose $(COMPOSE_FILES)
IMAGE ?= dede-scanner:1.10.0
VERSION := $(shell python -c 'import tomllib; print(tomllib.load(open("pyproject.toml", "rb"))["project"]["version"])')
DIST_DIR ?= dist/$(VERSION)
COVERAGE_MIN ?= 78

.PHONY: setup build model rules test test-parallel test-offline scan clean doctor sbom security-audit help install lint lint-fix format typecheck package release-check validate-rules lock lock-update code-scan

help:
	@echo "Dede targets:"
	@echo "  make setup          - build images, vendor rules, pull model"
	@echo "  make install        - install CLI (dede) for current user"
	@echo "  make build          - build scanner image"
	@echo "  make model MODEL=.. - check host fit then pull model (default: qwen3-coder:30b)"
	@echo "  make rules          - download/vendor semgrep rules"
	@echo "  make test           - run unit/integration tests"
	@echo "  make test-parallel  - pytest with xdist"
	@echo "  make test-offline   - verify offline scan"
	@echo "  make scan TARGET=.. - scan a project (reports → /tmp/<name>/)"
	@echo "  make code-scan      - run Dede on its own source"
	@echo "  make doctor         - run readiness checks in container"
	@echo "  make sbom           - generate scanner SBOM"
	@echo "  make security-audit - scan image and source dependencies with Trivy"
	@echo "  make clean          - remove local cache artifacts"
	@echo ""
	@echo "Quality targets (dev dependencies required):"
	@echo "  make lint           - ruff check"
	@echo "  make lint-fix       - ruff check --fix"
	@echo "  make format         - ruff format"
	@echo "  make typecheck      - mypy (ignore missing imports)"
	@echo "  make package        - build wheel + sdist, twine check"
	@echo "  make validate-rules - validate every native bundle and manifest"
	@echo "  make lock           - verify uv lock and hashed exports"
	@echo "  make lock-update    - regenerate hashed dependency exports"
	@echo "  make release-check  - validate code, locks, rules and packages (see release runbook)"

setup: rules build
	@echo "==> Starting Ollama and pulling model (requires network once)"
	$(COMPOSE) up -d ollama
	$(COMPOSE) --profile setup run --rm model-init
	@echo "==> Setup complete. Runtime scans can run offline."
	@echo "==> Install host CLI with: make install"
	@echo "==> Install pre-commit hooks: pre-commit install"

VENV := $(ROOT)/.venv
VPY := $(VENV)/bin/python

install:
	@if [ ! -x "$(VPY)" ] || ! "$(VPY)" -c "import sys" >/dev/null 2>&1; then \
		echo "==> Creating venv at $(VENV) (missing or broken)"; \
		rm -rf "$(VENV)"; \
		python3 -m venv "$(VENV)"; \
	fi
	"$(VPY)" -m pip install -e "$(ROOT)"
	@echo "CLI ready: $(VENV)/bin/dede"

build:
	$(COMPOSE) build scanner

MODEL ?= $(or $(DEDE_MODEL),qwen3-coder:30b)

model:
	$(COMPOSE) up -d ollama
	@echo "==> Pre-flight resource check for $(MODEL)"
	@if command -v dede >/dev/null 2>&1; then \
		dede model check "$(MODEL)" || { \
			echo "Model appears incompatible. Aborting pull."; \
			echo "Override only if you insist: dede model pull $(MODEL) --force"; \
			exit 2; \
		}; \
		dede model pull "$(MODEL)" -y; \
	else \
		DEDE_MODEL="$(MODEL)" $(COMPOSE) --profile setup run --rm model-init; \
	fi

rules:
	bash $(ROOT)/scripts/download_rules.sh

test:
	$(COMPOSE) --profile test build test
	$(COMPOSE) --profile test run --rm -e COVERAGE_FILE=/tmp/.coverage test -p no:cacheprovider -q /workspace/tests/unit /workspace/tests/integration --cov=dede --cov-report=term --cov-fail-under=$(COVERAGE_MIN)

test-parallel:
	$(COMPOSE) --profile test build test
	$(COMPOSE) --profile test run --rm -e COVERAGE_FILE=/tmp/.coverage test -p no:cacheprovider -q /workspace/tests/unit /workspace/tests/integration -n auto --cov=dede --cov-report=term --cov-fail-under=$(COVERAGE_MIN)

test-offline:
	bash $(ROOT)/scripts/verify_offline.sh

lint:
	python -m ruff check dede scripts/validate_release.py scripts/check_lock_exports.py scripts/validate_security_audit.py tests/unit/test_release_validation.py tests/unit/test_security_audit.py

lint-fix:
	python -m ruff check --fix dede

format:
	python -m ruff format dede

typecheck:
	python -m mypy dede --ignore-missing-imports --no-error-summary

package:
	python -m pip install --require-hashes -r requirements-build.lock
	python -m build --no-isolation --outdir "$(DIST_DIR)"
	python -m twine check "$(DIST_DIR)/dede-$(VERSION)-py3-none-any.whl" "$(DIST_DIR)/dede-$(VERSION).tar.gz"

validate-rules:
	python scripts/validate_release.py

lock:
	python scripts/check_lock_exports.py

lock-update:
	uv lock --check
	uv export --quiet --frozen --extra scanner --no-dev --no-emit-project --format requirements.txt --output-file requirements-scanner.lock
	uv export --quiet --frozen --all-extras --no-emit-project --format requirements.txt --output-file requirements-dev.lock

release-check: lint typecheck validate-rules lock package
	@echo "==> Checking bundled rules in wheel..."
	@python scripts/validate_release.py --wheel "$(DIST_DIR)/dede-$(VERSION)-py3-none-any.whl" --sdist "$(DIST_DIR)/dede-$(VERSION).tar.gz"

scan:
	mkdir -p "$(OUTPUT)" "$(HOST_CACHE)"
	chmod 700 "$(OUTPUT)" "$(HOST_CACHE)"
	TARGET="$(TARGET)" OUTPUT="$(OUTPUT)" DEDE_HOST_CACHE="$(HOST_CACHE)" \
		DEDE_UID="$(HOST_UID)" DEDE_GID="$(HOST_GID)" $(COMPOSE) run --rm \
		-e DEDE_OLLAMA_HOST=http://ollama:11434 \
		-e DEDE_PROJECT_NAME="$(notdir $(abspath $(TARGET)))" \
		scanner scan /workspace --output /reports

code-scan:
	@echo "==> Running Dede on itself (code smell / duplicate detection demo)"
	@if command -v dede >/dev/null 2>&1; then \
		dede scan $(ROOT) --output /tmp/dede-self-scan --no-ai; \
	else \
		echo "dede CLI not found — run make install first"; \
	fi

doctor:
	mkdir -p "$(OUTPUT)" "$(HOST_CACHE)"
	chmod 700 "$(OUTPUT)" "$(HOST_CACHE)"
	TARGET="$(TARGET)" OUTPUT="$(OUTPUT)" DEDE_HOST_CACHE="$(HOST_CACHE)" \
		DEDE_UID="$(HOST_UID)" DEDE_GID="$(HOST_GID)" $(COMPOSE) run --rm \
		scanner doctor --output /reports

sbom:
	bash $(ROOT)/scripts/generate_sbom.sh

security-audit:
	bash $(ROOT)/scripts/security_audit.sh

clean:
	rm -rf "$(ROOT)/.pytest_cache" "$(ROOT)/audit-reports"
	find $(ROOT) -type d -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true
