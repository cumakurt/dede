# syntax=docker/dockerfile:1.7

ARG SCANNER_RUNTIME=cgr.dev/chainguard/wolfi-base@sha256:65e1acb87a2bf356b92c5f70f3980f03b4bb51dfd483c834e01557525f15c1d9
ARG PYTHON_IMAGE=python:3.12.14-slim-trixie@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea

# Build the pure-Python wheel in a separate, locked environment. Keeping the
# build backend out of the runtime stage prevents an unpinned build-isolation
# download from changing the scanner image.
FROM ${PYTHON_IMAGE} AS wheel
WORKDIR /build
COPY pyproject.toml README.md LICENSE ./
COPY dede ./dede
COPY rules ./rules
COPY requirements-build.lock ./
RUN python -m pip install --no-cache-dir --require-hashes -r requirements-build.lock \
    && python -m pip wheel --no-cache-dir --no-deps --no-build-isolation --wheel-dir /dist .

FROM ${PYTHON_IMAGE} AS go-tools
ENV PATH="/usr/local/go/bin:${PATH}"
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*

# Install a current Go toolchain (pinned and checksum-verified) for go vet on
# both common Linux architectures.
ARG GO_VERSION=1.27.1
ARG GO_SHA256_AMD64=63d339f0da5ab53635a56f2490a7984dfe12dfcff22ad749f63edaf590168445
ARG GO_SHA256_ARM64=3450b45a3f9ee8568792736a5c5e70a1f2e9b36c35a8f74958c03e51d7d92bec
ARG TARGETARCH
RUN set -eu; \
    case "${TARGETARCH}" in \
      amd64) expected="${GO_SHA256_AMD64}" ;; \
      arm64) expected="${GO_SHA256_ARM64}" ;; \
      *) echo "Unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL --connect-timeout 20 --max-time 300 --retry 3 \
      "https://go.dev/dl/go${GO_VERSION}.linux-${TARGETARCH}.tar.gz" -o /tmp/go.tgz; \
    echo "${expected}  /tmp/go.tgz" | sha256sum -c -; \
    tar -C /usr/local -xzf /tmp/go.tgz; \
    rm /tmp/go.tgz

# Install Gitleaks from its tagged Go module. Go's checksum database verifies
# the module. The direct requirements keep transitive x/crypto and x/text on
# patched releases, while compiling here avoids shipping an old toolchain
# binary. Semgrep is installed from the hashed scanner lock export below.
ARG GITLEAKS_VERSION=8.30.1
RUN set -eux; \
    mkdir -p /tmp/gitleaks-build; \
    printf '%s\n' \
      'module dede-gitleaks-build' \
      'go 1.27' \
      '' \
      'require (' \
      "  github.com/zricethezav/gitleaks/v8 v${GITLEAKS_VERSION}" \
      '  golang.org/x/crypto v0.56.0' \
      '  golang.org/x/text v0.41.0' \
      '  github.com/nwaples/rardecode/v2 v2.2.0' \
      '  github.com/mholt/archives v0.1.5' \
      '  github.com/ulikunitz/xz v0.5.15' \
      ')' > /tmp/gitleaks-build/go.mod; \
    cd /tmp/gitleaks-build; \
    GOTOOLCHAIN=local GOPROXY=https://proxy.golang.org,direct \
      GOSUMDB=sum.golang.org go get \
      "github.com/zricethezav/gitleaks/v8@v${GITLEAKS_VERSION}" \
      golang.org/x/crypto@v0.56.0 golang.org/x/text@v0.41.0 \
      github.com/nwaples/rardecode/v2@v2.2.0 github.com/mholt/archives@v0.1.5 \
      github.com/ulikunitz/xz@v0.5.15; \
    GOTOOLCHAIN=local GOPROXY=https://proxy.golang.org,direct \
      GOSUMDB=sum.golang.org go build -trimpath -ldflags="-s -w -X github.com/zricethezav/gitleaks/v8/version.Version=${GITLEAKS_VERSION}" \
      -o /usr/local/bin/gitleaks github.com/zricethezav/gitleaks/v8; \
    mkdir -p /usr/local/share/dede/go-deps; \
    GOTOOLCHAIN=local GOPROXY=off go list -deps github.com/zricethezav/gitleaks/v8 > /usr/local/share/dede/go-deps/gitleaks.txt; \
    gitleaks version; \
    rm -rf /tmp/gitleaks-build /root/go /root/.cache/go-build

# Optional gosec binary (may be skipped at runtime if modules are missing).
# Build it from its tagged Go module so the Go checksum database verifies the
# source and the resulting binary uses the current, patched Go standard library
# instead of an older upstream build toolchain.
ARG GOSEC_VERSION=2.29.0
ARG GOSEC_GRPC_VERSION=1.83.2
RUN set -eux; \
    mkdir -p /tmp/gosec-build; \
    printf '%s\n' \
      'module dede-gosec-build' \
      'go 1.27' \
      '' \
      'require (' \
      "  github.com/securego/gosec/v2 v${GOSEC_VERSION}" \
      "  google.golang.org/grpc v${GOSEC_GRPC_VERSION}" \
      '  golang.org/x/crypto v0.56.0' \
      ')' > /tmp/gosec-build/go.mod; \
    cd /tmp/gosec-build; \
    GOTOOLCHAIN=local GOPROXY=https://proxy.golang.org,direct \
      GOSUMDB=sum.golang.org go get \
      "github.com/securego/gosec/v2/cmd/gosec@v${GOSEC_VERSION}" \
      "google.golang.org/grpc@v${GOSEC_GRPC_VERSION}" golang.org/x/crypto@v0.56.0; \
    GOTOOLCHAIN=local GOPROXY=https://proxy.golang.org,direct \
      GOSUMDB=sum.golang.org go build -trimpath -ldflags="-s -w -X main.Version=${GOSEC_VERSION} -X main.GitTag=v${GOSEC_VERSION}" \
      -o /usr/local/bin/gosec github.com/securego/gosec/v2/cmd/gosec; \
    mkdir -p /usr/local/share/dede/go-deps; \
    GOTOOLCHAIN=local GOPROXY=off go list -deps github.com/securego/gosec/v2/cmd/gosec > /usr/local/share/dede/go-deps/gosec.txt; \
    gosec -version; \
    rm -rf /tmp/gosec-build /root/go /root/.cache/go-build

FROM ${SCANNER_RUNTIME} AS base
LABEL org.opencontainers.image.title="Dede" \
      org.opencontainers.image.description="Offline static security scanner" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      com.dede.managed="true" \
      com.dede.component="scanner"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    SEMGREP_SEND_METRICS=off \
    SEMGREP_ENABLE_VERSION_CHECK=0 \
    DO_NOT_TRACK=1 \
    PATH="/opt/dede/bin:/home/auditor/.local/bin:/usr/local/go/bin:${PATH}" \
    DEDE_OLLAMA_HOST=http://ollama:11434

# Keep the glibc runtime current while preserving C compilation for Go/cgo.
RUN apk add --no-cache \
      bash=5.3-r13 ca-certificates-bundle=20260611-r1 python-3.12=3.12.14-r6 \
      git=2.55.0-r7 gcc=16.2.0-r1 glibc-2.44-dev=2.44-r6 \
      linux-headers=7.2.5-r0 pango=1.58.2-r1 harfbuzz=14.4.0-r1 ttf-dejavu=2.37-r8 \
    && python3.12 -m venv /opt/dede

COPY --from=go-tools /usr/local/share/dede/go-deps /usr/local/share/dede/go-deps
COPY --from=go-tools /usr/local/go /usr/local/go
COPY --from=go-tools /usr/local/bin/gitleaks /usr/local/bin/gosec /usr/local/bin/

RUN adduser -D -u 10001 -s /sbin/nologin auditor \
    && mkdir -p /workspace /reports /rules /var/lib/dede/cache \
    && chown -R auditor:auditor /reports /var/lib/dede

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY dede ./dede
COPY rules ./rules
COPY requirements-scanner.lock ./
COPY --from=wheel /dist/dede-*.whl /tmp/
# Native engine rules are also exposed at their conventional path.
RUN mkdir -p /rules/dede-engine

RUN python -m pip install --no-cache-dir --require-hashes -r requirements-scanner.lock \
    && python -m pip install --no-cache-dir --no-deps /tmp/dede-*.whl \
    && semgrep --version \
    && rm -rf /rules/* \
    && cp -a /app/rules/. /rules/ \
    && SEMGREP_SETTINGS_FILE=/tmp/semgrep-settings.yml semgrep --validate --config /rules/semgrep/custom \
    && chown -R auditor:auditor /rules /var/lib/dede \
    && test -f /rules/dede-engine/core.json \
    && touch /opt/dede-scanner \
    && python -m pip check \
    && python -m pip uninstall --yes pip

# Prebuild the font cache and verify PDF libraries before the filesystem becomes
# read-only. pip is needed only while installing build/test dependencies.
RUN mkdir -p /var/cache/fontconfig \
    && python -c 'from weasyprint import HTML; assert HTML(string="<p>Dede</p>").write_pdf().startswith(b"%PDF-")'

USER auditor
WORKDIR /workspace

ENTRYPOINT ["dede"]
CMD ["--help"]

# Test image: run the complete unit/integration suite with the exact scanner
# toolchain. Source is mounted by docker-compose so tests always exercise the
# current checkout, while analyzers remain inside the image.
FROM base AS test
USER root
WORKDIR /app
COPY requirements-dev.lock ./
# Host installer checks require GNU timeout, not the BusyBox applet.
RUN apk add --no-cache coreutils \
    && python -m ensurepip \
    && python -m pip install --no-cache-dir --require-hashes -r requirements-dev.lock
COPY tests ./tests
USER auditor
WORKDIR /workspace
ENTRYPOINT ["pytest"]
CMD ["-q", "/workspace/tests"]
