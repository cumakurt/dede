# Dede

<p align="center">
  <img src="dede.png" alt="Dede logo" width="220">
</p>

<p align="center">
  Offline-first static application security testing with deterministic analysis,
  optional Docker isolation, and optional local Ollama enrichment.
</p>

Dede scans a source tree without sending source code to a hosted service. Its
built-in engines perform rule matching, semantic data-flow analysis, dependency
reachability analysis, secret detection, security hardening checks, and code
quality analysis. External command-line analyzers extend coverage when they are
installed. A local Ollama model can explain findings and perform a bounded,
advisory vulnerability hunt.

The current release is **1.10.0**. Dede requires Python 3.12 or newer and is
distributed exclusively under the GNU Affero General Public License v3.0
(`AGPL-3.0-only`).

## Contents

- [What Dede provides](#what-dede-provides)
- [Requirements](#requirements)
- [Installation](#installation)
- [First scan](#first-scan)
- [Runtime selection](#runtime-selection)
- [Scan command](#scan-command)
- [Configuration](#configuration)
- [Analysis model](#analysis-model)
- [Language support](#language-support)
- [Reports and evidence](#reports-and-evidence)
- [CI, baselines, and policy gates](#ci-baselines-and-policy-gates)
- [Local AI](#local-ai)
- [Offline operation](#offline-operation)
- [Advanced workflows](#advanced-workflows)
- [Security and privacy](#security-and-privacy)
- [Development](#development)
- [Troubleshooting](#troubleshooting)
- [Uninstallation](#uninstallation)

## What Dede provides

- A built-in native rule engine that needs no external analyzer binary and is
  always available with the package.
- Project-wide semantic source-to-sink analysis for 15 application languages.
- A native ruleset with 287 rules across 13 bundles, including bounded document
  checks and local C# / Razor taint checks.
- Optional offline Semgrep, Bandit, Ruff, Gitleaks, Lizard, `go vet`, and Gosec
  execution.
- Offline software composition analysis from pinned dependency manifests and
  local advisory snapshots, with source reachability evidence.
- Precision profiles that distinguish production findings from broader audit and
  experimental results.
- JSON, self-contained HTML, archival PDF/A-3u, and SARIF 2.1.0 reports.
- Finding correlation, stable fingerprints, lifecycle states, attack graphs,
  DedeQL classifications, policy gates, and expiring suppressions.
- Optional local-only AI enrichment and a separate project-wide AI hunt.
- Native host execution or a hardened, read-only Docker runtime.

Dede is a static analysis tool. A finding is evidence for review, not proof that
the target is exploitable. Incomplete or skipped analyzer coverage remains
visible in the report and must not be interpreted as a clean bill of health.

## Requirements

The minimum host installation needs:

- Linux;
- Python 3.12 or newer;
- enough space for the Python environment and bundled rules.

Optional components have additional requirements:

- Docker Engine and Docker Compose v2 for the isolated scanner image;
- WeasyPrint and its system libraries for native PDF/PDF-A generation;
- Ollama for AI enrichment;
- approximately 20 GB of disk for the default `qwen3-coder:30b` model;
- an NVIDIA container runtime when `DEDE_DEVICE=cuda` is selected.

The Docker scanner contains the full supported analyzer toolchain and PDF
dependencies. Native scans remain useful when external analyzers are absent:
missing optional tools are recorded as skipped coverage rather than preventing
the built-in engines from running.

## Installation

Clone the repository and run the installer:

```bash
git clone https://github.com/cumakurt/dede.git
cd dede
./install.sh
```

The installer detects the Linux distribution, installs only missing packages,
creates the project virtual environment, validates bundled rules, and offers the
optional reporting, Docker, and Ollama components. Interactive questions default
to `yes`. Detailed setup output is stored in a private
`/tmp/dede-install.*/install.log` directory and can also be streamed with
`--verbose`.

Common installation modes:

```bash
./install.sh --skip-docker-setup --skip-model  # lightweight native installation
./install.sh --with-reporting --skip-model     # native scan + PDF support
./install.sh --with-docker --skip-model        # build the isolated scanner
./install.sh --with-docker --pull-model        # scanner + local AI model
./install.sh -y                                # accept all default components
./install.sh --force-rebuild                   # rebuild an existing scanner image
./install.sh --verbose                         # stream detailed setup output
```

`--skip-model` never starts Ollama. `--skip-docker-setup` never builds or verifies
the scanner image. `--force-rebuild` implies Docker setup. Already installed
packages, images, and models are reused.

For an editable development-oriented host install:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
```

Add native PDF support with:

```bash
python -m pip install -e '.[reporting]'
```

## First scan

Run a deterministic scan of the current project:

```bash
dede doctor --runtime native
dede scan . --runtime native --no-ai
```

By default, reports are written to `/tmp/<project-directory-name>/`. For a
project named `shop-api`, the path is `/tmp/shop-api/`. If that directory is
owned by another user, Dede uses `/tmp/shop-api-<uid>/` instead.

Choose an explicit output directory and a CI failure threshold when needed:

```bash
dede scan . \
  --runtime native \
  --no-ai \
  --output /tmp/shop-api-scan \
  --format json \
  --format sarif \
  --fail-on HIGH
```

Repeated `--format` options replace the configured format list. The default
formats are JSON, HTML, and PDF; SARIF is opt-in unless added to `.dede.yml`.
Native PDF is skipped when its optional dependency is unavailable. JSON, HTML,
and SARIF generation continue.

## Runtime selection

`dede scan` and `dede doctor` accept `--runtime auto|native|docker`.

| Runtime | Behavior | Best suited for |
| --- | --- | --- |
| `auto` | Uses the local scanner image when present; otherwise falls back to the host-native scanner. It never builds or pulls an image implicitly. | Normal interactive use |
| `native` | Runs directly on the host and does not probe Docker. Built-in analyzers always run; optional executables are discovered from `PATH`. | Lightweight setups and strict no-Docker workflows |
| `docker` | Requires the prebuilt `dede-scanner:1.10.0` image and runs the complete toolchain in an isolated container. | Reproducible scans and CI |

Build the Docker scanner with either command:

```bash
./install.sh --with-docker --skip-model
make build
```

In Docker mode the target is mounted read-only at `/workspace`, the report
directory and private cache are the only writable mounts, the container runs as
the invoking user, Linux capabilities are dropped, privilege escalation is
disabled, and the Docker socket is not mounted.

For NVIDIA acceleration of the local model:

```bash
export DEDE_DEVICE=cuda
./install.sh --with-docker --pull-model
```

## Scan command

The complete public scan interface is:

```text
dede scan TARGET
  [--format json|html|pdf|sarif]...
  [--output PATH]
  [--runtime auto|native|docker]
  [--no-ai]
  [--offline]
  [--ai-hunt | --no-ai-hunt]
  [--severity LEVEL | --fail-on LEVEL]
  [--exclude PATTERN]...
  [--respect-gitignore]
  [--baseline REPORT_JSON]
  [--config PATH]
  [--model NAME]
  [--security-profile strict|smart|audit|experimental]
  [--yes]
```

Useful examples:

```bash
# Default precision-first scan
dede scan . --security-profile smart

# Deterministic, network-independent scan
dede scan . --runtime native --no-ai

# Broad review with additional exclusions
dede scan . --security-profile audit \
  --exclude generated \
  --exclude 'examples/**'

# Respect the root .gitignore and emit CI formats
dede scan . --respect-gitignore \
  --format json --format html --format sarif \
  --fail-on HIGH

# Require the containerized toolchain
dede scan /path/to/project --runtime docker --no-ai
```

Dede applies its built-in exclusions by default, including VCS directories,
dependency trees, virtual environments, caches, and common build output. It does
not apply `.gitignore` unless `--respect-gitignore` or the corresponding config
option is enabled. Only the target root's `.gitignore` is read; nested files are
not consulted.

The output directory cannot be the source directory, a parent of the source, or
a symbolic link. In Docker mode, explicit config and baseline files must be
inside the scanned target and outside the report directory.

## Configuration

Dede automatically reads `.dede.yml` or `.dede.yaml` from the target root. Pass
`--config` to select a different file. Configuration precedence is:

```text
CLI options > environment variables > project YAML > saved model preference > defaults
```

The repository's [`.dede.yml`](.dede.yml) is a complete reference. A practical
starting configuration is:

```yaml
offline: true

scan:
  respect_gitignore: true
  max_file_size_mb: 5
  max_files: 50000
  analyzer_timeout_seconds: 300
  progress_interval_seconds: 5

exclude:
  - tests/fixtures
  - generated

severity:
  fail_on: HIGH

reports:
  formats: [json, html, sarif]

ai:
  enabled: false
  model: qwen3-coder:30b
  hunt_enabled: false

engine:
  profile: smart
  report_low_confidence: false

performance:
  persistent_index: true
  dependency_aware: true
  semantic_cache: true

semantic:
  enabled: true
  max_call_depth: 12
  max_contexts: 10000
  framework_models: true
  endpoint_parameters_as_sources: true
  builtin_flow_queries: true

sca:
  enabled: true
  builtin_advisories: true
  report_unreachable: true
  require_exact_version: true

experimental:
  authorization_analysis: false
  business_logic_analysis: false
  agent_security: true
```

Top-level `exclude` entries are added to the built-in exclusion list. CLI
`--exclude` values are added after project configuration rather than replacing
it.

Supported environment overrides include:

| Variable | Purpose | Default |
| --- | --- | --- |
| `DEDE_MODEL` | Ollama model name | `qwen3-coder:30b` |
| `DEDE_DEVICE` | Model device: `auto`, `cpu`, or `cuda` | `auto` |
| `DEDE_MAX_FILE_SIZE_MB` | Maximum source file size | `5` |
| `DEDE_LLM_MAX_CONTEXT` | Model context window | `32768` |
| `DEDE_OLLAMA_HOST` | Ollama endpoint | host config defaults to `http://127.0.0.1:11434` |
| `DEDE_OFFLINE` | Refuse model downloads during a scan | `false` |
| `ANALYZER_TIMEOUT_SECONDS` | Per-analyzer timeout | `300` |
| `MAX_FILES` | Discovery ceiling | `50000` |
| `MAX_LLM_FINDINGS` | Maximum findings sent for enrichment | `200` |
| `LLM_CONCURRENCY` | Concurrent local model requests | `4` |

See [semantic engine configuration](docs/semantic-engine.md),
[DedeQL](docs/dedeql.md), and [enterprise policy](docs/enterprise-policy.md) for
the advanced schema.

## Analysis model

The scan pipeline follows seven evidence-preserving stages:

```text
Source tree
  -> safe file discovery and language/framework detection
  -> applicable deterministic analyzers
  -> normalization, correlation, and deduplication
  -> optional local AI hunt and enrichment
  -> suppression, policy, lifecycle, and risk evaluation
  -> JSON / HTML / PDF / SARIF evidence
```

### Built-in analyzers

The package registers the following built-in analysis components:

- `dede-engine`: native line, bounded document, and local .NET taint rules;
- `dede-semantic-python`: deep Python AST and cross-file data-flow analysis;
- `dede-semantic-polyglot`: project semantic graphs for the other first-class
  languages;
- `dede-sca`: pinned dependency and local advisory matching with reachability;
- `dede-hardening`: high-confidence TLS, crypto, JWT/session, file-permission,
  logging, and token-randomness checks;
- `dede-agent-security`: explicit dangerous MCP and agent configuration checks;
- `dede-authz-experimental`: opt-in authorization and business-logic candidates;
- duplicate and code-smell analyzers;
- adapters for Semgrep, Gitleaks, Bandit, Ruff, Lizard, `go vet`, and Gosec.

Installed packages can add analyzers through the `dede.analyzers` entry-point
group. Invalid optional plugins are isolated and cannot prevent the built-in
registry from starting.

### Precision profiles

`smart` is the production default:

| Profile | Included evidence |
| --- | --- |
| `strict` | Very-high precision findings and independently corroborated high-precision findings |
| `smart` | Production-oriented evidence; filters uncorroborated low-precision native and experimental findings |
| `audit` | Adds lower-confidence review evidence while still filtering uncorroborated experimental findings |
| `experimental` | Exposes every produced finding for research and rule tuning |

Choosing the `experimental` profile does not enable disabled analyzers. Set
`experimental.authorization_analysis` and/or
`experimental.business_logic_analysis` explicitly. Those analyzers currently
target Python web handlers and label their results as experimental.

The engine profile and the Semgrep profile are separate settings. Semgrep accepts
`smart`, `full`, or `custom-only` through `semgrep.profile`.

### Evidence and correlation

Semantic findings retain source, propagation, and sink evidence when the analyzer
can prove it. Findings also carry CWE, confidence, precision, reachability,
exploitability, endpoint exposure, rule references, and standards mappings when
available. Cross-engine correlation merges compatible results while preserving
the contributing analyzers.

DedeQL classifies already-proven flows by source, sink, CWE, endpoint,
authentication, internet exposure, and exploitability. It does not create new
findings or change engine severity.

## Language support

Run the authoritative matrix shipped with the installed version:

```bash
dede languages
dede languages --json
```

First-class project-wide semantic analysis covers:

- Python;
- JavaScript and TypeScript;
- Java and Kotlin;
- C#/.NET;
- Go;
- PHP and Ruby;
- Rust;
- C and C++;
- Swift, Scala, and Dart.

Python uses a dedicated AST frontend. The remaining languages use Security IR
v4, which indexes modules, imports, functions, calls, control-flow nodes,
framework endpoints, and bounded cross-file taint. Resolution is conservative:
ambiguous dynamic calls are left unresolved instead of being guessed.

Shell, PowerShell, Perl, Lua, R, Julia, Elixir, Erlang, Clojure, Haskell, OCaml,
Solidity, Apex, Zig, Groovy, Objective-C, Vue, and Svelte receive supplementary
native and/or vendored rule coverage. See the detailed
[language support matrix](docs/language-support-1.9.md).

## Reports and evidence

A default scan can create:

```text
/tmp/<project-name>/
├── report.json              # canonical machine-readable result
├── report.html              # self-contained offline dashboard
├── report.pdf               # tagged PDF/A-3u evidence package
├── report.pdf.sha256        # PDF integrity sidecar
├── metadata.json            # scan and coverage metadata
├── scan-manifest.json       # configuration and rule digests
├── finding-lifecycle.json   # NEW/EXISTING/RESOLVED/REOPENED state
└── raw/                     # analyzer evidence and semantic graphs
```

`report.sarif` is added when `sarif` is requested. Exact output depends on the
selected formats, analyzer applicability, available optional dependencies, and
whether persistent indexing is enabled.

The HTML report has no CDN, remote font, analytics, or network dependency. It
provides local search and filters, finding permalinks, analyzer health,
lifecycle, policy, attack-surface, standards, DedeQL, and performance views.

The PDF report is generated locally and embeds the canonical scan evidence plus
the scan manifest. Its SHA-256 sidecar allows an archived PDF to be checked for
changes:

```bash
cd /tmp/myproject
sha256sum --check report.pdf.sha256
```

The `raw/` directory can include Security IR, source-to-sink attack graphs in JSON
and Graphviz DOT, the unified attack graph, and individual analyzer artifacts.
See [reporting](docs/reporting.md) for format details.

### Persistent index and lifecycle

Dede's local SQLite index stores file hashes, dependency edges, and finding
identities; it does not store source code. On later scans it expands changed
paths through reverse dependencies and safely reuses semantic results whose
evidence does not intersect the affected set. Analyzer or semantic configuration
changes invalidate incompatible cache entries.

Lifecycle states are advanced only when analyzer coverage is complete. A scan
with failed or skipped required coverage records the lifecycle result as
incomplete rather than falsely marking findings as resolved. See
[incremental analysis](docs/incremental-analysis.md).

## CI, baselines, and policy gates

Use `--fail-on` (an alias of `--severity`) to make findings at or above a level
fail the scan:

```bash
dede scan . --runtime native --no-ai \
  --format json --format sarif \
  --security-profile strict \
  --fail-on HIGH
```

AI-hunt findings are advisory and do not trigger the severity gate. Unsuppressed
deterministic findings and configured path policies do.

Exit codes are stable automation signals:

| Code | Meaning |
| ---: | --- |
| `0` | Scan completed and all configured gates passed |
| `1` | Severity threshold or path policy failed |
| `2` | Invalid configuration, option, or path |
| `3` | Runtime error or analyzer failure/incomplete coverage |
| `4` | One or more report writers failed |

### Baseline comparison

Create and use a previous JSON report as a baseline:

```bash
dede scan . --no-ai --output /tmp/myproject-baseline --format json
cp /tmp/myproject-baseline/report.json .dede-baseline.json

dede scan . --no-ai --baseline .dede-baseline.json
```

Baselines support delta review; persistent lifecycle tracking independently
records `NEW`, `EXISTING`, `RESOLVED`, and `REOPENED` identities.

### Scoped policy and suppression

Prefer reviewed, path-scoped, expiring suppressions over broad rule removal:

```yaml
suppress:
  entries:
    - rule: dede.example.rule
      path: tests/**
      reason: Approved vulnerable test fixture
      expires: 2027-01-01
      approved_by: security-team

policy:
  enabled: true
  rules:
    - name: public-services
      path: services/public/**
      deny_severity: HIGH
      categories: [security, secret]
```

Expired suppressions stop matching automatically. Policy violations are stored
in scan metadata and return exit code 1. See [enterprise policy](docs/enterprise-policy.md).

## Local AI

AI is optional and never replaces deterministic findings. It has two roles:

1. Enrichment explains and proposes remediation for existing findings.
2. AI hunt reviews a deterministic, bounded set of project files for additional
   advisory candidates.

Both use the configured local Ollama endpoint. Model output is schema-validated,
source-grounded, secret-redacted, and labeled separately. Suggested fixes are
checked through deterministic analyzers before verification metadata is attached.

Manage models with:

```bash
dede model list
dede model list --all
dede model recommend
dede model check qwen2.5-coder:7b
dede model pull qwen2.5-coder:7b
dede model use qwen2.5-coder:7b
dede model show
```

`dede model use` saves the preference under
`~/.config/dede/settings.yml`. Project YAML, environment variables, and CLI
options can override it.

Scan with a selected local model:

```bash
dede scan . --model qwen2.5-coder:7b --ai-hunt
```

Disable every model-related path with:

```bash
dede scan . --no-ai
```

`--no-ai` skips model probing, installation checks, enrichment, AI hunt, and AI
verification. Native runtime does not touch Docker. Docker runtime starts the
scanner with `--no-deps`, so Ollama is not started.

## Offline operation

Dede performs no package, rule, advisory, image, or model download during a
normal scan. Network access is needed only when deliberately bootstrapping or
updating dependencies, rules, images, or models.

Prepare the complete environment while online:

```bash
make setup       # vendor rules, build scanner, and pull the configured model
make install     # install the host CLI
```

Then verify network-independent operation:

```bash
dede scan . --runtime native --no-ai
dede scan . --runtime docker --no-ai
dede scan . --offline                 # local AI allowed; downloads forbidden
make test-offline
```

`--offline` differs from `--no-ai`: it permits local AI when the configured model
is already installed, but refuses to download a missing model. For the smallest
and clearest trust boundary, combine native runtime with `--no-ai`.

Vendored Semgrep packs can be inspected or refreshed explicitly:

```bash
dede rules list
dede rules update
dede rules update --force
```

Rule updates require network access. Runtime scans do not update rules.

Offline SCA consumes built-in advisories plus local Dede or OSV JSON snapshots.
Place project snapshots under `.dede/advisories/` or list them in
`sca.advisory_paths`. No vulnerability API is queried during scanning.

## Advanced workflows

### Watch mode

Watch source files and reuse the semantic cache:

```bash
dede watch .                  # deterministic by default
dede watch . --ai
dede watch . --interval 2
dede watch . --once
```

### Read-only report server

Serve an existing HTML/JSON report on localhost:

```bash
dede serve /tmp/myproject
dede serve /tmp/myproject --port 9000
```

The server binds to `127.0.0.1` and exposes a read-only report UI/API.

### MCP access

Expose normalized findings from a JSON report through a local read-only MCP
stdio server:

```bash
dede mcp /tmp/myproject/report.json
```

The MCP server does not scan source, execute target code, or open a network
socket.

### Fix verification

Compare deterministic reports before and after remediation:

```bash
dede verify-fix before-report.json after-report.json
dede verify-fix before-report.json after-report.json --finding <fingerprint>
```

Verification fails when earlier findings persist or new HIGH/CRITICAL findings
appear.

### Framework model packs

Offline JSON model packs extend semantic sources, sinks, and sanitizers. External
organization packs can be integrity-checked and signed with HMAC-SHA256:

```bash
export DEDE_MODEL_PACK_KEY='read-from-a-secure-secret-store'
dede packs sign corp-pack.json
dede packs verify corp-pack.json --require-signature
```

Set `model_packs.require_signature: true` to reject unsigned external packs. See
[platform capabilities](docs/platform-1.8.md).

### Feedback and precision benchmarks

Record local triage without silently creating a suppression:

```bash
dede feedback add <semantic-fingerprint> \
  --verdict false-positive \
  --reason 'Validated internal wrapper' \
  --rule-id dede.example
dede feedback list
```

Run the bundled deterministic regression corpora:

```bash
dede benchmark precision
dede benchmark hardening
```

The benchmark command returns non-zero when configured precision or recall
thresholds are missed. Bundled corpora are regression checks, not estimates of
real-world false-positive rates.

## Security and privacy

Dede's runtime design enforces these boundaries:

- source is processed locally;
- normal scans do not call rule registries, advisory services, or hosted LLMs;
- Docker source mounts are read-only;
- the scanner runs without root, added capabilities, or a Docker socket;
- secrets are redacted before logs, reports, and model prompts are serialized;
- HTML report behavior is self-contained and does not use remote assets;
- AI results remain visibly distinct and do not drive the default CI gate;
- output and cache paths must be owned by the invoking user and cannot be
  symbolic links.

Project configuration cannot redirect AI to an arbitrary remote host. The
Ollama URL validator accepts only loopback and the Docker service name used by
Dede. Review [SECURITY.md](SECURITY.md) for vulnerability reporting and supported
versions.

Rule coverage does not establish compliance. CWE, OWASP Top 10:2025, ASVS 5.0,
NIST SSDF, and selected platform mappings identify relevant static evidence for
review; they are not certifications or control pass/fail decisions.

## Development

Install the locked development environment with `uv`:

```bash
uv sync --locked --all-extras
uv run dede --help
```

The principal Make targets are:

```bash
make help
make lint
make typecheck
make test
make test-parallel
make test-offline
make validate-rules
make release-check
```

Other useful targets include `build`, `install`, `model`, `rules`, `scan`,
`code-scan`, `doctor`, `package`, `sbom`, `security-audit`, and `clean`.

Before opening a pull request, run:

```bash
make lint
make typecheck
make test
python scripts/validate_release.py
```

Rule changes require unsafe and safe regression examples. Release inputs use
hashed dependency exports and rule manifests. See [CONTRIBUTING.md](CONTRIBUTING.md)
and the [release runbook](docs/release-runbook.md).

## Troubleshooting

Check the installed version and runtime readiness first:

```bash
dede version
dede info
dede doctor --runtime native
dede doctor --runtime docker
```

Common conditions:

- **Docker image not found:** run `./install.sh --with-docker` or `make build`, or
  select `--runtime native`.
- **PDF skipped in native mode:** install `.[reporting]` and the required system
  libraries, or use the Docker runtime.
- **Model missing in offline mode:** pull it while online with
  `dede model pull <name>` or scan with `--no-ai`.
- **Report directory owned by another user:** choose `--output` pointing to a
  directory owned by the current user. Dede preserves foreign-owned paths.
- **Slow Docker verification:** retry installation with
  `DEDE_SCANNER_CHECK_TIMEOUT=180 ./install.sh --with-docker`.
- **Slow Ollama startup:** adjust `DEDE_OLLAMA_START_TIMEOUT` (default 300
  seconds) and `DEDE_OLLAMA_READY_TIMEOUT` (default 90 seconds).
- **Stale scanner after source changes:** rebuild it with
  `./install.sh --force-rebuild`.

Long scans emit heartbeat messages according to
`scan.progress_interval_seconds`, so a quiet analyzer is not mistaken for a
hung process. Analyzer duration and status are recorded in the final report.

## Uninstallation

Remove only Dede-managed runtime resources:

```bash
sudo ./uninstall.sh --yes
```

Preserve the Ollama model volume and Dede configuration if desired:

```bash
sudo ./uninstall.sh --yes --keep-models --keep-config
```

The uninstaller does not prune unrelated containers, networks, volumes, or
shared upstream images.

## Documentation

- [Security rule authoring](docs/security-rules.md)
- [Semantic engine](docs/semantic-engine.md)
- [Language support](docs/language-support-1.9.md)
- [Security hardening and profiles](docs/security-hardening.md)
- [Reporting](docs/reporting.md)
- [DedeQL](docs/dedeql.md)
- [Incremental analysis](docs/incremental-analysis.md)
- [Enterprise policy and suppression](docs/enterprise-policy.md)
- [Platform capabilities](docs/platform-1.8.md)
- [Release runbook](docs/release-runbook.md)
- [Changelog](CHANGELOG.md)

## Author

**Cuma KURT**

- Email: [cumakurt@gmail.com](mailto:cumakurt@gmail.com)
- LinkedIn: [linkedin.com/in/cuma-kurt-34414917](https://www.linkedin.com/in/cuma-kurt-34414917/)
- GitHub: [github.com/cumakurt/dede](https://github.com/cumakurt/dede)

## License

GNU Affero General Public License v3.0 only (`AGPL-3.0-only`). See
[LICENSE](LICENSE).
