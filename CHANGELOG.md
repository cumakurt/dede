## 1.10.0 - 2026-09-13

- Changed the Dede application distribution license to GNU Affero General Public License v3.0 only (`AGPL-3.0-only`) and added matching package and container metadata.
- Added a precision-first security hardening analyzer for explicit TLS validation bypasses, ECB/legacy crypto misuse, JWT/session weaknesses, insecure temporary files/permissions, secret logging and security-token PRNG misuse.
- Added a 44-rule native hardening bundle and bumped the native Dede Engine ruleset to 0.5.0.
- Expanded semantic vulnerability families for sensitive-data logging, LDAP/XPath/NoSQL injection, unsafe deserialization, template injection, open redirects, path/file operations and broader SSRF sinks.
- Added built-in Laravel, NestJS, Go web, Rails and Vapor model packs with deterministic integrity metadata.
- Upgraded experimental authorization/business-logic analysis with privileged-route, IDOR/BOLA, authorization-ordering, financial-value and state-transition candidates; these remain opt-in.
- Added strict/smart/audit/experimental security profiles and a second Precision Lab corpus dedicated to hardening rules.
- Expanded secret-environment recognition and kept production defaults evidence-first: experimental findings are excluded from smart/audit unless independently corroborated.

## 1.9.0 - 2026-09-13

- Rebuilt the non-Python semantic frontend as Security IR v4 with project-wide function/module indexing, import resolution, call graph edges, lightweight CFG nodes and bounded interprocedural/cross-file taint propagation.
- Added first-class semantic profiles for TypeScript, Kotlin, Ruby, Rust, C/C++, Swift, Scala and Dart in addition to JavaScript, Java, C#, Go and PHP; Python keeps its deeper AST frontend.
- Added fixed-point return/source/passthrough and sanitizer summaries so helper/service/repository chains retain taint and sink-specific validation across files.
- Added framework endpoint contexts including Express inline handlers, Spring/JVM mappings, ASP.NET attributes and common PHP/Ruby/Swift web patterns.
- Tightened precision for generic execute/query receivers, parameterized SQL, typed scalar endpoint parameters and fixed-origin SSRF paths.
- Added `dede languages` / `dede languages --json` as an authoritative runtime support matrix.
- Added language-parity regression fixtures covering project-wide dataflow across the first-class semantic languages.

## 1.8.0 - 2026-09-13

- Added conservative polyglot Security IR/taint frontend for JavaScript/TypeScript, Java, C#, Go and PHP.
- Added offline SCA with pinned-version advisory matching and source reachability evidence.
- Added SHA-256/HMAC-verified offline semantic model packs and bundled framework packs.
- Added precision benchmark laboratory with precision/recall/F1 gates.
- Added organization feedback annotations without automatic suppression by default.
- Added explicit MCP/agent dangerous-permission checks and opt-in experimental IDOR/BOLA analysis.
- Added unified attack graph v2, local MCP report queries, localhost report server, watch mode and deterministic fix verification.
- Added in-memory repeated-secret correlation without persisting raw or stable secret hashes.
- Changed every interactive installer prompt that previously defaulted to No to default to Yes; `-y` now accepts those defaults unless a `--skip-*` option is supplied.

## 1.7.0 - 2026-09-13

- Reworked `install.sh` with phase-based live status, elapsed command feedback, clearer optional runtime/AI choices, and native verification.
- Standardized all user-facing runtime/progress/error messages on English.
- Added precision-first semantic sink validation for SQL, SSRF, YAML deserialization, framework injection, and context-specific sanitizers.
- Changed Semgrep default profile to `smart` and filter uncorroborated LOW-confidence native alerts by default.
- Added regression tests for common semantic false-positive patterns.

# Changelog

## 1.6.1 - 2026-09-13

- Docker scanner image is optional; `scan --runtime auto` falls back to the native core scanner.
- Added explicit `--runtime auto|native|docker` selection for scan and doctor.
- Installer separates optional Docker scanner setup from optional AI/Ollama model setup.
- `-y` no longer builds a missing optional Docker image unless `--with-docker` is supplied.
- Missing Bandit/Ruff and native PDF dependencies are treated as optional coverage, not fatal runtime failures.
- Doctor reports optional analyzer/model/report dependencies as OPTIONAL rather than failing native readiness.

## 1.6.0 - 2026-09-13

- Added live scan heartbeats and per-analyzer duration/finding progress so long operations are visible.
- Reworked pipeline stage labels to remove the misleading duplicate Semgrep phase.
- Made `--no-ai` a hard runtime boundary: no model probe, hunt, enrichment, or verification path is entered.
- Host `--no-ai` scans now stop an idle Dede-managed Ollama service left by older runs before scanning.
- Ollama is now on-demand (`restart: no`) and unloads models immediately (`OLLAMA_KEEP_ALIVE=0`); AI scans release the managed service after completion when no concurrent scan is active.
- Installer no longer leaves Ollama/model resources resident after model checks or pulls.
- Avoided analyzer version subprocess probes for non-applicable analyzers and cached applicability decisions.


## 1.5.0 - 2026-09-13

- Rebuilt HTML reporting as a self-contained offline security dashboard with sticky navigation, dark/light themes, keyboard search, advanced finding filters, expandable findings and stable finding permalinks.
- Added lifecycle, attack-surface, analyzer-health, policy-gate, DedeQL, incremental-scan and performance dashboards derived only from recorded scan evidence.
- Added richer finding visualization for attack paths, source-to-sink dataflow, structured evidence, endpoint exposure and multi-engine corroboration.
- Upgraded PDF output to tagged PDF/A-3u with a page-numbered table of contents, bookmarks, report metadata and SHA-256 sidecar integrity file.
- Embedded canonical machine-readable scan evidence and the scan manifest inside PDF reports as data attachments for archival and audit workflows.
- Added report integrity, traceability and clearly-labelled suggested remediation SLA sections without treating guidance as organization policy.
- Added reporting analytics as a dedicated module and regression tests covering evidence-backed metrics, offline HTML controls and archival PDF options.

## 1.4.0 - 2026-09-13

- Upgraded the language-neutral Security IR to v2 with normalized source-to-sink security-flow records.
- Added deterministic DedeQL v0.1 flow queries over source, sink, CWE, endpoint, authentication, internet exposure and exploitability metadata.
- Added JSON and Graphviz DOT attack-graph exports derived from endpoint, call-graph and proven sink evidence.
- Added FastAPI/Starlette endpoint-parameter taint sources and Depends-based authentication signals, plus broader Flask/Django/DRF request modeling.
- Added semantic SSRF, path traversal, unsafe deserialization and template-injection sinks and keyword-argument propagation across project calls.
- Added signature-bound persistent semantic finding cache that reuses unaffected evidence during dependency-aware incremental scans.
- Upgraded the persistent index to schema v3 with automatic NEW / EXISTING / RESOLVED / REOPENED finding lifecycle tracking.
- Added attack path, DedeQL matches and lifecycle metadata to JSON, SARIF and HTML findings.
- Fixed duplicated `--respect-gitignore` forwarding in the Docker host CLI and expanded stale-report cleanup.

## 1.3.0 - 2026-09-13

- Added a language-neutral Security IR with function, call-graph, CFG, endpoint and dependency nodes.
- Upgraded Python semantic analysis to bounded context-sensitive cross-file taint propagation with import/alias resolution.
- Added fixed-point return summaries, field-aware local propagation, unreachable-code handling and narrow path-sensitive numeric guards.
- Added Flask/FastAPI-style endpoint discovery, authentication signals, attack-surface metadata and endpoint-aware exploitability scoring.
- Added project-configurable semantic source, sink and sanitizer models for private frameworks while remaining fully offline.
- Added AST-derived finding identity and report metadata for stronger line-shift-resistant lifecycle tracking.
- Replaced all-pairs finding correlation with identity and location-bucket indexes for large-repository scalability.
- Upgraded the persistent scan index to schema v2 with import dependency edges and transitive reverse-impact calculation.
- Added `semantic-python-ir.json` structural evidence export and dependency-aware incremental planning metadata.

## 1.2.0 - 2026-09-13

- Added semantic-v2 finding identity resilient to line-only shifts while retaining v1 baseline compatibility.
- Added conservative cross-tool finding correlation and consensus metadata.
- Added built-in Python AST semantic taint analyzer with lightweight interprocedural function summaries.
- Added source/sink, reachability, exploitability, precision, confidence and evidence metadata to findings and SARIF/JSON/HTML reports.
- Added persistent local SQLite scan index for change detection and finding history without storing source code.
- Added reproducible `scan-manifest.json` with configuration and rule digests.
- Added deterministic path-scoped policy gates and expiring approved suppressions.
- Added analyzer plugin discovery through the `dede.analyzers` Python entry-point group.
- Added evidence-aware risk weighting and multi-engine consensus factor.
- Added clean source-release packaging that excludes virtual environments, VCS metadata, caches, reports, build artifacts and `.env`.

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.1.0] — 2026-09-12

### CLI runtime fixes

- Upgrade Typer to 0.27.2 so invalid arguments and help work with the locked
  scanner dependencies instead of raising `TyperArgument.make_metavar` errors.
- Avoid foreign-owned default report directories with a per-user fallback;
  validate output and cache ownership even for root before cleanup or chmod.
- Show controlled errors for host doctor failures and cover parameter parsing
  and cross-user runtime directory regressions.

### Added

- Native engine 0.4.0 catalog: **243 rules in 12 bundles**, with 89 bounded
  document checks and 11 local C# / Razor taint checks across 50 language and
  configuration labels.
- Isolated native worker with hard timeouts, source/rule limits, rule digests,
  deterministic coverage diagnostics and redacted dataflow evidence.
- .NET coverage for C#, VB.NET, F#, Razor, classic ASP.NET and project/config
  files, including deserialization, JWT, TLS, cryptography, XML, cookies/CORS,
  antiforgery, EF Core, NuGet and build-analysis settings.
- Native checks for additional popular languages and discovery of UTF-16/UTF-32
  source, script shebangs, Razor, Vue/Svelte, JVM, functional and infrastructure
  files.
- Verifiable release tooling: hashed dependency exports, native and Semgrep
  integrity manifests, wheel validation, image SBOM generation and Trivy audit.

### Changed

- Move the scanner runtime to digest-pinned Wolfi with version-pinned direct
  system dependencies, retaining Python 3.12, Go/cgo and PDF rendering. Remove
  the runtime virtual environment's pip after locked dependency installation.
- Require official Trivy 0.74.0, recent vulnerability data, matching immutable
  image identity and complete OS/Python/Go/source inventories for release audits.
- Native reports now expose per-language rule/mode coverage and SARIF code flows;
  skipped or failed analyzers are never presented as complete coverage.
- Legacy file-wide safety markers were narrowed to the matched line, preventing
  unrelated safe code from suppressing an unsafe finding. Native secret and
  dataflow evidence is redacted before report serialization.

### Fixed

- Verify the installed scanner in an isolated, bounded Docker container instead
  of launching the Compose scanner service just to print a version. Preserve
  timeout diagnostics and clean up only the failed verification container.
- Keep installer output concise by default; add `--verbose` and private setup
  logs while retaining visible system package/sudo prompts and failure statuses.
- Update Gitleaks archive libraries and both Go analyzers' cryptography modules
  to address known memory exhaustion/SSH denial-of-service advisories. Record
  compiled Go package graphs for advisory review.
- Upgrade the locked pytest toolchain to 9.1.1 for secure temporary-directory
  handling and verify the full suite against it.
- Preserve the original Ollama volume configuration: added labels previously
  triggered a hidden, destructive Compose recreation prompt during installation.
- Bound Ollama startup and readiness waits, retain Docker diagnostics, verify
  existing scanner images, and use the current CLI path after moving a checkout.
- Preserve broken or unwritable virtual environments as backups before replacing
  them, including environments created by a different user.
- Keep package-status messages out of package-manager arguments.
- Pin the scanner base and Ollama images by digest, compile Gitleaks and Gosec
  from checksum-verified Go modules, and add tag-gated CI release smoke tests.
- Validate scan paths before report cleanup and prevent cleanup of source roots,
  symlinked report directories, and baseline/config inputs in report output.
- Let doctor diagnose readiness without starting its optional Ollama dependency.
- Preserve Compose DNS and configured request limits for model management inside
  the scanner; reject interrupted model downloads without a success event.
- Resolve host model preferences and disabled-AI settings before launching scans,
  forward the selected model, and preserve configured offline mode without a CLI flag.
- Connect subprocess stdin correctly and prevent tools from waiting on terminal input.
- Keep unique code windows out of duplicate-group limits and make capped candidate
  selection deterministic. Quality findings no longer inflate security risk scores.
- Native rules 0.3.1 restrict Python credential detection to literal assignments
  on the matching line. Unrelated assignments are no longer reported, and an
  environment lookup elsewhere in a file no longer hides literal credentials.

## [1.0.0] — 2026-09-10

First stable release. Rebrand from Sarmaşık to **Dede**.

### Added

- **Dede native engine** (`dede-engine`): deterministic, dependency-free weakness
  matcher that runs fully offline. Rules live under `rules/dede-engine/core.json`
  and `infra.json` with CWE, OWASP 2025 and ASVS 5.0 mappings.
- **64 advanced security rules** (`2026.09.09-advanced-security`): 18 for C#/ASP.NET
  and 46 for Go, PHP, Ruby, Rust, Python, JavaScript, Java, Kotlin, Scala, C/C++,
  Swift, Dart, Shell, PowerShell, Perl, Lua, Elixir, Clojure, OCaml, Apex, Solidity,
  SQL, Terraform, Kubernetes, Dockerfile, JSON, TOML, HTML.
- **AI vulnerability hunt** (`ai-hunt`): project-wide LLM pass that finds cross-file
  data flows and logic issues structural rules miss. Candidates are schema-validated,
  tied to real files/line ranges and advisory only (`confidence=LOW`).
- **146 native offline rules across nine bundles**, including additional PHP, Ruby,
  C#, Rust, C/C++ and shell injection/deserialization/memory-safety checks.
- **SARIF 2.1.0 report** with `helpUri` (CWE links), `shortDescription`, and
  `owasp` rule properties for IDE / GitHub code-scanning integration.
- **Deterministic AI verification**: after enrichment, Semgrep and Ruff recheck
  reviewed sources; `ai_validation_status` records `CORROBORATED`, `CONFLICT`,
  `UNVERIFIED`, `SOURCE_CHANGED`, or `ERROR`.
- **Baseline scanning** (`--baseline`): delta mode compares against a previous
  `report.json` and marks findings as `NEW`, `EXISTING`, or `RESOLVED`.
- **`dede model`** sub-commands: `list`, `check`, `recommend`, `pull`, `use`, `show`.
- **`dede rules`** sub-commands: `list`, `update [-f]`.
- **`dede doctor`** command for analyzer / LLM / report readiness checks.
- **Standards reporting**: JSON exposes `standards` on findings and
  `standards_assessment` with OWASP Top 10:2025, ASVS 5.0.0 and CWE counts.
- `ProjectContext` gains `has_csharp`, `has_php`, `has_ruby` flags (alongside
  existing Python, JavaScript, TypeScript, Go, Java, Rust, Docker).
- AI cache now defaults to `~/.cache/dede/ai`; override with `DEDE_CACHE_DIR`.
- `ai.hunt_max_files` config parameter (default `24`) controls how many files the
  hunt pass reads per batch.
- `__version__` read from package metadata via `importlib.metadata` — always in
  sync with `pyproject.toml`.

### Changed

- **Risk, maintainability and CI gates are static-evidence-only**. AI verdicts and
  AI-hunt candidates never raise, lower, hide or fail deterministic scan results.
- **Lizard** complexity findings now use `category=complexity` with `INFO` (CCN ≥ 15)
  or `LOW` (CCN ≥ 30) severity — they no longer trigger `--fail-on HIGH/MEDIUM` CI
  gates by default.
- `gitleaks` missing binary now returns `SKIPPED_OFFLINE_DEPENDENCY` (was `FAILED`),
  consistent with other optional tools. Scans no longer exit 3 solely because
  gitleaks is absent.
- File discovery updated to the non-deprecated `pathspec` `gitwildmatch` pattern
  factory.
- Default Ollama model updated to `qwen3-coder:30b`.

### Fixed

- DeprecationWarning storm from `pathspec.GitWildMatchPattern` in every scan.
- `dede-engine` rule ID prefixes no longer include installation-directory paths.
- Old blanket `dede.csharp.security.process-start` rule replaced by
  `dede.csharp.advanced.command-injection`; constant launches no longer trigger it.

### Security & Privacy

- Source mount is read-only; scanner runs as non-root with `cap_drop: ALL`.
- Every scan and readiness check runs in the pinned scanner image; the host CLI
  only resolves paths, manages Compose and forwards exit codes.
- Secrets redacted in logs, prompts, and reports.
- No telemetry; no external APIs at runtime.
- AI-originated candidates are explicitly marked (`ai_generated: true` and
  `analysis_kind: ai-hunt`) and require human verification.

---

## [0.1.0] — 2026-09-08

Initial development release (internal, as Sarmaşık).

- Semgrep + Bandit + Ruff + Lizard + Gosec + GoVet + Gitleaks analyzers.
- Local Ollama LLM enrichment (fail-open).
- HTML, PDF, JSON reports.
- Docker + install.sh offline setup.
