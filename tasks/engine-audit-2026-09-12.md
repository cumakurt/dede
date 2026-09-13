# Native engine and application quality audit

## Objective and working agreement

Strengthen Dede's deterministic offline static analysis, with priority on .NET,
honest coverage reporting, useful rules for popular languages, and reproducible
positive/negative regression tests. Preserve the CLI, existing findings and
external analyzer integration. Plan work here before implementation, check off
verified steps, and record commands/results so another session can resume.

Native engine status: **complete**. Release status is recorded in the latest
checkpoint at the end of this file; earlier decisions are historical.
No user files were modified at the initial checkpoint;
`git status --short` was empty. Repository instructions:
`/depo/cuma/projelerim/AGENTS.md`. Technical artifacts use English.

## Tasks (execute in order; update after each verified stage)

- [x] 1. Establish baseline: inspect pipeline, engine, discovery, configuration,
  evidence/reporting, existing rules and tests; run current checks; record concrete
  defects and scope before changing production code.
- [x] 2. Harden native rule loading and execution: strict schema validation,
  reliable read/error handling, bounded execution, deterministic matching and
  explicit partial-coverage diagnostics. Add failure/regression tests.
- [x] 3. Improve native matching: reusable source preparation, comment-aware and
  multiline matching with accurate original locations; retain legacy rule
  behavior where explicitly required. Validate safe counterexamples.
- [x] 4. Add native .NET flow analysis with source/assignment/sink evidence,
  bounded local propagation, safe argument handling and documented scope.
  Cover representative ASP.NET Core/classic request sources and major injection
  sinks without requiring Semgrep, Roslyn, builds or target code execution.
- [x] 5. Expand .NET checks: C#, VB.NET, F#, Razor, ASP.NET and project/config
  files; deserialization, authentication, TLS, cryptography, XML, cookies/CORS,
  disclosure and build/security settings. Give every new rule unsafe/safe tests
  and primary-source remediation references.
- [x] 6. Broaden popular-language discovery and native checks; validate that
  language recognition corresponds to actual rule coverage. Distinguish generic
  secret coverage, textual matching and flow support explicitly.
- [x] 7. Integrate coverage/provenance and native flow evidence into existing
  reports; address application consistency defects confirmed during audit.
- [x] 8. Verify complete unit/integration suite, lint, type checks, package and
  installed bundled rules, real offline scan, JSON/HTML/PDF/SARIF consistency,
  representative native self-scan and bounded stress/performance checks.
- [x] 9. Review final diff, update rule authoring/user documentation and changelog,
  record measured outcomes and remaining technical limitations, finish this file.

## Initial observations (not yet complete findings)

- Native engine currently uses per-line regex/literal rules; ordered matches
  do not bind variables and are not taint analysis.
- Native source load silently converts unreadable/oversize inputs into empty
  source while the analyzer counts them as scanned.
- Rule-file YAML/I/O failures are not normalized to `RuleSchemaError`;
  false-valued malformed optional fields can bypass validation.
- Native execution currently does not honor the analyzer timeout; rule count
  truncation is silent and is not a real per-file rule limit.
- Existing external Semgrep .NET checks are useful but do not provide the native
  engine with the same capabilities.

## Validation log

- Baseline running: `docker compose --profile test run --rm -e
  COVERAGE_FILE=/tmp/.coverage test -p no:cacheprovider -q --cov=dede
  --cov-report=term --durations=8` (existing scanner/test toolchain, no network).
- Native catalog baseline: 146 rules in 9 JSON bundles, including 3 C# rules.
  Host `.venv` contains runtime dependencies but no pytest/ruff; validation uses
  the existing Docker test image instead of changing the user's environment.
- Baseline complete: **488 passed in 199.50 seconds**, 76% statement coverage.
- Native hardening regression + original engine tests: **59 passed in 10.02s**.
  Includes a real catastrophic-backtracking regex terminated at a two-second
  process timeout while preserving a previous file's finding.
- Initial container lint required `--no-cache` because source is mounted read-only;
  one newly unused import was identified and removed.
- Lexical/multiline regression suite: **23 passed**. .NET unsafe/safe and local
  flow tests: **109 passed** after fixing lambda parenthesis scope.
- New .NET/language/discovery/lexical checks: **210 passed in 1.09s**.
- Current native focused regression set: **277 passed in 7.31s**.
- Full suite after all production changes: **767 passed in 204.70s**, 79%
  statement coverage (5,792 statements; 1,239 missed).
- Ruff (`dede`): passed; Ruff format check (`dede`): 71 files already formatted.
- Mypy (`dede`, missing imports ignored): passed.
- Scanner image rebuilt successfully; Semgrep custom validation found 138 rules.
- Packaged scanner image loads **243 rules from 12 bundles**.
- `bash scripts/verify_offline.sh`: passed with network disabled; JSON/HTML/PDF
  generated and secret-redaction assertion passed (36 findings in sample).
- AST parse of every `dede/**/*.py`: passed. `git diff --check`: passed.
- A repository self-scan was stopped after external Semgrep spent over five
  minutes on generated cache metadata; the root cause was confirmed and common
  Python analysis caches were added to the default discovery exclusions.
- Discovery/config regression after the cache exclusion: **108 passed**.
- Rebuilt scanner image self-scan of `tests/rule_samples` with network disabled:
  completed in roughly eight seconds, produced 266 findings, and all applicable
  analyzers reported success.

## Additional confirmed audit defects and planned corrections

- **P1 / false negatives:** 50+ legacy native rules suppress every finding in a
  file if unrelated safe-looking text appears anywhere (`getenv`, `?`,
  `PreparedStatement`, `normalize`, `example`). Move these exclusions onto the
  actual matched line; safe code elsewhere must not hide unsafe code. Preserve
  explicit project rule/fingerprint suppression. Add mixed unsafe/safe tests.
- **P1 / evidence privacy:** generic secret redaction cannot reliably redact
  unlabeled provider tokens. Native secret evidence must be fully redacted before
  leaving its worker; sanitize all dataflow text before report serialization.
- **P2 / metadata accuracy:** language percentages are source distribution, not
  security coverage. Report explicit native rule counts and matching modes;
  skipped analyzers must not produce a 'complete' coverage label.
- **P2 / discovery consistency:** project detection previously used unrestricted
  shallow directory reads and substring framework guesses. Use the bounded,
  discovered files, parse manifests safely, and honor exclusions/symlinks.
- **P2 / repository performance:** a full self-scan exposed generated
  `.mypy_cache`/test-tool cache files being sent to external analyzers. Common
  analysis caches are now excluded by default; targeted offline scans remain
  bounded and reproducible.

## Implementation decisions (planned before changes)

- Execute native matching in a bounded Python worker using the existing safe
  subprocess helper. A hard process timeout also bounds catastrophic regex
  backtracking; cooperative deadline checks alone cannot do this. Keep completed
  file results on timeout and expose explicit diagnostics and coverage counters.
- Add opt-in document matching and comment masking to the declarative schema;
  legacy rules retain line matching, and secret rules still inspect comments.
  Preserve source offsets for multi-line evidence.
- Introduce a small lexer for C# local flow, with source/assignment/sink traces.
  This is conservative local analysis, not a compiler or a claim of full Roslyn
  semantic analysis. No project build/restore or target execution is necessary.
- Publish native per-language rule/scan counts and rule digests through existing
  analyzer metadata. Export actual dataflow as SARIF codeFlows as well as existing
  JSON/HTML/PDF traces.
- Consult Microsoft Learn security rules and EF Core SQL-query documentation
  for .NET API semantics; rules include direct primary-source references.

## Resume checkpoint

Completed: .NET configuration variants, popular-language corpus, legacy guard
corrections, privacy redaction, coverage/provenance, documentation and final
validation. The native catalog is 243 rules in 12 bundles (143 line, 89 document,
11 taint) covering 50 language/configuration labels. If resumed, read this file
and `git diff` first; only follow-up work or a new audit remains.

## Release-readiness review (2026-09-12)

Plan: verify the working tree, package/release gate, CI coverage, container and
dependency provenance, SBOM freshness, platform support, and documented product
limits; classify each gap as a release blocker or follow-up.

- [x] Confirm implementation validation: 767 tests passed, offline/container
  checks passed, and native catalog loads 243 rules from 12 bundles.
- [x] Inspect release state: changes are still uncommitted; no `dist/` artifact,
  tag, signed release, or published checksum exists.
- [x] Inspect automation: CI does not run `make release-check`, validate every
  bundle, enforce coverage, build/test the release wheel, or scan/sign artifacts.
- [x] Inspect supply chain: base/tool images and downloaded binaries are not
  digest/checksum/signature pinned; Python dependencies are range-pinned but
  not lockfile/hash reproducible.
- [x] Inspect product scope: native .NET flow is bounded lexical/local analysis;
  Roslyn semantic, interprocedural, cross-file and dependency-CVE analysis are
  outside the current product.
- [x] Inspect operational readiness: tracked SBOM is stale/sample-derived and
  Linux support is the only tested installer path; public security/support
  policy files are absent.

Decision: **release candidate, not final GA**. The implementation is suitable
for controlled/internal release after review, but public publication should
wait for the P0 supply-chain, artifact, CI gate, and release hygiene fixes.

## Release hardening implementation plan (2026-09-12)

The goal is to make the repository reproducibly buildable and reviewable for a
public release without changing the scanner's public CLI or analysis semantics.

- [x] 1. Add deterministic release validation for every native bundle, the
  Semgrep manifest, wheel contents, and version consistency.
- [x] 2. Harden image and rule bootstrap provenance with checksum/signature
  hooks, immutable references, and fail-closed release configuration.
- [x] 3. Make SBOM generation release-aware and add artifact/image/dependency
  validation targets that can run in CI without network access at scan time.
- [x] 4. Extend CI with release checks, clean wheel installation, native rule
  smoke tests, coverage threshold, and a reproducible scanner image check.
- [x] 5. Add security, contribution, ownership, support, and release runbook
  documentation; document tested platform and .NET scope explicitly.
- [x] 6. Add regression tests for the new validation and release paths, run the
  complete suite and package checks, and record measured results here.
- [x] 7. Review the final diff for secrets, generated-file drift, and accidental
  behavior changes; mark this plan complete when all gates pass.

## Release hardening validation (2026-09-12)

- `python scripts/validate_release.py`: passed; native manifest and Semgrep
  manifest/checksums match 243 native rules, 12 bundles, 45 vendored packs and
  21 custom YAML files.
- `make release-check` in a clean uv-managed Python 3.14 environment: passed;
  Ruff, mypy, lock verification, wheel/sdist build, Twine metadata checks and
  wheel rule validation all succeeded for version 1.1.0.
- `make test`: **771 passed**, one expected WeasyPrint warning, 78.73% coverage
  against the 78% gate (Docker Python 3.12.14).
- `bash scripts/verify_offline.sh`: passed with network disabled; all ten
  analyzers succeeded and generated redacted JSON/HTML/PDF reports.
- `TRIVY_IGNORE_UNFIXED=true bash scripts/security_audit.sh`: passed; the
  scanner image and source tree reported zero high/critical vulnerabilities,
  secrets or high/critical misconfigurations. The runbook documents the
  vendor-unfixed policy and the strict `TRIVY_IGNORE_UNFIXED=false` option.
- `shellcheck`/`bash -n`, `docker compose config -q`, compileall and native
  image smoke test: passed. The scanner image runs as UID 10001 (`auditor`) and
  loads all 243 native rules.
- SBOMs were regenerated from the final `dede-scanner:1.0.0` image in both
  CycloneDX and SPDX formats. The final image tag is `dede-scanner:1.1.0`
  (local image digest `sha256:3d9126c834e37ae06951511d9b2104c1dffe2427ebcf35110f072ee76055c0af`).
- Final package hashes: wheel
  `b97d6a216598003352421253c00013f3c5525b9f441e09f6b895655203de1e75`, sdist
  `e4aea95932198e74dc564aaa2a5e0f9d68e88784e3f3fb7d9721de416a59ce0e`.

Correction: the preceding security result excluded vulnerabilities without a
published fix. A strict diagnostic found 262 HIGH/CRITICAL package occurrences
in the Bookworm image. This is not a clean security audit or evidence of GA
readiness. The earlier completion marks describe the initial implementation;
the follow-up below must be completed before making a release decision.

## Final release gate corrections (resume plan)

- [x] Investigate strict image findings and reduce the runtime dependency surface;
  record any remaining upstream blockers without suppressing them.
- [x] Make security audits strict by default, preserve full reports, and implement
  an explicit offline mode that fails when scanner databases are unavailable.
- [x] Reject incomplete Semgrep manifests and wheel content drift, with negative
  regression tests; verify dependency exports without rewriting them.
- [x] Make SBOM generation fail closed on missing tools/images, capture immutable
  image provenance, and remove the dependency-range fallback inventory.
- [x] Fix Docker download failure handling and embedded Go tool version reporting.
- [x] Wire actual security/SBOM/artifact validation into release CI and validate
  release tag/version consistency.
- [x] Update checksum bootstrap handling and documentation to match strict policy.
- [x] Correct the installer's stale default image tag and include every runtime
  image reference in the release-version consistency check.
- [x] Run relevant tests and final artifact checks, review the diff, and record an
  accurate release decision and next checkpoint here.

### Historical release blocker: operating-system security findings

- [x] Resolve or establish a reviewed, evidence-backed disposition for each
  remaining HIGH/CRITICAL OS alert, then pass the strict release audit.

The pinned Python image now uses Debian Trixie. Download/build-only packages
are isolated in a Go tools stage. Unnecessary GDK/image/MIME development
packages are removed; GCC and libc headers remain necessary for Go/cgo analysis.
The initial Trixie image is 1,290,247,209 bytes. With the same cached database,
the alert count fell from 262 to 147. A fresh database (updated 2026-09-12
07:04:21 UTC) reports **149 package/CVE occurrences: 135 HIGH, 14 CRITICAL,
89 distinct CVE IDs**. None has a fixed version in that scanner database.
The source scan has zero HIGH/CRITICAL findings. Counts are scanner alerts,
not proof that all affected code paths are reachable from Dede.

Some alerts disagree with distribution fix metadata: the installed GLib
2.84.4-3~deb13u5 is newer than the fix listed for
[CVE-2026-58016](https://security-tracker.debian.org/tracker/CVE-2026-58016),
and Perl 5.40.1-6+deb13u1 matches the listed fix for
[CVE-2026-42496](https://security-tracker.debian.org/tracker/CVE-2026-42496).
Other findings still lack a stable-distribution fix, including ncurses
[CVE-2025-69720](https://security-tracker.debian.org/tracker/CVE-2025-69720)
and util-linux
[CVE-2026-78410](https://security-tracker.debian.org/tracker/CVE-2026-78410).
These discrepancies are not automatically suppressed. Upgrading to Debian
unstable or removing Go/cgo support solely to clear the gate is not a verified
release fix. Resume by checking current stable security updates and reconciling
individual alerts with installed package revisions and vendor advisories.

Current full audit evidence is in `dist/security/run-U9kAO4dB/` (fresh online
database) and `dist/security/run-mng1MXSX/` (offline cache). These generated paths
are intentionally ignored by git. Subsequent builds must regenerate SBOMs and
audit reports against their new immutable image ID. CI is configured to retain
redacted audit evidence on failure and only attest/upload releasable packages
after a successful gate. Remote CI/attestation has not been executed locally.

### Latest validation and resume checkpoint

- Full unit/integration suite in the hardened, network-disabled Python 3.12
  container: **787 passed**, **78.73%** coverage (78% threshold), using four
  pytest workers. The preceding sequential run exposed two test-fixture
  noexec issues; these were fixed by invoking fixtures through their interpreter,
  preserving container isolation. The full rerun is green.
- Subsequent installer-version fix and release checks: **28 passed** in the
  same hardened container. This includes rejecting a stale installer image tag,
  incomplete manifests, altered wheel rules/versions, changed dependency exports,
  unfixed-CVE gate behavior, secret redaction and missing-image SBOM failure.
- `make release-check`: Ruff, mypy, native/Semgrep validation, read-only uv export
  consistency, wheel/sdist build and Twine metadata checks passed. Source archive
  and wheel rule contents are checked byte-for-byte against the checkout.
- A separate clean venv installed the built wheel and loaded all 243 bundled
  rules outside the checkout; CLI help succeeded. Runtime image Gitleaks reports
  8.30.1 and Gosec reports 2.29.0; `pip check` passed.
- `make test-offline`: all **10 analyzers SUCCESS**, 37 sample findings,
  JSON/HTML/PDF reports generated and secret masking verified. The script now
  rejects partial analyzer execution instead of merely checking for findings.
- Normal checksum-enforced rule bootstrap passed: 45 packs (including 3,203
  rules in `r/all`) and 21 custom files; 138 custom Semgrep rules validated.
- `actionlint`, ShellCheck, Bash syntax, Compose config, formatting and
  `git diff --check` passed. Final code/release diffs were reviewed. No commit,
  tag, remote attestation or publication was performed.
- Final scanner image: `dede-scanner:1.1.0`, immutable local ID
  `sha256:43cbedca2904cbad8ee73aada18bc58d0b0da7abab253d66f02cccc34cd3086b`.
  Both generated SBOMs and `sbom/provenance.json` match this image. The final
  strict audit against the provisioned fresh database is
  `dist/security/run-bFfmYnDV/`: **149 OS alerts, zero HIGH/CRITICAL source
  findings**, exit status 1 as required. SBOM provenance hashes were verified.

**Historical release decision: blocked at this checkpoint.** Application tests and package
validation pass, but the strict security gate does not. Continue with the open
OS-alert item above. Check stable distribution patches and database corrections;
retain evidence for any individual not-affected disposition. Rebuild, regenerate
SBOMs and re-audit after changing dependencies. Do not repeat completed native
engine development or treat the earlier filtered audit as a successful gate.

## Remaining OS findings: remediation plan

Candidate checkpoint: the first Wolfi build detects 93 OS packages and no OS
HIGH/CRITICAL findings. Two Python package alerts require reconciliation with
vendored pip contents before adoption. Hardened suite: 787 passed, one installer
test failed because BusyBox timeout lacks the GNU option used by the host
installer. Install GNU coreutils in the test stage only, retaining the same
runtime image and sandbox. Also close a release-gate validation gap: malformed
or incomplete Trivy reports, missing OS/language inventories and mismatched
image identities must fail instead of being treated as a clean scan. Add
negative regression tests and preserve redacted evidence.

- [x] Validate a pinned Wolfi runtime candidate with current patched libraries
  as an alternative to maintaining private backports of Debian system libraries.
  Adopt it only if package provenance, vulnerability detection, all analyzers,
  Go/cgo and report generation pass; otherwise retain the Debian remediation path.
- [x] Extract the 89 distinct HIGH/CRITICAL CVEs and package revisions. Primary
  vendor records confirm mixed backport discrepancies and missing Debian stable
  fixes. Replace this package set with current Wolfi libraries instead of
  maintaining private backports or issuing 89 individual exceptions.
- [x] Apply patched runtime packages and remove unnecessary installer components
  while retaining analyzer capabilities, including Go/cgo and PDF rendering.
- [x] Conditional disposition work is unnecessary: the replacement runtime passes
  without an ignore list, VEX or other CVE exceptions. Keep all HIGH/CRITICAL
  findings, including unfixed vulnerabilities, blocking.
- [x] Strengthen audit evidence validation instead: malformed/incomplete reports,
  stale databases and mismatched image identities fail; regression tests cover
  both complete inventories and failure cases. Retain redacted full findings.
- [x] Rebuild and run scanner integration/offline/cgo/PDF checks, strict security
  validation, release checks and SBOM regeneration against the final image.
- [x] Record the final release decision and resume state with measured results.

### Additional findings in the complete, unfiltered final audit

The initial final Wolfi gate (`run-wNWnu62P`) passes with zero HIGH/CRITICAL
findings. Review of all severities found available fixes that will also be
applied before closure:

- [x] Upgrade Gitleaks archive dependencies `rardecode/v2` to 2.2.0 and `xz`
  to 0.5.15; upgrade both Go analyzers' `x/crypto` to 0.56.0 for four SSH DoS
  occurrences. The patched RAR API requires `mholt/archives` 0.1.5 instead of
  0.1.2 (verified by the initial compile failure). Preserve module checksum
  verification and test real analyzers.
- [x] Upgrade locked development pytest from 8.4.2 to 9.1.1 for
  CVE-2025-71176; regenerate hashed lock exports and run the full suite.
- [x] Rebuild final images, repeat affected integration/release/security checks
  and regenerate inventories. Record remaining informational/unknown findings
  without hiding them or claiming universal zero vulnerabilities.

## Final release checkpoint (2026-09-12)

**Completed: all local release gates pass for Linux/amd64, Python 3.12.14.**
The historical OS blocker above is closed. This is a locally validated release
candidate with no remaining implementation item in this plan. Remote CI,
attestations, a signed tag and actual publication remain maintainer release
operations and have not been performed. Do not represent this as a published
release or as validation of every platform, model or language semantics.

### Changes closing the blocker

- Replaced Debian runtime packages with a digest-pinned Wolfi image and pinned
  direct APK versions. Verified actual installed Expat 2.8.4, SQLite 3.53.4,
  GLib 2.90.0, curl 8.22.0, util-linux libraries 2.42.3 and current headers.
  The complete Trivy report detects **90 OS packages**, Python application
  packages and all Go toolchain/analyzer binaries. No vulnerability exclusions,
  ignore lists or VEX dispositions were added.
- Removed duplicate system pip from the candidate and uninstalled virtualenv
  pip after dependency installation/checking. This also removes its stale
  embedded component inventory from the deployed environment. The test stage
  restores pip and adds GNU coreutils for installer timeout tests. The base
  image builds its font cache and verifies PDF rendering before switching to
  the non-root user; read-only/network-disabled operation remains supported.
- Updated Gitleaks archive modules (including the compatibility-required
  archives 0.1.5), both Go tools' x/crypto 0.56.0 and pytest 9.1.1. Compiled
  binary metadata confirms the expected module versions and Go checksums.
- Added strict audit report validation and 17 regression cases: pinned official
  Trivy, a database no older than 48 hours, matching immutable image identity,
  recognized non-EOL OS and complete OS/Python/Go/source inventories are required.
  Malformed/missing evidence returns 2, security blockers return 1 and a complete
  passing audit returns 0. Original secret source lines are never retained in
  shareable reports. A real Go/cgo integration regression protects C tooling.

### Final measured validation

- Final scanner: `dede-scanner:1.1.0`, image ID
  `sha256:1ff803e95b9b0c32a40b04257edb346b691d2eeeba913eedc0b5fd61b95d3595`.
- Final test image: `dede-scanner-test:1.1.0`, image ID
  `sha256:571644147589157d787276c63665e8113a44f5b1d2c7131422f2ed5ce92673a9`.
  Hardened container suite under pytest 9.1.1: **806 passed in 84.74 seconds**,
  **78.73% coverage**, four workers, no network and read-only source/root.
  Real C compilation, Go vet/Gosec, PDF and all earlier engine regressions pass.
- `make test-offline`: **10 analyzers SUCCESS**, 37 sample findings,
  JSON/HTML/PDF reports and secret redaction verified.
- `make release-check`: Ruff, mypy, native/Semgrep rule inventory/checksums,
  read-only lock export validation, wheel/sdist build and Twine checks pass.
  The new audit validator also passes mypy independently. ShellCheck,
  actionlint, formatting, Compose validation and `git diff --check` pass.
- Final strict online audit: `dist/security/run-bH7U1iXW/`, official Trivy 0.74.0,
  vulnerability DB updated 2026-09-12 07:04:21 UTC; exit **0**. Image and source
  have **zero HIGH/CRITICAL blockers**. There are no LOW/MEDIUM/HIGH/CRITICAL
  dependency CVEs in the image and no source dependency vulnerabilities.
- The image retains two **UNKNOWN** occurrences of `GO-2026-5932`, one per Go
  tool, about the unmaintained x/crypto/openpgp subpackage. The build-generated
  package graphs (391 Gitleaks packages, 590 Gosec packages) verify that neither
  tool imports OpenPGP. Evidence is at `/usr/local/share/dede/go-deps/` inside
  the exact image. This is recorded for review, not suppressed by the gate.
- Lower-severity non-vulnerability findings remain visible: vendored Semgrep
  rule/example strings trigger MEDIUM secret-pattern matches; the LOW missing
  HEALTHCHECK check concerns a finite CLI job. These are not real credentials
  or evidence of an incomplete scanner run. Do not claim a universally empty
  security report.
- Both SBOMs were regenerated with checksum-verified official **Syft 1.42.0**
  against the final image above. `sbom/provenance.json` binds their hashes and
  tool identity to that image. SHA-256: CycloneDX
  `1b497177508e55d3f3604c3b5017a344fac547b9eb8d3733f311fc9eba30117f`, SPDX
  `3df1645ebc9b1f3b93a600d6b56429abbd8561d4eaad8daedd832073bec12a73`.

### Resume and publication

All planned code changes are complete and remain uncommitted for review.
Packages are in `dist/1.1.0/`; audit outputs are intentionally git-ignored.
Follow `docs/release-runbook.md` for remote CI, attestation and publication.
Any changed dependency or rebuilt image requires fresh tests, an audit and SBOMs;
the transitive OS package repository is rolling and rebuilds are not claimed
to be bit-for-bit reproducible. The latest validated local tools are at
`/tmp/dede-trivy-0.74.0/trivy`, `/tmp/dede-syft-1.42.0/syft`, and
`/tmp/dede-release-venv-20260912/bin/python`; the provisioned Trivy cache is
`/tmp/dede-trivy-release-cache-20260912`. Put the official Trivy directory on
PATH for audits; the host's older development binary is deliberately rejected.
After 48 hours, refresh the vulnerability database online before another gate.

Native .NET remains bounded lexical/local analysis, with 243 rules across the
whole engine and 50 language/configuration labels. Roslyn semantics, cross-file
flow, untested platforms and live model quality are outside the verified scope.

Installer follow-up: the subsequently reported verification timeout and verbose
setup output are resolved in `tasks/installer-timeout-2026-09-12.md`. That file
records the latest installer changes, 40 targeted passing tests and real Docker
verification. The image/security results above remain a historical snapshot of
the preceding release build.
