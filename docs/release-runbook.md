# Release runbook

1. Start from a reviewed checkout and verify `git diff --check`. Resolve all
   release blockers in `tasks/engine-audit-2026-09-12.md` before tagging.
2. Update `pyproject.toml`, image references and `CHANGELOG.md`. Update native
   rules `VERSION` and `MANIFEST.json` when rule content changes. Run `uv lock`
   after changing Python dependencies; run `make lock-update` to refresh exports.
   `make lock` checks exports without modifying them. Build dependencies are
   separately pinned in `requirements-build.in` and `requirements-build.lock`.
3. Refresh only reviewed rule inputs. `FORCE_REFRESH=1 UPDATE_RULE_CHECKSUMS=1
   make rules` allows registry content changes and regenerates trusted hashes.
   Review `rules/semgrep/SHA256SUMS` and `MANIFEST.yml` before accepting the update.
   Normal `make rules` verifies cached/downloaded files against trusted hashes;
   changed optional packs and custom files also fail this check.
4. Use the locked development environment and run `make release-check` and
   `make test`. Package output is `dist/<version>/`. Validation compares every
   bundled rule file in the wheel and source archive to the checkout, including
   the native version and manifests. A passing package check alone is not the
   complete release gate.
5. Run `make build`, `make test-offline`, `make sbom`, and `make security-audit`.
   Syft and official Trivy 0.74.0 must be installed. Development builds and
   other Trivy versions are rejected; CI pins the same version as
   `scripts/validate_security_audit.py`. SBOM generation requires an existing local
   scanner image and never substitutes a source-tree inventory. Both formats
   come from one scan of the same immutable image ID. `sbom/provenance.json`
   binds the inventories to that image and records tool identity and hashes.
   `DEDE_SBOM_DIR` and `DEDE_AUDIT_DIR` override artifact output directories.
6. Security audits fail on HIGH/CRITICAL vulnerabilities, secrets and failed
   misconfiguration checks, including vulnerabilities without a published fix.
   Suppressing all unfixed findings is not a release policy. The default online
   audit can fetch databases; `TRIVY_OFFLINE=true` disables database/check
   updates and remote dependency lookups and requires a provisioned cache.
   Both modes require a vulnerability database updated within the last 48 hours.
   Missing/malformed reports, image identity mismatch, unrecognized/EOL operating
   systems, absent OS/Python/Go inventories and incomplete source scans fail the
   gate with exit status 2. HIGH/CRITICAL findings return 1; a complete clean
   scan returns 0. The gate does not apply vulnerability exceptions.
   Trivy metadata and complete findings (with secret matches redacted) are
   retained under `dist/security/run-*/`, even for a failed gate. These reports
   are sensitive internal audit evidence; review them before sharing publicly.
7. Review test output, SBOMs, image ID, rule provenance and all unresolved
   findings. Reconcile scanner/advisory disagreements using the distribution's
   security tracker and a current database. An unverified discrepancy remains
   a blocker. Do not claim a zero-vulnerability result from a filtered scan.
8. Only after all gates pass, create and push `vX.Y.Z`. The tag workflow rejects
   version mismatch, waits for tests, builds packages and the scanner image,
   generates SBOMs and runs the strict audit. Audit artifacts are uploaded on
   failure; validated package artifacts and GitHub provenance attestations are
   produced only on success. Verify attestations using `gh attestation verify
   <artifact> --repo cumakurt/dede` before publication. Registry publication
   and signing a git tag remain separate maintainer operations; no deployment
   or package publication is performed by this workflow.

## Validation scope

Linux/amd64 with Python 3.12 is the fully tested scanner platform. CI adds
Python 3.13 compatibility checks. Linux/arm64 checksum/build branches exist but
must pass equivalent platform tests before claiming support. Windows/macOS
native installations, GPU inference and live Ollama model quality are not
covered by the offline scanner suite. Native .NET flow remains lexical/local;
Roslyn semantics and cross-function/cross-file flow are outside this release.

The scanner uses a digest-pinned Wolfi runtime with Python 3.12, current system
libraries, GCC/libc headers for Go/cgo, and Pango/Harfbuzz fonts for PDF output.
Python dependencies live in `/opt/dede`; pip is removed from that environment
after installation and dependency validation. The test stage restores pip and
adds GNU coreutils for host installer tests. Go tools and the pure Python wheel
are built in separate Debian stages; Debian system packages are not copied into
the runtime. Existing CLI, report paths and non-root container isolation remain
compatible.

The image also records the actual compiled Go package graphs under
`/usr/local/share/dede/go-deps/`. Use these alongside full vulnerability reports
when reviewing module-level advisories for unused subpackages. This evidence
does not suppress findings. A Docker HEALTHCHECK is not configured for this
finite CLI job; its exit status and analyzer completion determine success.

Direct runtime APK versions are pinned in `Dockerfile`; transitive APK packages
are resolved from the base image's signed Chainguard repository at build time.
Python artifacts and Go module inputs are version/hash constrained. Image IDs,
SBOMs and security results must therefore be regenerated for each release build.
Review base digests and direct package pins together when applying security
updates. Do not describe independently rebuilt images as byte-for-byte reproducible.
