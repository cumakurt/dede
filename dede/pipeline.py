"""Scan orchestration pipeline."""

from __future__ import annotations

import json
import os
import time
from collections import Counter
from pathlib import Path

from rich.console import Console

from dede import __version__
from dede.analyzers import get_analyzers
from dede.analyzers.ruleset import default_rules_dir
from dede.config import AppConfig, default_report_dir
from dede.discovery import detect_languages, detect_projects, discover_files
from dede.engine.analyzer import default_engine_rules_dir
from dede.feedback import apply_feedback
from dede.llm.enrichment import enrich_findings
from dede.index import ScanIndex
from dede.manifest import build_scan_manifest
from dede.policy import evaluate_policy
from dede.progress import LiveProgress
from dede.llm.verification import verify_ai_reviews
from dede.models import (
    AnalyzerResult,
    Finding,
    ProjectContext,
    ScanMetadata,
    ScanResult,
    ToolStatus,
    utc_now,
)
from dede.normalization.baseline import apply_baseline
from dede.normalization.deduplicate import deduplicate_findings
from dede.normalization.findings import assign_ids, attach_snippets
from dede.normalization.maintainability import maintainability_rating
from dede.normalization.precision import apply_precision_gate
from dede.normalization.risk import compute_risk_score
from dede.normalization.severity import parse_fail_on
from dede.normalization.suppress import apply_suppressions
from dede.reporting.html_report import write_html_report
from dede.reporting.json_report import write_json_report
from dede.reporting.pdf_report import PDFDependencyUnavailable, write_pdf_report
from dede.reporting.sarif_report import write_sarif_report
from dede.semantic.attack_graph import write_unified_finding_graph
from dede.utils.git_info import collect_git_metadata
from dede.utils.paths import ensure_dir

console = Console(stderr=True)


def _build_project(root: Path, config: AppConfig) -> ProjectContext:
    files = discover_files(root, config)
    languages = detect_languages(files, root)
    project_types, frameworks = detect_projects(root, files)
    languages.project_types = project_types
    languages.frameworks = frameworks

    lang_names = set(languages.languages.keys())
    return ProjectContext(
        root=str(root),
        files=[str(p) for p in files],
        languages=languages,
        has_python="Python" in lang_names or "Python" in project_types,
        has_javascript="JavaScript" in lang_names,
        has_typescript="TypeScript" in lang_names,
        has_go="Go" in lang_names or "Go" in project_types,
        has_java="Java" in lang_names,
        has_rust="Rust" in lang_names,
        has_docker="Dockerfile" in lang_names or "Docker" in project_types,
        has_csharp="C#" in lang_names or "C#" in project_types,
        has_php="PHP" in lang_names,
        has_ruby="Ruby" in lang_names,
    )


def _relocate_finding_paths(findings: list[Finding], root: Path) -> list[Finding]:
    root = root.resolve()
    for finding in findings:
        file_path = finding.file.replace("\\", "/")
        try:
            finding.file = (root / file_path).resolve().relative_to(root).as_posix()
        except (OSError, RuntimeError, ValueError):
            finding.file = file_path
    return findings


def run_scan(
    target: Path,
    config: AppConfig,
    *,
    baseline: Path | None = None,
    progress: bool = True,
    assume_yes: bool = False,
) -> tuple[ScanResult, int]:
    """Run full scan. Returns (result, exit_code)."""
    config = AppConfig.model_validate(config.model_dump())
    started = utc_now()
    root = target.resolve()
    if not root.is_dir():
        raise FileNotFoundError(f"Target is not a directory: {root}")

    profile_marks: dict[str, float] = {}
    _phase_started = time.perf_counter()

    if not config.reports.output:
        config.reports.output = str(default_report_dir(root))
    output_dir = ensure_dir(Path(config.reports.output).resolve())
    raw_dir = ensure_dir(output_dir / "raw")
    live = LiveProgress(
        console,
        enabled=progress,
        interval_seconds=config.scan.progress_interval_seconds,
    )

    def step(msg: str) -> None:
        if progress:
            console.print(msg)

    step("[1/7] Discovering project...")
    with live.operation("Project discovery", detail=str(root)) as op:
        project = _build_project(root, config)
    discovered_paths = {Path(file).relative_to(root).as_posix() for file in project.files}
    profile_marks["discovery"] = time.perf_counter() - _phase_started
    live.done(
        op,
        findings=None,
        extra=f"{len(project.files)} files | {project.languages.lines_scanned:,} lines",
    )

    incremental: dict[str, object] = {}
    index_path: Path | None = None
    if config.performance.persistent_index:
        configured = config.performance.index_path.strip()
        index_path = Path(configured).expanduser() if configured else output_dir / ".dede" / "index.db"
        try:
            with ScanIndex(index_path) as scan_index:
                incremental = scan_index.detect_changes(root, project.files)
                incremental.pop("hashes", None)
                changed = list(incremental.get("changed_files", []))
                removed = list(incremental.get("removed_files", []))
                affected = (
                    scan_index.affected_files(changed, removed)
                    if config.performance.dependency_aware
                    else sorted(set(changed) | set(removed))
                )
                incremental["affected_files"] = affected
                incremental["dependency_edges_cached"] = scan_index.dependency_count()
                project.changed_files = changed
                project.affected_files = affected
        except (OSError, ValueError):
            incremental = {"status": "unavailable"}

    step("[2/7] Detecting languages...")
    if progress:
        console.print(f"  Security profile: {config.engine.profile}")
    # already done in build; show summary
    if progress:
        langs = ", ".join(f"{k} {v}%" for k, v in project.languages.languages.items()) or "none"
        console.print(f"  Languages: {langs}")
        if project.languages.frameworks:
            console.print(f"  Frameworks: {', '.join(project.languages.frameworks)}")
        if incremental:
            changed = len(incremental.get("changed_files", []))
            affected = len(incremental.get("affected_files", []))
            console.print(f"  Incremental: {changed} changed | {affected} affected files")

    analyzers = get_analyzers()
    analyzer_plan = [(analyzer, analyzer.supports(project)) for analyzer in analyzers]
    supported_count = sum(1 for _analyzer, applicable in analyzer_plan if applicable)
    step(f"[3/7] Preparing analyzers... {supported_count}/{len(analyzers)} applicable")
    step("[4/7] Running security analyzers...")
    tool_statuses: list[AnalyzerResult] = []
    all_findings = []
    _analyzers_started = time.perf_counter()
    applicable_index = 0
    for analyzer, applicable in analyzer_plan:
        if not applicable:
            tool_statuses.append(
                AnalyzerResult(
                    tool=analyzer.name,
                    status=ToolStatus.NOT_APPLICABLE,
                    version="not-run",
                    message="Project does not match analyzer language/ecosystem",
                )
            )
            if progress:
                console.print(f"  ↷ {analyzer.name}: not applicable")
            continue
        applicable_index += 1
        with live.operation(
            analyzer.name,
            detail=f"{applicable_index}/{supported_count} | timeout {config.scan.analyzer_timeout_seconds}s",
        ) as analyzer_op:
            try:
                result = analyzer.analyze(project, config, raw_dir)
            except Exception as exc:  # noqa: BLE001
                result = AnalyzerResult(
                    tool=analyzer.name,
                    status=ToolStatus.FAILED,
                    version=analyzer.version(),
                    message=str(exc)[:500],
                    duration_seconds=analyzer_op.elapsed_seconds,
                )
        result.findings = [
            finding
            for finding in _relocate_finding_paths(result.findings, root)
            if finding.file in discovered_paths
        ]
        # Analyzer-reported timing is preferred, but never leave the live UI blank.
        if not result.duration_seconds:
            result.duration_seconds = analyzer_op.elapsed_seconds
        tool_statuses.append(result)
        all_findings.extend(result.findings)
        live.done(
            analyzer_op,
            status=result.status.value,
            findings=len(result.findings),
            extra=(result.message[:120] if result.message and result.status != ToolStatus.SUCCESS else ""),
        )
    profile_marks["analyzers"] = time.perf_counter() - _analyzers_started

    step("[5/7] Normalizing findings...")
    _normalize_started = time.perf_counter()
    pre_normalize_count = len(all_findings)
    with live.operation("Normalization + deduplication", detail=f"{pre_normalize_count} raw findings") as normalize_op:
        all_findings = attach_snippets(all_findings, root, config)
        all_findings = deduplicate_findings(all_findings)
        all_findings, precision_filtered = apply_precision_gate(all_findings, config)
    profile_marks["normalization"] = time.perf_counter() - _normalize_started
    merged = pre_normalize_count - len(all_findings) - precision_filtered
    extra_parts = [f"{max(0, merged)} duplicates merged"]
    if precision_filtered:
        extra_parts.append(f"{precision_filtered} alerts filtered by {config.engine.profile} profile")
    live.done(normalize_op, findings=len(all_findings), extra=" | ".join(extra_parts))

    def ai_progress(msg: str) -> None:
        if progress:
            console.print(f"  {msg}")

    step("[6/7] AI enrichment...")
    # Cache directory precedence: DEDE_CACHE_DIR env > ~/.cache/dede/ai
    # Docker images may set DEDE_CACHE_DIR=/var/lib/dede/cache/ai for a
    # persistent volume mount; host installs use the XDG-style user cache.
    import os as _os

    _cache_env = _os.getenv("DEDE_CACHE_DIR")
    if _cache_env:
        cache_dir = Path(_cache_env) / "ai"
    else:
        cache_dir = Path.home() / ".cache" / "dede" / "ai"

    # AI vulnerability hunt: the model reads real project sources and looks for
    # issues the deterministic engines structurally miss — cross-file data
    # flows, broken access control between routes, second-order injection.
    # Advisory only: LOW confidence, analysis_kind="ai-hunt", never suppresses
    # engine findings; CI gates are unaffected by default (see fail_on).
    hunt_status = "disabled"
    hunt_used = False
    wants_hunt = config.ai.enabled and config.ai.hunt_enabled and config.ai.max_hunt_findings > 0
    wants_enrichment = config.ai.enabled and bool(all_findings) and config.ai.max_findings > 0
    model_available = False
    ensure_status = ""
    if wants_hunt or wants_enrichment:
        from dede.llm.ensure import ensure_model_installed

        model_available, ensure_status = ensure_model_installed(
            config,
            interactive=progress,
            assume_yes=assume_yes,
            offline=config.offline,
        )

    if wants_hunt and model_available:
        from dede.llm.hunt import run_vulnerability_hunt

        hunt_findings, hunt_status = run_vulnerability_hunt(
            root,
            config,
            discovered_files=sorted(discovered_paths),
            languages=dict(project.languages.languages),
            frameworks=list(project.languages.frameworks),
            cache_dir=cache_dir,
            on_progress=ai_progress if progress else None,
        )
        if hunt_findings:
            hunt_used = True
            all_findings.extend(attach_snippets(hunt_findings, root, config))
            all_findings = deduplicate_findings(all_findings)
    elif wants_hunt:
        hunt_status = ensure_status

    # Baselines and suppression rules must apply to hunt candidates too.
    all_findings, resolved = apply_baseline(all_findings, baseline)
    all_findings, suppressed = apply_suppressions(all_findings, config)
    all_findings = assign_ids(all_findings)
    feedback_summary = apply_feedback(all_findings, config, root)

    enrich_config = config
    if wants_enrichment and not model_available:
        enrich_config = config.model_copy(
            update={"ai": config.ai.model_copy(update={"enabled": False})}
        )

    if not config.ai.enabled:
        # Strict no-AI path: do not call model discovery, model installation, hunt,
        # enrichment, or Ollama client code at all.  This is stronger than merely
        # passing an disabled config into the enrichment function.
        findings = all_findings
        enrichment_used = False
        model_digest = ""
        enrichment_status = "hard-disabled (--no-ai/config)"
        hunt_status = "hard-disabled (--no-ai/config)"
        if progress:
            console.print("  ✓ AI fully disabled: no model probe, hunt, or enrichment calls were made")
    else:
        findings, enrichment_used, model_digest, enrichment_status = enrich_findings(
            all_findings,
            root,
            enrich_config,
            cache_dir=cache_dir,
            on_progress=ai_progress if progress else None,
        )
        if not enrichment_used and ensure_status and not enrich_config.ai.enabled:
            enrichment_status = ensure_status
            for finding in findings:
                if finding.analysis_kind != "ai-hunt":
                    finding.ai_status = "unavailable"
    ai_used = enrichment_used or hunt_used
    if not model_digest and hunt_used:
        model_digest = next(
            (f.ai_model_digest for f in findings if f.analysis_kind == "ai-hunt"), ""
        )
    ai_status = f"review={enrichment_status}; hunt={hunt_status}"
    if progress:
        if ai_used:
            console.print(f"  [green]AI enrichment {ai_status}[/green]")
        else:
            console.print(f"  [yellow]AI enrichment {ai_status}[/yellow]")

    if enrichment_used:
        step("[6/7] Statically verifying AI reviews and proposed examples...")
        try:
            verify_ai_reviews(findings, root, config, raw_dir / "ai-verification")
        except Exception as exc:  # noqa: BLE001
            for finding in findings:
                if finding.ai_status in {"reviewed", "cached"}:
                    finding.ai_validation_status = "ERROR"
                    finding.ai_fix_status = "ERROR"
                    finding.ai_validation_notes = [
                        f"Static verification unavailable: {type(exc).__name__}."
                    ]
                    finding.ai_fix_notes = [
                        "Example was not verified; do not treat it as a validated fix."
                    ]
        if progress:
            console.print(
                f"  AI static checks: {dict(Counter(f.ai_validation_status for f in findings if f.ai_generated))}"
            )

    step("[7/7] Generating reports...")
    finished = utc_now()
    duration = (finished - started).total_seconds()

    rules_version = ""
    rules_version_file = default_rules_dir() / "VERSION"
    if rules_version_file.is_file():
        rules_version = rules_version_file.read_text(encoding="utf-8").strip()

    engine_version = ""
    engine_version_file = default_engine_rules_dir() / "VERSION"
    if default_engine_rules_dir().is_dir() and engine_version_file.is_file():
        engine_version = engine_version_file.read_text(encoding="utf-8").strip()

    git_meta = collect_git_metadata(root)
    ruleset_versions = {
        "semgrep": rules_version or "bundled",
        **({"dede-engine": engine_version} if engine_version else {}),
    }
    scan_manifest = build_scan_manifest(
        config,
        scanner_version=__version__,
        rulesets=ruleset_versions,
        rules_dirs=[default_rules_dir(), default_engine_rules_dir()],
        commit=git_meta.get("commit", ""),
    )
    metadata = ScanMetadata(
        scanner_version=__version__,
        scan_started=started,
        scan_finished=finished,
        duration_seconds=duration,
        # Scanner containers are network-isolated by design.  The explicit
        # ``--offline`` flag additionally forbids missing-model downloads;
        # metadata therefore records the effective runtime as offline.
        offline_mode=True,
        ai_enabled=ai_used,
        ai_status=ai_status,
        ai_review_counts=dict(Counter(f.ai_status for f in findings)),
        ai_validation_counts=dict(
            Counter(f.ai_validation_status for f in findings if f.ai_generated)
        ),
        ai_fix_counts=dict(Counter(f.ai_fix_status for f in findings if f.ai_generated)),
        model=config.ai.model if config.ai.enabled else "",
        model_digest=model_digest,
        analyzers={
            t.tool: {
                "status": t.status.value,
                "version": t.version,
                "duration_seconds": t.duration_seconds,
                "message": t.message,
                **({"coverage": t.coverage} if t.coverage else {}),
            }
            for t in tool_statuses
        },
        ruleset_versions=ruleset_versions,
        files_scanned=project.languages.files_scanned,
        lines_scanned=project.languages.lines_scanned,
        target=str(root),
        fail_on=config.severity.fail_on,
        security_profile=config.engine.profile,
        repository=git_meta.get("repository", ""),
        branch=git_meta.get("branch", ""),
        commit=git_meta.get("commit", ""),
        scan_manifest=scan_manifest,
        profile={name: round(value, 6) for name, value in profile_marks.items()} if config.performance.profile else {},
        incremental=incremental,
        feedback=feedback_summary,
    )

    try:
        write_unified_finding_graph(findings, raw_dir)
    except OSError:
        pass

    risk = compute_risk_score(findings)
    rating, debt_minutes, debt_ratio = maintainability_rating(
        findings, project.languages.lines_scanned
    )
    scan_result = ScanResult(
        metadata=metadata,
        languages=project.languages,
        findings=findings,
        suppressed_findings=suppressed,
        resolved_findings=resolved,
        tool_statuses=tool_statuses,
        risk=risk,
        maintainability_rating=rating,
        maintainability_debt_minutes=debt_minutes,
        maintainability_debt_ratio=debt_ratio,
    )
    scan_result.compute_severity_counts()
    policy_violations = evaluate_policy(findings, config)
    metadata.policy_violations = policy_violations
    if index_path is not None:
        try:
            with ScanIndex(index_path) as scan_index:
                dependencies: dict[str, list[str]] = {}
                for status in tool_statuses:
                    for file, targets in status.dependency_graph.items():
                        dependencies.setdefault(file, []).extend(targets)
                dependencies = {
                    file: sorted(set(targets)) for file, targets in dependencies.items()
                }
                lifecycle_incomplete = any(
                    status.status
                    in {ToolStatus.FAILED, ToolStatus.SKIPPED, ToolStatus.SKIPPED_OFFLINE_DEPENDENCY}
                    for status in tool_statuses
                )
                if lifecycle_incomplete:
                    lifecycle = {
                        "status": "incomplete_coverage",
                        "message": "Finding lifecycle snapshot was not advanced because analyzer coverage was incomplete.",
                    }
                else:
                    lifecycle = scan_index.lifecycle_diff(findings)
                metadata.lifecycle = lifecycle
                (output_dir / "finding-lifecycle.json").write_text(
                    json.dumps(lifecycle, indent=2, sort_keys=True), encoding="utf-8"
                )
                scan_index.commit(
                    root,
                    project.files,
                    findings,
                    dependencies=dependencies or None,
                    update_findings=not lifecycle_incomplete,
                )
                if dependencies:
                    metadata.incremental["dependency_edges_current"] = sum(
                        len(values) for values in dependencies.values()
                    )
        except (OSError, ValueError):
            metadata.lifecycle = {"status": "unavailable"}

    # Continue generating the remaining formats if one writer fails.
    paths: dict[str, str] = {}
    report_error = False
    formats = [f.lower() for f in config.reports.formats]
    try:
        if "json" in formats:
            with live.operation("JSON report") as report_op:
                paths["JSON"] = str(write_json_report(scan_result, output_dir))
            live.done(report_op)
        (output_dir / "metadata.json").write_text(
            json.dumps(metadata.model_dump(mode="json"), indent=2, default=str),
            encoding="utf-8",
        )
        (output_dir / "scan-manifest.json").write_text(
            json.dumps(scan_manifest, indent=2, sort_keys=True), encoding="utf-8"
        )
    except Exception as exc:  # noqa: BLE001
        report_error = True
        if progress:
            console.print(f"[red]JSON report error: {exc}[/red]")
    if "html" in formats:
        try:
            with live.operation("HTML report") as report_op:
                paths["HTML"] = str(write_html_report(scan_result, output_dir))
            live.done(report_op)
        except Exception as exc:  # noqa: BLE001
            report_error = True
            if progress:
                console.print(f"[red]HTML report error: {exc}[/red]")
    if "pdf" in formats:
        try:
            with live.operation("PDF report", detail="PDF/A-3u") as report_op:
                paths["PDF"] = str(write_pdf_report(scan_result, output_dir))
            live.done(report_op)
        except PDFDependencyUnavailable as exc:
            if os.getenv("DEDE_NATIVE_RUNTIME") == "1":
                if progress:
                    console.print(f"[yellow]PDF skipped (optional native dependency): {exc}[/yellow]")
            else:
                report_error = True
                if progress:
                    console.print(f"[red]PDF report error: {exc}[/red]")
        except Exception as exc:  # noqa: BLE001
            report_error = True
            if progress:
                console.print(f"[red]PDF report error: {exc}[/red]")
    if "sarif" in formats:
        try:
            with live.operation("SARIF report") as report_op:
                paths["SARIF"] = str(write_sarif_report(scan_result, output_dir))
            live.done(report_op)
        except Exception as exc:  # noqa: BLE001
            report_error = True
            if progress:
                console.print(f"[red]SARIF report error: {exc}[/red]")

    if progress:
        counts = scan_result.severity_counts
        console.print()
        console.print("Scan completed.")
        console.print()
        console.print(f"Files scanned : {metadata.files_scanned}")
        console.print(f"Lines scanned : {metadata.lines_scanned}")
        console.print()
        console.print(f"CRITICAL : {counts.get('CRITICAL', 0)}")
        console.print(f"HIGH     : {counts.get('HIGH', 0)}")
        console.print(f"MEDIUM   : {counts.get('MEDIUM', 0)}")
        console.print(f"LOW      : {counts.get('LOW', 0)}")
        console.print(f"INFO     : {counts.get('INFO', 0)}")
        console.print()
        console.print(f"Risk Score: {risk.score}/100 - {risk.category}")
        console.print(f"Total duration: {metadata.duration_seconds:.1f}s")
        console.print()
        if ai_used:
            console.print(f"AI         : ON  ({ai_status})")
        else:
            console.print(f"AI         : OFF ({ai_status})")
        console.print()
        console.print("Reports:")
        for label, path in paths.items():
            console.print(f"  {label} : {path}")
        console.print()
        console.print("Analyzer status:")
        for t in tool_statuses:
            console.print(f"  {t.tool:12} {t.status.value}")

    # Exit codes
    if policy_violations:
        if progress:
            console.print(f"[red]Policy violations: {len(policy_violations)}[/red]")
    if report_error:
        return scan_result, 4

    # Partial analyzer failure is incomplete coverage, even if other tools succeeded.
    if any(t.status == ToolStatus.FAILED for t in tool_statuses):
        return scan_result, 3

    if policy_violations:
        return scan_result, 1

    if config.severity.fail_on:
        try:
            failing = parse_fail_on(config.severity.fail_on)
        except ValueError:
            return scan_result, 2
        if any(
            f.severity in failing and not f.suppressed and f.analysis_kind != "ai-hunt"
            for f in findings
        ):
            return scan_result, 1

    return scan_result, 0
