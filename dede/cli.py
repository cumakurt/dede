"""Typer CLI for Dede."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from dede import __version__
from dede.analyzers.semgrep import default_rules_dir
from dede.config import build_config, default_report_dir
from dede.doctor import run_doctor
from dede.llm import manage as model_manage
from dede.pipeline import run_scan

app = typer.Typer(
    name="dede",
    help="Fully offline static code analysis with local LLM enrichment.",
    add_completion=False,
    no_args_is_help=True,
    # Plain-text help (no rich panels/frames) for a clean, professional look.
    rich_markup_mode=None,
)
rules_app = typer.Typer(
    help="Manage / inspect vendored rules.",
    rich_markup_mode=None,
)
model_app = typer.Typer(
    help="List, check, download, and select local LLM models.",
    rich_markup_mode=None,
)
packs_app = typer.Typer(help="Verify and sign offline semantic model packs.", rich_markup_mode=None)
benchmark_app = typer.Typer(help="Run deterministic scanner quality benchmarks.", rich_markup_mode=None)
feedback_app = typer.Typer(help="Record and inspect local organization finding feedback.", rich_markup_mode=None)
app.add_typer(rules_app, name="rules")
app.add_typer(model_app, name="model")
app.add_typer(packs_app, name="packs")
app.add_typer(benchmark_app, name="benchmark")
app.add_typer(feedback_app, name="feedback")
console = Console()
SCANNER_MARKER = Path("/opt/dede-scanner")


class ReportCleanupError(RuntimeError):
    """A stale report created by an older container UID could not be replaced."""


def _inside_scanner_container() -> bool:
    """Return whether this CLI is already running in the scanner image."""
    # /.dockerenv only means *some* container. Treating any container as the
    # scanner would allow a scan to use an arbitrary, incomplete toolchain.
    return os.getenv("DEDE_IN_CONTAINER") == "1" and SCANNER_MARKER.is_file()


def _compose_prefix(project_root: Path) -> list[str]:
    """Build the pinned Compose invocation, including optional GPU access."""
    compose_file = project_root / "docker-compose.yml"
    if not compose_file.is_file():
        raise FileNotFoundError(f"Docker Compose file not found: {compose_file}")
    args = ["docker", "compose", "-f", str(compose_file)]
    if os.getenv("DEDE_DEVICE", "auto").lower() == "cuda":
        gpu_file = project_root / "docker-compose.gpu.yml"
        if not gpu_file.is_file():
            raise FileNotFoundError(f"GPU Compose override not found: {gpu_file}")
        args.extend(["-f", str(gpu_file)])
    return args


def _scanner_image_available() -> bool:
    """Return whether the pinned Docker scanner image is locally available.

    Auto runtime selection must never trigger an implicit pull or make Docker a
    prerequisite.  The full Docker path remains opt-in/available when the image
    already exists.
    """
    try:
        _require_scanner_image()
    except RuntimeError:
        return False
    return True


def _require_scanner_image() -> str:
    """Fail locally instead of letting Compose attempt an implicit online pull."""
    image = os.getenv("DEDE_SCANNER_IMAGE", "dede-scanner:1.10.0")
    try:
        result = subprocess.run(
            ["docker", "image", "inspect", image],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=15,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("Docker is not available; run ./install.sh or choose --runtime native") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("Docker did not respond within 15 seconds; check docker info") from exc
    if result.returncode != 0:
        raise RuntimeError(
            f"Scanner image not found ({image}); run ./install.sh --with-docker or make build"
        )
    return image


def _host_runtime_env(
    root: Path, output_dir: Path, *, clean_reports: bool = False
) -> dict[str, str]:
    """Return mounts/identity used by every host-to-container command."""
    cache_base = Path(os.getenv("XDG_CACHE_HOME", str(Path.home() / ".cache")))
    cache_dir = cache_base / "dede"
    if root.resolve().is_relative_to(output_dir.resolve()):
        raise ValueError("Report output must not be the scanned target or one of its parents")
    if output_dir.is_symlink() or cache_dir.is_symlink():
        raise RuntimeError("Report or cache directory must not be a symbolic link")
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    cache_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    for directory in (output_dir, cache_dir):
        if directory.stat().st_uid != os.getuid():
            raise RuntimeError(
                f"Runtime directory is owned by another user: {directory}. "
                "Choose a directory owned by the current user with --output or XDG_CACHE_HOME."
            )
    output_dir.chmod(0o700)
    cache_dir.chmod(0o700)
    # Older releases wrote reports as a fixed container UID. The host owns the
    # report directory and can safely replace only Dede's documented outputs,
    # avoiding upgrade failures on non-writable stale files/directories.
    if clean_reports:
        for name in (
            "report.json",
            "report.html",
            "report.pdf",
            "report.pdf.sha256",
            "report.sarif",
            "metadata.json",
            "scan-manifest.json",
            "finding-lifecycle.json",
        ):
            try:
                (output_dir / name).unlink(missing_ok=True)
            except OSError as exc:
                raise ReportCleanupError(
                    f"Could not clean previous Dede output: {output_dir / name}"
                ) from exc
        raw_dir = output_dir / "raw"
        if raw_dir.exists():
            try:
                shutil.rmtree(raw_dir)
            except OSError as exc:
                raise ReportCleanupError(f"Could not clean previous Dede raw output: {raw_dir}") from exc
    env = os.environ.copy()
    env.update(
        {
            "TARGET": str(root),
            "OUTPUT": str(output_dir),
            "DEDE_HOST_CACHE": str(cache_dir),
            "DEDE_UID": str(os.getuid()),
            "DEDE_GID": str(os.getgid()),
            "DEDE_IN_CONTAINER": "1",
            "DEDE_PROJECT_NAME": root.name,
        }
    )
    return env


def _clean_legacy_reports_with_image(output_dir: Path, image: str) -> None:
    """One-time migration for reports owned by the old fixed container UID."""
    targets = [
        "/reports/report.json",
        "/reports/report.html",
        "/reports/report.pdf",
        "/reports/report.pdf.sha256",
        "/reports/report.sarif",
        "/reports/metadata.json",
        "/reports/raw",
    ]
    result = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--security-opt",
            "no-new-privileges:true",
            "--cap-drop",
            "ALL",
            "--cap-add",
            "DAC_OVERRIDE",
            "--user",
            "0:0",
            "--entrypoint",
            "/bin/rm",
            "-v",
            f"{output_dir.resolve()}:/reports",
            image,
            "-rf",
            "--",
            *targets,
        ],
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Could not repair permissions on previous Dede reports: {output_dir}")


def _container_path(path: Path, root: Path) -> str:
    """Map a host path inside the read-only /workspace mount."""
    resolved = path.resolve()
    try:
        relative = resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError("config/baseline must be inside the scanned target") from exc
    return "/workspace" if str(relative) == "." else f"/workspace/{relative.as_posix()}"



def _running_dede_scanners() -> bool:
    """Return whether another Dede scanner container is currently running."""
    try:
        result = subprocess.run(
            [
                "docker", "ps", "-q",
                "--filter", "label=com.docker.compose.project=dede",
                "--filter", "label=com.docker.compose.service=scanner",
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired, TypeError):
        return False
    return bool(getattr(result, "stdout", "").strip())


def _stop_managed_ollama(compose_prefix: list[str], env: dict[str, str]) -> bool:
    """Stop Dede's Ollama service when it is safe to release model resources.

    Never stop it while another Dede scanner is active; this keeps concurrent
    AI scans safe while making --no-ai genuinely model-free for normal use.
    """
    if _running_dede_scanners():
        return False
    try:
        result = subprocess.run(
            [*compose_prefix, "stop", "--timeout", "2", "ollama"],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired, TypeError):
        return False
    return result.returncode == 0


def _docker_scan(
    target: Path,
    *,
    formats: list[str] | None,
    output: Path | None,
    no_ai: bool,
    offline: bool,
    ai_hunt: bool | None,
    severity: str | None,
    exclude: list[str],
    respect_gitignore: bool,
    baseline: Path | None,
    config: Path | None,
    model: str | None,
    security_profile: str | None = None,
    yes: bool = False,
) -> int:
    """Run every analyzer in the pinned Docker scanner environment."""
    root = target.resolve()
    if not root.is_dir():
        raise FileNotFoundError(f"Target is not a directory: {root}")
    host_config = build_config(
        root,
        config_path=config,
        cli_overrides={
            "formats": formats,
            "output": str(output) if output else None,
            "no_ai": no_ai,
            "offline": offline or None,
            "model": model,
            "fail_on": severity,
            "security_profile": security_profile,
        },
    )
    no_ai = not host_config.ai.enabled
    offline = host_config.offline
    model = host_config.ai.model
    output_path = (output or default_report_dir(root)).expanduser().absolute()
    if output_path.is_symlink():
        raise ValueError("Report output must not be a symbolic link")
    output_dir = output_path.resolve()
    project_root = Path(__file__).resolve().parents[1]
    compose_prefix = _compose_prefix(project_root)
    # Validate all input paths before deleting any previous scan artifacts.
    input_paths: list[tuple[str, str]] = []
    for option, path in (("--baseline", baseline), ("--config", config)):
        if path is not None:
            if not path.is_file():
                raise FileNotFoundError(f"Input file not found: {path}")
            if path.resolve().is_relative_to(output_dir):
                raise ValueError(f"{option} must be outside the report output directory")
            input_paths.append((option, _container_path(path, root)))
    image = _require_scanner_image()
    try:
        env = _host_runtime_env(root, output_dir, clean_reports=True)
    except ReportCleanupError:
        _clean_legacy_reports_with_image(output_dir, image)
        env = _host_runtime_env(root, output_dir, clean_reports=True)
    if no_ai:
        env["DEDE_AI_DISABLED"] = "1"
        # --no-deps prevents Compose from starting Ollama, but older Dede
        # releases may have left the managed service/model runner alive.
        _stop_managed_ollama(compose_prefix, env)
    args = [
        *compose_prefix,
        "run",
        "--rm",
        "scanner",
        "scan",
        "/workspace",
        "--output",
        "/reports",
    ]
    if no_ai:
        # Deterministic scans do not need to start or wait for Ollama.
        args.insert(args.index("scanner"), "--no-deps")
    for report_format in formats or []:
        args.extend(["--format", report_format])
    if no_ai:
        args.append("--no-ai")
    if offline:
        args.append("--offline")
    if ai_hunt is not None:
        args.append("--ai-hunt" if ai_hunt else "--no-ai-hunt")
    if severity:
        args.extend(["--severity", severity])
    if security_profile:
        args.extend(["--security-profile", security_profile])
    for pattern in exclude:
        args.extend(["--exclude", pattern])
    if respect_gitignore:
        args.append("--respect-gitignore")
    for option, container_path in input_paths:
        args.extend([option, container_path])
    if model:
        args.extend(["--model", model])
    if yes:
        args.append("--yes")

    mode = "AI disabled" if no_ai else f"AI enabled ({model})"
    console.print(f"Starting Docker scanner; reports: {output_dir}")
    console.print(f"Runtime mode: {mode}")
    if no_ai:
        console.print("Model status: Ollama dependency disabled; Dede will not use a model service.")
    try:
        completed = subprocess.run(args, env=env, check=False)
        return completed.returncode
    finally:
        # AI scans should not pin RAM/VRAM after completion or interruption.
        # If another Dede scan is active, cleanup deliberately leaves Ollama alone.
        if not no_ai:
            _stop_managed_ollama(compose_prefix, env)


def _native_scan(
    target: Path,
    *,
    formats: list[str] | None,
    output: Path | None,
    no_ai: bool,
    offline: bool,
    ai_hunt: bool | None,
    severity: str | None,
    exclude: list[str],
    respect_gitignore: bool,
    baseline: Path | None,
    config: Path | None,
    model: str | None,
    security_profile: str | None = None,
    yes: bool = False,
) -> int:
    """Run Dede directly on the host without requiring a Docker image.

    Built-in analyzers always run. Optional external analyzers are discovered
    from PATH and report SKIPPED_OFFLINE_DEPENDENCY when not installed.
    """
    root = target.resolve()
    cfg = build_config(
        root,
        config_path=config,
        cli_overrides={
            "formats": formats,
            "output": str(output) if output else None,
            "no_ai": no_ai,
            "offline": offline or None,
            "ai_hunt": ai_hunt,
            "fail_on": severity,
            "exclude": exclude or [],
            "respect_gitignore": respect_gitignore or None,
            "model": model,
            "security_profile": security_profile,
        },
    )
    previous_native = os.environ.get("DEDE_NATIVE_RUNTIME")
    previous_ai_disabled = os.environ.get("DEDE_AI_DISABLED")
    os.environ["DEDE_NATIVE_RUNTIME"] = "1"
    console.print("Using native scanner; Docker image is not required.")
    if not cfg.ai.enabled:
        os.environ["DEDE_AI_DISABLED"] = "1"
        console.print("Runtime mode: AI disabled")
    else:
        os.environ.pop("DEDE_AI_DISABLED", None)
        console.print(f"Runtime mode: AI enabled ({cfg.ai.model})")
    try:
        _result, code = run_scan(root, cfg, baseline=baseline, assume_yes=yes)
        return code
    finally:
        if previous_native is None:
            os.environ.pop("DEDE_NATIVE_RUNTIME", None)
        else:
            os.environ["DEDE_NATIVE_RUNTIME"] = previous_native
        if previous_ai_disabled is None:
            os.environ.pop("DEDE_AI_DISABLED", None)
        else:
            os.environ["DEDE_AI_DISABLED"] = previous_ai_disabled


@app.command("languages")
def languages_command(
    json_output: bool = typer.Option(False, "--json", help="Emit the language support matrix as JSON."),
) -> None:
    """Show first-class semantic and supplementary rule-based language support."""
    from dede.semantic.language_support import FULL_LANGUAGE_SUPPORT, RULE_BASED_LANGUAGE_SUPPORT, support_payload

    if json_output:
        console.print_json(json.dumps(support_payload()))
        return
    table = Table(title="Dede language support", show_lines=False)
    table.add_column("Language")
    table.add_column("Engine")
    table.add_column("Level")
    table.add_column("Project-wide", justify="center")
    table.add_column("Cross-file", justify="center")
    table.add_column("Call graph", justify="center")
    table.add_column("CFG", justify="center")
    table.add_column("Taint", justify="center")
    for item in FULL_LANGUAGE_SUPPORT:
        table.add_row(
            item.language, item.engine, item.level,
            "yes" if item.project_wide else "no",
            "yes" if item.cross_file else "no",
            "yes" if item.call_graph else "no",
            "yes" if item.cfg else "no",
            "yes" if item.taint else "no",
        )
    console.print(table)
    console.print("Supplementary rule-based coverage: " + ", ".join(RULE_BASED_LANGUAGE_SUPPORT))
    console.print("Note: semantic support is evidence-first; ambiguous dynamic dispatch is left unresolved rather than guessed.")


@app.command()
def scan(
    target: Path = typer.Argument(..., exists=True, file_okay=False, dir_okay=True, readable=True),
    format: list[str] | None = typer.Option(
        None, "--format", help="Report format (repeatable): json, html, pdf, sarif"
    ),
    output: Path | None = typer.Option(None, "--output", "-o", help="Report output directory"),
    runtime: str = typer.Option(
        "auto",
        "--runtime",
        help="Execution runtime: auto, native, or docker (Docker is optional)",
    ),
    no_ai: bool = typer.Option(False, "--no-ai", help="Disable local LLM enrichment"),
    offline: bool = typer.Option(
        False,
        "--offline",
        help="Forbid model downloads and require all AI/cache data to be local",
    ),
    ai_hunt: bool | None = typer.Option(
        None,
        "--ai-hunt/--no-ai-hunt",
        help="AI project-wide vulnerability hunt (finds issues engines miss)",
    ),
    severity: str | None = typer.Option(
        None, "--severity", "--fail-on", help="Fail if findings at/above this severity"
    ),
    exclude: list[str] | None = typer.Option(None, "--exclude", help="Extra exclude path/name"),
    respect_gitignore: bool = typer.Option(
        False,
        "--respect-gitignore",
        help=(
            "Also apply .gitignore patterns during file discovery. "
            "By default Dede scans all non-excluded files regardless of .gitignore. "
            "Enable this flag to skip files your VCS ignores (e.g. build artefacts, "
            "local secrets). Only the root .gitignore is read; nested .gitignore files "
            "are not consulted."
        ),
    ),
    baseline: Path | None = typer.Option(
        None, "--baseline", help="Previous report.json for delta scan"
    ),
    config: Path | None = typer.Option(None, "--config", help="Path to .dede.yml"),
    model: str | None = typer.Option(None, "--model", help="Override Ollama model"),
    security_profile: str | None = typer.Option(
        None, "--security-profile",
        help="Finding profile: strict, smart, audit, or experimental",
    ),
    yes: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help="Non-interactive: auto-confirm downloading a missing AI model",
    ),
) -> None:
    """Scan a source directory and generate reports."""
    try:
        if not _inside_scanner_container():
            runtime_mode = runtime.strip().lower()
            if runtime_mode not in {"auto", "native", "docker"}:
                raise ValueError("--runtime must be one of: auto, native, docker")
            use_docker = runtime_mode == "docker" or (
                runtime_mode == "auto" and _scanner_image_available()
            )
            if use_docker:
                raise typer.Exit(
                    _docker_scan(
                        target,
                        formats=format,
                        output=output,
                        no_ai=no_ai,
                        offline=offline,
                        ai_hunt=ai_hunt,
                        severity=severity,
                        exclude=exclude or [],
                        respect_gitignore=respect_gitignore,
                        baseline=baseline,
                        config=config,
                        model=model,
                        security_profile=security_profile,
                        yes=yes,
                    )
                )
            if runtime_mode == "auto":
                if no_ai:
                    # Preserve the --no-ai resource invariant when auto mode
                    # falls back to native execution: an Ollama service left by
                    # an older Dede run should not keep a model resident.  This
                    # is best-effort and only applies to Dede's own Compose
                    # service; explicit --runtime native never probes Docker.
                    try:
                        project_root = Path(__file__).resolve().parents[1]
                        stopped = _stop_managed_ollama(
                            _compose_prefix(project_root), os.environ.copy()
                        )
                        if stopped:
                            console.print("Stopped a previously managed Dede Ollama service (--no-ai).")
                    except (OSError, RuntimeError, FileNotFoundError):
                        pass
                console.print(
                    "Docker scanner image not found; falling back to native runtime "
                    "(use --runtime docker to require Docker)."
                )
            raise typer.Exit(
                _native_scan(
                    target,
                    formats=format,
                    output=output,
                    no_ai=no_ai,
                    offline=offline,
                    ai_hunt=ai_hunt,
                    severity=severity,
                    exclude=exclude or [],
                    respect_gitignore=respect_gitignore,
                    baseline=baseline,
                    config=config,
                    model=model,
                    security_profile=security_profile,
                    yes=yes,
                )
            )
        cfg = build_config(
            target.resolve(),
            config_path=config,
            cli_overrides={
                "formats": format,
                "output": str(output) if output else None,
                "no_ai": no_ai,
                "offline": offline or None,
                "ai_hunt": ai_hunt,
                "fail_on": severity,
                "exclude": exclude or [],
                "respect_gitignore": respect_gitignore or None,
                "model": model,
                "security_profile": security_profile,
            },
        )
        _result, code = run_scan(
            target.resolve(),
            cfg,
            baseline=baseline,
            assume_yes=yes,
        )
        raise typer.Exit(code)
    except FileNotFoundError as exc:
        console.print(f"[red]Configuration/path error: {exc}[/red]")
        raise typer.Exit(2) from exc
    except ValueError as exc:
        console.print(f"[red]Configuration error: {exc}[/red]")
        raise typer.Exit(2) from exc
    except typer.Exit:
        raise
    except Exception as exc:
        console.print(f"[red]Runtime error: {exc}[/red]")
        raise typer.Exit(3) from exc


@app.command()
def info() -> None:
    """Show scanner information."""
    console.print(f"Dede {__version__}")
    console.print(f"Rules directory: {default_rules_dir()}")
    console.print("Offline runtime: supported")
    console.print("Models: dede model list | recommend | pull <name>")
    console.print()
    console.print("[bold]Developer[/bold]")
    console.print("  Cuma KURT — cumakurt@gmail.com")
    console.print("  https://www.linkedin.com/in/cuma-kurt-34414917/")
    console.print("  https://github.com/cumakurt/dede")


@app.command()
def doctor(
    output: Path | None = typer.Option(None, "--output", "-o"),
    runtime: str = typer.Option(
        "auto", "--runtime", help="Execution runtime: auto, native, or docker"
    ),
) -> None:
    """Check analyzer / LLM / report readiness."""
    runtime_mode = runtime.strip().lower()
    if runtime_mode not in {"auto", "native", "docker"}:
        console.print("[red]Configuration error: --runtime must be auto, native, or docker[/red]")
        raise typer.Exit(2)
    if not _inside_scanner_container():
        use_docker = runtime_mode == "docker" or (
            runtime_mode == "auto" and _scanner_image_available()
        )
        if use_docker:
            try:
                root = Path.cwd().resolve()
                report_dir = output.expanduser().absolute() if output else default_report_dir(root)
                project_root = Path(__file__).resolve().parents[1]
                _require_scanner_image()
                env = _host_runtime_env(root, report_dir)
                args = [
                    *_compose_prefix(project_root),
                    "run",
                    "--rm",
                    "--no-deps",
                    "scanner",
                    "doctor",
                    "--output",
                    "/reports",
                ]
                raise typer.Exit(subprocess.run(args, env=env, check=False).returncode)
            except (OSError, ValueError, RuntimeError) as exc:
                console.print(f"[red]Runtime error:[/red] {exc}")
                raise typer.Exit(3) from exc
        if runtime_mode == "auto":
            console.print("Docker scanner image not found; running native doctor checks.")
    cfg = build_config(Path.cwd())
    if output:
        cfg.reports.output = str(output)
    code = run_doctor(cfg, report_dir=Path(cfg.reports.output))
    raise typer.Exit(code)


@app.command()
def version() -> None:
    """Print version."""
    console.print(__version__)


@rules_app.command("list")
def rules_list() -> None:
    """List vendored Semgrep rule files and packs."""
    rules_dir = default_rules_dir()
    if not rules_dir.is_dir():
        console.print("No rules directory found.")
        raise typer.Exit(1)
    version_file = rules_dir / "VERSION"
    if version_file.is_file():
        console.print(f"Ruleset version: {version_file.read_text(encoding='utf-8').strip()}")
    manifest = rules_dir / "MANIFEST.yml"
    if manifest.is_file():
        console.print(f"Manifest: {manifest}")
    custom = sorted((rules_dir / "custom").glob("*.yml")) if (rules_dir / "custom").is_dir() else []
    packs = sorted((rules_dir / "packs").glob("*.yml")) if (rules_dir / "packs").is_dir() else []
    console.print("Profile default: full (packs/all.yml CE dump when vendored)")
    console.print(f"Custom: {len(custom)} files | Packs: {len(packs)} files")
    all_dump = rules_dir / "packs" / "all.yml"
    if all_dump.is_file():
        console.print("Full offline dump: packs/all.yml present")
    else:
        console.print("[yellow]packs/all.yml missing — run: dede rules update[/yellow]")
    if custom:
        console.print("[bold]custom/[/bold]")
        for path in custom:
            console.print(f"  {path.name}")
    if packs:
        console.print("[bold]packs/[/bold]")
        for path in packs:
            console.print(f"  {path.name}")
    if not custom and not packs:
        files = sorted(list(rules_dir.rglob("*.yaml")) + list(rules_dir.rglob("*.yml")))
        console.print(f"{len(files)} rule files under {rules_dir}")
        for path in files[:50]:
            console.print(f"  {path.relative_to(rules_dir)}")


def _find_download_rules_script() -> Path | None:
    """Locate scripts/download_rules.sh from rules dir or package checkout."""
    candidates: list[Path] = []
    rules_dir = default_rules_dir()
    # .../rules/semgrep → repo root
    candidates.append(rules_dir.parent.parent / "scripts" / "download_rules.sh")
    # package-relative (editable install / source tree)
    pkg_root = Path(__file__).resolve().parents[1]
    candidates.append(pkg_root / "scripts" / "download_rules.sh")
    candidates.append(Path.cwd() / "scripts" / "download_rules.sh")
    for path in candidates:
        if path.is_file():
            return path
    return None


@rules_app.command("update")
def rules_update(
    force: bool = typer.Option(
        False,
        "--force",
        "-f",
        help="Re-download packs even if already vendored (FORCE_REFRESH=1)",
    ),
) -> None:
    """Download / refresh offline Semgrep registry packs (runs scripts/download_rules.sh)."""
    import os
    import subprocess

    script = _find_download_rules_script()
    if script is None:
        console.print(
            "[red]scripts/download_rules.sh not found.[/red] "
            "Run from the Dede repo or use: make rules"
        )
        raise typer.Exit(1)

    env = os.environ.copy()
    if force:
        env["FORCE_REFRESH"] = "1"

    console.print(f"Running {script} ...")
    result = subprocess.run(["bash", str(script)], env=env, check=False)
    if result.returncode != 0:
        console.print(f"[red]Rules update failed (exit {result.returncode})[/red]")
        raise typer.Exit(result.returncode)
    console.print("[green]Rules update complete.[/green]")


@model_app.command("list")
def model_list(
    all_models: bool = typer.Option(False, "--all", help="Include non-coding catalog entries"),
) -> None:
    """List curated models with host fit assessment."""
    raise typer.Exit(model_manage.cmd_list(coding_only=not all_models))


@model_app.command("check")
def model_check(
    name: str = typer.Argument(..., help="Ollama model name, e.g. qwen2.5-coder:7b"),
) -> None:
    """Pre-flight resource check before downloading a model."""
    raise typer.Exit(model_manage.cmd_check(name))


@model_app.command("recommend")
def model_recommend() -> None:
    """Recommend models that fit current RAM/VRAM/disk."""
    raise typer.Exit(model_manage.cmd_recommend())


@model_app.command("pull")
def model_pull(
    name: str = typer.Argument(..., help="Ollama model to download"),
    force: bool = typer.Option(
        False, "--force", help="Download even if marked INCOMPATIBLE (not recommended)"
    ),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip marginal-compatibility confirmation"),
) -> None:
    """Check compatibility, then download the model via local Ollama."""
    raise typer.Exit(model_manage.cmd_pull(name, force=force, yes=yes))


@model_app.command("use")
def model_use(
    name: str = typer.Argument(..., help="Model name to select as default"),
    yes: bool = typer.Option(
        False, "--yes", "-y", help="Auto-download if the model is not installed"
    ),
) -> None:
    """Set the active model preference; offer to download if missing."""
    raise typer.Exit(model_manage.cmd_use(name, assume_yes=yes))


@model_app.command("show")
def model_show() -> None:
    """Show active / preferred model."""
    raise typer.Exit(model_manage.cmd_show())



@packs_app.command("verify")
def packs_verify(
    path: Path = typer.Argument(..., exists=True, readable=True),
    require_signature: bool = typer.Option(False, "--require-signature"),
    key_env: str = typer.Option("DEDE_MODEL_PACK_KEY", "--key-env"),
) -> None:
    """Verify an offline semantic model pack's digest/signature."""
    from dede.semantic.model_packs import verify_pack
    secret = os.getenv(key_env) or None
    try:
        pack = verify_pack(path, secret=secret, require_signature=require_signature)
    except (ValueError, OSError) as exc:
        console.print(f"[red]Model pack verification failed: {exc}[/red]")
        raise typer.Exit(2) from exc
    console.print(f"Pack: {pack.name} {pack.version}")
    console.print(f"SHA-256: {pack.digest}")
    console.print(f"Signature verified: {'yes' if pack.verified else 'no'}")
    if pack.warnings:
        console.print(f"Warnings: {', '.join(pack.warnings)}")


@packs_app.command("sign")
def packs_sign(
    path: Path = typer.Argument(..., exists=True, readable=True, writable=True),
    key_env: str = typer.Option("DEDE_MODEL_PACK_KEY", "--key-env"),
) -> None:
    """Sign an offline semantic model pack with HMAC-SHA256."""
    from dede.semantic.model_packs import sign_pack
    secret = os.getenv(key_env, "")
    if not secret:
        console.print(f"[red]{key_env} is not set; refusing to create an empty-key signature.[/red]")
        raise typer.Exit(2)
    digest = sign_pack(path, secret)
    console.print(f"[green]Signed[/green] {path} | SHA-256 {digest}")


@benchmark_app.command("precision")
def benchmark_precision(
    corpus: Path | None = typer.Option(None, "--corpus", help="Precision corpus JSON; defaults to Dede's built-in corpus."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write detailed benchmark JSON."),
) -> None:
    """Measure semantic-engine precision/recall/F1 against a deterministic corpus."""
    from dede.precision_lab import run_precision_corpus
    corpus_path = corpus or (Path(__file__).resolve().parent / "benchmarks" / "precision-corpus.json")
    cfg = build_config(Path.cwd(), cli_overrides={"no_ai": True})
    metrics, detail = run_precision_corpus(corpus_path, cfg)
    console.print(f"TP={metrics.true_positive} FP={metrics.false_positive} FN={metrics.false_negative}")
    console.print(f"Precision={metrics.precision:.3f} Recall={metrics.recall:.3f} F1={metrics.f1:.3f} Runtime={metrics.runtime_seconds:.2f}s")
    language_metrics = detail.get("by_language", {})
    if language_metrics:
        table = Table(title="Precision by language", show_lines=False)
        table.add_column("Language")
        table.add_column("Cases", justify="right")
        table.add_column("TP", justify="right")
        table.add_column("FP", justify="right")
        table.add_column("FN", justify="right")
        table.add_column("Precision", justify="right")
        table.add_column("Recall", justify="right")
        table.add_column("F1", justify="right")
        for language, item in language_metrics.items():
            table.add_row(language, str(item["cases"]), str(item["tp"]), str(item["fp"]), str(item["fn"]), f"{item['precision']:.3f}", f"{item['recall']:.3f}", f"{item['f1']:.3f}")
        console.print(table)
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(__import__('json').dumps(detail, indent=2), encoding='utf-8')
        console.print(f"Benchmark report: {output}")
    if metrics.precision < cfg.precision_lab.minimum_precision or metrics.recall < cfg.precision_lab.minimum_recall:
        raise typer.Exit(1)


@benchmark_app.command("hardening")
def benchmark_hardening(
    corpus: Path | None = typer.Option(None, "--corpus", help="Hardening corpus JSON; defaults to Dede's built-in corpus."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write detailed benchmark JSON."),
) -> None:
    """Measure high-precision hardening-rule precision/recall/F1."""
    from dede.precision_lab import run_hardening_corpus
    corpus_path = corpus or (Path(__file__).resolve().parent / "benchmarks" / "hardening-corpus.json")
    cfg = build_config(Path.cwd(), cli_overrides={"no_ai": True})
    metrics, detail = run_hardening_corpus(corpus_path, cfg)
    console.print(f"TP={metrics.true_positive} FP={metrics.false_positive} FN={metrics.false_negative}")
    console.print(f"Precision={metrics.precision:.3f} Recall={metrics.recall:.3f} F1={metrics.f1:.3f} Runtime={metrics.runtime_seconds:.2f}s")
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(detail, indent=2), encoding="utf-8")
        console.print(f"Benchmark report: {output}")
    if metrics.precision < cfg.precision_lab.minimum_precision or metrics.recall < cfg.precision_lab.minimum_recall:
        raise typer.Exit(1)


@feedback_app.command("add")
def feedback_add(
    semantic_fingerprint: str = typer.Argument(..., help="Finding semantic fingerprint."),
    verdict: str = typer.Option(..., "--verdict", help="false-positive, accepted-risk, mitigated, confirmed, or wont-fix"),
    reason: str = typer.Option("", "--reason"),
    rule_id: str = typer.Option("", "--rule-id"),
    sink_kind: str = typer.Option("", "--sink-kind"),
    ast_fingerprint: str = typer.Option("", "--ast-fingerprint"),
    author: str = typer.Option("", "--author"),
    path: Path = typer.Option(Path(".dede/feedback.json"), "--path"),
) -> None:
    """Record a local triage verdict without silently creating a suppression."""
    from dede.feedback import record_feedback
    try:
        entry = record_feedback(path, semantic_fingerprint=semantic_fingerprint, verdict=verdict, reason=reason, rule_id=rule_id, sink_kind=sink_kind, ast_fingerprint=ast_fingerprint, author=author)
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(2) from exc
    console.print(f"[green]Feedback recorded[/green]: {entry['id']} ({entry['verdict']})")
    console.print("No suppression was created; feedback is advisory unless explicit policy enables auto-suppression.")


@feedback_app.command("list")
def feedback_list(path: Path = typer.Option(Path(".dede/feedback.json"), "--path")) -> None:
    """List local organization finding feedback."""
    import json
    if not path.is_file():
        console.print("No feedback file found.")
        return
    data = json.loads(path.read_text(encoding="utf-8"))
    for entry in data.get("entries", []):
        console.print(f"{entry.get('id','-')}  {entry.get('verdict','-'):14}  {entry.get('semantic_fingerprint','')[:16]}  {entry.get('reason','')}")


@app.command("watch")
def watch_scan(
    target: Path = typer.Argument(Path("."), exists=True, file_okay=False, readable=True),
    interval: float = typer.Option(1.0, "--interval", min=0.25, max=60.0),
    no_ai: bool = typer.Option(True, "--no-ai/--ai", help="Watch mode defaults to deterministic no-AI scans."),
    once: bool = typer.Option(False, "--once", help="Run one scan and exit; useful for editor integrations/tests."),
) -> None:
    """Watch source files and re-scan on change using persistent semantic caches."""
    from dede.watch import watch
    cfg = build_config(target.resolve(), cli_overrides={"no_ai": no_ai})
    raise typer.Exit(watch(target, cfg, interval=interval, once=once))


@app.command("serve")
def serve_report(
    report_dir: Path = typer.Argument(..., exists=True, file_okay=False, readable=True, help="Directory containing report.json/report.html."),
    port: int = typer.Option(8765, "--port", min=1024, max=65535),
) -> None:
    """Serve an existing Dede report over a read-only localhost HTTP API/UI."""
    from dede.team_server import serve
    try:
        raise typer.Exit(serve(report_dir, port=port))
    except FileNotFoundError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(2) from exc


@app.command("mcp")
def mcp_server(
    report: Path = typer.Argument(..., exists=True, readable=True, help="Dede report.json to expose read-only over MCP stdio."),
) -> None:
    """Run a local, read-only MCP stdio server for a Dede JSON report."""
    from dede.mcp_server import serve_stdio
    raise typer.Exit(serve_stdio(report))


@app.command("verify-fix")
def verify_fix(
    before: Path = typer.Argument(..., exists=True, readable=True),
    after: Path = typer.Argument(..., exists=True, readable=True),
    finding_id: str | None = typer.Option(None, "--finding", help="Verify one semantic fingerprint; default checks all prior findings."),
) -> None:
    """Verify remediation by comparing deterministic before/after scan reports."""
    from dede.fix_verification import verify_reports
    result = verify_reports(before, after, finding_id=finding_id)
    console.print(f"Status: {result.status}")
    console.print(f"Removed: {len(result.removed)} | Persisted: {len(result.persisted)} | New HIGH/CRITICAL: {len(result.new_high_or_critical)}")
    raise typer.Exit(0 if result.status in {"VERIFIED_BY_RESCAN", "NO_MATCHING_FINDING"} else 1)

def main() -> None:
    app()


if __name__ == "__main__":
    main()
