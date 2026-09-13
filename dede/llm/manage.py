"""Model management: list, check, recommend, pull, use."""

from __future__ import annotations

import os

from rich.console import Console

from dede.config import AppConfig, build_config
from dede.llm.catalog import list_catalog, resolve_model_spec
from dede.llm.client import OllamaClient
from dede.llm.resources import (
    Compatibility,
    check_model_compatibility,
    probe_host,
    recommend_models,
)
from dede.llm.settings import get_preferred_model, set_preferred_model

console = Console()


def _client_from_config(config: AppConfig | None = None) -> OllamaClient:
    cfg = config or build_config(__import__("pathlib").Path.cwd())
    # Prefer localhost when running host CLI outside compose network
    client = OllamaClient(cfg)
    if os.getenv("DEDE_IN_CONTAINER") != "1" and "://ollama:" in client.host:
        client.host = client.host.replace("://ollama:", "://127.0.0.1:", 1)
    return client


def _fmt_size(size_bytes: int) -> str:
    if size_bytes <= 0:
        return "—"
    value = float(size_bytes)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return f"{value:.1f} GB"


def cmd_list(*, coding_only: bool = False, config: AppConfig | None = None) -> int:
    """Show installed models first (any Ollama model works with Dede), then
    compatible catalog suggestions — in clean, borderless aligned tables."""
    from rich.table import Table

    cfg = config or build_config(__import__("pathlib").Path.cwd())
    host = probe_host(cfg.ai.device)
    preferred = get_preferred_model() or cfg.ai.model

    client = _client_from_config(cfg)
    if not client.is_reachable() and "ollama:" in client.host:
        client = OllamaClient(host="http://127.0.0.1:11434", model=cfg.ai.model)
    reachable = client.is_reachable()
    installed_models = client.list_installed() if reachable else []
    installed = {str(m.get("name") or "") for m in installed_models}

    console.print()
    console.print(
        "[bold]Dede models[/bold]  "
        f"host: RAM {host.ram_total_gb:.0f}GB (free {host.ram_available_gb:.0f}GB)"
        + (f", GPU {host.vram_total_gb:.0f}GB" if host.has_nvidia else ", CPU only")
    )

    # ---------------------------------------------------------------
    # Section 1 — installed models (anything in Ollama is usable)
    # ---------------------------------------------------------------
    console.print()
    if not reachable:
        console.print(f"[yellow]Ollama not reachable at {client.host}[/yellow]")
        console.print("  Start it with: docker compose up -d ollama")
        console.print()

    table = Table(
        title="Installed models" if reachable else "Installed models (unavailable)",
        title_style="bold",
        title_justify="left",
        box=None,
        show_header=True,
        header_style="dim",
        padding=(0, 2, 0, 0),
    )
    table.add_column("Name", style="cyan", no_wrap=True)
    table.add_column("Size", justify="right", no_wrap=True)
    table.add_column("Fit", justify="left", no_wrap=True)
    table.add_column("Notes", ratio=1, overflow="fold")

    if installed_models:
        for model in sorted(installed_models, key=lambda m: str(m.get("name") or "")):
            name = str(model.get("name") or "")
            size = _fmt_size(int(model.get("size") or 0))
            details = model["details"] if isinstance(model.get("details"), dict) else {}
            family = str(details.get("family") or "") if isinstance(details, dict) else ""
            if name == preferred:
                fit, note = "[green]active[/green]", "current default"
            else:
                report = check_model_compatibility(name, device_preference=cfg.ai.device, host=host)
                fit = {
                    Compatibility.COMPATIBLE: "[green]ok[/green]",
                    Compatibility.MARGINAL: "[yellow]tight[/yellow]",
                    Compatibility.INCOMPATIBLE: "[red]tight[/red]",
                }[report.level]
                # Keep the note compact so rows stay on one line.
                note = family if family else "installed"
            table.add_row(name + (" [bold]*[/bold]" if name == preferred else ""), size, fit, note)
        console.print(table)
        console.print("[dim]  * active model   use: dede model use <name>[/dim]")
    else:
        console.print("  No models installed." if reachable else "  Cannot list models.")
        console.print("  Install one: [bold]dede model recommend[/bold] → dede model pull <name>")
        console.print("  Any Ollama model works: dede model pull <any-model>")

    # ---------------------------------------------------------------
    # Section 2 — curated suggestions that fit this host
    # ---------------------------------------------------------------
    suggestions = [
        (spec, check_model_compatibility(spec.name, device_preference=cfg.ai.device, host=host))
        for spec in list_catalog(coding_only=coding_only)
    ]
    fitting = [
        (spec, report)
        for spec, report in suggestions
        if report.level == Compatibility.COMPATIBLE and spec.name not in installed
    ][:4]
    if fitting:
        console.print()
        sugg = Table(
            title="Suggested (fit this host, not yet installed)",
            title_style="bold",
            title_justify="left",
            box=None,
            show_header=True,
            header_style="dim",
            padding=(0, 2, 0, 0),
        )
        sugg.add_column("Name", style="cyan", no_wrap=True)
        sugg.add_column("Download", justify="right", no_wrap=True)
        sugg.add_column("Min RAM", justify="right", no_wrap=True)
        sugg.add_column("Notes", ratio=1, overflow="fold")
        for spec, report in fitting:
            sugg.add_row(
                spec.name,
                f"~{spec.size_gb:.1f} GB",
                f"{spec.min_ram_gb:.0f} GB",
                spec.notes or "coding model",
            )
        console.print(sugg)
        console.print(
            "[dim]  install: dede model pull <name>   ·   any other Ollama model also works[/dim]"
        )

    console.print()
    return 0


def cmd_check(model: str, *, config: AppConfig | None = None) -> int:
    cfg = config or build_config(__import__("pathlib").Path.cwd())
    report = check_model_compatibility(model, device_preference=cfg.ai.device)
    spec = report.spec
    console.print(f"Model: {spec.name} ({spec.display_name})")
    console.print(f"Estimated download: ~{spec.size_gb:.1f}GB")
    console.print(
        f"Recommended RAM: ≥{spec.min_ram_gb:.1f}GB | VRAM: ≥{spec.min_vram_gb:.1f}GB (0=CPU OK)"
    )
    console.print(
        f"Host: RAM {report.host.ram_total_gb:.1f}GB / avail {report.host.ram_available_gb:.1f}GB | "
        f"disk {report.host.disk_free_gb:.1f}GB | VRAM {report.host.vram_total_gb:.1f}GB"
    )
    color = {
        Compatibility.COMPATIBLE: "green",
        Compatibility.MARGINAL: "yellow",
        Compatibility.INCOMPATIBLE: "red",
    }[report.level]
    console.print(f"Compatibility: [{color}]{report.level.value}[/{color}]")
    for reason in report.reasons:
        console.print(f"  • {reason}")
    if report.recommendations:
        console.print("Recommendations:")
        for rec in report.recommendations:
            console.print(f"  → {rec}")
    return 0 if report.ok_to_download else 1


def cmd_recommend(*, config: AppConfig | None = None) -> int:
    cfg = config or build_config(__import__("pathlib").Path.cwd())
    picks = recommend_models(device_preference=cfg.ai.device, coding_only=True)
    if not picks:
        console.print("[red]No compatible coding models found for this host.[/red]")
        return 1
    console.print("Recommended models for this host")
    console.print("-" * 60)
    for spec, report in picks:
        why = (spec.notes or report.reasons[0])[:60]
        console.print(f"  {spec.name:28} {spec.size_gb:5.1f}GB  {report.level.value:12} {why}")
    best = picks[0][0].name
    console.print(f"Suggested: [bold]{best}[/bold]  →  dede model pull {best}")
    return 0


def cmd_pull(
    model: str,
    *,
    force: bool = False,
    yes: bool = False,
    config: AppConfig | None = None,
) -> int:
    cfg = config or build_config(__import__("pathlib").Path.cwd())

    # The model persists in the 'ollama-data' Docker volume and survives
    # reinstalls/updates — never re-download something that is already there.
    pre_client = _client_from_config(cfg)
    if not pre_client.is_reachable() and "ollama:" in pre_client.host:
        pre_client = OllamaClient(host="http://127.0.0.1:11434", model=model)
    if pre_client.is_reachable() and pre_client.model_installed(model):
        console.print(f"Model already installed: {model} — no download needed.")
        console.print(
            "It is stored in the persistent 'ollama-data' volume and survives reinstalls/updates."
        )
        set_preferred_model(model)
        console.print(f"Active model set to {model}")
        return 0

    report = check_model_compatibility(model, device_preference=cfg.ai.device)
    cmd_check(model, config=cfg)

    if report.level == Compatibility.INCOMPATIBLE and not force:
        console.print(
            "[red]Download blocked: model is not compatible with current system resources.[/red]"
        )
        console.print("Use --force to override (not recommended), or pick another model.")
        return 2

    if report.level == Compatibility.MARGINAL and not force and not yes:
        console.print("[yellow]Warning: model is only marginally compatible.[/yellow]")
        answer = (
            console.input("Do you want to download it anyway? Type 'yes' or 'no' [default: no]: ")
            .strip()
            .lower()
        )
        if answer in {"y", "yes"}:
            console.print("Answer 'yes' received — continuing download.")
        else:
            console.print("Answer 'no' (or empty) — download cancelled.")
            return 1

    client = _client_from_config(cfg)
    if not client.is_reachable():
        # Try compose service name only when explicitly configured
        alt = OllamaClient(host=cfg.ai.ollama_host, model=model)
        if alt.is_reachable():
            client = alt
        else:
            console.print(
                f"[red]Ollama is not reachable at {client.host}.[/red]\n"
                "Start it with: docker compose up -d ollama\n"
                "If using host networking, set DEDE_OLLAMA_HOST=http://127.0.0.1:11434"
            )
            return 3

    if client.model_installed(model):
        console.print(f"Model already installed: {model}")
        set_preferred_model(model)
        console.print(f"Active model set to {model}")
        return 0

    console.print(f"Pulling {model} (~{report.spec.size_gb:.1f}GB) — this may take a while...")

    def _fmt_bytes(n: int) -> str:
        if n <= 0:
            return "0B"
        units = ["B", "KB", "MB", "GB", "TB"]
        value = float(n)
        for unit in units:
            if value < 1024 or unit == units[-1]:
                return f"{value:.1f}{unit}" if unit != "B" else f"{int(value)}B"
            value /= 1024
        return f"{n}B"

    last_line = {"text": ""}

    def on_progress(status: str, completed: int, total: int) -> None:
        if total > 0:
            pct = min(100.0, (completed / total) * 100.0)
            bar_w = 28
            filled = int(bar_w * pct / 100.0)
            bar = "█" * filled + "░" * (bar_w - filled)
            line = f"\r  [{bar}] {pct:5.1f}%  {_fmt_bytes(completed)}/{_fmt_bytes(total)}  {status[:40]:<40}"
        else:
            line = f"\r  … {status[:70]:<70}"
        # Avoid flooding identical lines
        if line != last_line["text"]:
            print(line, end="", flush=True)
            last_line["text"] = line

    ok, message = client.pull_model(model, on_progress=on_progress)
    print()  # newline after progress
    if not ok:
        console.print(f"[red]Pull failed: {message}[/red]")
        return 3
    console.print(f"[green]Pull OK:[/green] {message}")
    set_preferred_model(model)
    console.print(f"Active model set to {model} (saved under ~/.config/dede/settings.yml)")
    return 0


def cmd_use(model: str, *, config: AppConfig | None = None, assume_yes: bool = False) -> int:
    cfg = config or build_config(__import__("pathlib").Path.cwd())
    report = check_model_compatibility(model, device_preference=cfg.ai.device)
    if report.level == Compatibility.INCOMPATIBLE:
        console.print("[yellow]Warning: selected model looks incompatible with this host.[/yellow]")
        for reason in report.reasons:
            console.print(f"  • {reason}")
    path = set_preferred_model(model)
    console.print(f"Active model → {model}")
    console.print(f"Saved: {path}")
    console.print("Also export for this shell: " f"export DEDE_MODEL={model}")
    cfg.ai.model = model
    from dede.llm.ensure import ensure_model_installed

    available, status = ensure_model_installed(
        cfg,
        interactive=True,
        assume_yes=assume_yes,
    )
    if not available:
        console.print(f"[yellow]{status}[/yellow]")
        return 0
    console.print(f"[green]{status}[/green]")
    return 0


def cmd_show(*, config: AppConfig | None = None) -> int:
    cfg = config or build_config(__import__("pathlib").Path.cwd())
    preferred = get_preferred_model()
    console.print(f"Config default: {cfg.ai.model}")
    console.print(f"User preference: {preferred or '(none)'}")
    console.print(f"Effective: {preferred or cfg.ai.model}")
    console.print(f"Device: {cfg.ai.device}")
    console.print(f"Ollama host: {cfg.ai.ollama_host}")
    spec = resolve_model_spec(preferred or cfg.ai.model)
    console.print(
        f"Spec: ~{spec.size_gb:.1f}GB, min RAM {spec.min_ram_gb:.1f}GB, "
        f"min VRAM {spec.min_vram_gb:.1f}GB"
    )
    return 0
