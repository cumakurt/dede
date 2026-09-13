"""Ensure the configured Ollama model is available (prompt to pull if missing)."""

from __future__ import annotations

import sys
from collections.abc import Callable

from rich.console import Console

from dede.config import AppConfig
from dede.llm.catalog import resolve_model_spec
from dede.llm.client import OllamaClient
from dede.llm.manage import _client_from_config, cmd_pull
from dede.llm.resources import Compatibility, check_model_compatibility

console = Console(stderr=True)

ConfirmFn = Callable[[str], bool]


def _default_confirm(message: str) -> bool:
    try:
        answer = (
            console.input(f"[yellow]{message}[/yellow] Type 'yes' or 'no' [default: no]: ")
            .strip()
            .lower()
        )
    except (EOFError, KeyboardInterrupt):
        console.print()
        return False
    if answer in {"y", "yes"}:
        console.print("Answer 'yes' received — starting download.")
        return True
    console.print("Answer 'no' (or empty) — download skipped.")
    return False


def ensure_model_installed(
    config: AppConfig,
    *,
    interactive: bool = True,
    assume_yes: bool = False,
    offline: bool | None = None,
    confirm: ConfirmFn | None = None,
) -> tuple[bool, str]:
    """Make sure ``config.ai.model`` is installed in Ollama.

    If missing:
    - interactive + confirm → offer download
    - assume_yes → download without asking
    - otherwise → return False with guidance

    Returns (available, status_message).
    """
    model = config.ai.model
    offline_mode = config.offline if offline is None else offline
    client = _client_from_config(config)
    if not client.is_reachable() and "ollama:" in client.host:
        client = OllamaClient(host="http://127.0.0.1:11434", model=model)

    if not client.is_reachable():
        return False, f"Ollama not reachable at {client.host}"

    if client.model_installed(model):
        return True, f"model ready: {model}"

    if offline_mode:
        return (
            False,
            f"offline: model not installed ({model}); run: dede model pull {model} while online",
        )

    # Missing model
    try:
        spec = resolve_model_spec(model)
        size_hint = f" (~{spec.size_gb:.1f}GB)"
    except Exception:  # noqa: BLE001
        size_hint = ""

    report = check_model_compatibility(model, device_preference=config.ai.device)
    console.print(f"[yellow]Model not installed:[/yellow] [bold]{model}[/bold]{size_hint}")
    console.print(
        f"  Compatibility: {report.level.value}"
        + (f" — {report.reasons[0]}" if report.reasons else "")
    )

    if report.level == Compatibility.INCOMPATIBLE and not assume_yes:
        console.print(
            "[red]Download blocked: model looks incompatible with this host.[/red]\n"
            f"  Pull manually with force if you insist: dede model pull {model} --force"
        )
        return False, f"skipped: model not installed and incompatible ({model})"

    should_pull = False
    if assume_yes:
        should_pull = True
        console.print("  Auto-confirm enabled (-y): downloading...")
    elif interactive and (confirm is not None or sys.stdin.isatty()):
        ask = confirm or _default_confirm
        should_pull = ask(
            f"The AI model '{model}' is not installed. "
            f"Do you want to download it now? (yes or no)"
        )
        if not should_pull:
            console.print(
                "  [dim]Skipped download. AI enrichment will be disabled for this scan.[/dim]\n"
                f"  Later: dede model pull {model}"
            )
            return False, f"skipped: model not installed ({model}); download declined"
    else:
        console.print(
            f"  Non-interactive session — not downloading.\n"
            f"  Run: dede model pull {model}\n"
            f"  Or re-run scan with -y to auto-download."
        )
        return False, f"skipped: model not installed ({model}) — run: dede model pull {model}"

    code = cmd_pull(
        model, force=report.level == Compatibility.INCOMPATIBLE, yes=True, config=config
    )
    if code != 0:
        return False, f"skipped: failed to pull model ({model})"

    # Re-check
    client = _client_from_config(config)
    if not client.model_installed(model):
        return False, f"skipped: pull finished but model still missing ({model})"
    return True, f"model downloaded: {model}"
