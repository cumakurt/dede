"""Doctor checks for local tooling and offline readiness."""

from __future__ import annotations

from pathlib import Path

from rich.console import Console

from dede.analyzers.semgrep import default_rules_dir
from dede.config import AppConfig
from dede.llm.client import OllamaClient
from dede.utils.process import run_command, which

console = Console()


def run_doctor(config: AppConfig, report_dir: Path | None = None) -> int:
    checks: list[tuple[str, bool, str]] = []

    def add(name: str, ok: bool, detail: str) -> None:
        checks.append((name, ok, detail))

    for binary in ("semgrep", "gitleaks", "bandit", "ruff"):
        path = which(binary)
        add(binary, path is not None, path or "not found")

    # Native engine — always available; rules must load.
    from dede.engine.analyzer import DedeEngineAnalyzer, default_engine_rules_dir

    engine = DedeEngineAnalyzer()
    engine_rules = default_engine_rules_dir()
    engine_rule_count = engine.rule_count()
    add(
        "dede engine",
        engine_rule_count > 0 and not engine.load_error,
        f"{engine_rule_count} rules, {engine_rules}"
        if engine_rule_count
        else f"no rules at {engine_rules}",
    )

    lizard_ok = which("lizard") is not None
    if not lizard_ok:
        # python module may still work
        result = run_command(["python", "-c", "import lizard; print('ok')"], timeout=20)
        lizard_ok = result.returncode == 0
    add("lizard", lizard_ok, "available" if lizard_ok else "not found")

    rules = default_rules_dir()
    rules_ok = rules.is_dir() and (any(rules.rglob("*.yaml")) or any(rules.rglob("*.yml")))
    add("semgrep rules", rules_ok, str(rules))

    packs_dir = rules / "packs"
    custom_dir = rules / "custom"
    pack_count = len(list(packs_dir.glob("*.yml"))) if packs_dir.is_dir() else 0
    custom_count = len(list(custom_dir.glob("*.yml"))) if custom_dir.is_dir() else 0
    manifest_ok = (rules / "MANIFEST.yml").is_file()
    all_ok = (packs_dir / "all.yml").is_file() if packs_dir.is_dir() else False
    add(
        "semgrep packs",
        pack_count > 0 and custom_count > 0,
        f"{pack_count} packs, {custom_count} custom, manifest={'yes' if manifest_ok else 'no'}",
    )
    add(
        "semgrep full dump (r/all)",
        all_ok,
        "packs/all.yml" if all_ok else "missing — run: dede rules update",
    )
    add(
        "semgrep profile",
        config.semgrep.profile in {"smart", "full", "custom-only"},
        config.semgrep.profile,
    )
    client = OllamaClient(config)
    reachable = client.is_reachable()
    add("ollama reachable", reachable, config.ai.ollama_host)
    model_ok = reachable and client.model_installed()
    add("ollama model", model_ok, config.ai.model)

    # PDF engine
    try:
        import weasyprint  # noqa: F401

        add("weasyprint", True, "importable")
    except Exception as exc:  # noqa: BLE001
        add("weasyprint", False, str(exc)[:120])

    out = report_dir or Path(config.reports.output)
    writable = True
    detail = str(out)
    try:
        out.mkdir(parents=True, exist_ok=True)
        probe = out / ".write_probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
    except OSError as exc:
        writable = False
        detail = str(exc)
    add("writable reports", writable, detail)

    add(
        "network isolation compatible",
        True,
        "use: docker run --rm --network none dede-scanner:1.10.0 scan /workspace --no-ai",
    )

    optional_checks = {
        "semgrep",
        "gitleaks",
        "bandit",
        "ruff",
        "lizard",
        "semgrep rules",
        "semgrep packs",
        "semgrep full dump (r/all)",
        "ollama reachable",
        "ollama model",
        "weasyprint",
    }

    console.print()
    console.print("Dede doctor", soft_wrap=True)
    console.print("-" * 60, soft_wrap=True)
    for name, ok_flag, detail in checks:
        if ok_flag:
            status = "[green]OK[/green]"
        elif name in optional_checks:
            status = "[yellow]OPTIONAL[/yellow]"
        else:
            status = "[red]FAIL[/red]"
        console.print(f"  {status} {name:32} {detail}", soft_wrap=True)
    console.print()

    required_fail = any(
        (not ok) and name not in optional_checks for name, ok, _ in checks
    )
    return 1 if required_fail else 0
