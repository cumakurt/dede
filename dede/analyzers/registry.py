"""Analyzer registry with built-in and third-party plugin discovery."""

from __future__ import annotations

from importlib import metadata

from dede.analyzers.bandit import BanditAnalyzer
from dede.agent_security import AgentSecurityAnalyzer
from dede.authorization import ExperimentalAuthorizationAnalyzer
from dede.analyzers.base import Analyzer
from dede.analyzers.code_smell import CodeSmellAnalyzer
from dede.analyzers.duplicate import DuplicateAnalyzer
from dede.analyzers.gitleaks import GitleaksAnalyzer
from dede.analyzers.gosec import GosecAnalyzer
from dede.analyzers.govet import GoVetAnalyzer
from dede.analyzers.lizard import LizardAnalyzer
from dede.analyzers.ruff import RuffAnalyzer
from dede.analyzers.semgrep import SemgrepAnalyzer
from dede.semantic.python_ast import PythonSemanticAnalyzer
from dede.semantic.polyglot import PolyglotSemanticAnalyzer
from dede.sca import DependencyReachabilityAnalyzer
from dede.security_hardening import SecurityHardeningAnalyzer

PLUGIN_GROUP = "dede.analyzers"


def _builtin_analyzers() -> list[Analyzer]:
    # Imported lazily: dede.engine.analyzer imports dede.analyzers.base, whose
    # package __init__ runs this registry — a module-level import would cycle.
    from dede.engine.analyzer import DedeEngineAnalyzer

    return [
        DedeEngineAnalyzer(),
        PythonSemanticAnalyzer(),
        PolyglotSemanticAnalyzer(),
        DependencyReachabilityAnalyzer(),
        SecurityHardeningAnalyzer(),
        AgentSecurityAnalyzer(),
        ExperimentalAuthorizationAnalyzer(),
        SemgrepAnalyzer(),
        DuplicateAnalyzer(),
        CodeSmellAnalyzer(),
        GitleaksAnalyzer(),
        BanditAnalyzer(),
        RuffAnalyzer(),
        LizardAnalyzer(),
        GoVetAnalyzer(),
        GosecAnalyzer(),
    ]


def _plugin_analyzers() -> list[Analyzer]:
    """Load installed analyzers from the ``dede.analyzers`` entry-point group.

    Invalid plugins are ignored by design: an optional extension must never
    prevent the deterministic built-in scanner from starting.
    """
    loaded: list[Analyzer] = []
    try:
        entries = metadata.entry_points().select(group=PLUGIN_GROUP)
    except (AttributeError, TypeError):  # pragma: no cover - old importlib API fallback
        entries = metadata.entry_points().get(PLUGIN_GROUP, [])
    for entry in entries:
        try:
            obj = entry.load()
            analyzer = obj() if isinstance(obj, type) else obj
            if isinstance(analyzer, Analyzer):
                loaded.append(analyzer)
        except Exception:  # noqa: BLE001 - third-party plugin isolation boundary
            continue
    return loaded


def get_analyzers() -> list[Analyzer]:
    analyzers = [*_builtin_analyzers(), *_plugin_analyzers()]
    # Stable order and deterministic handling of accidentally duplicated names.
    unique: dict[str, Analyzer] = {}
    for analyzer in analyzers:
        unique.setdefault(analyzer.name, analyzer)
    return list(unique.values())
