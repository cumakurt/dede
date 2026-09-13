"""Tests for missing-model download confirmation."""

from __future__ import annotations

from dede.config import AIConfig, AppConfig
from dede.llm.ensure import ensure_model_installed


class _FakeClient:
    def __init__(self, *, reachable: bool = True, installed: bool = False) -> None:
        self.host = "http://127.0.0.1:11434"
        self.model = "qwen2.5-coder:1.5b"
        self._reachable = reachable
        self._installed = installed

    def is_reachable(self) -> bool:
        return self._reachable

    def model_installed(self, name: str | None = None) -> bool:
        return self._installed


def test_ensure_skips_when_declined(monkeypatch):
    cfg = AppConfig(ai=AIConfig(model="qwen2.5-coder:1.5b", enabled=True))

    monkeypatch.setattr(
        "dede.llm.ensure._client_from_config",
        lambda config: _FakeClient(installed=False),
    )
    monkeypatch.setattr(
        "dede.llm.ensure.check_model_compatibility",
        lambda *a, **k: type(
            "R",
            (),
            {"level": __import__("dede.llm.resources", fromlist=["Compatibility"]).Compatibility.COMPATIBLE, "reasons": []},
        )(),
    )
    monkeypatch.setattr(
        "dede.llm.ensure.resolve_model_spec",
        lambda name: type("S", (), {"size_gb": 1.0})(),
    )
    monkeypatch.setattr("dede.llm.ensure.sys.stdin.isatty", lambda: True)

    pulled = {"called": False}

    def _no_pull(*a, **k):
        pulled["called"] = True
        return 0

    monkeypatch.setattr("dede.llm.ensure.cmd_pull", _no_pull)

    ok, msg = ensure_model_installed(
        cfg,
        interactive=True,
        assume_yes=False,
        confirm=lambda _m: False,
    )
    assert ok is False
    assert "declined" in msg
    assert pulled["called"] is False


def test_ensure_pulls_when_confirmed(monkeypatch):
    cfg = AppConfig(ai=AIConfig(model="qwen2.5-coder:1.5b", enabled=True))
    Compatibility = __import__("dede.llm.resources", fromlist=["Compatibility"]).Compatibility

    state = {"installed": False}

    class Client(_FakeClient):
        def model_installed(self, name: str | None = None) -> bool:
            return state["installed"]

    monkeypatch.setattr("dede.llm.ensure._client_from_config", lambda config: Client())
    monkeypatch.setattr(
        "dede.llm.ensure.check_model_compatibility",
        lambda *a, **k: type("R", (), {"level": Compatibility.COMPATIBLE, "reasons": []})(),
    )
    monkeypatch.setattr(
        "dede.llm.ensure.resolve_model_spec",
        lambda name: type("S", (), {"size_gb": 1.0})(),
    )
    monkeypatch.setattr("dede.llm.ensure.sys.stdin.isatty", lambda: True)

    def _pull(*a, **k):
        state["installed"] = True
        return 0

    monkeypatch.setattr("dede.llm.ensure.cmd_pull", _pull)

    ok, msg = ensure_model_installed(
        cfg,
        interactive=True,
        assume_yes=False,
        confirm=lambda _m: True,
    )
    assert ok is True
    assert "downloaded" in msg


def test_ensure_already_installed(monkeypatch):
    cfg = AppConfig(ai=AIConfig(model="gemma4:26b"))
    monkeypatch.setattr(
        "dede.llm.ensure._client_from_config",
        lambda config: _FakeClient(installed=True),
    )
    ok, msg = ensure_model_installed(cfg, interactive=False, assume_yes=False)
    assert ok is True
    assert "ready" in msg
