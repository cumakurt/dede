"""Model identity and optional enrichment failure regressions."""

import json

import httpx
import pytest

from dede.config import AIConfig, AppConfig
from dede.llm import manage as model_manage
from dede.llm.cache import AICache
from dede.llm.client import OllamaClient
from dede.llm.enrichment import enrich_findings
from dede.models import Finding


@pytest.mark.parametrize(
    "in_container,expected_host",
    [
        ("1", "http://ollama:11434"),
        ("0", "http://127.0.0.1:11434"),
    ],
)
def test_model_management_uses_correct_network_and_config(monkeypatch, in_container, expected_host):
    monkeypatch.setenv("DEDE_IN_CONTAINER", in_container)
    config = AppConfig(
        ai=AIConfig(ollama_host="http://ollama:11434", request_timeout_seconds=17, max_context=4096)
    )
    client = model_manage._client_from_config(config)
    assert client.host == expected_host
    assert client.timeout == 17
    assert client.max_context == 4096
    assert config.ai.ollama_host == "http://ollama:11434"


@pytest.mark.parametrize(
    "stream,expected",
    [
        ('{"status":"success"}\n', True),
        ('{"status":"downloading","completed":10,"total":100}\n', False),
        ("", False),
        ("[]\n", False),
        ('{"error":"download failed"}\n', False),
    ],
)
def test_model_pull_requires_explicit_success(monkeypatch, stream, expected):
    original_client = httpx.Client
    transport = httpx.MockTransport(lambda request: httpx.Response(200, text=stream))
    monkeypatch.setattr(
        httpx, "Client", lambda **kwargs: original_client(transport=transport, **kwargs)
    )
    ok, message = OllamaClient().pull_model("example:latest")
    assert ok is expected
    assert message


def test_model_lookup_requires_requested_tag(monkeypatch):
    client = OllamaClient(model="example:large")
    monkeypatch.setattr(
        client,
        "list_installed",
        lambda: [
            {"name": "example:small", "digest": "small-digest"},
            {"name": "example:large", "digest": "large-digest"},
        ],
    )
    assert client.model_digest() == "large-digest"
    assert not client.model_installed("example:missing")
    assert client.model_digest("example:missing") == ""
    assert not client.model_installed("example")


def test_untagged_model_means_latest(monkeypatch):
    client = OllamaClient(model="example")
    monkeypatch.setattr(
        client,
        "list_installed",
        lambda: [
            {"name": "example:latest", "digest": "latest-digest"},
        ],
    )
    assert client.model_installed()
    assert client.model_digest() == "latest-digest"


@pytest.mark.parametrize("payload", [[], "text", 1, None])
def test_cache_rejects_non_object_payloads(tmp_path, payload):
    cache = AICache(tmp_path)
    cache._path("fp", "context").write_text(json.dumps(payload))
    assert cache.get("fp", "context") is None


def test_pull_skips_when_model_already_installed(monkeypatch, capsys):
    """An installed model must never trigger a re-download (persistent volume)."""
    from dede.llm.manage import set_preferred_model

    cfg = AppConfig(ai=AIConfig(model="example:7b", enabled=True))

    class _InstalledClient:
        host = "http://127.0.0.1:11434"

        def is_reachable(self) -> bool:
            return True

        def model_installed(self, name: str | None = None) -> bool:
            return True

    monkeypatch.setattr("dede.llm.manage._client_from_config", lambda config: _InstalledClient())
    monkeypatch.setattr(model_manage, "set_preferred_model", lambda name: None)

    def _fail_pull(*a, **k):
        raise AssertionError("pull_model must not be called for an installed model")

    monkeypatch.setattr(OllamaClient, "pull_model", _fail_pull)

    code = model_manage.cmd_pull("example:7b", config=cfg)
    out = capsys.readouterr().out
    assert code == 0
    assert "already installed" in out
    assert "no download needed" in out


@pytest.fixture
def llm_client(monkeypatch):
    monkeypatch.setattr(OllamaClient, "is_reachable", lambda self: True)
    monkeypatch.setattr(OllamaClient, "model_installed", lambda self: True)
    monkeypatch.setattr(OllamaClient, "model_digest", lambda self: "test-digest")
    calls = []

    def chat(self, *args):
        calls.append(self.model)
        return {
            "summary": self.model,
            "technical_explanation": "Review of the supplied finding.",
            "impact": "",
            "exploitability": "",
            "false_positive_probability": "MEDIUM",
            "recommended_fix": "Inspect the affected call and add an appropriate guard.",
            "secure_code_example": "",
            "confidence": 0.5,
            "verdict": "NEEDS_CONTEXT",
            "rationale": "Source context was not provided.",
            "assumptions": "Runtime input origin is unknown.",
            "verification": "Add a test with untrusted input.",
        }

    monkeypatch.setattr(OllamaClient, "chat_json", chat)
    return calls


def test_enrichment_survives_unavailable_cache(tmp_path, llm_client):
    cache = tmp_path / "not-a-directory"
    cache.write_text("occupied")
    finding = Finding(tool="test", rule_id="r", file="missing.py", fingerprint="fp")
    result, used, _, _ = enrich_findings([finding], tmp_path, AppConfig(), cache_dir=cache)
    assert used
    assert result[0].summary


def test_enrichment_cache_tracks_model_and_prompt(tmp_path, llm_client):
    cfg = AppConfig()
    for model, message in [
        ("first:latest", "one"),
        ("second:latest", "one"),
        ("second:latest", "two"),
    ]:
        cfg.ai.model = model
        finding = Finding(
            tool="test", rule_id="r", file="missing.py", fingerprint="fp", message=message
        )
        result, used, _, _ = enrich_findings([finding], tmp_path, cfg, cache_dir=tmp_path / "cache")
        assert used
        assert result[0].summary == model
    assert len(llm_client) == 3


def test_failed_cache_write_preserves_previous_entry(tmp_path, monkeypatch):
    cache = AICache(tmp_path)
    cache.set("fp", "context", {"summary": "previous"})

    def fail_replace(*args):
        raise OSError("disk unavailable")

    monkeypatch.setattr("dede.llm.cache.os.replace", fail_replace)
    cache.set("fp", "context", {"summary": "new"})
    assert cache.get("fp", "context") == {"summary": "previous"}
    assert list(tmp_path.iterdir()) == [cache._path("fp", "context")]


def test_enrichment_survives_cache_write_error(tmp_path, llm_client, monkeypatch):
    def fail_replace(*args):
        raise OSError("disk unavailable")

    monkeypatch.setattr("dede.llm.cache.os.replace", fail_replace)
    finding = Finding(tool="test", rule_id="r", file="missing.py", fingerprint="fp")
    result, used, _, _ = enrich_findings(
        [finding], tmp_path, AppConfig(), cache_dir=tmp_path / "cache"
    )
    assert used
    assert result[0].summary
